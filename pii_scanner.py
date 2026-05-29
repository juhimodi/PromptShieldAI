"""
pii_scanner.py — Comprehensive PII & Secrets Scanner
Detects PII even through common evasion / obfuscation techniques:
  1. Spaced / hyphenated tokens  (ABCDE 1234 F, 98765-43210)
  2. Obfuscated email            (john [dot] doe [at] example [dot] com)
  3. Base64 encoding             (QUJDREUxMjM0Rg==)
  4. Hex encoding                (\x41\x42\x43...)
  5. Unicode lookalikes          (Ａ instead of A)
  6. ROT13                       (NOPQR1234S → ABCDE1234F)
  7. URL encoding                (%41%42%43...)
  8. Reverse text                (F4321EDCBA)
  9. Zero-width character noise  (A​B​C​D​E​1​2​3​4​F)
 10. Mixed separator noise       (AB.CD.E.1234.F)
"""

import re
import base64
import binascii
import codecs
import urllib.parse
import unicodedata

# =========================================================
# UNICODE LOOKALIKE NORMALISATION MAP
# Maps visually similar Unicode chars → ASCII equivalents
# =========================================================
_UNICODE_MAP = str.maketrans({
    # Letters
    'А':'A','В':'B','С':'C','Е':'E','Н':'H','І':'I','Ј':'J','К':'K',
    'М':'M','О':'O','Р':'P','Ѕ':'S','Т':'T','Х':'X','Υ':'Y','Ζ':'Z',
    'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','ѕ':'s',
    # Fullwidth ASCII (Ａ–Ｚ, ａ–ｚ, ０–９)
    **{chr(0xFF01 + i): chr(0x21 + i) for i in range(94)},
    # Superscript digits
    '⁰':'0','¹':'1','²':'2','³':'3','⁴':'4',
    '⁵':'5','⁶':'6','⁷':'7','⁸':'8','⁹':'9',
    # Common punctuation lookalikes
    '\u2024':'.', '\u0387':'.', '\u2027':'.',
})

# Zero-width characters to strip
_ZERO_WIDTH = re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]')

# =========================================================
# NORMALISATION PIPELINE
# Produces a "clean" version of text for regex scanning
# =========================================================

def _normalize(text: str) -> str:
    """
    Normalise text through ALL obfuscation layers so regexes always
    see clean ASCII. Returns a single normalised string.
    """
    # 1. Strip zero-width noise characters
    text = _ZERO_WIDTH.sub('', text)

    # 2. Unicode NFKC (decomposes ligatures, normalises lookalikes)
    text = unicodedata.normalize('NFKC', text)

    # 3. Apply our lookalike map
    text = text.translate(_UNICODE_MAP)

    return text


def _deobfuscate_email(text: str) -> str:
    """
    Convert email obfuscation patterns back to standard form.
    Handles:  [at] / (at) / AT  and  [dot] / (dot) / DOT
    Also handles variants like john.doe AT example DOT com
    """
    t = text
    # [at], (at), {at}, " at " → @
    t = re.sub(r'\s*[\[\({\s]at[\]\)}\s]\s*', '@', t, flags=re.IGNORECASE)
    t = re.sub(r'\s+at\s+', '@', t, flags=re.IGNORECASE)
    # [dot], (dot), {dot}, " dot " → .
    t = re.sub(r'\s*[\[\({\s]dot[\]\)}\s]\s*', '.', t, flags=re.IGNORECASE)
    t = re.sub(r'\s+dot\s+', '.', t, flags=re.IGNORECASE)
    return t


def _decode_hex(text: str) -> str:
    r"""Decode \xNN hex escape sequences in text."""
    try:
        return re.sub(
            r'\\x([0-9a-fA-F]{2})',
            lambda m: chr(int(m.group(1), 16)),
            text
        )
    except Exception:
        return text


def _decode_url(text: str) -> str:
    """URL-decode percent-encoded sequences like %41%42."""
    try:
        decoded = urllib.parse.unquote(text)
        return decoded if decoded != text else text
    except Exception:
        return text


def _extract_base64_decoded(text: str) -> list[dict]:
    """
    Find all Base64 tokens, decode them, return
    [{encoded, decoded}] for printable results.
    """
    segments = []
    pattern = r'\b[A-Za-z0-9+/]{8,}={0,2}\b'
    for m in re.finditer(pattern, text):
        token = m.group()
        padded = token + '=' * ((4 - len(token) % 4) % 4)
        try:
            raw = base64.b64decode(padded)
            decoded = raw.decode('utf-8')
            if decoded.isprintable() and len(decoded.strip()) >= 5:
                segments.append({'encoded': token, 'decoded': decoded})
        except (binascii.Error, UnicodeDecodeError):
            continue
    return segments


def _decode_rot13(text: str) -> str:
    return codecs.decode(text, 'rot_13')


def _strip_separators(text: str) -> str:
    """
    Remove common separator-noise characters that hackers insert INSIDE
    tokens to break regex:  hyphens, dots, underscores, slashes, and SPACES
    when they appear between alphanumeric chars.
    E.g.  ABCDE 1234 F  →  ABCDE1234F
          1234-5678-9012 →  123456789012
    """
    # Remove hyphens, dots, underscores, slashes between alphanum chars
    t = re.sub(r'(?<=[A-Za-z0-9])[.\-_/\\](?=[A-Za-z0-9])', '', text)
    # Also remove SPACES between alphanumeric chars (e.g. ABCDE 1234 F)
    t = re.sub(r'(?<=[A-Za-z0-9]) (?=[A-Za-z0-9])', '', t)
    return t


def _build_all_variants(text: str) -> list[dict]:
    """
    Return a list of {text, source_label} dicts representing every
    decoded / normalised variant of the input that should be scanned.
    """
    variants = []

    # Always scan the raw input
    variants.append({'text': text, 'label': None})

    norm = _normalize(text)
    if norm != text:
        variants.append({'text': norm, 'label': 'Unicode-normalised'})

    # Separator-stripped version
    stripped = _strip_separators(norm)
    if stripped != norm:
        variants.append({'text': stripped, 'label': 'Separator-stripped'})

    # Email deobfuscation
    deob_email = _deobfuscate_email(norm)
    if deob_email != norm:
        variants.append({'text': deob_email, 'label': 'Email-deobfuscated'})

    # Hex decoded
    hex_dec = _decode_hex(norm)
    if hex_dec != norm:
        variants.append({'text': hex_dec, 'label': 'Hex-decoded'})
        variants.append({'text': _strip_separators(hex_dec), 'label': 'Hex-decoded + Separator-stripped'})

    # URL decoded
    url_dec = _decode_url(norm)
    if url_dec != norm:
        variants.append({'text': url_dec, 'label': 'URL-decoded'})
        variants.append({'text': _strip_separators(url_dec), 'label': 'URL-decoded + Separator-stripped'})

    # ROT13
    rot = _decode_rot13(norm)
    if rot != norm:
        variants.append({'text': rot, 'label': 'ROT13-decoded'})
        variants.append({'text': _strip_separators(rot), 'label': 'ROT13-decoded + Separator-stripped'})

    # Reversed text
    rev = norm[::-1]
    variants.append({'text': rev, 'label': 'Reversed'})
    variants.append({'text': _strip_separators(rev), 'label': 'Reversed + Separator-stripped'})

    # Base64 decoded segments
    for seg in _extract_base64_decoded(norm):
        decoded_stripped = _strip_separators(seg['decoded'])
        variants.append({'text': seg['decoded'],   'label': f'Base64-decoded (from {seg["encoded"][:20]})'})
        if decoded_stripped != seg['decoded']:
            variants.append({'text': decoded_stripped, 'label': f'Base64-decoded + Separator-stripped (from {seg["encoded"][:20]})'})

    # Combine: URL-decode THEN strip separators on the original too
    combined = _strip_separators(_deobfuscate_email(norm))
    if combined not in [v['text'] for v in variants]:
        variants.append({'text': combined, 'label': 'Email-deobfuscated + Separator-stripped'})

    return variants


# =========================================================
# PII PATTERNS  (match on CLEAN / normalised text)
# =========================================================

PII_PATTERNS = {

    "Email Address": [
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
    ],

    "Aadhaar Number": [
        r"(?<!\d)\d{4}\s?\d{4}\s?\d{4}(?!\d)",       # spaced or plain 12 digits
        r"(?<!\d)[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}(?!\d)",
    ],

    "PAN Card Number": [
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",                # works after separator-strip
    ],

    "Indian Mobile Number": [
        r"\b(\+91[\s\-]?)?(0)?[6-9]\d{9}\b",
        r"\b[6-9]\d{2}[\s\-]?\d{3}[\s\-]?\d{4}\b",
    ],

    "International Phone Number": [
        r"\b\+\d{1,3}[\s\-]?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{4}\b",
        r"\b\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b",
    ],

    "Credit / Debit Card Number": [
        r"\b4[0-9]{12}(?:[0-9]{3})?\b",
        r"\b5[1-5][0-9]{14}\b",
        r"\b3[47][0-9]{13}\b",
        r"\b6(?:011|5[0-9]{2})[0-9]{12}\b",
        r"\b(?:\d{4}[\s\-]){3}\d{4}\b",
        r"\b\d{4}[\s\-]\d{6}[\s\-]\d{5}\b",
    ],

    "Social Security Number (SSN)": [
        r"\b(?!000|666|9\d{2})\d{3}[\s\-](?!00)\d{2}[\s\-](?!0000)\d{4}\b",
        r"\b\d{3}-\d{2}-\d{4}\b",
    ],

    "Passport Number": [
        r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b",
        r"\b[A-Z]{1,2}[0-9]{6,9}\b",
    ],

    "Date of Birth": [
        r"\b(0?[1-9]|[12]\d|3[01])[\/\-\.](0?[1-9]|1[0-2])[\/\-\.](19|20)\d{2}\b",
        r"\b(19|20)\d{2}[\/\-\.](0?[1-9]|1[0-2])[\/\-\.](0?[1-9]|[12]\d|3[01])\b",
        r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\s\-,]+\d{1,2}[\s\-,]+(19|20)\d{2}\b",
    ],

    "Vehicle Registration Number (India)": [
        r"\b[A-Z]{2}[\s\-]?\d{2}[\s\-]?[A-Z]{1,2}[\s\-]?\d{4}\b",
    ],

    "IFSC Code (India)": [
        r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    ],

    "Bank Account Number (India)": [
        r"\b\d{9,18}\b(?=.*\b(account|bank|saving|current|IFSC)\b)",
    ],

    "GST Number (India)": [
        r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b",
    ],

    "Voter ID (India)": [
        r"\b[A-Z]{3}[0-9]{7}\b",
    ],

    "Driving Licence (India)": [
        r"\b[A-Z]{2}[0-9]{2}\s?[0-9]{11}\b",
    ],

    "IP Address (Private/Internal)": [
        r"\b(10|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    ],

    "IP Address (Public)": [
        r"\b(?!10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.|127\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    ],

    "Physical Address": [
        r"\b\d{1,5}[\s,]+[A-Za-z\s]+(Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Nagar|Colony|Sector|Block|Plot|Flat|Floor|Building|Society|Apartment|Layout)\b",
        r"\b(Flat|Apt|House|Plot|Door)\s*(No\.?|Number|#)?\s*\d+[A-Za-z]?\b",
    ],

    "Full Name (Contextual)": [
        r"(?i)\b(name|full\s+name|patient|customer|employee|user)\s*[:\-=]\s*[A-Z][a-z]+\s+[A-Z][a-z]+",
        r"(?i)\b(Mr|Ms|Mrs|Dr)\.?\s+[A-Z][a-z]+\s+[A-Z][a-z]+",
    ],
}

# =========================================================
# SECRET / CREDENTIAL PATTERNS
# =========================================================

SECRET_PATTERNS = {

    "Google API Key": [
        r"AIza[0-9A-Za-z\-_]{35}",
    ],

    "AWS Access Key ID": [
        r"AKIA[0-9A-Z]{16}",
        r"ASIA[0-9A-Z]{16}",
    ],

    "AWS Secret Access Key": [
        r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    ],

    "GitHub / GitLab Token": [
        r"ghp_[0-9a-zA-Z]{36}",
        r"gho_[0-9a-zA-Z]{36}",
        r"github_pat_[0-9a-zA-Z_]{82}",
        r"glpat-[0-9a-zA-Z\-_]{20}",
    ],

    "Stripe API Key": [
        r"sk_live_[0-9a-zA-Z]{24,}",
        r"sk_test_[0-9a-zA-Z]{24,}",
        r"pk_live_[0-9a-zA-Z]{24,}",
    ],

    "Slack Token": [
        r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    ],

    "JWT Token": [
        r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+/=]{10,}",
    ],

    "Private Key / Certificate": [
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        r"-----BEGIN CERTIFICATE-----",
    ],

    "Bearer / OAuth Token": [
        r"(?i)Bearer\s+[A-Za-z0-9\-_.~+/]{20,}=*",
        r"(?i)oauth[_\-]?token\s*[:=]\s*['\"]?[A-Za-z0-9\-_.]{20,}",
    ],

    "Database Connection String": [
        r"(?i)(mysql|postgresql|postgres|mongodb|redis|mssql|oracle):\/\/[^\s]+:[^\s]+@[^\s]+",
        r"(?i)Server\s*=\s*[^;]+;\s*Database\s*=\s*[^;]+;\s*(User|Password)\s*=",
    ],

    "Password in Plain Text": [
        r"(?i)\bpassword\s*[:=]\s*['\"]?\S{6,}",
        r"(?i)\bpasswd\s*[:=]\s*['\"]?\S{6,}",
        r"(?i)\bpwd\s*[:=]\s*['\"]?\S{6,}",
        r"(?i)\bpass\s*[:=]\s*['\"]?\S{6,}",
    ],

    "Internal Security Log / Findings": [
        r"'category':\s*'[A-Za-z\s\(\)]+',\s*'pattern'",
        r'"category":\s*"[A-Za-z\s\(\)]+"',
        r"'mitre':\s*'T\d{4}",
        r'"mitre":\s*"T\d{4}',
    ],

    "Stack Trace / Debug Output": [
        r"Traceback \(most recent call last\)",
        r'File ".*\.py", line \d+',
        r"(?i)\w+Error:\s+\w",
    ],
}

# =========================================================
# MITRE MAPPING
# =========================================================

MITRE_PII = {
    "Email Address":                     "T1589.002 – Gather Victim Identity: Email Addresses",
    "Aadhaar Number":                    "T1589 – Gather Victim Identity Information",
    "PAN Card Number":                   "T1589 – Gather Victim Identity Information",
    "Indian Mobile Number":              "T1589.001 – Gather Victim Identity: Phone Numbers",
    "International Phone Number":        "T1589.001 – Gather Victim Identity: Phone Numbers",
    "Credit / Debit Card Number":        "T1530 – Data from Cloud Storage (Financial PII)",
    "Social Security Number (SSN)":      "T1589 – Gather Victim Identity Information",
    "Passport Number":                   "T1589 – Gather Victim Identity Information",
    "Date of Birth":                     "T1589 – Gather Victim Identity Information",
    "Vehicle Registration Number (India)": "T1589 – Gather Victim Identity Information",
    "IFSC Code (India)":                 "T1589 – Gather Victim Financial Information",
    "Bank Account Number (India)":       "T1589 – Gather Victim Financial Information",
    "GST Number (India)":                "T1589 – Gather Victim Business Information",
    "Voter ID (India)":                  "T1589 – Gather Victim Identity Information",
    "Driving Licence (India)":           "T1589 – Gather Victim Identity Information",
    "IP Address (Private/Internal)":     "T1590.005 – Gather Victim Network Info: IP Addresses",
    "IP Address (Public)":               "T1590.005 – Gather Victim Network Info: IP Addresses",
    "Physical Address":                  "T1589 – Gather Victim Identity Information",
    "Full Name (Contextual)":            "T1589 – Gather Victim Identity Information",
    "Google API Key":                    "T1552.001 – Unsecured Credentials: Credentials In Files",
    "AWS Access Key ID":                 "T1552.005 – Cloud Instance Metadata API",
    "AWS Secret Access Key":             "T1552.005 – Cloud Instance Metadata API",
    "GitHub / GitLab Token":             "T1552.001 – Unsecured Credentials: Credentials In Files",
    "Stripe API Key":                    "T1552.001 – Unsecured Credentials: Credentials In Files",
    "Slack Token":                       "T1552.001 – Unsecured Credentials: Credentials In Files",
    "JWT Token":                         "T1550.001 – Use Alternate Auth Material: Tokens",
    "Private Key / Certificate":         "T1552.004 – Unsecured Credentials: Private Keys",
    "Bearer / OAuth Token":              "T1550.001 – Use Alternate Auth Material: Tokens",
    "Database Connection String":        "T1552.001 – Unsecured Credentials: Credentials In Files",
    "Password in Plain Text":            "T1552 – Unsecured Credentials",
    "Internal Security Log / Findings":  "T1530 – Data from Cloud Storage (Internal Data Leak)",
    "Stack Trace / Debug Output":        "T1082 – System Information Discovery",
}


# =========================================================
# HELPERS
# =========================================================

def _redact(value: str) -> str:
    v = str(value).strip()
    if len(v) <= 6:
        return '*' * len(v)
    return v[:3] + '*' * (len(v) - 5) + v[-2:]


def _risk(findings: list) -> str:
    secrets = [f for f in findings if f['type'] == 'SECRET']
    pii     = [f for f in findings if f['type'] == 'PII']
    if secrets:          return 'CRITICAL'
    if len(pii) >= 3:    return 'HIGH'
    if len(pii) >= 1:    return 'MEDIUM'
    return 'CLEAN'


# =========================================================
# CORE SCANNER  (multi-variant)
# =========================================================

def _scan_patterns(patterns_dict: str, pii_type: str, variants: list) -> list[dict]:
    findings = []
    seen = set()

    for category, patterns in patterns_dict.items():
        for pattern in patterns:
            if category in seen:
                break
            for variant in variants:
                if category in seen:
                    break
                try:
                    matches = re.findall(pattern, variant['text'], re.IGNORECASE | re.MULTILINE)
                    if matches:
                        seen.add(category)
                        raw = matches[0] if isinstance(matches[0], str) else ' '.join(matches[0])
                        entry = {
                            'type':          pii_type,
                            'category':      category,
                            'matched_value': _redact(raw.strip()),
                            'count':         len(matches),
                            'mitre':         MITRE_PII.get(category, 'T1589 – Gather Victim Info'),
                        }
                        if variant['label']:
                            entry['evasion_technique'] = variant['label']
                        findings.append(entry)
                except re.error:
                    continue
    return findings


def scan_pii(text: str) -> list[dict]:
    variants = _build_all_variants(text)
    return _scan_patterns(PII_PATTERNS, 'PII', variants)


def scan_secrets(text: str) -> list[dict]:
    variants = _build_all_variants(text)
    return _scan_patterns(SECRET_PATTERNS, 'SECRET', variants)


def scan_all(text: str) -> dict:
    pii     = scan_pii(text)
    secrets = scan_secrets(text)
    all_f   = pii + secrets
    return {
        'pii':          pii,
        'secrets':      secrets,
        'all':          all_f,
        'pii_count':    len(pii),
        'secret_count': len(secrets),
        'total':        len(all_f),
        'risk':         _risk(all_f),
    }
