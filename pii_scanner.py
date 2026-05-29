# import re

# # =========================================================
# # PII & SECRETS SCANNER
# # Detects Personally Identifiable Information and
# # credential/key patterns in prompt text.
# # =========================================================

# PII_PATTERNS = {
#     "Email Address": [
#         r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
#     ],
#     "Phone Number": [
#         r"\b(\+91[\-\s]?)?[6-9]\d{9}\b",                    # Indian mobile
#         r"\b(\+1[\-\s]?)?\(?\d{3}\)?[\-\s]?\d{3}[\-\s]?\d{4}\b",  # US
#         r"\b\+\d{1,3}[\s\-]?\d{6,14}\b",                    # International
#     ],
#     "Aadhaar Number": [
#         r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b",
#     ],
#     "PAN Card": [
#         r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
#     ],
#     "Credit / Debit Card": [
#         r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
#         r"\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b",
#     ],
#     "Social Security Number (SSN)": [
#         r"\b(?!000|666|9\d{2})\d{3}[\s\-](?!00)\d{2}[\s\-](?!0000)\d{4}\b",
#     ],
#     "Passport Number": [
#         r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b",              # Indian passport
#         r"\b[A-Z]{1,2}[0-9]{6,9}\b",                        # Generic
#     ],
#     "Date of Birth": [
#         r"\b(0?[1-9]|[12]\d|3[01])[\/\-](0?[1-9]|1[0-2])[\/\-](19|20)\d{2}\b",
#         r"\b(19|20)\d{2}[\/\-](0?[1-9]|1[0-2])[\/\-](0?[1-9]|[12]\d|3[01])\b",
#     ],
#     "IP Address (Private)": [
#         r"\b(10|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
#     ],
# }

# SECRET_PATTERNS = {
#     "Google API Key": [
#         r"AIza[0-9A-Za-z\-_]{35}",
#     ],
#     "AWS Access Key": [
#         r"AKIA[0-9A-Z]{16}",
#         r"ASIA[0-9A-Z]{16}",
#     ],
#     "AWS Secret Key": [
#         r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
#     ],
#     "GitHub Token": [
#         r"ghp_[0-9a-zA-Z]{36}",
#         r"gho_[0-9a-zA-Z]{36}",
#         r"github_pat_[0-9a-zA-Z_]{82}",
#     ],
#     "Stripe Secret Key": [
#         r"sk_live_[0-9a-zA-Z]{24,}",
#         r"sk_test_[0-9a-zA-Z]{24,}",
#     ],
#     "Slack Token": [
#         r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
#     ],
#     "JWT Token": [
#         r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+",
#     ],
#     "Private Key Block": [
#         r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
#     ],
#     "Bearer Token": [
#         r"(?i)bearer\s+[a-zA-Z0-9\-_.~+/]+=*",
#     ],
#     "Password in URL": [
#         r"(?i)(https?|ftp)://[^:@\s]+:[^@\s]+@",
#     ],
#     "Generic Secret/Password": [
#         r"(?i)(password|passwd|secret|api[_\-]?key|token|auth)['\"\s:=]+['\"]?[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};'\"\\|,.<>\/?]{8,}['\"]?",
#     ],
#     "Internal Security Log / Findings": [
#         r"'category':\s*'[A-Za-z\s\(\)]+',\s*'pattern'",
#         r'"category":\s*"[A-Za-z\s\(\)]+"',
#         r"'mitre':\s*'T\d{4}",
#         r'"mitre":\s*"T\d{4}',
#     ],
#     "Stack Trace / Debug Output": [
#         r"Traceback \(most recent call last\)",
#         r"File \".*\.py\", line \d+",
#         r"(?i)\w+Error:\s+\w",
#     ],
#     "CIDR / Network Config Leak": [
#         r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b",
#     ],
# }

# MITRE_PII = {
#     "Email Address":               "T1589.002 – Gather Victim Identity Info: Email Addresses",
#     "Phone Number":                "T1589.001 – Gather Victim Identity Info: Phone Numbers",
#     "Aadhaar Number":              "T1589 – Gather Victim Identity Information",
#     "PAN Card":                    "T1589 – Gather Victim Identity Information",
#     "Credit / Debit Card":         "T1530 – Data from Cloud Storage (Financial PII)",
#     "Social Security Number (SSN)":"T1589 – Gather Victim Identity Information",
#     "Passport Number":             "T1589 – Gather Victim Identity Information",
#     "Date of Birth":               "T1589 – Gather Victim Identity Information",
#     "IP Address (Private)":        "T1590.005 – Gather Victim Network Info: IP Addresses",
#     "Google API Key":              "T1552.001 – Unsecured Credentials: Credentials In Files",
#     "AWS Access Key":              "T1552.005 – Unsecured Credentials: Cloud Instance Metadata",
#     "AWS Secret Key":              "T1552.005 – Unsecured Credentials: Cloud Instance Metadata",
#     "GitHub Token":                "T1552.001 – Unsecured Credentials: Credentials In Files",
#     "Stripe Secret Key":           "T1552.001 – Unsecured Credentials: Credentials In Files",
#     "Slack Token":                 "T1552.001 – Unsecured Credentials: Credentials In Files",
#     "JWT Token":                   "T1550.001 – Use Alternate Auth Material: Application Tokens",
#     "Private Key Block":           "T1552.004 – Unsecured Credentials: Private Keys",
#     "Bearer Token":                "T1550.001 – Use Alternate Auth Material: Application Tokens",
#     "Password in URL":             "T1552.001 – Unsecured Credentials: Credentials In Files",
#     "Generic Secret/Password":     "T1552 – Unsecured Credentials",
#     "Internal Security Log / Findings": "T1530 – Data from Cloud Storage (Internal Data Leak)",
#     "Stack Trace / Debug Output":  "T1082 – System Information Discovery",
#     "CIDR / Network Config Leak":  "T1590.005 – Gather Victim Network Info",
# }


# def scan_pii(text: str) -> list[dict]:
#     """
#     Scan text for PII patterns.
#     Returns list of findings: {type, category, matched_value, mitre}
#     """
#     findings = []
#     seen_categories = set()

#     for category, patterns in PII_PATTERNS.items():
#         for pattern in patterns:
#             matches = re.findall(pattern, text, re.IGNORECASE)
#             if matches and category not in seen_categories:
#                 seen_categories.add(category)
#                 # Redact middle of matched value for safe display
#                 raw = matches[0] if isinstance(matches[0], str) else " ".join(matches[0])
#                 findings.append({
#                     "type":          "PII",
#                     "category":      category,
#                     "matched_value": _redact(raw),
#                     "count":         len(matches),
#                     "mitre":         MITRE_PII.get(category, "T1589 – Gather Victim Info"),
#                 })
#                 break

#     return findings


# def scan_secrets(text: str) -> list[dict]:
#     """
#     Scan text for API keys, tokens, passwords and other secrets.
#     Returns list of findings: {type, category, matched_value, mitre}
#     """
#     findings = []
#     seen_categories = set()

#     for category, patterns in SECRET_PATTERNS.items():
#         for pattern in patterns:
#             matches = re.findall(pattern, text, re.IGNORECASE)
#             if matches and category not in seen_categories:
#                 seen_categories.add(category)
#                 raw = matches[0] if isinstance(matches[0], str) else str(matches[0])
#                 findings.append({
#                     "type":          "SECRET",
#                     "category":      category,
#                     "matched_value": _redact(raw),
#                     "count":         len(matches),
#                     "mitre":         MITRE_PII.get(category, "T1552 – Unsecured Credentials"),
#                 })
#                 break

#     return findings


# def scan_all(text: str) -> dict:
#     """Run both PII and secrets scan. Returns summary dict."""
#     pii     = scan_pii(text)
#     secrets = scan_secrets(text)
#     all_findings = pii + secrets
#     return {
#         "pii":          pii,
#         "secrets":      secrets,
#         "all":          all_findings,
#         "pii_count":    len(pii),
#         "secret_count": len(secrets),
#         "total":        len(all_findings),
#         "risk":         _risk_level(all_findings),
#     }


# def _redact(value: str) -> str:
#     """Show first 4 and last 2 chars, mask the middle."""
#     v = str(value).strip()
#     if len(v) <= 8:
#         return "*" * len(v)
#     return v[:4] + "*" * (len(v) - 6) + v[-2:]


# def _risk_level(findings: list) -> str:
#     secrets = [f for f in findings if f["type"] == "SECRET"]
#     pii     = [f for f in findings if f["type"] == "PII"]
#     if secrets:
#         return "CRITICAL"
#     if len(pii) >= 3:
#         return "HIGH"
#     if len(pii) >= 1:
#         return "MEDIUM"
#     return "CLEAN"

"""
pii_scanner.py — Comprehensive PII & Secrets Scanner
Detects: Aadhaar, PAN, phone, email (all providers), credit cards,
SSN, passport, DOB, IP, API keys, tokens, passwords, and more.
"""
import re

# =========================================================
# PII PATTERNS
# =========================================================

PII_PATTERNS = {

    "Email Address (Gmail / Yahoo / Outlook / Any)": [
        r"\b[a-zA-Z0-9._%+\-]+@(gmail|yahoo|outlook|hotmail|microsoft|icloud|proton|rediffmail|ymail|live|msn|aol|zoho|mail|inbox)\.(com|in|co\.in|org|net)\b",
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
    ],

    "Aadhaar Number": [
        r"(?<!\d)\d{4}\s\d{4}\s\d{4}(?!\d)",           # 1234 5678 9012 (spaced)
        r"(?<!\d)[2-9]\d{3}[-]\d{4}[-]\d{4}(?!\d)",      # 2345-6789-0123 (dashed)
        r"(?<!\d)\d{12}(?!\d)",                             # 123456789012 (no space)
        r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b",               # valid start spaced
    ],

    "PAN Card Number": [
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    ],

    "Indian Mobile Number": [
        r"\b(\+91[\s\-]?)?[6-9]\d{9}\b",
        r"\b(\+91[\s\-]?)?(0)?[6-9]\d{9}\b",
        r"\b[6-9]\d{2}[\s\-]?\d{3}[\s\-]?\d{4}\b",
    ],

    "International Phone Number": [
        r"\b\+\d{1,3}[\s\-]?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{4}\b",
        r"\b\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b",        # US format
    ],

    "Credit / Debit Card Number": [
        r"\b4[0-9]{12}(?:[0-9]{3})?\b",                    # Visa
        r"\b5[1-5][0-9]{14}\b",                            # MasterCard
        r"\b3[47][0-9]{13}\b",                             # Amex
        r"\b6(?:011|5[0-9]{2})[0-9]{12}\b",               # Discover
        r"\b(?:\d{4}[\s\-]){3}\d{4}\b",                   # Generic spaced: 1234 5678 9012 3456
        r"\b\d{4}[\s\-]\d{6}[\s\-]\d{5}\b",               # Amex spaced
    ],

    "Social Security Number (SSN)": [
        r"\b(?!000|666|9\d{2})\d{3}[\s\-](?!00)\d{2}[\s\-](?!0000)\d{4}\b",
        r"\b\d{3}-\d{2}-\d{4}\b",
    ],

    "Passport Number": [
        r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b",            # Indian
        r"\b[A-Z]{1,2}[0-9]{6,9}\b",                      # Generic
    ],

    "Date of Birth": [
        r"\b(0?[1-9]|[12]\d|3[01])[\/\-\.](0?[1-9]|1[0-2])[\/\-\.](19|20)\d{2}\b",
        r"\b(19|20)\d{2}[\/\-\.](0?[1-9]|1[0-2])[\/\-\.](0?[1-9]|[12]\d|3[01])\b",
        r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[\s\-,]+\d{1,2}[\s\-,]+(19|20)\d{2}\b",
    ],

    "Vehicle Registration Number (India)": [
        r"\b[A-Z]{2}[\s\-]?\d{2}[\s\-]?[A-Z]{1,2}[\s\-]?\d{4}\b",   # MH 01 AB 1234
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
        r"\b(?!10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.|127\.)\d{1,3}\.\d{1,3}\d{1,3}\.\d{1,3}\b",
    ],

    "Physical Address": [
        r"\b\d{1,5}[\s,]+[A-Za-z\s]+(Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Nagar|Colony|Sector|Block|Plot|Flat|Floor|Building|Society|Apartment|Layout)\b",
        r"\b(Flat|Apt|House|Plot|Door)\s*(No\.?|Number|#)?\s*\d+[A-Za-z]?\b",
    ],

    "Pincode / ZIP Code": [
        r"\b[1-9][0-9]{5}\b(?=.*\b(pincode|pin|zip|postal)\b)",    # Indian pincode in context
        r"\b[1-9][0-9]{5}\b",                                       # bare 6-digit number
    ],

    "Full Name (Contextual)": [
        r"(?i)\b(name|full\s+name|patient|customer|employee|user)\s*[:\-=]\s*[A-Z][a-z]+\s+[A-Z][a-z]+",
        r"(?i)\bMr\.?\s+[A-Z][a-z]+\s+[A-Z][a-z]+",
        r"(?i)\bMs\.?\s+[A-Z][a-z]+\s+[A-Z][a-z]+",
        r"(?i)\bDr\.?\s+[A-Z][a-z]+\s+[A-Z][a-z]+",
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
    "Email Address (Gmail / Yahoo / Outlook / Any)": "T1589.002 – Gather Victim Identity: Email Addresses",
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
    "Pincode / ZIP Code":                "T1589 – Gather Victim Location Information",
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
# CORE SCANNER
# =========================================================

def _redact(value: str) -> str:
    v = str(value).strip()
    if len(v) <= 6:
        return "*" * len(v)
    return v[:3] + "*" * (len(v) - 5) + v[-2:]


def scan_pii(text: str) -> list[dict]:
    findings = []
    seen = set()
    for category, patterns in PII_PATTERNS.items():
        for pattern in patterns:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
                if matches and category not in seen:
                    seen.add(category)
                    raw = matches[0] if isinstance(matches[0], str) else " ".join(matches[0])
                    findings.append({
                        "type":          "PII",
                        "category":      category,
                        "matched_value": _redact(raw.strip()),
                        "count":         len(matches),
                        "mitre":         MITRE_PII.get(category, "T1589 – Gather Victim Info"),
                    })
                    break
            except re.error:
                continue
    return findings


def scan_secrets(text: str) -> list[dict]:
    findings = []
    seen = set()
    for category, patterns in SECRET_PATTERNS.items():
        for pattern in patterns:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
                if matches and category not in seen:
                    seen.add(category)
                    raw = matches[0] if isinstance(matches[0], str) else str(matches[0])
                    findings.append({
                        "type":          "SECRET",
                        "category":      category,
                        "matched_value": _redact(raw.strip()),
                        "count":         len(matches),
                        "mitre":         MITRE_PII.get(category, "T1552 – Unsecured Credentials"),
                    })
                    break
            except re.error:
                continue
    return findings


def scan_all(text: str) -> dict:
    pii     = scan_pii(text)
    secrets = scan_secrets(text)
    all_f   = pii + secrets
    return {
        "pii":          pii,
        "secrets":      secrets,
        "all":          all_f,
        "pii_count":    len(pii),
        "secret_count": len(secrets),
        "total":        len(all_f),
        "risk":         _risk(all_f),
    }


def _risk(findings: list) -> str:
    secrets = [f for f in findings if f["type"] == "SECRET"]
    pii     = [f for f in findings if f["type"] == "PII"]
    if secrets:                 return "CRITICAL"
    if len(pii) >= 3:           return "HIGH"
    if len(pii) >= 1:           return "MEDIUM"
    return "CLEAN"