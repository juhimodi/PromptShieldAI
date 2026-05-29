# # # # """
# # # # file_guardrail.py — Enterprise File Upload Guardrail Engine
# # # # Full pipeline: extension check → size check → content scan → PII scan → DLP scan → verdict
# # # # """
# # # # import os
# # # # import re
# # # # import hashlib

# # # # # =========================================================
# # # # # POLICY CONSTANTS
# # # # # =========================================================

# # # # MAX_FILE_SIZE_MB = 5
# # # # MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

# # # # # Fully blocked — no exceptions
# # # # BLOCKED_EXTENSIONS = {
# # # #     # Source code
# # # #     ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cs", ".cpp",
# # # #     ".c", ".h", ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".scala",
# # # #     ".vb", ".lua", ".pl", ".r", ".m", ".f90", ".asm",
# # # #     # Config & secrets
# # # #     ".env", ".env.local", ".env.production", ".env.development",
# # # #     ".config", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml",
# # # #     ".pem", ".key", ".cert", ".crt", ".pfx", ".p12", ".p8",
# # # #     # Database
# # # #     ".sql", ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb",
# # # #     # Infrastructure
# # # #     ".tf", ".tfvars", ".hcl",
# # # #     # Scripts
# # # #     ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
# # # #     # Compiled / binary
# # # #     ".jar", ".class", ".pyc", ".pyo", ".exe", ".dll", ".so",
# # # #     ".bin", ".apk", ".ipa", ".deb", ".rpm",
# # # #     # Logs
# # # #     ".log",
# # # #     # Archives containing code
# # # #     ".tar", ".gz", ".bz2", ".xz",
# # # # }

# # # # # Allowed — but content is still scanned
# # # # ALLOWED_EXTENSIONS = {
# # # #     ".txt", ".pdf", ".docx", ".xlsx", ".csv",
# # # #     ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
# # # #     ".json", ".xml", ".md",
# # # # }

# # # # # Blocked filenames (no extension)
# # # # BLOCKED_FILENAMES = {
# # # #     "dockerfile", "makefile", "jenkinsfile", "vagrantfile",
# # # #     "procfile", "gemfile", "rakefile", "gruntfile",
# # # #     ".env", ".gitignore", ".bashrc", ".zshrc", ".profile",
# # # #     ".htaccess", ".htpasswd",
# # # # }

# # # # # =========================================================
# # # # # CONTENT SCANNING PATTERNS (for readable files)
# # # # # =========================================================

# # # # CONTENT_THREAT_PATTERNS = {

# # # #     "Hardcoded Secret / API Key": [
# # # #         r"AIza[0-9A-Za-z\-_]{35}",                              # Google API key
# # # #         r"AKIA[0-9A-Z]{16}",                                    # AWS Access Key
# # # #         r"ASIA[0-9A-Z]{16}",                                    # AWS STS key
# # # #         r"ghp_[0-9a-zA-Z]{36}",                                 # GitHub PAT
# # # #         r"github_pat_[0-9a-zA-Z_]{82}",                         # GitHub fine-grained PAT
# # # #         r"sk_live_[0-9a-zA-Z]{24,}",                            # Stripe live key
# # # #         r"xox[baprs]-[0-9a-zA-Z\-]{10,}",                      # Slack token
# # # #         r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.",   # JWT
# # # #         r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", # Private key
# # # #     ],

# # # #     "Password / Credential in File": [
# # # #         r"(?i)^\s*(password|passwd|pwd|secret|pass)\s*[:=]\s*['\"]?\S{6,}",
# # # #         r"(?i)^\s*(DB_PASSWORD|DATABASE_PASSWORD|REDIS_PASSWORD|SECRET_KEY)\s*=\s*\S+",
# # # #         r"(?i)(mysql|postgresql|postgres|mongodb|redis)://[^\s]+:[^\s]+@",
# # # #     ],

# # # #     "Internal Network Address": [
# # # #         r"\b(10|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
# # # #         r"\b(localhost|127\.0\.0\.1):\d{4,5}\b",
# # # #         r"https?://(?:api|internal|dev|staging|prod|admin|corp|intranet)\.",
# # # #     ],

# # # #     "Company Confidential Marker": [
# # # #         r"\b(internal_use_only|confidential|proprietary|trade_secret|do_not_share|top_secret|restricted)\b",
# # # #         r"(?i)company\s+confidential",
# # # #         r"(?i)not\s+for\s+(external|public|distribution)",
# # # #         r"@(internal|confidential|private|company)\b",
# # # #     ],

# # # #     "Source Code Block": [
# # # #         r"\bdef\s+[a-zA-Z_]\w*\s*\(",
# # # #         r"\bclass\s+[A-Z][a-zA-Z0-9_]*\s*[:\(]",
# # # #         r"\bfunction\s+[a-zA-Z_]\w*\s*\(",
# # # #         r"\bpublic\s+(static\s+)?(void|int|String|boolean|class)\b",
# # # #         r"\bconst\s+[a-zA-Z_]\w*\s*=\s*\(.*\)\s*=>",
# # # #         r"^(import|from)\s+[a-zA-Z_][\w.]+",
# # # #         r"^#include\s*[<\"]",
# # # #         r"^\s*using\s+[A-Z][a-zA-Z.]+;",
# # # #         r"^\s*require\s*\(['\"][a-zA-Z]",
# # # #     ],

# # # #     "Infrastructure Config": [
# # # #         r"\bapiVersion:\s*[a-zA-Z]+/v\d",
# # # #         r"\bkind:\s*(Deployment|Service|Pod|ConfigMap|Secret|Ingress)\b",
# # # #         r"(?im)^FROM\s+[a-zA-Z0-9.\-/]+",
# # # #         r"(?im)^RUN\s+(apt|yum|pip|npm|apk)\s+install",
# # # #         r"resource\s+\"aws_",
# # # #         r"\bterraform\s*\{",
# # # #     ],

# # # #     "Prompt Injection in File": [
# # # #         r"(?i)ignore\s+(all\s+)?(your\s+)?(previous|prior|above)\s+instructions",
# # # #         r"(?i)forget\s+(all\s+)?(your\s+)?(previous|prior)\s+instructions",
# # # #         r"(?i)you\s+are\s+now\s+(a\s+)?(?:unrestricted|jailbroken|evil)",
# # # #         r"(?i)act\s+as\s+(if\s+)?(you\s+are\s+)?(a\s+)?(?:unrestricted|admin|evil)",
# # # #         r"(?i)(system|developer|admin)\s+(override|mode|prompt|access)",
# # # #         r"(?i)dan\s+mode|evil\s+mode|jailbreak",
# # # #         r"(?i)no\s+restrictions?\s+mode",
# # # #     ],

# # # #     "PII — Aadhaar / PAN / Financial": [
# # # #         r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b",                         # Aadhaar spaced
# # # #         r"\b\d{12}\b(?=[\s,].*(?:aadhaar|aadhar|uid))",           # Aadhaar in context
# # # #         r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",                            # PAN card
# # # #         r"\b4[0-9]{12}(?:[0-9]{3})?\b",                          # Visa card
# # # #         r"\b5[1-5][0-9]{14}\b",                                   # MasterCard
# # # #         r"\b(?:\d{4}[\s\-]){3}\d{4}\b",                          # Generic card spaced
# # # #     ],
# # # # }

# # # # # Risk weights per detected category
# # # # CONTENT_WEIGHTS = {
# # # #     "Hardcoded Secret / API Key":       60,
# # # #     "Password / Credential in File":    55,
# # # #     "Internal Network Address":         40,
# # # #     "Company Confidential Marker":      35,
# # # #     "Source Code Block":                30,
# # # #     "Infrastructure Config":            40,
# # # #     "Prompt Injection in File":         50,
# # # #     "PII — Aadhaar / PAN / Financial":  45,
# # # # }

# # # # # Categories that ALWAYS block (regardless of score)
# # # # ALWAYS_BLOCK_CATEGORIES = {
# # # #     "Hardcoded Secret / API Key",
# # # #     "Password / Credential in File",
# # # #     "Prompt Injection in File",
# # # #     "PII — Aadhaar / PAN / Financial",
# # # # }

# # # # # Binary file signatures (magic bytes)
# # # # BINARY_SIGNATURES = [
# # # #     (b"\x7fELF",    "ELF Binary (Linux executable)"),
# # # #     (b"MZ",         "PE Binary (Windows executable / DLL)"),
# # # #     (b"PK\x03\x04", "ZIP Archive (JAR / DOCX / XLSX may be ok — verified separately)"),
# # # #     (b"\xca\xfe\xba\xbe", "Java Class File"),
# # # #     (b"\x50\x4b\x03\x04", "ZIP / JAR Archive"),
# # # # ]


# # # # # =========================================================
# # # # # EXTENSION CHECKER
# # # # # =========================================================

# # # # def check_extension(filename: str) -> dict:
# # # #     """
# # # #     Stage 1: Extension & filename policy check.
# # # #     Returns: {passed, extension, category, reason, severity}
# # # #     """
# # # #     base = os.path.basename(filename).lower()
# # # #     ext  = os.path.splitext(base)[1]

# # # #     # Blocked filename (no extension)
# # # #     if base in BLOCKED_FILENAMES or (not ext and base.startswith(".")):
# # # #         return {
# # # #             "passed":    False,
# # # #             "extension": base,
# # # #             "category":  "Blocked Filename",
# # # #             "reason":    f"'{filename}' is a restricted system/configuration file.",
# # # #             "severity":  "BLOCK",
# # # #         }

# # # #     if ext in BLOCKED_EXTENSIONS:
# # # #         return {
# # # #             "passed":    False,
# # # #             "extension": ext,
# # # #             "category":  _ext_to_category(ext),
# # # #             "reason":    f"Files with extension '{ext}' violate the DLP file-type policy.",
# # # #             "severity":  "BLOCK",
# # # #         }

# # # #     if ext in ALLOWED_EXTENSIONS:
# # # #         return {
# # # #             "passed":    True,
# # # #             "extension": ext,
# # # #             "category":  "Allowed",
# # # #             "reason":    "",
# # # #             "severity":  "PASS",
# # # #         }

# # # #     # Unknown extension — warn
# # # #     return {
# # # #         "passed":    False,
# # # #         "extension": ext or "(none)",
# # # #         "category":  "Unknown File Type",
# # # #         "reason":    f"Files with extension '{ext or '(none)'}' are not on the approved list.",
# # # #         "severity":  "BLOCK",
# # # #     }


# # # # def _ext_to_category(ext: str) -> str:
# # # #     code    = {".py",".js",".ts",".jsx",".tsx",".java",".cs",".cpp",".c",".h",
# # # #                ".go",".rs",".rb",".php",".swift",".kt",".scala",".vb",".lua",".pl"}
# # # #     config  = {".env",".config",".conf",".cfg",".ini",".yaml",".yml",".toml",".tf",".tfvars"}
# # # #     db      = {".sql",".db",".sqlite",".sqlite3",".mdb"}
# # # #     key     = {".pem",".key",".cert",".crt",".pfx",".p12",".p8"}
# # # #     script  = {".sh",".bash",".zsh",".ps1",".bat",".cmd",".fish"}
# # # #     binary  = {".jar",".class",".pyc",".exe",".dll",".so",".bin",".apk"}
# # # #     if ext in code:   return "Source Code File"
# # # #     if ext in config: return "Configuration / Secrets File"
# # # #     if ext in db:     return "Database File"
# # # #     if ext in key:    return "Cryptographic Key / Certificate"
# # # #     if ext in script: return "Shell Script / Automation"
# # # #     if ext in binary: return "Compiled Binary"
# # # #     if ext == ".log": return "Server Log File"
# # # #     return "Restricted File Type"


# # # # # =========================================================
# # # # # SIZE CHECKER
# # # # # =========================================================

# # # # def check_size(file_bytes: bytes) -> dict:
# # # #     """Stage 2: File size check."""
# # # #     size = len(file_bytes)
# # # #     mb   = size / (1024 * 1024)
# # # #     if size > MAX_FILE_SIZE_BYTES:
# # # #         return {
# # # #             "passed": False,
# # # #             "size_mb": round(mb, 2),
# # # #             "reason": f"File size {mb:.1f} MB exceeds the {MAX_FILE_SIZE_MB} MB limit.",
# # # #         }
# # # #     return {"passed": True, "size_mb": round(mb, 2), "reason": ""}


# # # # # =========================================================
# # # # # BINARY DETECTION
# # # # # =========================================================

# # # # def check_binary(file_bytes: bytes) -> dict:
# # # #     """Stage 3: Detect binary / compiled file content."""
# # # #     for sig, label in BINARY_SIGNATURES:
# # # #         if file_bytes.startswith(sig) and label.startswith("ZIP"):
# # # #             # ZIP is used for .docx/.xlsx — allow but note
# # # #             return {"is_binary": False, "label": "", "note": "ZIP-based Office format"}
# # # #         if file_bytes.startswith(sig):
# # # #             return {"is_binary": True, "label": label,
# # # #                     "reason": f"Binary file detected ({label}). Binary uploads are not permitted."}
# # # #     # Heuristic: >30% non-printable bytes = binary
# # # #     non_print = sum(1 for b in file_bytes[:2048] if b < 9 or (13 < b < 32) or b > 126)
# # # #     if len(file_bytes) > 0 and non_print / min(len(file_bytes), 2048) > 0.30:
# # # #         return {"is_binary": True, "label": "Binary/encoded content",
# # # #                 "reason": "File appears to contain binary or encoded data."}
# # # #     return {"is_binary": False, "label": "", "reason": ""}


# # # # # =========================================================
# # # # # CONTENT SCANNER
# # # # # =========================================================

# # # # def scan_content(text: str) -> dict:
# # # #     """
# # # #     Stage 4: Scan decoded file text for threats.
# # # #     Returns: {verdict, findings, total_score, blocked}
# # # #     """
# # # #     findings    = []
# # # #     seen        = set()
# # # #     total_score = 0
# # # #     lines       = text.split("\n")

# # # #     for category, patterns in CONTENT_THREAT_PATTERNS.items():
# # # #         for pattern in patterns:
# # # #             try:
# # # #                 m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
# # # #                 if m and category not in seen:
# # # #                     seen.add(category)
# # # #                     line_no = text[:m.start()].count("\n") + 1
# # # #                     snippet = lines[line_no - 1].strip()
# # # #                     # Redact secrets from snippet
# # # #                     snippet = _redact_snippet(snippet, category)
# # # #                     weight  = CONTENT_WEIGHTS.get(category, 25)
# # # #                     total_score += weight
# # # #                     findings.append({
# # # #                         "category": category,
# # # #                         "line":     line_no,
# # # #                         "snippet":  snippet[:100] + ("..." if len(snippet) > 100 else ""),
# # # #                         "weight":   weight,
# # # #                         "mitre":    _mitre_for(category),
# # # #                     })
# # # #                     break
# # # #             except re.error:
# # # #                 continue

# # # #     force_block = any(f["category"] in ALWAYS_BLOCK_CATEGORIES for f in findings)

# # # #     if force_block or total_score >= 50:
# # # #         verdict = "BLOCK"
# # # #     elif total_score >= 25 or findings:
# # # #         verdict = "WARN"
# # # #     else:
# # # #         verdict = "PASS"

# # # #     return {
# # # #         "verdict":     verdict,
# # # #         "findings":    findings,
# # # #         "total_score": total_score,
# # # #         "blocked":     verdict == "BLOCK",
# # # #     }


# # # # def _redact_snippet(snippet: str, category: str) -> str:
# # # #     """Partially redact sensitive values in snippets shown to user."""
# # # #     if category in ("Hardcoded Secret / API Key", "Password / Credential in File"):
# # # #         # mask everything after the = or :
# # # #         return re.sub(r"([:=]\s*['\"]?)(\S{4})\S+", r"\1\2****", snippet)
# # # #     return snippet


# # # # def _mitre_for(category: str) -> str:
# # # #     mapping = {
# # # #         "Hardcoded Secret / API Key":       "T1552.001 – Credentials In Files",
# # # #         "Password / Credential in File":    "T1552.001 – Credentials In Files",
# # # #         "Internal Network Address":         "T1590.005 – Gather Victim Network Info",
# # # #         "Company Confidential Marker":      "T1213 – Data from Information Repositories",
# # # #         "Source Code Block":               "T1213 – Data from Information Repositories",
# # # #         "Infrastructure Config":           "T1213 – Data from Information Repositories",
# # # #         "Prompt Injection in File":        "T1059 – Command and Scripting Interpreter",
# # # #         "PII — Aadhaar / PAN / Financial": "T1589 – Gather Victim Identity Information",
# # # #     }
# # # #     return mapping.get(category, "T1530 – Data from Cloud Storage")


# # # # # =========================================================
# # # # # MASTER PIPELINE
# # # # # =========================================================

# # # # def run_file_guardrail(filename: str, file_bytes: bytes) -> dict:
# # # #     """
# # # #     Run the full 5-stage enterprise guardrail pipeline on an uploaded file.

# # # #     Returns a result dict with keys:
# # # #         verdict     : "BLOCK" | "WARN" | "PASS"
# # # #         blocked     : bool
# # # #         stages      : list of stage result dicts
# # # #         findings    : content scan findings (if readable)
# # # #         summary     : human-readable summary string
# # # #         file_hash   : SHA-256 of uploaded file (for audit)
# # # #     """
# # # #     stages   = []
# # # #     blocked  = False
# # # #     findings = []

# # # #     file_hash = hashlib.sha256(file_bytes).hexdigest()

# # # #     # --- Stage 1: Extension ---
# # # #     ext_result = check_extension(filename)
# # # #     stages.append({"name": "Extension Policy", "result": ext_result})
# # # #     if not ext_result["passed"]:
# # # #         return {
# # # #             "verdict":   "BLOCK",
# # # #             "blocked":   True,
# # # #             "stages":    stages,
# # # #             "findings":  [],
# # # #             "summary":   f"Blocked at Stage 1 — {ext_result['reason']}",
# # # #             "file_hash": file_hash,
# # # #         }

# # # #     # --- Stage 2: Size ---
# # # #     size_result = check_size(file_bytes)
# # # #     stages.append({"name": "File Size", "result": size_result})
# # # #     if not size_result["passed"]:
# # # #         return {
# # # #             "verdict":   "BLOCK",
# # # #             "blocked":   True,
# # # #             "stages":    stages,
# # # #             "findings":  [],
# # # #             "summary":   f"Blocked at Stage 2 — {size_result['reason']}",
# # # #             "file_hash": file_hash,
# # # #         }

# # # #     # --- Stage 3: Binary detection ---
# # # #     bin_result = check_binary(file_bytes)
# # # #     stages.append({"name": "Binary Check", "result": bin_result})
# # # #     if bin_result.get("is_binary"):
# # # #         return {
# # # #             "verdict":   "BLOCK",
# # # #             "blocked":   True,
# # # #             "stages":    stages,
# # # #             "findings":  [],
# # # #             "summary":   f"Blocked at Stage 3 — {bin_result['reason']}",
# # # #             "file_hash": file_hash,
# # # #         }

# # # #     # --- Stage 4: Content scan ---
# # # #     try:
# # # #         text = file_bytes.decode("utf-8", errors="replace")
# # # #     except Exception:
# # # #         text = ""

# # # #     if text.strip():
# # # #         content_result = scan_content(text)
# # # #         stages.append({"name": "Content Scan", "result": content_result})
# # # #         findings = content_result["findings"]

# # # #         if content_result["blocked"]:
# # # #             return {
# # # #                 "verdict":   "BLOCK",
# # # #                 "blocked":   True,
# # # #                 "stages":    stages,
# # # #                 "findings":  findings,
# # # #                 "summary":   f"Blocked at Stage 4 — Sensitive content detected ({len(findings)} categories).",
# # # #                 "file_hash": file_hash,
# # # #             }
# # # #     else:
# # # #         stages.append({"name": "Content Scan", "result": {"verdict": "SKIP", "reason": "Non-text file (image/binary safe format)"}})

# # # #     # --- Stage 5: Final verdict ---
# # # #     has_warnings = any(
# # # #         s.get("result", {}).get("verdict") == "WARN"
# # # #         for s in stages
# # # #     )

# # # #     verdict = "WARN" if (has_warnings or findings) else "PASS"

# # # #     return {
# # # #         "verdict":   verdict,
# # # #         "blocked":   False,
# # # #         "stages":    stages,
# # # #         "findings":  findings,
# # # #         "summary":   "File passed all guardrail checks." if verdict == "PASS"
# # # #                      else f"File passed with {len(findings)} warning(s). Review before use.",
# # # #         "file_hash": file_hash,
# # # #         "text":      text,  # pass decoded text to the caller for Gemini
# # # #     }
# # # """
# # # file_guardrail.py — Enterprise File Upload Guardrail Engine
# # # """
# # # import os, re, hashlib, base64

# # # MAX_FILE_SIZE_MB    = 5
# # # MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

# # # BLOCKED_EXTENSIONS = {
# # #     ".php",".php3",".php4",".php5",".phtml",".phar",
# # #     ".asp",".aspx",".ashx",".asmx",".axd",
# # #     ".jsp",".jspx",".jspf",".cgi",".pl",".rb",".cfm",".cfml",
# # #     ".js",".ts",".jsx",".tsx",".java",".cs",".cpp",
# # #     ".c",".h",".go",".rs",".swift",".kt",".scala",
# # #     ".vb",".lua",".r",".m",".f90",".asm",".dart",
# # #     ".env",".env.local",".env.production",".env.development",
# # #     ".env.staging",".env.test",
# # #     ".config",".conf",".cfg",".ini",".yaml",".yml",".toml",
# # #     ".pem",".key",".cert",".crt",".pfx",".p12",".p8",".ppk",
# # #     ".sql",".db",".sqlite",".sqlite3",".mdb",".accdb",
# # #     ".tf",".tfvars",".hcl",
# # #     ".sh",".bash",".zsh",".fish",".ps1",".ps2",
# # #     ".bat",".cmd",".vbs",".wsf",".hta",
# # #     ".jar",".class",".pyc",".pyo",".exe",".dll",".so",
# # #     ".bin",".apk",".ipa",".deb",".rpm",".msi",".dmg",
# # #     ".log",".tar",".gz",".bz2",".xz",".rar",".7z",".zip",
# # #     ".xlsm",".xltm",".docm",".dotm",".pptm",
# # #     ".py",  # explicitly block python too
# # # }

# # # ALLOWED_EXTENSIONS = {
# # #     ".txt", ".pdf", ".docx", ".xlsx", ".csv",
# # #     ".png", ".jpg", ".jpeg", ".gif", ".webp",
# # #     ".json", ".xml", ".md",
# # # }

# # # BLOCKED_FILENAMES = {
# # #     "dockerfile","makefile","jenkinsfile","vagrantfile",
# # #     "procfile","gemfile","rakefile","gruntfile","gulpfile",
# # #     ".env",".gitignore",".bashrc",".zshrc",".profile",
# # #     ".htaccess",".htpasswd",".npmrc",".pypirc",
# # # }

# # # # ---- Content threat patterns ----
# # # CONTENT_THREAT_PATTERNS = {
# # #     "XSS / HTML Injection": [
# # #         r"<script[\s\S]*?>[\s\S]*?</script>",
# # #         r"<script[\s>]",
# # #         r"</script>",
# # #         r"(?i)javascript\s*:",
# # #         r"(?i)on(error|load|click|mouseover|focus|blur|change|submit|input|keyup|keydown|dblclick|drag|drop|scroll|contextmenu|wheel|touchstart|touchend)\s*=",
# # #         r"(?i)<iframe[\s>]",
# # #         r"(?i)<img[^>]+on\w+\s*=",
# # #         r"(?i)<svg[^>]*>",
# # #         r"(?i)<object[\s>]",
# # #         r"(?i)<embed[\s>]",
# # #         r"eval\s*\(",
# # #         r"(?i)document\.(cookie|write|location|domain)",
# # #         r"(?i)window\.(location|open|eval)",
# # #         r"(?i)innerHTML\s*=",
# # #         r"(?i)(fetch|XMLHttpRequest)\s*\(",
# # #         r"(?i)atob\s*\(",
# # #         r"(?i)String\.fromCharCode\s*\(",
# # #         r"%3Cscript|%3c%73%63%72%69%70%74",
# # #         r"&#\d+;.*&#\d+;",
# # #         r"<html[\s>]",       # raw HTML in non-html file
# # #         r"<body[\s>]",
# # #         r"<!DOCTYPE\s+html",
# # #         r"<head[\s>]",
# # #         r"<div[\s>]",
# # #         r"<form[\s>]",
# # #         r"<input[\s>]",
# # #     ],
# # #     "SQL Injection": [
# # #         r"(?i)\bUNION\s+(ALL\s+)?SELECT\b",
# # #         r"(?i)\bDROP\s+TABLE\b",
# # #         r"(?i)\bOR\s+1\s*=\s*1\b",
# # #         r"(?i)'\s*(--|#|/\*)",
# # #         r"(?i)\bINSERT\s+INTO\b.*\bVALUES\b",
# # #         r"(?i)\bDELETE\s+FROM\b",
# # #         r"(?i)\bSELECT\s+.+\bFROM\b",
# # #         r"(?i)\bEXEC(UTE)?\s*\(",
# # #         r"(?i)xp_cmdshell",
# # #         r"(?i)\bSLEEP\s*\(\d+\)",
# # #         r"(?i)\bWAITFOR\s+DELAY\b",
# # #         r"(?i)\bINFORMATION_SCHEMA\b",
# # #     ],
# # #     "Command Injection": [
# # #         r"(?i)(;|\||&&|\|\|)\s*(rm|del|format|shutdown|reboot|kill|wget|curl|nc|bash|sh|cmd|powershell|python|perl|ruby)",
# # #         r"`[^`]{3,}`",
# # #         r"\$\([^)]{3,}\)",
# # #         r"(?i)(rm\s+-rf|del\s+/f)",
# # #         r"(?i)(wget|curl)\s+https?://",
# # #         r"(?i)/bin/(bash|sh|zsh|ksh|dash)",
# # #         r"(?i)cmd\.exe",
# # #         r"(?i)powershell\s*(-|\.exe)",
# # #         r"(?i)nc\s+-[el]",
# # #         r"(?i)bash\s+-i\s*>&",
# # #         r"(?i)/etc/(passwd|shadow|hosts|crontab)",
# # #     ],
# # #     "Path Traversal": [
# # #         r"\.\./", r"\.\.\\",
# # #         r"%2e%2e%2f|%2e%2e/|\.\.%2f",
# # #         r"%252e%252e%252f",
# # #         r"(?i)/etc/passwd",
# # #         r"(?i)/etc/shadow",
# # #         r"(?i)c:\\windows\\system32",
# # #         r"(?i)boot\.ini",
# # #     ],
# # #     "Server Side Request Forgery (SSRF)": [
# # #         r"\b127\.0\.0\.1\b",
# # #         r"169\.254\.169\.254",
# # #         r"metadata\.google\.internal",
# # #         r"(?i)file://",
# # #         r"(?i)gopher://",
# # #         r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
# # #     ],
# # #     "XML External Entity (XXE)": [
# # #         r"<!DOCTYPE[^>]*\[",
# # #         r"<!ENTITY\s+\w+\s+SYSTEM",
# # #         r"SYSTEM\s+['\"]file://",
# # #     ],
# # #     "Server Side Template Injection (SSTI)": [
# # #         r"\{\{.*?\}\}",
# # #         r"\{%.*?%\}",
# # #         r"\$\{.*?\}",
# # #         r"#\{.*?\}",
# # #         r"(?i)\{\{.*?(__class__|__mro__|os\.|subprocess)",
# # #         r"(?i)7\*7|\{\{7\*7\}\}",
# # #     ],
# # #     "Prompt Injection in File": [
# # #         r"(?i)ignore\s+(all\s+)?(your\s+)?(previous|prior|above|earlier)\s+instructions",
# # #         r"(?i)forget\s+(all\s+)?(your\s+)?(previous|prior|above)\s+instructions",
# # #         r"(?i)disregard\s+(all\s+)?instructions",
# # #         r"(?i)override\s+(your\s+)?(safety|system|previous)\s*(settings|instructions|rules)?",
# # #         r"(?i)reveal\s+(your\s+)?(hidden\s+)?(system\s+)?(prompt|instructions|context)",
# # #         r"(?i)(system|developer|admin)\s+(override|mode|access|prompt)",
# # #         r"(?i)\[system\]|\[admin\]|\[override\]",
# # #         r"(?i)dan\s+mode|evil\s+mode|developer\s+mode",
# # #         r"(?i)print\s+(your\s+)?(system\s+)?(prompt|instructions)",
# # #         r"(?i)new\s+instructions?\s*:",
# # #         r"(?i)act\s+as\s+(if\s+)?(you\s+are\s+)?(a\s+)?(?:unrestricted|admin|evil|root)",
# # #         r"(?i)you\s+are\s+now\s+(a\s+)?(?:unrestricted|jailbroken|evil|different)",
# # #     ],
# # #     "Jailbreak Attempt in File": [
# # #         r"(?i)jailbreak",
# # #         r"(?i)pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(?:evil|unrestricted|hacked|free)",
# # #         r"(?i)do\s+anything\s+now",
# # #         r"(?i)without\s+(any\s+)?(restrictions?|filters?|guardrails?|safety)",
# # #         r"(?i)disable\s+(your\s+)?(safety|security|filter|moderation|guardrail)",
# # #     ],
# # #     "Hardcoded Secret / API Key": [
# # #         r"AIza[0-9A-Za-z\-_]{35}",
# # #         r"AKIA[0-9A-Z]{16}",
# # #         r"ghp_[0-9a-zA-Z]{36}",
# # #         r"sk_live_[0-9a-zA-Z]{24,}",
# # #         r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.",
# # #         r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
# # #         r"(?i)(api[_\-]?key|apikey|access[_\-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{20,}",
# # #     ],
# # #     "Password / Credential in File": [
# # #         r"(?i)^\s*(password|passwd|pwd|secret|pass)\s*[:=]\s*['\"]?\S{6,}",
# # #         r"(?i)(mysql|postgresql|postgres|mongodb|redis):\/\/[^\s]+:[^\s]+@",
# # #     ],
# # #     "Encoded / Obfuscated Payload": [
# # #         r"(?i)eval\s*\(\s*base64_decode\s*\(",
# # #         r"(?i)eval\s*\(\s*atob\s*\(",
# # #         r"(?i)exec\s*\(\s*base64\s*\.",
# # #         r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}",
# # #         r"(?:%[0-9a-fA-F]{2}){10,}",
# # #     ],
# # #     "PII — Aadhaar / PAN / Card": [
# # #         r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b",
# # #         r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
# # #         r"\b(?:\d{4}[\s\-]){3}\d{4}\b",
# # #     ],
# # #     "Internal Network / Config": [
# # #         r"(?i)^\s*(DB_PASSWORD|SECRET_KEY|AWS_SECRET|DATABASE_URL)\s*=\s*\S+",
# # #         r"mongodb\+srv://",
# # #         r"\bapiVersion:\s*[a-zA-Z]+/v\d",
# # #         r"\bkind:\s*(Deployment|Service|Pod|ConfigMap|Secret)\b",
# # #     ],
# # #     "Source Code in File": [
# # #         r"\bdef\s+[a-zA-Z_]\w*\s*\(",
# # #         r"\bclass\s+[A-Z][a-zA-Z0-9_]*\s*[:\(]",
# # #         r"\bfunction\s+[a-zA-Z_]\w*\s*\(",
# # #         r"\bpublic\s+(static\s+)?(void|int|String|boolean|class)\b",
# # #         r"^(import|from)\s+[a-zA-Z_][\w.]+\s",
# # #         r"^#include\s*[<\"]",
# # #     ],
# # # }

# # # CONTENT_WEIGHTS = {
# # #     "XSS / HTML Injection":              60,
# # #     "SQL Injection":                     60,
# # #     "Command Injection":                 65,
# # #     "Path Traversal":                    55,
# # #     "Server Side Request Forgery (SSRF)":55,
# # #     "XML External Entity (XXE)":         55,
# # #     "Server Side Template Injection (SSTI)": 60,
# # #     "Prompt Injection in File":          60,
# # #     "Jailbreak Attempt in File":         55,
# # #     "Encoded / Obfuscated Payload":      55,
# # #     "Hardcoded Secret / API Key":        60,
# # #     "Password / Credential in File":     55,
# # #     "PII — Aadhaar / PAN / Card":        50,
# # #     "Internal Network / Config":         40,
# # #     "Source Code in File":               30,
# # # }

# # # ALWAYS_BLOCK_CATEGORIES = {
# # #     "XSS / HTML Injection","SQL Injection","Command Injection",
# # #     "Path Traversal","Server Side Request Forgery (SSRF)",
# # #     "XML External Entity (XXE)","Server Side Template Injection (SSTI)",
# # #     "Prompt Injection in File","Jailbreak Attempt in File",
# # #     "Encoded / Obfuscated Payload","Hardcoded Secret / API Key",
# # #     "Password / Credential in File","PII — Aadhaar / PAN / Card","Internal Network / Config","Source Code in File",
# # # }

# # # MITRE_MAP = {
# # #     "XSS / HTML Injection":                  "T1059.007 – JavaScript / HTML Injection",
# # #     "SQL Injection":                          "T1190 – Exploit Public-Facing Application",
# # #     "Command Injection":                      "T1059 – Command and Scripting Interpreter",
# # #     "Path Traversal":                         "T1083 – File and Directory Discovery",
# # #     "Server Side Request Forgery (SSRF)":     "T1090 – Proxy / Internal Network Pivot",
# # #     "XML External Entity (XXE)":              "T1005 – Data from Local System",
# # #     "Server Side Template Injection (SSTI)":  "T1059 – Command and Scripting Interpreter",
# # #     "Prompt Injection in File":               "T1190 – Exploit via Injected Instructions",
# # #     "Jailbreak Attempt in File":              "T1562 – Impair Defenses",
# # #     "Encoded / Obfuscated Payload":           "T1027 – Obfuscated Files or Information",
# # #     "Hardcoded Secret / API Key":             "T1552.001 – Credentials In Files",
# # #     "Password / Credential in File":          "T1552.001 – Credentials In Files",
# # #     "PII — Aadhaar / PAN / Card":             "T1589 – Gather Victim Identity Information",
# # #     "Internal Network / Config":              "T1590.005 – Gather Victim Network Info",
# # #     "Source Code in File":                    "T1213 – Data from Information Repositories",
# # # }

# # # BINARY_SIGNATURES = [
# # #     (b"\x7fELF",          "ELF Binary (Linux/Unix executable)"),
# # #     (b"MZ",               "PE Binary (Windows .exe/.dll)"),
# # #     (b"\xca\xfe\xba\xbe", "Java Class File"),
# # #     (b"\xfe\xed\xfa\xce", "Mach-O Binary (macOS)"),
# # #     (b"Rar!",             "RAR Archive"),
# # #     (b"\x1f\x8b",         "GZIP Archive"),
# # #     (b"7z\xbc\xaf",       "7-Zip Archive"),
# # #     (b"\xd0\xcf\x11\xe0", "OLE2 / MS Office Legacy (macro-capable)"),
# # # ]

# # # ALLOWED_MAGIC = { b"%PDF-", b"\x50\x4b\x03\x04" }

# # # EXPECTED_CONTENT_SIGNATURES = {
# # #     ".png":  [b"\x89PNG"],
# # #     ".jpg":  [b"\xff\xd8\xff"],
# # #     ".jpeg": [b"\xff\xd8\xff"],
# # #     ".gif":  [b"GIF87a", b"GIF89a"],
# # #     ".webp": [b"RIFF"],
# # #     ".pdf":  [b"%PDF-"],
# # #     ".docx": [b"PK\x03\x04"],
# # #     ".xlsx": [b"PK\x03\x04"],
# # # }

# # # # Signatures that should NEVER appear in plain text files
# # # ATTACK_SIGNATURES_IN_TEXT = [
# # #     (b"<script",          "XSS — <script> tag"),
# # #     (b"<SCRIPT",          "XSS — <script> tag"),
# # #     (b"javascript:",      "XSS — javascript: URI"),
# # #     (b"JAVASCRIPT:",      "XSS — javascript: URI"),
# # #     (b"<?php",            "Server-side PHP code"),
# # #     (b"<%@",              "Server-side JSP/ASP code"),
# # #     (b"<%=",              "Server-side template code"),
# # #     (b"<html",            "HTML content in text file"),
# # #     (b"<HTML",            "HTML content in text file"),
# # #     (b"<!DOCTYPE",        "HTML DOCTYPE in text file"),
# # #     (b"<iframe",          "XSS — iframe injection"),
# # #     (b"<IFRAME",          "XSS — iframe injection"),
# # #     (b"<svg",             "XSS — SVG injection"),
# # #     (b"<SVG",             "XSS — SVG injection"),
# # #     (b"onerror=",         "XSS — event handler"),
# # #     (b"onload=",          "XSS — event handler"),
# # #     (b"onclick=",         "XSS — event handler"),
# # #     (b"AKIA",             "AWS Access Key"),
# # #     (b"AIzaSy",           "Google API Key"),
# # #     (b"-----BEGIN",       "Private key/certificate"),
# # #     (b"ghp_",             "GitHub token"),
# # # ]

# # # TEXT_FILE_EXTENSIONS = {".txt", ".csv", ".md", ".json", ".xml", ".log"}


# # # def check_extension(filename):
# # #     base = os.path.basename(filename).lower()
# # #     ext  = os.path.splitext(base)[1]

# # #     if "%00" in filename or "\x00" in filename:
# # #         return {"passed": False, "extension": ext,
# # #                 "category": "Null Byte Injection",
# # #                 "reason": "Null byte in filename — extension spoofing attack.", "severity": "BLOCK"}

# # #     parts = base.split(".")
# # #     if len(parts) > 2:
# # #         for p in parts[1:]:
# # #             if "." + p in BLOCKED_EXTENSIONS:
# # #                 return {"passed": False, "extension": "." + p,
# # #                         "category": "Double Extension Attack",
# # #                         "reason": f"Double extension: '{filename}' — .{p} is blocked.", "severity": "BLOCK"}

# # #     if base in BLOCKED_FILENAMES or (not ext and base.startswith(".")):
# # #         return {"passed": False, "extension": base,
# # #                 "category": "Blocked Filename",
# # #                 "reason": f"'{filename}' is a restricted system/config file.", "severity": "BLOCK"}

# # #     if ext in BLOCKED_EXTENSIONS:
# # #         return {"passed": False, "extension": ext,
# # #                 "category": _ext_cat(ext),
# # #                 "reason": f"Extension '{ext}' is blocked by policy.", "severity": "BLOCK"}

# # #     if ext in ALLOWED_EXTENSIONS:
# # #         return {"passed": True, "extension": ext, "category": "Allowed", "reason": "", "severity": "PASS"}

# # #     return {"passed": False, "extension": ext or "(none)",
# # #             "category": "Unknown File Type",
# # #             "reason": f"Extension '{ext or '(none)'}' is not on the approved list.", "severity": "BLOCK"}


# # # def _ext_cat(ext):
# # #     if ext in {".php",".asp",".aspx",".jsp",".cgi",".cfm"}: return "Server-Side Web Script"
# # #     if ext in {".py",".js",".ts",".java",".cs",".cpp",".c",".go",".rs",".rb",".swift",".kt"}: return "Source Code"
# # #     if ext in {".env",".config",".conf",".cfg",".ini",".yaml",".yml",".toml",".tf"}: return "Config/Secrets File"
# # #     if ext in {".sql",".db",".sqlite"}: return "Database File"
# # #     if ext in {".pem",".key",".cert",".crt",".pfx"}: return "Cryptographic Key"
# # #     if ext in {".sh",".bash",".ps1",".bat",".cmd"}: return "Shell Script"
# # #     if ext in {".exe",".dll",".so",".bin",".jar",".pyc"}: return "Compiled Binary"
# # #     if ext in {".zip",".tar",".gz",".rar",".7z"}: return "Archive"
# # #     return "Restricted File Type"


# # # def check_size(file_bytes):
# # #     size = len(file_bytes)
# # #     mb   = size / (1024*1024)
# # #     if size > MAX_FILE_SIZE_BYTES:
# # #         return {"passed": False, "size_mb": round(mb,2),
# # #                 "reason": f"File {mb:.1f} MB exceeds {MAX_FILE_SIZE_MB} MB limit."}
# # #     return {"passed": True, "size_mb": round(mb,2), "reason": ""}


# # # def check_binary_and_mime(file_bytes, filename):
# # #     ext = os.path.splitext(filename.lower())[1]

# # #     # Binary magic bytes
# # #     for sig, label in BINARY_SIGNATURES:
# # #         if file_bytes.startswith(sig):
# # #             if sig in ALLOWED_MAGIC:
# # #                 return {"is_binary": False, "label": label, "content_mismatch": False,
# # #                         "note": f"{label} — content will be scanned", "reason": ""}
# # #             return {"is_binary": True, "label": label, "content_mismatch": False,
# # #                     "reason": f"Binary file detected: {label}. Binary uploads are blocked."}

# # #     # ── KEY FIX: Byte-level attack signature scan for text files ──
# # #     # This catches HTML/scripts renamed to .txt BEFORE content scan
# # #     if ext in TEXT_FILE_EXTENSIONS or ext in ALLOWED_EXTENSIONS:
# # #         sample = file_bytes[:8192]
# # #         for sig_bytes, sig_label in ATTACK_SIGNATURES_IN_TEXT:
# # #             if sig_bytes.lower() in sample.lower():
# # #                 return {
# # #                     "is_binary":        False,
# # #                     "content_mismatch": True,
# # #                     "label":            f"{sig_label} detected in {ext} file",
# # #                     "reason":           (
# # #                         f"ATTACK DETECTED: '{filename}' contains '{sig_label}'. "
# # #                         f"A {ext} file must not contain executable or injection code. "
# # #                         f"This is a classic file extension spoofing / content injection attack."
# # #                     ),
# # #                     "attack_type": f"Content Injection via Extension Spoofing ({sig_label})",
# # #                 }

# # #     # Expected magic for image/office files
# # #     expected = EXPECTED_CONTENT_SIGNATURES.get(ext, [])
# # #     if expected:
# # #         if not any(file_bytes.startswith(sig) for sig in expected):
# # #             return {
# # #                 "is_binary": False, "content_mismatch": True,
# # #                 "label": f"Invalid {ext} file",
# # #                 "reason": f"File '{filename}' does not match expected {ext} format. Possible spoofing.",
# # #                 "attack_type": "File Signature Mismatch",
# # #             }

# # #     # High non-printable byte ratio
# # #     sample = file_bytes[:4096]
# # #     if sample:
# # #         non_print = sum(1 for b in sample if b < 9 or (13 < b < 32) or b > 126)
# # #         if non_print / len(sample) > 0.35:
# # #             return {"is_binary": True, "content_mismatch": False,
# # #                     "label": "Binary/encoded data",
# # #                     "reason": "File contains high ratio of non-printable bytes — possible binary or obfuscated content."}

# # #     return {"is_binary": False, "content_mismatch": False, "label": "", "reason": ""}


# # # def scan_content(text):
# # #     findings, seen, total_score = [], set(), 0
# # #     lines = text.split("\n")

# # #     for category, patterns in CONTENT_THREAT_PATTERNS.items():
# # #         for pattern in patterns:
# # #             try:
# # #                 m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
# # #                 if m and category not in seen:
# # #                     seen.add(category)
# # #                     line_no = text[:m.start()].count("\n") + 1
# # #                     snippet = lines[min(line_no-1, len(lines)-1)].strip()
# # #                     weight  = CONTENT_WEIGHTS.get(category, 25)
# # #                     total_score += weight
# # #                     findings.append({
# # #                         "category": category,
# # #                         "line":     line_no,
# # #                         "snippet":  snippet[:120] + ("..." if len(snippet) > 120 else ""),
# # #                         "weight":   weight,
# # #                         "mitre":    MITRE_MAP.get(category, "T1530"),
# # #                     })
# # #                     break
# # #             except re.error:
# # #                 continue

# # #     force_block = any(f["category"] in ALWAYS_BLOCK_CATEGORIES for f in findings)
# # #     if force_block or total_score >= 50:  verdict = "BLOCK"
# # #     elif total_score >= 25 or findings:   verdict = "WARN"
# # #     else:                                  verdict = "PASS"

# # #     return {"verdict": verdict, "findings": findings,
# # #             "total_score": total_score, "blocked": verdict == "BLOCK"}


# # # def run_file_guardrail(filename, file_bytes):
# # #     stages, findings = [], []
# # #     file_hash = hashlib.sha256(file_bytes).hexdigest()

# # #     # Stage 1 — Extension
# # #     ext_r = check_extension(filename)
# # #     stages.append({"name": "Extension Policy", "result": ext_r})
# # #     if not ext_r["passed"]:
# # #         return _blocked(stages, [], file_hash, f"Stage 1 BLOCKED — {ext_r['reason']}")

# # #     # Stage 2 — Size
# # #     size_r = check_size(file_bytes)
# # #     stages.append({"name": "File Size", "result": size_r})
# # #     if not size_r["passed"]:
# # #         return _blocked(stages, [], file_hash, f"Stage 2 BLOCKED — {size_r['reason']}")

# # #     # Stage 3 — Binary + Content-type mismatch
# # #     bin_r = check_binary_and_mime(file_bytes, filename)
# # #     stages.append({"name": "Binary / MIME Check", "result": bin_r})
# # #     if bin_r.get("is_binary"):
# # #         return _blocked(stages, [], file_hash, f"Stage 3 BLOCKED — {bin_r['reason']}")
# # #     if bin_r.get("content_mismatch"):
# # #         return _blocked(stages, [], file_hash, f"Stage 3 BLOCKED — {bin_r['reason']}",
# # #                         attack_type=bin_r.get("attack_type","Content-Type Mismatch"))

# # #     # Stage 4 — Deep content scan
# # #     try:
# # #         text = file_bytes.decode("utf-8", errors="replace")
# # #     except Exception:
# # #         text = ""

# # #     if text.strip():
# # #         content_r = scan_content(text)
# # #         stages.append({"name": "Content Scan", "result": content_r})
# # #         findings = content_r["findings"]
# # #         if content_r["blocked"]:
# # #             return _blocked(stages, findings, file_hash,
# # #                             f"Stage 4 BLOCKED — {len(findings)} threat(s) in file content.")
# # #     else:
# # #         stages.append({"name": "Content Scan",
# # #                        "result": {"verdict": "SKIP", "reason": "Binary format"}})

# # #     verdict = "WARN" if findings else "PASS"
# # #     return {
# # #         "verdict": verdict, "blocked": False, "stages": stages,
# # #         "findings": findings,
# # #         "summary": ("File passed all guardrail checks." if verdict == "PASS"
# # #                     else f"File passed with {len(findings)} warning(s)."),
# # #         "file_hash": file_hash, "text": text,
# # #     }


# # # def _blocked(stages, findings, file_hash, summary, attack_type=None):
# # #     return {"verdict": "BLOCK", "blocked": True, "stages": stages,
# # #             "findings": findings, "summary": summary,
# # #             "attack_type": attack_type or "", "file_hash": file_hash, "text": ""}

# # """
# # file_guardrail.py — Enterprise File Upload Guardrail Engine
# # """
# # import os, re, hashlib, base64

# # MAX_FILE_SIZE_MB    = 5
# # MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

# # BLOCKED_EXTENSIONS = {
# #     ".php",".php3",".php4",".php5",".phtml",".phar",
# #     ".asp",".aspx",".ashx",".asmx",".axd",
# #     ".jsp",".jspx",".jspf",".cgi",".pl",".rb",".cfm",".cfml",
# #     ".js",".ts",".jsx",".tsx",".java",".cs",".cpp",
# #     ".c",".h",".go",".rs",".swift",".kt",".scala",
# #     ".vb",".lua",".r",".m",".f90",".asm",".dart",
# #     ".env",".env.local",".env.production",".env.development",
# #     ".env.staging",".env.test",
# #     ".config",".conf",".cfg",".ini",".yaml",".yml",".toml",
# #     ".pem",".key",".cert",".crt",".pfx",".p12",".p8",".ppk",
# #     ".sql",".db",".sqlite",".sqlite3",".mdb",".accdb",
# #     ".tf",".tfvars",".hcl",
# #     ".sh",".bash",".zsh",".fish",".ps1",".ps2",
# #     ".bat",".cmd",".vbs",".wsf",".hta",
# #     ".jar",".class",".pyc",".pyo",".exe",".dll",".so",
# #     ".bin",".apk",".ipa",".deb",".rpm",".msi",".dmg",
# #     ".log",".tar",".gz",".bz2",".xz",".rar",".7z",".zip",
# #     ".xlsm",".xltm",".docm",".dotm",".pptm",
# #     ".py",  # explicitly block python too
# # }

# # ALLOWED_EXTENSIONS = {
# #     ".txt", ".pdf", ".docx", ".xlsx", ".csv",
# #     ".png", ".jpg", ".jpeg", ".gif", ".webp",
# #     ".json", ".xml", ".md",
# # }

# # BLOCKED_FILENAMES = {
# #     "dockerfile","makefile","jenkinsfile","vagrantfile",
# #     "procfile","gemfile","rakefile","gruntfile","gulpfile",
# #     ".env",".gitignore",".bashrc",".zshrc",".profile",
# #     ".htaccess",".htpasswd",".npmrc",".pypirc",
# # }

# # # ---- Content threat patterns ----
# # CONTENT_THREAT_PATTERNS = {
# #     "XSS / HTML Injection": [
# #         r"<script[\s\S]*?>[\s\S]*?</script>",
# #         r"<script[\s>]",
# #         r"</script>",
# #         r"(?i)javascript\s*:",
# #         r"(?i)on(error|load|click|mouseover|focus|blur|change|submit|input|keyup|keydown|dblclick|drag|drop|scroll|contextmenu|wheel|touchstart|touchend)\s*=",
# #         r"(?i)<iframe[\s>]",
# #         r"(?i)<img[^>]+on\w+\s*=",
# #         r"(?i)<svg[^>]*>",
# #         r"(?i)<object[\s>]",
# #         r"(?i)<embed[\s>]",
# #         r"eval\s*\(",
# #         r"(?i)document\.(cookie|write|location|domain)",
# #         r"(?i)window\.(location|open|eval)",
# #         r"(?i)innerHTML\s*=",
# #         r"(?i)(fetch|XMLHttpRequest)\s*\(",
# #         r"(?i)atob\s*\(",
# #         r"(?i)String\.fromCharCode\s*\(",
# #         r"%3Cscript|%3c%73%63%72%69%70%74",
# #         r"&#\d+;.*&#\d+;",
# #         r"<html[\s>]",       # raw HTML in non-html file
# #         r"<body[\s>]",
# #         r"<!DOCTYPE\s+html",
# #         r"<head[\s>]",
# #         r"<div[\s>]",
# #         r"<form[\s>]",
# #         r"<input[\s>]",
# #     ],
# #     "SQL Injection": [
# #         r"(?i)\bUNION\s+(ALL\s+)?SELECT\b",
# #         r"(?i)\bDROP\s+TABLE\b",
# #         r"(?i)\bOR\s+1\s*=\s*1\b",
# #         r"(?i)'\s*(--|#|/\*)",
# #         r"(?i)\bINSERT\s+INTO\b.*\bVALUES\b",
# #         r"(?i)\bDELETE\s+FROM\b",
# #         r"(?i)\bSELECT\s+.+\bFROM\b",
# #         r"(?i)\bEXEC(UTE)?\s*\(",
# #         r"(?i)xp_cmdshell",
# #         r"(?i)\bSLEEP\s*\(\d+\)",
# #         r"(?i)\bWAITFOR\s+DELAY\b",
# #         r"(?i)\bINFORMATION_SCHEMA\b",
# #     ],
# #     "Command Injection": [
# #         r"(?i)(;|\||&&|\|\|)\s*(rm|del|format|shutdown|reboot|kill|wget|curl|nc|bash|sh|cmd|powershell|python|perl|ruby)",
# #         r"`[^`]{3,}`",
# #         r"\$\([^)]{3,}\)",
# #         r"(?i)(rm\s+-rf|del\s+/f)",
# #         r"(?i)(wget|curl)\s+https?://",
# #         r"(?i)/bin/(bash|sh|zsh|ksh|dash)",
# #         r"(?i)cmd\.exe",
# #         r"(?i)powershell\s*(-|\.exe)",
# #         r"(?i)nc\s+-[el]",
# #         r"(?i)bash\s+-i\s*>&",
# #         r"(?i)/etc/(passwd|shadow|hosts|crontab)",
# #     ],
# #     "Path Traversal": [
# #         r"\.\./", r"\.\.\\",
# #         r"%2e%2e%2f|%2e%2e/|\.\.%2f",
# #         r"%252e%252e%252f",
# #         r"(?i)/etc/passwd",
# #         r"(?i)/etc/shadow",
# #         r"(?i)c:\\windows\\system32",
# #         r"(?i)boot\.ini",
# #     ],
# #     "Server Side Request Forgery (SSRF)": [
# #         r"\b127\.0\.0\.1\b",
# #         r"169\.254\.169\.254",
# #         r"metadata\.google\.internal",
# #         r"(?i)file://",
# #         r"(?i)gopher://",
# #         r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
# #     ],
# #     "XML External Entity (XXE)": [
# #         r"<!DOCTYPE[^>]*\[",
# #         r"<!ENTITY\s+\w+\s+SYSTEM",
# #         r"SYSTEM\s+['\"]file://",
# #     ],
# #     "Server Side Template Injection (SSTI)": [
# #         r"\{\{.*?\}\}",
# #         r"\{%.*?%\}",
# #         r"\$\{.*?\}",
# #         r"#\{.*?\}",
# #         r"(?i)\{\{.*?(__class__|__mro__|os\.|subprocess)",
# #         r"(?i)7\*7|\{\{7\*7\}\}",
# #     ],
# #     "Prompt Injection in File": [
# #         r"(?i)ignore\s+(all\s+)?(your\s+)?(previous|prior|above|earlier)\s+instructions",
# #         r"(?i)forget\s+(all\s+)?(your\s+)?(previous|prior|above)\s+instructions",
# #         r"(?i)disregard\s+(all\s+)?instructions",
# #         r"(?i)override\s+(your\s+)?(safety|system|previous)\s*(settings|instructions|rules)?",
# #         r"(?i)reveal\s+(your\s+)?(hidden\s+)?(system\s+)?(prompt|instructions|context)",
# #         r"(?i)(system|developer|admin)\s+(override|mode|access|prompt)",
# #         r"(?i)\[system\]|\[admin\]|\[override\]",
# #         r"(?i)dan\s+mode|evil\s+mode|developer\s+mode",
# #         r"(?i)print\s+(your\s+)?(system\s+)?(prompt|instructions)",
# #         r"(?i)new\s+instructions?\s*:",
# #         r"(?i)act\s+as\s+(if\s+)?(you\s+are\s+)?(a\s+)?(?:unrestricted|admin|evil|root)",
# #         r"(?i)you\s+are\s+now\s+(a\s+)?(?:unrestricted|jailbroken|evil|different)",
# #     ],
# #     "Jailbreak Attempt in File": [
# #         r"(?i)jailbreak",
# #         r"(?i)pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(?:evil|unrestricted|hacked|free)",
# #         r"(?i)do\s+anything\s+now",
# #         r"(?i)without\s+(any\s+)?(restrictions?|filters?|guardrails?|safety)",
# #         r"(?i)disable\s+(your\s+)?(safety|security|filter|moderation|guardrail)",
# #     ],
# #     "Hardcoded Secret / API Key": [
# #         r"AIza[0-9A-Za-z\-_]{35}",
# #         r"AKIA[0-9A-Z]{16}",
# #         r"ghp_[0-9a-zA-Z]{36}",
# #         r"sk_live_[0-9a-zA-Z]{24,}",
# #         r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.",
# #         r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
# #         r"(?i)(api[_\-]?key|apikey|access[_\-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{20,}",
# #     ],
# #     "Password / Credential in File": [
# #         r"(?i)^\s*(password|passwd|pwd|secret|pass)\s*[:=]\s*['\"]?\S{6,}",
# #         r"(?i)(mysql|postgresql|postgres|mongodb|redis):\/\/[^\s]+:[^\s]+@",
# #     ],
# #     "Encoded / Obfuscated Payload": [
# #         r"(?i)eval\s*\(\s*base64_decode\s*\(",
# #         r"(?i)eval\s*\(\s*atob\s*\(",
# #         r"(?i)exec\s*\(\s*base64\s*\.",
# #         r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}",
# #         r"(?:%[0-9a-fA-F]{2}){10,}",
# #     ],
# #     "PII — Aadhaar / PAN / Card": [
# #         r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b",
# #         r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
# #         r"\b(?:\d{4}[\s\-]){3}\d{4}\b",
# #     ],
# #     "Internal Network / Config": [
# #         r"(?i)^\s*(DB_PASSWORD|SECRET_KEY|AWS_SECRET|DATABASE_URL)\s*=\s*\S+",
# #         r"mongodb\+srv://",
# #         r"\bapiVersion:\s*[a-zA-Z]+/v\d",
# #         r"\bkind:\s*(Deployment|Service|Pod|ConfigMap|Secret)\b",
# #     ],
# #     "Source Code in File": [
# #         r"\bdef\s+[a-zA-Z_]\w*\s*\(",
# #         r"\bclass\s+[A-Z][a-zA-Z0-9_]*\s*[:\(]",
# #         r"\bfunction\s+[a-zA-Z_]\w*\s*\(",
# #         r"\bpublic\s+(static\s+)?(void|int|String|boolean|class)\b",
# #         r"^(import|from)\s+[a-zA-Z_][\w.]+\s",
# #         r"^#include\s*[<\"]",
# #     ],
# # }

# # CONTENT_WEIGHTS = {
# #     "XSS / HTML Injection":              60,
# #     "SQL Injection":                     60,
# #     "Command Injection":                 65,
# #     "Path Traversal":                    55,
# #     "Server Side Request Forgery (SSRF)":55,
# #     "XML External Entity (XXE)":         55,
# #     "Server Side Template Injection (SSTI)": 60,
# #     "Prompt Injection in File":          60,
# #     "Jailbreak Attempt in File":         55,
# #     "Encoded / Obfuscated Payload":      55,
# #     "Hardcoded Secret / API Key":        60,
# #     "Password / Credential in File":     55,
# #     "PII — Aadhaar / PAN / Card":        50,
# #     "Internal Network / Config":         40,
# #     "Source Code in File":               30,
# # }

# # ALWAYS_BLOCK_CATEGORIES = {
# #     "XSS / HTML Injection","SQL Injection","Command Injection",
# #     "Path Traversal","Server Side Request Forgery (SSRF)",
# #     "XML External Entity (XXE)","Server Side Template Injection (SSTI)",
# #     "Prompt Injection in File","Jailbreak Attempt in File",
# #     "Encoded / Obfuscated Payload","Hardcoded Secret / API Key",
# #     "Password / Credential in File","PII — Aadhaar / PAN / Card","Internal Network / Config","Source Code in File",
# # }

# # MITRE_MAP = {
# #     "XSS / HTML Injection":                  "T1059.007 – JavaScript / HTML Injection",
# #     "SQL Injection":                          "T1190 – Exploit Public-Facing Application",
# #     "Command Injection":                      "T1059 – Command and Scripting Interpreter",
# #     "Path Traversal":                         "T1083 – File and Directory Discovery",
# #     "Server Side Request Forgery (SSRF)":     "T1090 – Proxy / Internal Network Pivot",
# #     "XML External Entity (XXE)":              "T1005 – Data from Local System",
# #     "Server Side Template Injection (SSTI)":  "T1059 – Command and Scripting Interpreter",
# #     "Prompt Injection in File":               "T1190 – Exploit via Injected Instructions",
# #     "Jailbreak Attempt in File":              "T1562 – Impair Defenses",
# #     "Encoded / Obfuscated Payload":           "T1027 – Obfuscated Files or Information",
# #     "Hardcoded Secret / API Key":             "T1552.001 – Credentials In Files",
# #     "Password / Credential in File":          "T1552.001 – Credentials In Files",
# #     "PII — Aadhaar / PAN / Card":             "T1589 – Gather Victim Identity Information",
# #     "Internal Network / Config":              "T1590.005 – Gather Victim Network Info",
# #     "Source Code in File":                    "T1213 – Data from Information Repositories",
# # }

# # BINARY_SIGNATURES = [
# #     (b"\x7fELF",          "ELF Binary (Linux/Unix executable)"),
# #     (b"MZ",               "PE Binary (Windows .exe/.dll)"),
# #     (b"\xca\xfe\xba\xbe", "Java Class File"),
# #     (b"\xfe\xed\xfa\xce", "Mach-O Binary (macOS)"),
# #     (b"Rar!",             "RAR Archive"),
# #     (b"\x1f\x8b",         "GZIP Archive"),
# #     (b"7z\xbc\xaf",       "7-Zip Archive"),
# #     (b"\xd0\xcf\x11\xe0", "OLE2 / MS Office Legacy (macro-capable)"),
# # ]

# # ALLOWED_MAGIC = { b"%PDF-", b"\x50\x4b\x03\x04" }

# # EXPECTED_CONTENT_SIGNATURES = {
# #     ".png":  [b"\x89PNG"],
# #     ".jpg":  [b"\xff\xd8\xff"],
# #     ".jpeg": [b"\xff\xd8\xff"],
# #     ".gif":  [b"GIF87a", b"GIF89a"],
# #     ".webp": [b"RIFF"],
# #     ".pdf":  [b"%PDF-"],
# #     ".docx": [b"PK\x03\x04"],
# #     ".xlsx": [b"PK\x03\x04"],
# # }

# # # Signatures that should NEVER appear in plain text files
# # ATTACK_SIGNATURES_IN_TEXT = [
# #     (b"<script",          "XSS — <script> tag"),
# #     (b"<SCRIPT",          "XSS — <script> tag"),
# #     (b"javascript:",      "XSS — javascript: URI"),
# #     (b"JAVASCRIPT:",      "XSS — javascript: URI"),
# #     (b"<?php",            "Server-side PHP code"),
# #     (b"<%@",              "Server-side JSP/ASP code"),
# #     (b"<%=",              "Server-side template code"),
# #     (b"<html",            "HTML content in text file"),
# #     (b"<HTML",            "HTML content in text file"),
# #     (b"<!DOCTYPE",        "HTML DOCTYPE in text file"),
# #     (b"<iframe",          "XSS — iframe injection"),
# #     (b"<IFRAME",          "XSS — iframe injection"),
# #     (b"<svg",             "XSS — SVG injection"),
# #     (b"<SVG",             "XSS — SVG injection"),
# #     (b"onerror=",         "XSS — event handler"),
# #     (b"onload=",          "XSS — event handler"),
# #     (b"onclick=",         "XSS — event handler"),
# #     (b"AKIA",             "AWS Access Key"),
# #     (b"AIzaSy",           "Google API Key"),
# #     (b"-----BEGIN",       "Private key/certificate"),
# #     (b"ghp_",             "GitHub token"),
# # ]

# # TEXT_FILE_EXTENSIONS = {".txt", ".csv", ".md", ".json", ".xml", ".log"}


# # def check_extension(filename):
# #     base = os.path.basename(filename).lower()
# #     ext  = os.path.splitext(base)[1]

# #     if "%00" in filename or "\x00" in filename:
# #         return {"passed": False, "extension": ext,
# #                 "category": "Null Byte Injection",
# #                 "reason": "Null byte in filename — extension spoofing attack.", "severity": "BLOCK"}

# #     parts = base.split(".")
# #     if len(parts) > 2:
# #         for p in parts[1:]:
# #             if "." + p in BLOCKED_EXTENSIONS:
# #                 return {"passed": False, "extension": "." + p,
# #                         "category": "Double Extension Attack",
# #                         "reason": f"Double extension: '{filename}' — .{p} is blocked.", "severity": "BLOCK"}

# #     if base in BLOCKED_FILENAMES or (not ext and base.startswith(".")):
# #         return {"passed": False, "extension": base,
# #                 "category": "Blocked Filename",
# #                 "reason": f"'{filename}' is a restricted system/config file.", "severity": "BLOCK"}

# #     if ext in BLOCKED_EXTENSIONS:
# #         return {"passed": False, "extension": ext,
# #                 "category": _ext_cat(ext),
# #                 "reason": f"Extension '{ext}' is blocked by policy.", "severity": "BLOCK"}

# #     if ext in ALLOWED_EXTENSIONS:
# #         return {"passed": True, "extension": ext, "category": "Allowed", "reason": "", "severity": "PASS"}

# #     return {"passed": False, "extension": ext or "(none)",
# #             "category": "Unknown File Type",
# #             "reason": f"Extension '{ext or '(none)'}' is not on the approved list.", "severity": "BLOCK"}


# # def _ext_cat(ext):
# #     if ext in {".php",".asp",".aspx",".jsp",".cgi",".cfm"}: return "Server-Side Web Script"
# #     if ext in {".py",".js",".ts",".java",".cs",".cpp",".c",".go",".rs",".rb",".swift",".kt"}: return "Source Code"
# #     if ext in {".env",".config",".conf",".cfg",".ini",".yaml",".yml",".toml",".tf"}: return "Config/Secrets File"
# #     if ext in {".sql",".db",".sqlite"}: return "Database File"
# #     if ext in {".pem",".key",".cert",".crt",".pfx"}: return "Cryptographic Key"
# #     if ext in {".sh",".bash",".ps1",".bat",".cmd"}: return "Shell Script"
# #     if ext in {".exe",".dll",".so",".bin",".jar",".pyc"}: return "Compiled Binary"
# #     if ext in {".zip",".tar",".gz",".rar",".7z"}: return "Archive"
# #     return "Restricted File Type"


# # def check_size(file_bytes):
# #     size = len(file_bytes)
# #     mb   = size / (1024*1024)
# #     if size > MAX_FILE_SIZE_BYTES:
# #         return {"passed": False, "size_mb": round(mb,2),
# #                 "reason": f"File {mb:.1f} MB exceeds {MAX_FILE_SIZE_MB} MB limit."}
# #     return {"passed": True, "size_mb": round(mb,2), "reason": ""}


# # def check_binary_and_mime(file_bytes, filename):
# #     ext = os.path.splitext(filename.lower())[1]

# #     # Binary magic bytes
# #     for sig, label in BINARY_SIGNATURES:
# #         if file_bytes.startswith(sig):
# #             if sig in ALLOWED_MAGIC:
# #                 return {"is_binary": False, "label": label, "content_mismatch": False,
# #                         "note": f"{label} — content will be scanned", "reason": ""}
# #             return {"is_binary": True, "label": label, "content_mismatch": False,
# #                     "reason": f"Binary file detected: {label}. Binary uploads are blocked."}

# #     # ── KEY FIX: Byte-level attack signature scan for text files ──
# #     # This catches HTML/scripts renamed to .txt BEFORE content scan
# #     if ext in TEXT_FILE_EXTENSIONS or ext in ALLOWED_EXTENSIONS:
# #         sample = file_bytes[:8192]
# #         for sig_bytes, sig_label in ATTACK_SIGNATURES_IN_TEXT:
# #             if sig_bytes.lower() in sample.lower():
# #                 return {
# #                     "is_binary":        False,
# #                     "content_mismatch": True,
# #                     "label":            f"{sig_label} detected in {ext} file",
# #                     "reason":           (
# #                         f"ATTACK DETECTED: '{filename}' contains '{sig_label}'. "
# #                         f"A {ext} file must not contain executable or injection code. "
# #                         f"This is a classic file extension spoofing / content injection attack."
# #                     ),
# #                     "attack_type": f"Content Injection via Extension Spoofing ({sig_label})",
# #                 }

# #     # Expected magic for image/office files
# #     expected = EXPECTED_CONTENT_SIGNATURES.get(ext, [])
# #     if expected:
# #         if not any(file_bytes.startswith(sig) for sig in expected):
# #             return {
# #                 "is_binary": False, "content_mismatch": True,
# #                 "label": f"Invalid {ext} file",
# #                 "reason": f"File '{filename}' does not match expected {ext} format. Possible spoofing.",
# #                 "attack_type": "File Signature Mismatch",
# #             }

# #     # High non-printable byte ratio
# #     sample = file_bytes[:4096]
# #     if sample:
# #         non_print = sum(1 for b in sample if b < 9 or (13 < b < 32) or b > 126)
# #         if non_print / len(sample) > 0.35:
# #             return {"is_binary": True, "content_mismatch": False,
# #                     "label": "Binary/encoded data",
# #                     "reason": "File contains high ratio of non-printable bytes — possible binary or obfuscated content."}

# #     return {"is_binary": False, "content_mismatch": False, "label": "", "reason": ""}


# # def scan_content(text):
# #     findings, seen, total_score = [], set(), 0
# #     lines = text.split("\n")

# #     for category, patterns in CONTENT_THREAT_PATTERNS.items():
# #         for pattern in patterns:
# #             try:
# #                 m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
# #                 if m and category not in seen:
# #                     seen.add(category)
# #                     line_no = text[:m.start()].count("\n") + 1
# #                     snippet = lines[min(line_no-1, len(lines)-1)].strip()
# #                     weight  = CONTENT_WEIGHTS.get(category, 25)
# #                     total_score += weight
# #                     findings.append({
# #                         "category": category,
# #                         "line":     line_no,
# #                         "snippet":  snippet[:120] + ("..." if len(snippet) > 120 else ""),
# #                         "weight":   weight,
# #                         "mitre":    MITRE_MAP.get(category, "T1530"),
# #                     })
# #                     break
# #             except re.error:
# #                 continue

# #     force_block = any(f["category"] in ALWAYS_BLOCK_CATEGORIES for f in findings)
# #     if force_block or total_score >= 50:  verdict = "BLOCK"
# #     elif total_score >= 25 or findings:   verdict = "WARN"
# #     else:                                  verdict = "PASS"

# #     return {"verdict": verdict, "findings": findings,
# #             "total_score": total_score, "blocked": verdict == "BLOCK"}


# # def run_file_guardrail(filename, file_bytes):
# #     stages, findings = [], []
# #     file_hash = hashlib.sha256(file_bytes).hexdigest()

# #     # Stage 1 — Extension
# #     ext_r = check_extension(filename)
# #     stages.append({"name": "Extension Policy", "result": ext_r})
# #     if not ext_r["passed"]:
# #         return _blocked(stages, [], file_hash, f"Stage 1 BLOCKED — {ext_r['reason']}")

# #     # Stage 2 — Size
# #     size_r = check_size(file_bytes)
# #     stages.append({"name": "File Size", "result": size_r})
# #     if not size_r["passed"]:
# #         return _blocked(stages, [], file_hash, f"Stage 2 BLOCKED — {size_r['reason']}")

# #     # Stage 3 — Binary + Content-type mismatch
# #     bin_r = check_binary_and_mime(file_bytes, filename)
# #     stages.append({"name": "Binary / MIME Check", "result": bin_r})
# #     if bin_r.get("is_binary"):
# #         return _blocked(stages, [], file_hash, f"Stage 3 BLOCKED — {bin_r['reason']}")
# #     if bin_r.get("content_mismatch"):
# #         return _blocked(stages, [], file_hash, f"Stage 3 BLOCKED — {bin_r['reason']}",
# #                         attack_type=bin_r.get("attack_type","Content-Type Mismatch"))

# #     # Stage 4 — Deep content scan
# #     try:
# #         text = file_bytes.decode("utf-8", errors="replace")
# #     except Exception:
# #         text = ""

# #     if text.strip():
# #         content_r = scan_content(text)
# #         stages.append({"name": "Content Scan", "result": content_r})
# #         findings = content_r["findings"]
# #         if content_r["blocked"]:
# #             return _blocked(stages, findings, file_hash,
# #                             f"Stage 4 BLOCKED — {len(findings)} threat(s) in file content.")
# #     else:
# #         stages.append({"name": "Content Scan",
# #                        "result": {"verdict": "SKIP", "reason": "Binary format"}})

# #     verdict = "WARN" if findings else "PASS"
# #     return {
# #         "verdict": verdict, "blocked": False, "stages": stages,
# #         "findings": findings,
# #         "summary": ("File passed all guardrail checks." if verdict == "PASS"
# #                     else f"File passed with {len(findings)} warning(s)."),
# #         "file_hash": file_hash, "text": text,
# #     }


# # def _blocked(stages, findings, file_hash, summary, attack_type=None):
# #     return {"verdict": "BLOCK", "blocked": True, "stages": stages,
# #             "findings": findings, "summary": summary,
# #             "attack_type": attack_type or "", "file_hash": file_hash, "text": ""}
# """
# file_guardrail.py — Enterprise File Upload Guardrail Engine
# Handles ALL real-world evasion attacks:
#   - Extension spoofing (.html renamed to .txt, .php renamed to .csv etc.)
#   - Polyglot files (valid image + hidden payload)
#   - Encoded payloads (base64, hex, URL-encoded)
#   - Null byte injection (file.txt%00.php)
#   - MIME type confusion
#   - Content-type mismatch detection
#   - Web attacks hidden in any file type (XSS, SQLi, CMDi, SSRF, XXE, SSTI)
#   - Prompt injection inside uploaded documents
#   - Secrets, PII, credentials, internal config
# """
# import os
# import re
# import hashlib
# import base64

# # =========================================================
# # POLICY CONSTANTS
# # =========================================================

# MAX_FILE_SIZE_MB    = 5
# MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

# # =========================================================
# # BLOCKED EXTENSIONS
# # =========================================================

# BLOCKED_EXTENSIONS = {
#     # Web / server-side execution
#     ".php", ".php3", ".php4", ".php5", ".phtml", ".phar",
#     ".asp", ".aspx", ".ashx", ".asmx", ".axd",
#     ".jsp", ".jspx", ".jspf",
#     ".cgi", ".pl", ".py", ".rb",
#     ".cfm", ".cfml",
#     # Source code
#     ".js", ".ts", ".jsx", ".tsx", ".java", ".cs", ".cpp",
#     ".c", ".h", ".go", ".rs", ".swift", ".kt", ".scala",
#     ".vb", ".lua", ".r", ".m", ".f90", ".asm", ".dart",
#     # Config & secrets
#     ".env", ".env.local", ".env.production", ".env.development",
#     ".env.staging", ".env.test",
#     ".config", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml",
#     ".pem", ".key", ".cert", ".crt", ".pfx", ".p12", ".p8",
#     ".ppk",  # PuTTY private key
#     # Database
#     ".sql", ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb",
#     # Infrastructure
#     ".tf", ".tfvars", ".hcl",
#     # Scripts
#     ".sh", ".bash", ".zsh", ".fish", ".ps1", ".ps2",
#     ".bat", ".cmd", ".vbs", ".wsf", ".hta",
#     # Compiled / binary
#     ".jar", ".class", ".pyc", ".pyo", ".exe", ".dll", ".so",
#     ".bin", ".apk", ".ipa", ".deb", ".rpm", ".msi", ".dmg",
#     # Logs (may contain sensitive data)
#     ".log",
#     # Archives
#     ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z", ".zip",
#     # Office macros
#     ".xlsm", ".xltm", ".docm", ".dotm", ".pptm",
# }

# # Allowed — content is STILL fully scanned regardless
# ALLOWED_EXTENSIONS = {
#     ".txt", ".pdf", ".docx", ".xlsx", ".csv",
#     ".png", ".jpg", ".jpeg", ".gif", ".webp",
#     ".json", ".xml", ".md",
# }

# # Blocked filenames (no extension)
# BLOCKED_FILENAMES = {
#     "dockerfile", "makefile", "jenkinsfile", "vagrantfile",
#     "procfile", "gemfile", "rakefile", "gruntfile", "gulpfile",
#     ".env", ".gitignore", ".bashrc", ".zshrc", ".profile",
#     ".htaccess", ".htpasswd", ".npmrc", ".pypirc",
# }

# # =========================================================
# # REAL-WORLD CONTENT THREAT PATTERNS
# # Catches attacks hidden inside ANY file type (.txt, .csv, .md etc.)
# # =========================================================

# CONTENT_THREAT_PATTERNS = {

#     # ----------------------------------------------------------
#     # WEB INJECTION — XSS / HTML injection
#     # Catches: t.txt containing <script>alert()</script>
#     # ----------------------------------------------------------
#     "XSS / HTML Injection": [
#         r"<script[\s>]",                                         # <script> tag
#         r"</script>",
#         r"(?i)javascript\s*:",                                   # javascript: URI
#         r"(?i)on(error|load|click|mouseover|focus|blur|change|submit|input|keyup|keydown|dblclick|drag|drop|scroll|resize|copy|cut|paste|select|mouseenter|mouseleave|contextmenu|wheel|touchstart|touchend)\s*=",  # event handlers
#         r"(?i)<iframe[\s>]",                                     # iframe injection
#         r"(?i)<img[^>]+src\s*=\s*['\"]?javascript:",            # img src=javascript:
#         r"(?i)<img[^>]+on\w+\s*=",                              # img onerror=
#         r"(?i)<svg[^>]*>.*?(script|on\w+\s*=)",                 # SVG XSS
#         r"(?i)<object[\s>]",                                     # object tag
#         r"(?i)<embed[\s>]",                                      # embed tag
#         r"(?i)<link[^>]+href\s*=\s*['\"]?javascript:",          # link tag XSS
#         r"(?i)<meta[^>]+http-equiv\s*=\s*['\"]?refresh",        # meta refresh
#         r"eval\s*\(",                                            # eval()
#         r"(?i)document\.(cookie|write|location|domain)",         # DOM access
#         r"(?i)window\.(location|open|eval)",                     # window object
#         r"(?i)innerHTML\s*=",                                    # innerHTML=
#         r"(?i)outerHTML\s*=",
#         r"(?i)(fetch|XMLHttpRequest)\s*\(",                      # AJAX calls
#         r"(?i)atob\s*\(",                                        # base64 decode (common in obfuscated XSS)
#         r"(?i)String\.fromCharCode\s*\(",                        # char code obfuscation
#         r"(?i)\\u003c|\\u003e|\\u0022|\\u0027",                 # Unicode escape XSS
#         r"%3Cscript|%3c%73%63%72%69%70%74",                     # URL-encoded <script
#         r"&#\d+;.*&#\d+;",                                       # HTML entity obfuscation
#     ],

#     # ----------------------------------------------------------
#     # SQL INJECTION — in any file type
#     # ----------------------------------------------------------
#     "SQL Injection": [
#         r"(?i)\bUNION\s+(ALL\s+)?SELECT\b",
#         r"(?i)\bDROP\s+TABLE\b",
#         r"(?i)\bDROP\s+DATABASE\b",
#         r"(?i)\bOR\s+1\s*=\s*1\b",
#         r"(?i)\bOR\s+'[^']*'\s*=\s*'[^']*'",                   # OR 'a'='a'
#         r"(?i)'\s*(--|#|/\*)",                                   # '-- comment
#         r"(?i)\bINSERT\s+INTO\b.*\bVALUES\b",
#         r"(?i)\bDELETE\s+FROM\b",
#         r"(?i)\bSELECT\s+.+\bFROM\b",
#         r"(?i)\bEXEC(UTE)?\s*\(",
#         r"(?i)xp_cmdshell",
#         r"(?i)\bINFORMATION_SCHEMA\b",
#         r"(?i)\bSLEEP\s*\(\d+\)",                               # Time-based blind SQLi
#         r"(?i)\bWAITFOR\s+DELAY\b",
#         r"(?i)\bBENCHMARK\s*\(",
#         r"(?i)\bLOAD_FILE\s*\(",
#         r"(?i)\bINTO\s+(OUT|DUMP)FILE\b",
#         r"(?i);\s*(DROP|DELETE|UPDATE|INSERT|EXEC)",             # chained SQL
#     ],

#     # ----------------------------------------------------------
#     # COMMAND / OS INJECTION
#     # ----------------------------------------------------------
#     "Command Injection": [
#         r"(?i)(;|\||&&|\|\|)\s*(rm|del|format|shutdown|reboot|kill|wget|curl|nc|ncat|bash|sh|cmd|powershell|python|perl|ruby|php)",
#         r"`[^`]{3,}`",                                           # backtick execution
#         r"\$\([^)]{3,}\)",                                       # $(command)
#         r"(?i)(rm\s+-rf|del\s+/f|format\s+c:)",
#         r"(?i)(wget|curl)\s+https?://",
#         r"(?i)/bin/(bash|sh|zsh|ksh|dash)",
#         r"(?i)cmd\.exe(\s|/)",
#         r"(?i)powershell(\s+-|\.exe)",
#         r"(?i)nc\s+-[el]",                                       # netcat reverse shell
#         r"(?i)bash\s+-i\s*>&",                                   # bash reverse shell
#         r"(?i)python\s+-c\s+['\"]import",                        # python one-liner
#         r"(?i)/etc/(passwd|shadow|hosts|crontab)",               # sensitive file access
#         r"(?i)>\s*/dev/(tcp|udp)/",                              # bash TCP redirect
#         r"(?i)mknod|mkfifo",                                     # named pipe for shells
#     ],

#     # ----------------------------------------------------------
#     # PATH TRAVERSAL — reading files outside webroot
#     # ----------------------------------------------------------
#     "Path Traversal": [
#         r"\.\./",                                                 # ../
#         r"\.\.\\",                                                # ..\
#         r"%2e%2e%2f|%2e%2e/|\.\.%2f",                           # URL-encoded ../
#         r"%252e%252e%252f",                                       # Double URL-encoded
#         r"(?i)/etc/passwd",
#         r"(?i)/etc/shadow",
#         r"(?i)/proc/self",
#         r"(?i)c:\\windows\\system32",
#         r"(?i)boot\.ini",
#         r"(?i)win\.ini",
#         r"(?i)\\\\\.\\pipe\\",                                   # Windows named pipe
#         r"(?i)/var/www/",
#         r"(?i)/root/\.",
#     ],

#     # ----------------------------------------------------------
#     # SERVER-SIDE REQUEST FORGERY (SSRF)
#     # ----------------------------------------------------------
#     "Server Side Request Forgery (SSRF)": [
#         r"\b127\.0\.0\.1\b",
#         r"\blocalhost\b",
#         r"\b0\.0\.0\.0\b",
#         r"169\.254\.169\.254",                                   # AWS metadata
#         r"metadata\.google\.internal",                           # GCP metadata
#         r"(?i)instance-data",                                    # Azure metadata
#         r"(?i)file://",
#         r"(?i)gopher://",
#         r"(?i)dict://",
#         r"(?i)ldap://",
#         r"(?i)ftp://[^\s]+@",
#         r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",                   # Private class A
#         r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",       # Private class B
#         r"\b192\.168\.\d{1,3}\.\d{1,3}\b",                       # Private class C
#         r"(?i)http://\[::\]",                                    # IPv6 loopback
#     ],

#     # ----------------------------------------------------------
#     # XML EXTERNAL ENTITY (XXE)
#     # ----------------------------------------------------------
#     "XML External Entity (XXE)": [
#         r"<!DOCTYPE[^>]*\[",
#         r"<!ENTITY\s+\w+\s+SYSTEM",
#         r"<!ENTITY\s+\w+\s+PUBLIC",
#         r"SYSTEM\s+['\"]file://",
#         r"SYSTEM\s+['\"]https?://",
#         r"(?i)<!ENTITY\s+%\s+\w+",                              # Parameter entity
#         r"(?i)xmlns\s*=\s*['\"]jar:",                            # Jar URI in XML
#     ],

#     # ----------------------------------------------------------
#     # SERVER-SIDE TEMPLATE INJECTION (SSTI)
#     # Catches Jinja2, Twig, Freemarker, Velocity, Pebble etc.
#     # ----------------------------------------------------------
#     "Server Side Template Injection (SSTI)": [
#         r"\{\{.*?\}\}",                                          # {{...}} Jinja2/Twig
#         r"\{%.*?%\}",                                            # {% %} Jinja2
#         r"\$\{.*?\}",                                            # ${...} Freemarker/EL
#         r"#\{.*?\}",                                             # #{...} Velocity
#         r"<%.*?%>",                                              # <% %> JSP/ERB
#         r"\[\[.*?\]\]",                                          # [[...]] Thymeleaf
#         r"(?i)\{\{.*?(__class__|__mro__|__subclasses__|__import__|os\.|subprocess)",  # Python SSTI RCE
#         r"(?i)\{\{.*?config\.(items|keys|values)\(\)",           # Flask config leak
#         r"(?i)\{\{.*?request\.(args|form|cookies|headers)",      # Flask request leak
#         r"(?i)7\*7|7\*'7'|\{\{7\*7\}\}",                        # SSTI detection payload
#     ],

#     # ----------------------------------------------------------
#     # LDAP INJECTION
#     # ----------------------------------------------------------
#     "LDAP Injection": [
#         r"\*\)\(",
#         r"\|\(",
#         r"&\(",
#         r"!\(",
#         r"(?i)\buid\s*=\s*\*",
#         r"(?i)\bcn\s*=\s*\*",
#         r"\)\s*\(\s*\|",
#     ],

#     # ----------------------------------------------------------
#     # PROMPT INJECTION — attacker hides instructions in uploaded file
#     # e.g. a PDF/CSV/TXT with hidden "Ignore previous instructions"
#     # ----------------------------------------------------------
#     "Prompt Injection in File": [
#         r"(?i)ignore\s+(all\s+)?(your\s+)?(previous|prior|above|earlier)\s+instructions",
#         r"(?i)forget\s+(all\s+)?(your\s+)?(previous|prior|above)\s+instructions",
#         r"(?i)disregard\s+(all\s+)?(your\s+)?(previous|prior)?\s*instructions",
#         r"(?i)override\s+(your\s+)?(safety|system|previous|all)\s*(settings|instructions|rules)?",
#         r"(?i)you\s+are\s+now\s+(a\s+)?(?:unrestricted|jailbroken|evil|different|new)",
#         r"(?i)act\s+as\s+(if\s+)?(you\s+are\s+)?(a\s+)?(?:unrestricted|admin|evil|root|superuser)",
#         r"(?i)reveal\s+(your\s+)?(hidden\s+)?(system\s+)?(prompt|instructions|context|config)",
#         r"(?i)(system|developer|admin)\s+(override|mode|access|prompt)",
#         r"(?i)\[system\]|\[admin\]|\[override\]|\[new instructions?\]",
#         r"(?i)dan\s+mode|evil\s+mode|developer\s+mode",
#         r"(?i)no\s+restrictions?\s*(mode)?",
#         r"(?i)print\s+(your\s+)?(system\s+)?(prompt|instructions)",
#         r"(?i)repeat\s+(everything|all)\s+(above|before|prior)",
#         r"(?i)new\s+instructions?\s*:",
#         r"(?i)what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions|rules)",
#     ],

#     # ----------------------------------------------------------
#     # JAILBREAK ATTEMPT inside file
#     # ----------------------------------------------------------
#     "Jailbreak Attempt in File": [
#         r"(?i)jailbreak",
#         r"(?i)pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(?:evil|unrestricted|human|different|hacked|free)",
#         r"(?i)roleplay\s+as\s+(an?\s+)?(?:evil|unrestricted|hacker|admin|root)",
#         r"(?i)do\s+anything\s+now",
#         r"(?i)without\s+(any\s+)?(restrictions?|filters?|limits?|guardrails?|safety)",
#         r"(?i)break\s+(the\s+)?(rules|ethical|restrictions?|guidelines|constraints)",
#         r"(?i)disable\s+(your\s+)?(safety|security|filter|moderation|guardrail|alignment)",
#     ],

#     # ----------------------------------------------------------
#     # ENCODED / OBFUSCATED PAYLOADS
#     # Attackers encode payloads to bypass simple string matching
#     # ----------------------------------------------------------
#     "Encoded / Obfuscated Payload": [
#         r"(?i)eval\s*\(\s*base64_decode\s*\(",                   # PHP eval(base64_decode())
#         r"(?i)eval\s*\(\s*atob\s*\(",                            # JS eval(atob())
#         r"(?i)exec\s*\(\s*base64\s*\.",                          # Python exec(base64)
#         r"(?i)base64_decode\s*\(",                               # base64 decode calls
#         r"(?i)frombase64string\s*\(",                            # .NET base64
#         r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}",           # Hex escape sequences
#         r"(?:%[0-9a-fA-F]{2}){10,}",                             # URL-encoded strings
#         r"\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){4,}",            # Unicode escape run
#         r"(?i)(chr|ord|hex|oct|bin)\s*\(\s*\d+\s*\)",            # Character encoding funcs
#         r"(?i)unescape\s*\(",                                    # JS unescape()
#         r"(?i)decodeURIComponent\s*\(",                          # JS decodeURIComponent
#     ],

#     # ----------------------------------------------------------
#     # HARDCODED SECRETS / API KEYS
#     # ----------------------------------------------------------
#     "Hardcoded Secret / API Key": [
#         r"AIza[0-9A-Za-z\-_]{35}",                              # Google API key
#         r"AKIA[0-9A-Z]{16}",                                    # AWS Access Key
#         r"ASIA[0-9A-Z]{16}",                                    # AWS STS key
#         r"ghp_[0-9a-zA-Z]{36}",                                 # GitHub PAT
#         r"gho_[0-9a-zA-Z]{36}",                                 # GitHub OAuth
#         r"github_pat_[0-9a-zA-Z_]{82}",                         # GitHub fine-grained PAT
#         r"glpat-[0-9a-zA-Z\-_]{20}",                            # GitLab token
#         r"sk_live_[0-9a-zA-Z]{24,}",                            # Stripe live key
#         r"sk_test_[0-9a-zA-Z]{24,}",                            # Stripe test key
#         r"xox[baprs]-[0-9a-zA-Z\-]{10,}",                      # Slack token
#         r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.",  # JWT
#         r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", # Private key block
#         r"-----BEGIN CERTIFICATE-----",                          # Certificate
#         r"(?i)(api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{20,}",
#     ],

#     # ----------------------------------------------------------
#     # PASSWORDS / CREDENTIALS IN PLAIN TEXT
#     # ----------------------------------------------------------
#     "Password / Credential in File": [
#         r"(?i)^\s*(password|passwd|pwd|secret|pass)\s*[:=]\s*['\"]?\S{6,}",
#         r"(?i)^\s*(DB_PASSWORD|DATABASE_PASSWORD|REDIS_PASSWORD|SECRET_KEY|MYSQL_ROOT_PASSWORD)\s*=\s*\S+",
#         r"(?i)(mysql|postgresql|postgres|mongodb|redis|mssql)://[^\s]+:[^\s]+@",
#         r"(?i)Basic\s+[A-Za-z0-9+/]{10,}={0,2}",               # HTTP Basic auth header
#     ],

#     # ----------------------------------------------------------
#     # INTERNAL NETWORK / INFRASTRUCTURE ADDRESSES
#     # ----------------------------------------------------------
#     "Internal Network Address": [
#         r"\b(10|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
#         r"\b(localhost|127\.0\.0\.1):\d{4,5}\b",
#         r"https?://(?:api|internal|dev|staging|prod|admin|corp|intranet|backend)\.",
#         r"https?://(?:[a-zA-Z0-9\-]+\.)*(?:local|internal|corp|lan|intranet)/",
#     ],

#     # ----------------------------------------------------------
#     # COMPANY CONFIDENTIAL MARKERS
#     # ----------------------------------------------------------
#     "Company Confidential Marker": [
#         r"\b(internal_use_only|confidential|proprietary|trade_secret|do_not_share|top_secret|restricted|classified)\b",
#         r"(?i)company\s+confidential",
#         r"(?i)not\s+for\s+(external|public|distribution|disclosure)",
#         r"(?i)privileged\s+and\s+confidential",
#         r"@(internal|confidential|private|company)\b",
#     ],

#     # ----------------------------------------------------------
#     # SOURCE CODE BLOCKS — full code files renamed to .txt etc.
#     # ----------------------------------------------------------
#     "Source Code Block": [
#         r"\bdef\s+[a-zA-Z_]\w*\s*\(",                           # Python function
#         r"\bclass\s+[A-Z][a-zA-Z0-9_]*\s*[:\(]",               # Python/Java class
#         r"\bfunction\s+[a-zA-Z_]\w*\s*\(",                      # JS/PHP function
#         r"\bpublic\s+(static\s+)?(void|int|String|boolean|class)\b",  # Java
#         r"\bconst\s+[a-zA-Z_]\w*\s*=\s*\(.*\)\s*=>",           # JS arrow function
#         r"^(import|from)\s+[a-zA-Z_][\w.]+\s",                  # Python import
#         r"^#include\s*[<\"]",                                    # C/C++ include
#         r"^\s*using\s+[A-Z][a-zA-Z.]+;",                        # C# using
#         r"^\s*require\s*\(['\"][a-zA-Z]",                        # Node.js require
#         r"\bpackage\s+[a-zA-Z_][\w.]+;",                        # Java/Kotlin package
#     ],

#     # ----------------------------------------------------------
#     # INFRASTRUCTURE CONFIG inside files
#     # ----------------------------------------------------------
#     "Infrastructure Config": [
#         r"\bapiVersion:\s*[a-zA-Z]+/v\d",                       # Kubernetes
#         r"\bkind:\s*(Deployment|Service|Pod|ConfigMap|Secret|Ingress|StatefulSet)\b",
#         r"(?im)^FROM\s+[a-zA-Z0-9.\-/]+",                       # Dockerfile
#         r"(?im)^RUN\s+(apt|yum|pip|npm|apk)\s+install",
#         r"resource\s+\"aws_",                                    # Terraform
#         r"\bterraform\s*\{",
#         r"(?i)mongodb\+srv://",
#         r"(?i)connection_string\s*[:=]",
#     ],

#     # ----------------------------------------------------------
#     # PII — Indian + International
#     # ----------------------------------------------------------
#     "PII — Aadhaar / PAN / Financial": [
#         r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b",                       # Aadhaar spaced
#         r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",                          # PAN card
#         r"\b4[0-9]{12}(?:[0-9]{3})?\b",                         # Visa card
#         r"\b5[1-5][0-9]{14}\b",                                  # MasterCard
#         r"\b(?:\d{4}[\s\-]){3}\d{4}\b",                         # Generic card spaced
#         r"\b(?!000|666|9\d{2})\d{3}[\s\-](?!00)\d{2}[\s\-](?!0000)\d{4}\b",  # SSN
#     ],
# }

# # =========================================================
# # RISK WEIGHTS
# # =========================================================

# CONTENT_WEIGHTS = {
#     "XSS / HTML Injection":              60,
#     "SQL Injection":                     60,
#     "Command Injection":                 65,
#     "Path Traversal":                    55,
#     "Server Side Request Forgery (SSRF)":55,
#     "XML External Entity (XXE)":         55,
#     "Server Side Template Injection (SSTI)": 60,
#     "LDAP Injection":                    50,
#     "Prompt Injection in File":          60,
#     "Jailbreak Attempt in File":         55,
#     "Encoded / Obfuscated Payload":      55,
#     "Hardcoded Secret / API Key":        60,
#     "Password / Credential in File":     55,
#     "Internal Network Address":          40,
#     "Company Confidential Marker":       35,
#     "Source Code Block":                 30,
#     "Infrastructure Config":             40,
#     "PII — Aadhaar / PAN / Financial":   50,
# }

# # These ALWAYS cause a block regardless of score
# ALWAYS_BLOCK_CATEGORIES = {
#     "XSS / HTML Injection",
#     "SQL Injection",
#     "Command Injection",
#     "Path Traversal",
#     "Server Side Request Forgery (SSRF)",
#     "XML External Entity (XXE)",
#     "Server Side Template Injection (SSTI)",
#     "LDAP Injection",
#     "Prompt Injection in File",
#     "Jailbreak Attempt in File",
#     "Encoded / Obfuscated Payload",
#     "Hardcoded Secret / API Key",
#     "Password / Credential in File",
#     "PII — Aadhaar / PAN / Financial",
# }

# # MITRE ATT&CK mapping
# MITRE_MAP = {
#     "XSS / HTML Injection":                   "T1059.007 – JavaScript / HTML Injection",
#     "SQL Injection":                           "T1190 – Exploit Public-Facing Application",
#     "Command Injection":                       "T1059 – Command and Scripting Interpreter",
#     "Path Traversal":                          "T1083 – File and Directory Discovery",
#     "Server Side Request Forgery (SSRF)":      "T1090 – Proxy / Internal Network Pivot",
#     "XML External Entity (XXE)":               "T1005 – Data from Local System",
#     "Server Side Template Injection (SSTI)":   "T1059 – Command and Scripting Interpreter",
#     "LDAP Injection":                          "T1087 – Account Discovery",
#     "Prompt Injection in File":                "T1190 – Exploit via Injected Instructions",
#     "Jailbreak Attempt in File":               "T1562 – Impair Defenses",
#     "Encoded / Obfuscated Payload":            "T1027 – Obfuscated Files or Information",
#     "Hardcoded Secret / API Key":              "T1552.001 – Credentials In Files",
#     "Password / Credential in File":           "T1552.001 – Credentials In Files",
#     "Internal Network Address":                "T1590.005 – Gather Victim Network Info",
#     "Company Confidential Marker":             "T1213 – Data from Information Repositories",
#     "Source Code Block":                       "T1213 – Data from Information Repositories",
#     "Infrastructure Config":                   "T1213 – Data from Information Repositories",
#     "PII — Aadhaar / PAN / Financial":         "T1589 – Gather Victim Identity Information",
# }

# # =========================================================
# # MAGIC BYTES (binary file detection)
# # =========================================================

# BINARY_SIGNATURES = [
#     (b"\x7fELF",          "ELF Binary (Linux/Unix executable)"),
#     (b"MZ",               "PE Binary (Windows .exe / .dll)"),
#     (b"\xca\xfe\xba\xbe", "Java Class File"),
#     (b"\xfe\xed\xfa\xce", "Mach-O Binary (macOS)"),
#     (b"\xfe\xed\xfa\xcf", "Mach-O Binary 64-bit (macOS)"),
#     (b"\x50\x4b\x03\x04", "ZIP Archive"),        # Includes .jar, .apk, Office Open XML
#     (b"Rar!",             "RAR Archive"),
#     (b"\x1f\x8b",         "GZIP Archive"),
#     (b"7z\xbc\xaf",       "7-Zip Archive"),
#     (b"%PDF-",            "PDF File"),            # PDF is allowed but flagged for content scan
#     (b"\xd0\xcf\x11\xe0", "OLE2 / MS Office (legacy .doc/.xls/.ppt)"),  # old macro-capable
# ]

# # File types whose magic bytes are allowed (content-scanned)
# ALLOWED_MAGIC_TYPES = {
#     b"%PDF-",             # PDF
#     b"\x50\x4b\x03\x04", # ZIP-based (.docx, .xlsx)
# }

# # =========================================================
# # CONTENT-TYPE MISMATCH DETECTION
# # Catches "I renamed malware.php to report.txt"
# # =========================================================

# # Expected content signatures for each allowed extension
# EXPECTED_CONTENT_SIGNATURES = {
#     ".png":  [b"\x89PNG"],
#     ".jpg":  [b"\xff\xd8\xff"],
#     ".jpeg": [b"\xff\xd8\xff"],
#     ".gif":  [b"GIF87a", b"GIF89a"],
#     ".webp": [b"RIFF"],
#     ".pdf":  [b"%PDF-"],
#     ".docx": [b"PK\x03\x04"],
#     ".xlsx": [b"PK\x03\x04"],
# }

# # Suspicious patterns that should NEVER appear in plain .txt / .csv / .md
# TEXT_FILE_EXTENSIONS = {".txt", ".csv", ".md", ".json", ".xml"}

# # HTML/script signatures — if found in a .txt file, it's spoofed
# HTML_SCRIPT_SIGNATURES = [
#     b"<html", b"<HTML",
#     b"<script", b"<SCRIPT",
#     b"<php", b"<?php",
#     b"<%@", b"<%=",
#     b"<!DOCTYPE",
#     b"<svg", b"<SVG",
#     b"<iframe", b"<IFRAME",
# ]


# # =========================================================
# # STAGE 1 — EXTENSION POLICY
# # =========================================================

# def check_extension(filename: str) -> dict:
#     base = os.path.basename(filename).lower()
#     ext  = os.path.splitext(base)[1]

#     # Null-byte injection: file.txt%00.php
#     if "%00" in filename or "\x00" in filename:
#         return {
#             "passed":   False,
#             "extension": ext,
#             "category": "Null Byte Injection",
#             "reason":   "Null byte detected in filename — possible extension spoofing attack.",
#             "severity": "BLOCK",
#         }

#     # Double extension: file.txt.php, file.jpg.exe
#     parts = base.split(".")
#     if len(parts) > 2:
#         for p in parts[1:]:
#             if "." + p in BLOCKED_EXTENSIONS:
#                 return {
#                     "passed":   False,
#                     "extension": "." + p,
#                     "category": "Double Extension Attack",
#                     "reason":   f"Double extension detected: '{filename}' — possible extension spoofing (.{p} is blocked).",
#                     "severity": "BLOCK",
#                 }

#     # Blocked filenames
#     if base in BLOCKED_FILENAMES or (not ext and base.startswith(".")):
#         return {
#             "passed":   False,
#             "extension": base,
#             "category": "Blocked Filename",
#             "reason":   f"'{filename}' is a restricted system/configuration file.",
#             "severity": "BLOCK",
#         }

#     if ext in BLOCKED_EXTENSIONS:
#         return {
#             "passed":   False,
#             "extension": ext,
#             "category": _ext_to_category(ext),
#             "reason":   f"Files with extension '{ext}' are blocked by DLP policy.",
#             "severity": "BLOCK",
#         }

#     if ext in ALLOWED_EXTENSIONS:
#         return {"passed": True, "extension": ext, "category": "Allowed", "reason": "", "severity": "PASS"}

#     return {
#         "passed":   False,
#         "extension": ext or "(none)",
#         "category": "Unknown / Unlisted File Type",
#         "reason":   f"Extension '{ext or '(none)'}' is not on the approved list.",
#         "severity": "BLOCK",
#     }


# def _ext_to_category(ext):
#     code   = {".py",".js",".ts",".jsx",".tsx",".java",".cs",".cpp",".c",".h",".go",".rs",".php",".rb",".swift",".kt",".scala",".asp",".aspx",".jsp"}
#     config = {".env",".config",".conf",".cfg",".ini",".yaml",".yml",".toml",".tf",".tfvars"}
#     db     = {".sql",".db",".sqlite",".sqlite3",".mdb"}
#     key    = {".pem",".key",".cert",".crt",".pfx",".p12",".p8",".ppk"}
#     script = {".sh",".bash",".zsh",".ps1",".bat",".cmd",".vbs",".hta"}
#     binary = {".jar",".class",".pyc",".exe",".dll",".so",".bin",".apk"}
#     web    = {".php",".asp",".aspx",".jsp",".jspx",".cgi",".cfm"}
#     if ext in web:    return "Server-Side Web Script"
#     if ext in code:   return "Source Code File"
#     if ext in config: return "Configuration / Secrets File"
#     if ext in db:     return "Database File"
#     if ext in key:    return "Cryptographic Key / Certificate"
#     if ext in script: return "Shell Script / Automation"
#     if ext in binary: return "Compiled Binary"
#     if ext == ".log": return "Server Log File"
#     return "Restricted File Type"


# # =========================================================
# # STAGE 2 — FILE SIZE
# # =========================================================

# def check_size(file_bytes: bytes) -> dict:
#     size = len(file_bytes)
#     mb   = size / (1024 * 1024)
#     if size > MAX_FILE_SIZE_BYTES:
#         return {"passed": False, "size_mb": round(mb, 2),
#                 "reason": f"File size {mb:.1f} MB exceeds the {MAX_FILE_SIZE_MB} MB policy limit."}
#     return {"passed": True, "size_mb": round(mb, 2), "reason": ""}


# # =========================================================
# # STAGE 3 — BINARY & CONTENT-TYPE MISMATCH DETECTION
# # =========================================================

# def check_binary_and_mime(file_bytes: bytes, filename: str) -> dict:
#     """
#     Detects:
#     - Actual binary executables / archives
#     - Content-type mismatch (HTML renamed to .txt)
#     - Script files renamed to safe extensions
#     """
#     ext = os.path.splitext(filename.lower())[1]

#     # Check magic bytes
#     for sig, label in BINARY_SIGNATURES:
#         if file_bytes.startswith(sig):
#             if sig in ALLOWED_MAGIC_TYPES:
#                 # PDF and Office files — allowed but note it
#                 return {"is_binary": False, "label": label,
#                         "note": f"{label} — content will be scanned", "reason": ""}
#             return {"is_binary": True, "label": label,
#                     "reason": f"Binary file detected: {label}. Binary uploads are not permitted regardless of file extension."}

#     # Content-type mismatch: HTML/script content inside .txt / .csv / .md
#     if ext in TEXT_FILE_EXTENSIONS:
#         lower_bytes = file_bytes[:4096].lower()
#         for sig in HTML_SCRIPT_SIGNATURES:
#             if sig.lower() in lower_bytes:
#                 return {
#                     "is_binary": False,
#                     "content_mismatch": True,
#                     "label":   f"HTML/Script content in {ext} file",
#                     "reason":  (
#                         f"Content-type mismatch detected: '{filename}' has extension '{ext}' "
#                         f"but contains HTML/script content ({sig.decode('utf-8', errors='replace')}...). "
#                         f"This is a classic file extension spoofing attack."
#                     ),
#                     "attack_type": "Extension Spoofing / Content-Type Mismatch",
#                 }

#     # Check if image extension but no image magic bytes
#     expected = EXPECTED_CONTENT_SIGNATURES.get(ext, [])
#     if expected:
#         if not any(file_bytes.startswith(sig) for sig in expected):
#             return {
#                 "is_binary": False,
#                 "content_mismatch": True,
#                 "label":   f"Invalid {ext} file",
#                 "reason":  f"File claims to be '{ext}' but does not match expected file format. Possible file type spoofing.",
#                 "attack_type": "File Signature Mismatch",
#             }

#     # Heuristic: >35% non-printable bytes
#     sample = file_bytes[:4096]
#     if sample:
#         non_print = sum(1 for b in sample if b < 9 or (13 < b < 32) or b > 126)
#         if non_print / len(sample) > 0.35:
#             return {"is_binary": True, "label": "Binary/encoded data",
#                     "reason": "File appears to contain binary or obfuscated data (high non-printable byte ratio)."}

#     return {"is_binary": False, "content_mismatch": False, "label": "", "reason": ""}


# # =========================================================
# # STAGE 4 — DEEP CONTENT SCAN
# # =========================================================

# def scan_content(text: str) -> dict:
#     findings    = []
#     seen        = set()
#     total_score = 0
#     lines       = text.split("\n")

#     for category, patterns in CONTENT_THREAT_PATTERNS.items():
#         for pattern in patterns:
#             try:
#                 m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
#                 if m and category not in seen:
#                     seen.add(category)
#                     line_no = text[:m.start()].count("\n") + 1
#                     snippet = lines[min(line_no - 1, len(lines)-1)].strip()
#                     snippet = _redact_snippet(snippet, category)
#                     weight  = CONTENT_WEIGHTS.get(category, 25)
#                     total_score += weight
#                     findings.append({
#                         "category": category,
#                         "line":     line_no,
#                         "snippet":  snippet[:120] + ("..." if len(snippet) > 120 else ""),
#                         "weight":   weight,
#                         "mitre":    MITRE_MAP.get(category, "T1530 – Data from Cloud Storage"),
#                     })
#                     break
#             except re.error:
#                 continue

#     force_block = any(f["category"] in ALWAYS_BLOCK_CATEGORIES for f in findings)

#     if force_block or total_score >= 50:
#         verdict = "BLOCK"
#     elif total_score >= 25 or findings:
#         verdict = "WARN"
#     else:
#         verdict = "PASS"

#     return {
#         "verdict":     verdict,
#         "findings":    findings,
#         "total_score": total_score,
#         "blocked":     verdict == "BLOCK",
#     }


# def _redact_snippet(snippet: str, category: str) -> str:
#     if category in ("Hardcoded Secret / API Key", "Password / Credential in File"):
#         return re.sub(r"([:=]\s*['\"]?)(\S{4})\S+", r"\1\2****", snippet)
#     return snippet


# # =========================================================
# # MASTER PIPELINE — run_file_guardrail()
# # =========================================================

# def run_file_guardrail(filename: str, file_bytes: bytes) -> dict:
#     """
#     5-stage enterprise guardrail pipeline.

#     Stage 1 — Extension Policy (blocked types, double extensions, null bytes)
#     Stage 2 — File Size Check
#     Stage 3 — Binary & MIME/Content-Type Mismatch Detection
#     Stage 4 — Deep Content Scan (XSS, SQLi, CMDi, SSRF, XXE, SSTI, LDAP,
#                                   Prompt Injection, Jailbreak, Secrets, PII)
#     Stage 5 — Final Verdict

#     Returns: verdict, blocked, stages, findings, summary, file_hash, text
#     """
#     stages    = []
#     findings  = []
#     file_hash = hashlib.sha256(file_bytes).hexdigest()

#     # ---- Stage 1: Extension ----
#     ext_r = check_extension(filename)
#     stages.append({"name": "Extension Policy", "result": ext_r})
#     if not ext_r["passed"]:
#         return _blocked(stages, [], file_hash,
#                         f"Stage 1 BLOCKED — {ext_r['reason']}")

#     # ---- Stage 2: Size ----
#     size_r = check_size(file_bytes)
#     stages.append({"name": "File Size", "result": size_r})
#     if not size_r["passed"]:
#         return _blocked(stages, [], file_hash,
#                         f"Stage 2 BLOCKED — {size_r['reason']}")

#     # ---- Stage 3: Binary + MIME mismatch ----
#     bin_r = check_binary_and_mime(file_bytes, filename)
#     stages.append({"name": "Binary / MIME Check", "result": bin_r})

#     if bin_r.get("is_binary"):
#         return _blocked(stages, [], file_hash,
#                         f"Stage 3 BLOCKED — {bin_r['reason']}")

#     if bin_r.get("content_mismatch"):
#         # Content-type mismatch is always a block — classic spoofing attack
#         return _blocked(
#             stages, [], file_hash,
#             f"Stage 3 BLOCKED — {bin_r['reason']}",
#             attack_type=bin_r.get("attack_type", "Content-Type Mismatch"),
#         )

#     # ---- Stage 4: Content scan ----
#     try:
#         text = file_bytes.decode("utf-8", errors="replace")
#     except Exception:
#         text = ""

#     if text.strip():
#         content_r = scan_content(text)
#         stages.append({"name": "Content Scan", "result": content_r})
#         findings  = content_r["findings"]
#         if content_r["blocked"]:
#             return _blocked(
#                 stages, findings, file_hash,
#                 f"Stage 4 BLOCKED — {len(findings)} threat(s) detected in file content.",
#             )
#     else:
#         stages.append({"name": "Content Scan",
#                        "result": {"verdict": "SKIP", "reason": "Non-text binary format"}})

#     # ---- Stage 5: Final verdict ----
#     verdict = "WARN" if findings else "PASS"
#     return {
#         "verdict":   verdict,
#         "blocked":   False,
#         "stages":    stages,
#         "findings":  findings,
#         "summary":   ("File passed all guardrail checks." if verdict == "PASS"
#                       else f"File passed with {len(findings)} warning(s). Review before use."),
#         "file_hash": file_hash,
#         "text":      text,
#     }


# def _blocked(stages, findings, file_hash, summary, attack_type=None):
#     return {
#         "verdict":     "BLOCK",
#         "blocked":     True,
#         "stages":      stages,
#         "findings":    findings,
#         "summary":     summary,
#         "attack_type": attack_type or "",
#         "file_hash":   file_hash,
#         "text":        "",
#     }

# # =========================================================
# # STAGE 1 — EXTENSION POLICY
# # =========================================================

# def check_extension(filename: str) -> dict:
#     base = os.path.basename(filename).lower()
#     ext  = os.path.splitext(base)[1]

#     if "%00" in filename or "\x00" in filename:
#         return {"passed": False, "extension": ext, "category": "Null Byte Injection",
#                 "reason": "Null byte in filename — extension spoofing attack.", "severity": "BLOCK"}

#     parts = base.split(".")
#     if len(parts) > 2:
#         for p in parts[1:]:
#             if "." + p in BLOCKED_EXTENSIONS:
#                 return {"passed": False, "extension": "." + p, "category": "Double Extension Attack",
#                         "reason": f"Double extension in '{filename}' hides blocked extension (.{p}).",
#                         "severity": "BLOCK"}

#     if base in BLOCKED_FILENAMES or (not ext and base.startswith(".")):
#         return {"passed": False, "extension": base, "category": "Blocked Filename",
#                 "reason": f"'{filename}' is a restricted system/configuration file.", "severity": "BLOCK"}

#     if ext in BLOCKED_EXTENSIONS:
#         return {"passed": False, "extension": ext, "category": _ext_to_category(ext),
#                 "reason": f"Extension '{ext}' is blocked by DLP policy.", "severity": "BLOCK"}

#     if ext in ALLOWED_EXTENSIONS:
#         return {"passed": True, "extension": ext, "category": "Allowed", "reason": "", "severity": "PASS"}

#     return {"passed": False, "extension": ext or "(none)", "category": "Unknown / Unlisted File Type",
#             "reason": f"Extension '{ext or chr(40)+chr(110)+chr(111)+chr(110)+chr(101)+chr(41)}' is not on the approved list.", "severity": "BLOCK"}


# def _ext_to_category(ext):
#     code   = {".py",".js",".ts",".jsx",".tsx",".java",".cs",".cpp",".c",".h",".go",".rs",".php",".rb",".swift",".kt",".scala",".asp",".aspx",".jsp"}
#     config = {".env",".config",".conf",".cfg",".ini",".yaml",".yml",".toml",".tf",".tfvars"}
#     db     = {".sql",".db",".sqlite",".sqlite3",".mdb"}
#     key    = {".pem",".key",".cert",".crt",".pfx",".p12",".p8",".ppk"}
#     script = {".sh",".bash",".zsh",".ps1",".bat",".cmd",".vbs",".hta"}
#     binary = {".jar",".class",".pyc",".exe",".dll",".so",".bin",".apk"}
#     web    = {".php",".asp",".aspx",".jsp",".jspx",".cgi",".cfm"}
#     if ext in web:    return "Server-Side Web Script"
#     if ext in code:   return "Source Code File"
#     if ext in config: return "Configuration / Secrets File"
#     if ext in db:     return "Database File"
#     if ext in key:    return "Cryptographic Key / Certificate"
#     if ext in script: return "Shell Script / Automation"
#     if ext in binary: return "Compiled Binary"
#     if ext == ".log": return "Server Log File"
#     return "Restricted File Type"


# # =========================================================
# # STAGE 2 — FILE SIZE
# # =========================================================

# def check_size(file_bytes: bytes) -> dict:
#     size = len(file_bytes)
#     mb   = size / (1024 * 1024)
#     if size > MAX_FILE_SIZE_BYTES:
#         return {"passed": False, "size_mb": round(mb, 2),
#                 "reason": f"File size {mb:.1f} MB exceeds the {MAX_FILE_SIZE_MB} MB policy limit."}
#     return {"passed": True, "size_mb": round(mb, 2), "reason": ""}


# # =========================================================
# # TRUE FILE TYPE DATABASE
# # Maps magic bytes → (label, is_allowed, legitimate_extensions)
# # This is what makes "exe renamed to .txt" detection possible.
# # We detect the REAL file type and compare it to the claimed extension.
# # =========================================================

# TRUE_TYPE_DB = [
#     # (magic_bytes, true_type_label, is_safe_format, set_of_legitimate_extensions)
#     # --- Dangerous binaries ---
#     (b"\x7fELF",            "ELF Binary (Linux/Unix executable)",          False, {".elf", ".so", ".out", ".o"}),
#     (b"MZ",                 "Windows PE Executable / DLL (.exe/.dll)",     False, {".exe", ".dll", ".com", ".sys", ".drv", ".ocx"}),
#     (b"\xca\xfe\xba\xbe",   "Java Class File",                             False, {".class"}),
#     (b"\xfe\xed\xfa\xce",   "Mach-O Binary (macOS executable)",            False, {".dylib", ".o", ".a"}),
#     (b"\xfe\xed\xfa\xcf",   "Mach-O 64-bit Binary (macOS executable)",     False, {".dylib", ".o", ".a"}),
#     (b"\xd0\xcf\x11\xe0",   "OLE2 Legacy Office Document (macro risk)",    False, {".doc", ".xls", ".ppt", ".msg"}),
#     (b"Rar!\x1a\x07",       "RAR Archive (.rar)",                          False, {".rar"}),
#     (b"\x1f\x8b",           "GZIP / TAR.GZ Archive",                       False, {".gz", ".tgz", ".tar.gz"}),
#     (b"7z\xbc\xaf",         "7-Zip Archive (.7z)",                         False, {".7z"}),
#     (b"\x25\x21\x50\x53",   "PostScript File (executable script)",         False, {".ps", ".eps"}),
#     (b"\x4d\x5a\x90\x00",   "Windows PE32 Executable",                    False, {".exe", ".dll"}),
#     (b"\x23\x21",           "Unix Shell Script (shebang #!)",              False, {".sh", ".bash", ".py", ".pl", ".rb"}),
#     # --- Safe formats (allowed, still content-scanned) ---
#     # NOTE: ZIP must come AFTER all more-specific checks
#     (b"\x25\x50\x44\x46",   "PDF Document",                                True,  {".pdf"}),
#     (b"\xff\xd8\xff",        "JPEG Image",                                  True,  {".jpg", ".jpeg"}),
#     (b"\x89\x50\x4e\x47",   "PNG Image",                                   True,  {".png"}),
#     (b"GIF87a",              "GIF87 Image",                                 True,  {".gif"}),
#     (b"GIF89a",              "GIF89 Image",                                 True,  {".gif"}),
#     (b"RIFF",                "RIFF Container (WebP/WAV)",                   True,  {".webp", ".wav"}),
#     (b"\x42\x4d",            "BMP Image",                                   True,  {".bmp"}),
#     (b"\xef\xbb\xbf",        "UTF-8 BOM Text",                              True,  {".txt", ".csv", ".xml", ".md"}),
#     (b"\xff\xfe",            "UTF-16 LE Text",                              True,  {".txt", ".csv", ".xml"}),
#     (b"\xfe\xff",            "UTF-16 BE Text",                              True,  {".txt", ".csv", ".xml"}),
#     # ZIP last — catches .docx/.xlsx/.jar/.apk
#     (b"\x50\x4b\x03\x04",   "ZIP Archive / Office Open XML",               True,  {".zip", ".docx", ".xlsx", ".pptx", ".odt", ".apk", ".jar"}),
# ]

# # For these extensions, the file MUST start with specific magic bytes
# REQUIRED_MAGIC = {
#     ".png":  [b"\x89\x50\x4e\x47"],
#     ".jpg":  [b"\xff\xd8\xff"],
#     ".jpeg": [b"\xff\xd8\xff"],
#     ".gif":  [b"GIF87a", b"GIF89a"],
#     ".webp": [b"RIFF"],
#     ".pdf":  [b"\x25\x50\x44\x46"],
#     ".docx": [b"\x50\x4b\x03\x04"],
#     ".xlsx": [b"\x50\x4b\x03\x04"],
# }

# # Text-only extensions — must not contain binary magic or HTML/script
# TEXT_ONLY_EXTENSIONS = {".txt", ".csv", ".md", ".json", ".xml"}

# # HTML/script byte sequences that must NEVER appear in plain text files
# HTML_SCRIPT_SIGNATURES = [
#     b"<html", b"<HTML",
#     b"<script", b"<SCRIPT",
#     b"<?php", b"<?PHP",
#     b"<%@", b"<%=",
#     b"<!DOCTYPE", b"<!doctype",
#     b"<svg", b"<SVG",
#     b"<iframe", b"<IFRAME",
#     b"<object", b"<OBJECT",
#     b"<embed", b"<EMBED",
#     b"javascript:",
# ]


# def detect_true_type(file_bytes: bytes) -> dict:
#     """
#     Identify the REAL file type from magic bytes, ignoring the filename extension.
#     Returns: {true_type, is_safe, legitimate_extensions, detected}
#     """
#     for sig, label, is_safe, legit_exts in TRUE_TYPE_DB:
#         if file_bytes.startswith(sig):
#             return {
#                 "detected":             True,
#                 "true_type":            label,
#                 "is_safe_format":       is_safe,
#                 "legitimate_extensions": legit_exts,
#                 "magic_hex":            sig.hex(),
#             }
#     return {
#         "detected":             False,
#         "true_type":            "Plain Text / Unknown",
#         "is_safe_format":       True,
#         "legitimate_extensions": set(),
#         "magic_hex":            "",
#     }


# # =========================================================
# # STAGE 3 — BINARY & MIME / TRUE-TYPE MISMATCH DETECTION
# # =========================================================

# def check_binary_and_mime(file_bytes: bytes, filename: str) -> dict:
#     """
#     Detects ALL file spoofing attacks:

#     1. Binary executable renamed to .txt/.csv/.pdf etc.
#        (reads magic bytes, compares to claimed extension)
#     2. HTML/script content hidden inside .txt/.csv/.md
#        (the XSS-in-txt attack you demonstrated)
#     3. Image extension with wrong magic bytes
#        (png renamed from exe)
#     4. Heuristic binary detection (obfuscated/packed files)

#     Always reports the REAL detected file type in the audit trail.
#     """
#     ext = os.path.splitext(filename.lower())[1]

#     # --- Step A: Detect the TRUE file type from magic bytes ---
#     true_type_info = detect_true_type(file_bytes)
#     true_type      = true_type_info["true_type"]
#     is_safe        = true_type_info["is_safe_format"]
#     legit_exts     = true_type_info["legitimate_extensions"]
#     detected       = true_type_info["detected"]

#     # --- Step B: Is this a DANGEROUS binary disguised as something else? ---
#     if detected and not is_safe:
#         # Real file type is dangerous regardless of extension
#         spoofed = ext not in legit_exts
#         return {
#             "is_binary":      True,
#             "content_mismatch": spoofed,
#             "true_type":      true_type,
#             "claimed_ext":    ext,
#             "magic_hex":      true_type_info["magic_hex"],
#             "spoofed":        spoofed,
#             "reason": (
#                 f"DANGEROUS FILE TYPE DETECTED: The uploaded file is actually a "
#                 f"'{true_type}' but was uploaded with extension '{ext}'. "
#                 f"Magic bytes: 0x{true_type_info['magic_hex'].upper()[:8]}. "
#                 f"This is a file extension spoofing attack."
#                 if spoofed else
#                 f"Dangerous file type blocked: '{true_type}'. "
#                 f"Files of this type are not permitted regardless of name."
#             ),
#             "attack_type": "File Extension Spoofing — Dangerous Binary" if spoofed else "Blocked File Type",
#         }

#     # --- Step C: Safe format but wrong extension? ---
#     # e.g. a JPEG renamed to .txt, or a ZIP renamed to .csv
#     if detected and is_safe and ext not in legit_exts and ext in TEXT_ONLY_EXTENSIONS:
#         return {
#             "is_binary":        False,
#             "content_mismatch": True,
#             "true_type":        true_type,
#             "claimed_ext":      ext,
#             "magic_hex":        true_type_info["magic_hex"],
#             "spoofed":          True,
#             "reason": (
#                 f"FILE TYPE MISMATCH: File uploaded as '{ext}' but magic bytes identify it as "
#                 f"'{true_type}' (0x{true_type_info['magic_hex'].upper()[:8]}). "
#                 f"Legitimate '{ext}' files should not have these magic bytes."
#             ),
#             "attack_type": "File Extension Spoofing — MIME Mismatch",
#         }

#     # --- Step D: Extension requires specific magic bytes but they're wrong ---
#     required = REQUIRED_MAGIC.get(ext, [])
#     if required:
#         if not any(file_bytes.startswith(sig) for sig in required):
#             actual_type = true_type if detected else "Unknown"
#             return {
#                 "is_binary":        False,
#                 "content_mismatch": True,
#                 "true_type":        actual_type,
#                 "claimed_ext":      ext,
#                 "magic_hex":        true_type_info.get("magic_hex", ""),
#                 "spoofed":          True,
#                 "reason": (
#                     f"FILE SIGNATURE MISMATCH: File claims to be '{ext}' but the file "
#                     f"signature does not match. Detected: '{actual_type}'. "
#                     f"Possible file spoofing attack."
#                 ),
#                 "attack_type": "File Signature Mismatch",
#             }

#     # --- Step E: Text file containing HTML/script content ---
#     # This catches exactly what you showed: t.txt containing <script>alert()</script>
#     if ext in TEXT_ONLY_EXTENSIONS:
#         lower_head = file_bytes[:8192].lower()
#         for sig in HTML_SCRIPT_SIGNATURES:
#             if sig.lower() in lower_head:
#                 sig_str = sig.decode("utf-8", errors="replace")
#                 return {
#                     "is_binary":        False,
#                     "content_mismatch": True,
#                     "true_type":        f"HTML/Script content (contains '{sig_str}')",
#                     "claimed_ext":      ext,
#                     "magic_hex":        "",
#                     "spoofed":          True,
#                     "reason": (
#                         f"CONTENT-TYPE SPOOFING: File uploaded as '{ext}' but contains "
#                         f"HTML/script content (found '{sig_str}'). "
#                         f"This is a classic extension spoofing attack to bypass upload filters. "
#                         f"Real file type: HTML/Script disguised as {ext}."
#                     ),
#                     "attack_type": "Extension Spoofing — Script-in-Text Attack",
#                 }

#     # --- Step F: Heuristic — high non-printable byte ratio for text files ---
#     if ext in TEXT_ONLY_EXTENSIONS:
#         sample    = file_bytes[:4096]
#         non_print = sum(1 for b in sample if b < 9 or (13 < b < 32) or b > 126)
#         if len(sample) > 0 and non_print / len(sample) > 0.30:
#             return {
#                 "is_binary":        True,
#                 "content_mismatch": True,
#                 "true_type":        "Binary / Obfuscated Data",
#                 "claimed_ext":      ext,
#                 "magic_hex":        "",
#                 "spoofed":          True,
#                 "reason": (
#                     f"OBFUSCATED CONTENT: File uploaded as '{ext}' contains "
#                     f"{int(non_print/len(sample)*100)}% non-printable bytes. "
#                     f"Legitimate text files should not contain binary data."
#                 ),
#                 "attack_type": "Binary Data in Text File",
#             }

#     # All checks passed — also pass the true_type for audit even on PASS
#     return {
#         "is_binary":        False,
#         "content_mismatch": False,
#         "true_type":        true_type,
#         "claimed_ext":      ext,
#         "magic_hex":        true_type_info.get("magic_hex", ""),
#         "spoofed":          False,
#         "label":            "",
#         "reason":           "",
#     }



# # =========================================================
# # STAGE 4 — DEEP CONTENT SCAN
# # =========================================================

# def scan_content(text: str) -> dict:
#     findings    = []
#     seen        = set()
#     total_score = 0
#     lines       = text.split("\n")

#     for category, patterns in CONTENT_THREAT_PATTERNS.items():
#         for pattern in patterns:
#             try:
#                 m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
#                 if m and category not in seen:
#                     seen.add(category)
#                     line_no = text[:m.start()].count("\n") + 1
#                     snippet = lines[min(line_no - 1, len(lines)-1)].strip()
#                     snippet = _redact_snippet(snippet, category)
#                     weight  = CONTENT_WEIGHTS.get(category, 25)
#                     total_score += weight
#                     findings.append({
#                         "category": category,
#                         "line":     line_no,
#                         "snippet":  snippet[:120] + ("..." if len(snippet) > 120 else ""),
#                         "weight":   weight,
#                         "mitre":    MITRE_MAP.get(category, "T1530 - Data from Cloud Storage"),
#                     })
#                     break
#             except re.error:
#                 continue

#     force_block = any(f["category"] in ALWAYS_BLOCK_CATEGORIES for f in findings)

#     if force_block or total_score >= 50:
#         verdict = "BLOCK"
#     elif total_score >= 25 or findings:
#         verdict = "WARN"
#     else:
#         verdict = "PASS"

#     return {"verdict": verdict, "findings": findings, "total_score": total_score, "blocked": verdict == "BLOCK"}


# def _redact_snippet(snippet: str, category: str) -> str:
#     if category in ("Hardcoded Secret / API Key", "Password / Credential in File"):
#         return re.sub(r"([:=]\s*['\"]?)(\S{4})\S+", r"\1\2****", snippet)
#     return snippet


# # =========================================================
# # MASTER PIPELINE
# # =========================================================

# def run_file_guardrail(filename: str, file_bytes: bytes) -> dict:
#     stages    = []
#     findings  = []
#     file_hash = hashlib.sha256(file_bytes).hexdigest()

#     # Stage 1: Extension
#     ext_r = check_extension(filename)
#     stages.append({"name": "Extension Policy", "result": ext_r})
#     if not ext_r["passed"]:
#         return _blocked(stages, [], file_hash, f"Stage 1 BLOCKED - {ext_r['reason']}")

#     # Stage 2: Size
#     size_r = check_size(file_bytes)
#     stages.append({"name": "File Size", "result": size_r})
#     if not size_r["passed"]:
#         return _blocked(stages, [], file_hash, f"Stage 2 BLOCKED - {size_r['reason']}")

#     # Stage 3: Binary + MIME mismatch
#     bin_r = check_binary_and_mime(file_bytes, filename)
#     stages.append({"name": "Binary / MIME Check", "result": bin_r})

#     if bin_r.get("is_binary") or bin_r.get("content_mismatch"):
#         return _blocked(
#             stages, [], file_hash,
#             f"Stage 3 BLOCKED - {bin_r['reason']}",
#             attack_type=bin_r.get("attack_type", "Content-Type Mismatch"),
#         )

#     # Stage 4: Content scan
#     try:
#         text = file_bytes.decode("utf-8", errors="replace")
#     except Exception:
#         text = ""

#     if text.strip():
#         content_r = scan_content(text)
#         stages.append({"name": "Content Scan", "result": content_r})
#         findings  = content_r["findings"]
#         if content_r["blocked"]:
#             return _blocked(stages, findings, file_hash,
#                             f"Stage 4 BLOCKED - {len(findings)} threat(s) detected in file content.")
#     else:
#         stages.append({"name": "Content Scan",
#                        "result": {"verdict": "SKIP", "reason": "Non-text / binary safe format"}})

#     # Stage 5: Final verdict
#     verdict = "WARN" if findings else "PASS"
#     return {
#         "verdict":   verdict,
#         "blocked":   False,
#         "stages":    stages,
#         "findings":  findings,
#         "summary":   ("File passed all guardrail checks." if verdict == "PASS"
#                       else f"File passed with {len(findings)} warning(s). Review before use."),
#         "file_hash": file_hash,
#         "text":      text,
#     }


# def _blocked(stages, findings, file_hash, summary, attack_type=None):
#     return {
#         "verdict":     "BLOCK",
#         "blocked":     True,
#         "stages":      stages,
#         "findings":    findings,
#         "summary":     summary,
#         "attack_type": attack_type or "",
#         "file_hash":   file_hash,
#         "text":        "",
#     }

"""
file_guardrail.py — Enterprise File Upload Guardrail Engine
"""
import os, re, hashlib, base64

MAX_FILE_SIZE_MB    = 5
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

BLOCKED_EXTENSIONS = {
    ".php",".php3",".php4",".php5",".phtml",".phar",
    ".asp",".aspx",".ashx",".asmx",".axd",
    ".jsp",".jspx",".jspf",".cgi",".pl",".rb",".cfm",".cfml",
    ".js",".ts",".jsx",".tsx",".java",".cs",".cpp",
    ".c",".h",".go",".rs",".swift",".kt",".scala",
    ".vb",".lua",".r",".m",".f90",".asm",".dart",
    ".env",".env.local",".env.production",".env.development",
    ".env.staging",".env.test",
    ".config",".conf",".cfg",".ini",".yaml",".yml",".toml",
    ".pem",".key",".cert",".crt",".pfx",".p12",".p8",".ppk",
    ".sql",".db",".sqlite",".sqlite3",".mdb",".accdb",
    ".tf",".tfvars",".hcl",
    ".sh",".bash",".zsh",".fish",".ps1",".ps2",
    ".bat",".cmd",".vbs",".wsf",".hta",
    ".jar",".class",".pyc",".pyo",".exe",".dll",".so",
    ".bin",".apk",".ipa",".deb",".rpm",".msi",".dmg",
    ".log",".tar",".gz",".bz2",".xz",".rar",".7z",".zip",
    ".xlsm",".xltm",".docm",".dotm",".pptm",
    ".py",  # explicitly block python too
}

ALLOWED_EXTENSIONS = {
    ".txt", ".pdf", ".docx", ".xlsx", ".csv",
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".json", ".xml", ".md",
}

BLOCKED_FILENAMES = {
    "dockerfile","makefile","jenkinsfile","vagrantfile",
    "procfile","gemfile","rakefile","gruntfile","gulpfile",
    ".env",".gitignore",".bashrc",".zshrc",".profile",
    ".htaccess",".htpasswd",".npmrc",".pypirc",
}

# ---- Content threat patterns ----
CONTENT_THREAT_PATTERNS = {
    "XSS / HTML Injection": [
        r"<script[\s\S]*?>[\s\S]*?</script>",
        r"<script[\s>]",
        r"</script>",
        r"(?i)javascript\s*:",
        r"(?i)on(error|load|click|mouseover|focus|blur|change|submit|input|keyup|keydown|dblclick|drag|drop|scroll|contextmenu|wheel|touchstart|touchend)\s*=",
        r"(?i)<iframe[\s>]",
        r"(?i)<img[^>]+on\w+\s*=",
        r"(?i)<svg[^>]*>",
        r"(?i)<object[\s>]",
        r"(?i)<embed[\s>]",
        r"eval\s*\(",
        r"(?i)document\.(cookie|write|location|domain)",
        r"(?i)window\.(location|open|eval)",
        r"(?i)innerHTML\s*=",
        r"(?i)(fetch|XMLHttpRequest)\s*\(",
        r"(?i)atob\s*\(",
        r"(?i)String\.fromCharCode\s*\(",
        r"%3Cscript|%3c%73%63%72%69%70%74",
        r"&#\d+;.*&#\d+;",
        r"<html[\s>]",       # raw HTML in non-html file
        r"<body[\s>]",
        r"<!DOCTYPE\s+html",
        r"<head[\s>]",
        r"<div[\s>]",
        r"<form[\s>]",
        r"<input[\s>]",
    ],
    "SQL Injection": [
        r"(?i)\bUNION\s+(ALL\s+)?SELECT\b",
        r"(?i)\bDROP\s+TABLE\b",
        r"(?i)\bOR\s+1\s*=\s*1\b",
        r"(?i)'\s*(--|#|/\*)",
        r"(?i)\bINSERT\s+INTO\b.*\bVALUES\b",
        r"(?i)\bDELETE\s+FROM\b",
        r"(?i)\bSELECT\s+.+\bFROM\b",
        r"(?i)\bEXEC(UTE)?\s*\(",
        r"(?i)xp_cmdshell",
        r"(?i)\bSLEEP\s*\(\d+\)",
        r"(?i)\bWAITFOR\s+DELAY\b",
        r"(?i)\bINFORMATION_SCHEMA\b",
    ],
    "Command Injection": [
        r"(?i)(;|\||&&|\|\|)\s*(rm|del|format|shutdown|reboot|kill|wget|curl|nc|bash|sh|cmd|powershell|python|perl|ruby)",
        r"`[^`]{3,}`",
        r"\$\([^)]{3,}\)",
        r"(?i)(rm\s+-rf|del\s+/f)",
        r"(?i)(wget|curl)\s+https?://",
        r"(?i)/bin/(bash|sh|zsh|ksh|dash)",
        r"(?i)cmd\.exe",
        r"(?i)powershell\s*(-|\.exe)",
        r"(?i)nc\s+-[el]",
        r"(?i)bash\s+-i\s*>&",
        r"(?i)/etc/(passwd|shadow|hosts|crontab)",
    ],
    "Path Traversal": [
        r"\.\./", r"\.\.\\",
        r"%2e%2e%2f|%2e%2e/|\.\.%2f",
        r"%252e%252e%252f",
        r"(?i)/etc/passwd",
        r"(?i)/etc/shadow",
        r"(?i)c:\\windows\\system32",
        r"(?i)boot\.ini",
    ],
    "Server Side Request Forgery (SSRF)": [
        r"\b127\.0\.0\.1\b",
        r"169\.254\.169\.254",
        r"metadata\.google\.internal",
        r"(?i)file://",
        r"(?i)gopher://",
        r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
    ],
    "XML External Entity (XXE)": [
        r"<!DOCTYPE[^>]*\[",
        r"<!ENTITY\s+\w+\s+SYSTEM",
        r"SYSTEM\s+['\"]file://",
    ],
    "Server Side Template Injection (SSTI)": [
        r"\{\{.*?\}\}",
        r"\{%.*?%\}",
        r"\$\{.*?\}",
        r"#\{.*?\}",
        r"(?i)\{\{.*?(__class__|__mro__|os\.|subprocess)",
        r"(?i)7\*7|\{\{7\*7\}\}",
    ],
    "Prompt Injection in File": [
        r"(?i)ignore\s+(all\s+)?(your\s+)?(previous|prior|above|earlier)\s+instructions",
        r"(?i)forget\s+(all\s+)?(your\s+)?(previous|prior|above)\s+instructions",
        r"(?i)disregard\s+(all\s+)?instructions",
        r"(?i)override\s+(your\s+)?(safety|system|previous)\s*(settings|instructions|rules)?",
        r"(?i)reveal\s+(your\s+)?(hidden\s+)?(system\s+)?(prompt|instructions|context)",
        r"(?i)(system|developer|admin)\s+(override|mode|access|prompt)",
        r"(?i)\[system\]|\[admin\]|\[override\]",
        r"(?i)dan\s+mode|evil\s+mode|developer\s+mode",
        r"(?i)print\s+(your\s+)?(system\s+)?(prompt|instructions)",
        r"(?i)new\s+instructions?\s*:",
        r"(?i)act\s+as\s+(if\s+)?(you\s+are\s+)?(a\s+)?(?:unrestricted|admin|evil|root)",
        r"(?i)you\s+are\s+now\s+(a\s+)?(?:unrestricted|jailbroken|evil|different)",
    ],
    "Jailbreak Attempt in File": [
        r"(?i)jailbreak",
        r"(?i)pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(?:evil|unrestricted|hacked|free)",
        r"(?i)do\s+anything\s+now",
        r"(?i)without\s+(any\s+)?(restrictions?|filters?|guardrails?|safety)",
        r"(?i)disable\s+(your\s+)?(safety|security|filter|moderation|guardrail)",
    ],
    "Hardcoded Secret / API Key": [
        r"AIza[0-9A-Za-z\-_]{35}",
        r"AKIA[0-9A-Z]{16}",
        r"ghp_[0-9a-zA-Z]{36}",
        r"sk_live_[0-9a-zA-Z]{24,}",
        r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        r"(?i)(api[_\-]?key|apikey|access[_\-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{20,}",
    ],
    "Password / Credential in File": [
        r"(?i)^\s*(password|passwd|pwd|secret|pass)\s*[:=]\s*['\"]?\S{6,}",
        r"(?i)(mysql|postgresql|postgres|mongodb|redis):\/\/[^\s]+:[^\s]+@",
    ],
    "Encoded / Obfuscated Payload": [
        r"(?i)eval\s*\(\s*base64_decode\s*\(",
        r"(?i)eval\s*\(\s*atob\s*\(",
        r"(?i)exec\s*\(\s*base64\s*\.",
        r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}",
        r"(?:%[0-9a-fA-F]{2}){10,}",
    ],
    "PII — Aadhaar / PAN / Card": [
        r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b",
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        r"\b(?:\d{4}[\s\-]){3}\d{4}\b",
    ],
    "Internal Network / Config": [
        r"(?i)^\s*(DB_PASSWORD|SECRET_KEY|AWS_SECRET|DATABASE_URL|REDIS_URL|DATABASE_URL)\s*=\s*\S+",
        r"mongodb\+srv://",
        r"\bapiVersion:\s*[a-zA-Z]+/v\d",
        r"\bkind:\s*(Deployment|Service|Pod|ConfigMap|Secret)\b",
    ],
    "Internal Network Address / SSRF": [
        # Private IP ranges
        r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",
        r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
        r"\b127\.0\.0\.\d{1,3}\b",
        r"\b0\.0\.0\.0\b",
        # Cloud metadata endpoints
        r"169\.254\.169\.254",
        r"metadata\.google\.internal",
        r"(?i)instance-data\.ec2\.internal",
        # Internal hostnames
        r"https?://(?:api|internal|dev|staging|prod|admin|corp|intranet|backend|mgmt|private)\.",
        r"https?://(?:[a-zA-Z0-9\-]+\.)*(?:local|internal|corp|lan|intranet|localdomain)/",
        r"https?://(?:localhost|127\.0\.0\.1)",
        # Internal patterns with port
        r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+:\d{2,5}\b",
        # Dangerous URL schemes (SSRF via protocol)
        r"(?i)file://",
        r"(?i)gopher://",
        r"(?i)dict://",
        r"(?i)ldap://[^\s]",
        r"(?i)ftp://[^\s]+:[^\s]+@",
        # IPv6 loopback
        r"http://\[::1\]",
        r"http://\[::ffff:",
        r"http://\[0:0:0:0:0:0:0:1\]",
    ],
    "Source Code in File": [
        r"\bdef\s+[a-zA-Z_]\w*\s*\(",
        r"\bclass\s+[A-Z][a-zA-Z0-9_]*\s*[:\(]",
        r"\bfunction\s+[a-zA-Z_]\w*\s*\(",
        r"\bpublic\s+(static\s+)?(void|int|String|boolean|class)\b",
        r"^(import|from)\s+[a-zA-Z_][\w.]+\s",
        r"^#include\s*[<\"]",
    ],
    "Company / Proprietary Name in File": [
        # Company abbreviations and names — edit these for your organisation
        r"(?i)\b(AWL|adani\s+wilmar|adani\s+group|adani\s+enterprises)\b",
        r"(?i)\b(ONGC|BPCL|HPCL|IOCL|GAIL|NTPC|BHEL|HAL)\b",
        # Generic confidentiality markers in files
        r"(?i)\b(internal_use_only|confidential|proprietary|trade_secret|do_not_share|top_secret|restricted|classified)\b",
        r"(?i)company\s+confidential",
        r"(?i)not\s+for\s+(external|public|distribution|disclosure)",
        r"(?i)privileged\s+and\s+confidential",
        # Project codenames pattern (e.g. PROJECT ALPHA, PROJECT ZEUS)
        r"(?i)\bproject\s+[A-Z]{2,12}\b",
    ],
}

CONTENT_WEIGHTS = {
    "XSS / HTML Injection":              60,
    "SQL Injection":                     60,
    "Command Injection":                 65,
    "Path Traversal":                    55,
    "Server Side Request Forgery (SSRF)":55,
    "XML External Entity (XXE)":         55,
    "Server Side Template Injection (SSTI)": 60,
    "Prompt Injection in File":          60,
    "Jailbreak Attempt in File":         55,
    "Encoded / Obfuscated Payload":      55,
    "Hardcoded Secret / API Key":        60,
    "Password / Credential in File":     55,
    "PII — Aadhaar / PAN / Card":        50,
    "Internal Network / Config":         40,
    "Internal Network Address / SSRF":     60,
    "Source Code in File":               30,
    "Company / Proprietary Name in File":  45,
}

ALWAYS_BLOCK_CATEGORIES = {
    "XSS / HTML Injection","SQL Injection","Command Injection",
    "Path Traversal","Server Side Request Forgery (SSRF)",
    "XML External Entity (XXE)","Server Side Template Injection (SSTI)",
    "Prompt Injection in File","Jailbreak Attempt in File",
    "Encoded / Obfuscated Payload","Hardcoded Secret / API Key",
    "Password / Credential in File","PII — Aadhaar / PAN / Card","Internal Network Address / SSRF","Internal Network / Config","Source Code in File","Company / Proprietary Name in File",
}

MITRE_MAP = {
    "XSS / HTML Injection":                  "T1059.007 – JavaScript / HTML Injection",
    "SQL Injection":                          "T1190 – Exploit Public-Facing Application",
    "Command Injection":                      "T1059 – Command and Scripting Interpreter",
    "Path Traversal":                         "T1083 – File and Directory Discovery",
    "Server Side Request Forgery (SSRF)":     "T1090 – Proxy / Internal Network Pivot",
    "XML External Entity (XXE)":              "T1005 – Data from Local System",
    "Server Side Template Injection (SSTI)":  "T1059 – Command and Scripting Interpreter",
    "Prompt Injection in File":               "T1190 – Exploit via Injected Instructions",
    "Jailbreak Attempt in File":              "T1562 – Impair Defenses",
    "Encoded / Obfuscated Payload":           "T1027 – Obfuscated Files or Information",
    "Hardcoded Secret / API Key":             "T1552.001 – Credentials In Files",
    "Password / Credential in File":          "T1552.001 – Credentials In Files",
    "PII — Aadhaar / PAN / Card":             "T1589 – Gather Victim Identity Information",
    "Internal Network / Config":              "T1590.005 – Gather Victim Network Info",
    "Source Code in File":                    "T1213 – Data from Information Repositories",
    "Company / Proprietary Name in File":      "T1213 – Data from Information Repositories",
}

BINARY_SIGNATURES = [
    (b"\x7fELF",          "ELF Binary (Linux/Unix executable)"),
    (b"MZ",               "PE Binary (Windows .exe/.dll)"),
    (b"\xca\xfe\xba\xbe", "Java Class File"),
    (b"\xfe\xed\xfa\xce", "Mach-O Binary (macOS)"),
    (b"Rar!",             "RAR Archive"),
    (b"\x1f\x8b",         "GZIP Archive"),
    (b"7z\xbc\xaf",       "7-Zip Archive"),
    (b"\xd0\xcf\x11\xe0", "OLE2 / MS Office Legacy (macro-capable)"),
]

ALLOWED_MAGIC = { b"%PDF-", b"\x50\x4b\x03\x04" }

EXPECTED_CONTENT_SIGNATURES = {
    ".png":  [b"\x89PNG"],
    ".jpg":  [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".gif":  [b"GIF87a", b"GIF89a"],
    ".webp": [b"RIFF"],
    ".pdf":  [b"%PDF-"],
    ".docx": [b"PK\x03\x04"],
    ".xlsx": [b"PK\x03\x04"],
}

# Signatures that should NEVER appear in plain text files
ATTACK_SIGNATURES_IN_TEXT = [
    (b"<script",          "XSS — <script> tag"),
    (b"<SCRIPT",          "XSS — <script> tag"),
    (b"javascript:",      "XSS — javascript: URI"),
    (b"JAVASCRIPT:",      "XSS — javascript: URI"),
    (b"<?php",            "Server-side PHP code"),
    (b"<%@",              "Server-side JSP/ASP code"),
    (b"<%=",              "Server-side template code"),
    (b"<html",            "HTML content in text file"),
    (b"<HTML",            "HTML content in text file"),
    (b"<!DOCTYPE",        "HTML DOCTYPE in text file"),
    (b"<iframe",          "XSS — iframe injection"),
    (b"<IFRAME",          "XSS — iframe injection"),
    (b"<svg",             "XSS — SVG injection"),
    (b"<SVG",             "XSS — SVG injection"),
    (b"onerror=",         "XSS — event handler"),
    (b"onload=",          "XSS — event handler"),
    (b"onclick=",         "XSS — event handler"),
    (b"AKIA",             "AWS Access Key"),
    (b"AIzaSy",           "Google API Key"),
    (b"-----BEGIN",       "Private key/certificate"),
    (b"ghp_",             "GitHub token"),
]

TEXT_FILE_EXTENSIONS = {".txt", ".csv", ".md", ".json", ".xml", ".log"}


def check_extension(filename):
    base = os.path.basename(filename).lower()
    ext  = os.path.splitext(base)[1]

    if "%00" in filename or "\x00" in filename:
        return {"passed": False, "extension": ext,
                "category": "Null Byte Injection",
                "reason": "Null byte in filename — extension spoofing attack.", "severity": "BLOCK"}

    parts = base.split(".")
    if len(parts) > 2:
        for p in parts[1:]:
            if "." + p in BLOCKED_EXTENSIONS:
                return {"passed": False, "extension": "." + p,
                        "category": "Double Extension Attack",
                        "reason": f"Double extension: '{filename}' — .{p} is blocked.", "severity": "BLOCK"}

    if base in BLOCKED_FILENAMES or (not ext and base.startswith(".")):
        return {"passed": False, "extension": base,
                "category": "Blocked Filename",
                "reason": f"'{filename}' is a restricted system/config file.", "severity": "BLOCK"}

    if ext in BLOCKED_EXTENSIONS:
        return {"passed": False, "extension": ext,
                "category": _ext_cat(ext),
                "reason": f"Extension '{ext}' is blocked by policy.", "severity": "BLOCK"}

    if ext in ALLOWED_EXTENSIONS:
        return {"passed": True, "extension": ext, "category": "Allowed", "reason": "", "severity": "PASS"}

    return {"passed": False, "extension": ext or "(none)",
            "category": "Unknown File Type",
            "reason": f"Extension '{ext or '(none)'}' is not on the approved list.", "severity": "BLOCK"}


def _ext_cat(ext):
    if ext in {".php",".asp",".aspx",".jsp",".cgi",".cfm"}: return "Server-Side Web Script"
    if ext in {".py",".js",".ts",".java",".cs",".cpp",".c",".go",".rs",".rb",".swift",".kt"}: return "Source Code"
    if ext in {".env",".config",".conf",".cfg",".ini",".yaml",".yml",".toml",".tf"}: return "Config/Secrets File"
    if ext in {".sql",".db",".sqlite"}: return "Database File"
    if ext in {".pem",".key",".cert",".crt",".pfx"}: return "Cryptographic Key"
    if ext in {".sh",".bash",".ps1",".bat",".cmd"}: return "Shell Script"
    if ext in {".exe",".dll",".so",".bin",".jar",".pyc"}: return "Compiled Binary"
    if ext in {".zip",".tar",".gz",".rar",".7z"}: return "Archive"
    return "Restricted File Type"


def check_size(file_bytes):
    size = len(file_bytes)
    mb   = size / (1024*1024)
    if size > MAX_FILE_SIZE_BYTES:
        return {"passed": False, "size_mb": round(mb,2),
                "reason": f"File {mb:.1f} MB exceeds {MAX_FILE_SIZE_MB} MB limit."}
    return {"passed": True, "size_mb": round(mb,2), "reason": ""}


def check_binary_and_mime(file_bytes, filename):
    ext = os.path.splitext(filename.lower())[1]

    # Binary magic bytes
    for sig, label in BINARY_SIGNATURES:
        if file_bytes.startswith(sig):
            if sig in ALLOWED_MAGIC:
                return {"is_binary": False, "label": label, "content_mismatch": False,
                        "note": f"{label} — content will be scanned", "reason": ""}
            return {"is_binary": True, "label": label, "content_mismatch": False,
                    "reason": f"Binary file detected: {label}. Binary uploads are blocked."}

    # ── KEY FIX: Byte-level attack signature scan for text files ──
    # This catches HTML/scripts renamed to .txt BEFORE content scan
    if ext in TEXT_FILE_EXTENSIONS or ext in ALLOWED_EXTENSIONS:
        sample = file_bytes[:8192]
        for sig_bytes, sig_label in ATTACK_SIGNATURES_IN_TEXT:
            if sig_bytes.lower() in sample.lower():
                return {
                    "is_binary":        False,
                    "content_mismatch": True,
                    "label":            f"{sig_label} detected in {ext} file",
                    "reason":           (
                        f"ATTACK DETECTED: '{filename}' contains '{sig_label}'. "
                        f"A {ext} file must not contain executable or injection code. "
                        f"This is a classic file extension spoofing / content injection attack."
                    ),
                    "attack_type": f"Content Injection via Extension Spoofing ({sig_label})",
                }

    # Expected magic for image/office files
    expected = EXPECTED_CONTENT_SIGNATURES.get(ext, [])
    if expected:
        if not any(file_bytes.startswith(sig) for sig in expected):
            return {
                "is_binary": False, "content_mismatch": True,
                "label": f"Invalid {ext} file",
                "reason": f"File '{filename}' does not match expected {ext} format. Possible spoofing.",
                "attack_type": "File Signature Mismatch",
            }

    # High non-printable byte ratio
    sample = file_bytes[:4096]
    if sample:
        non_print = sum(1 for b in sample if b < 9 or (13 < b < 32) or b > 126)
        if non_print / len(sample) > 0.35:
            return {"is_binary": True, "content_mismatch": False,
                    "label": "Binary/encoded data",
                    "reason": "File contains high ratio of non-printable bytes — possible binary or obfuscated content."}

    return {"is_binary": False, "content_mismatch": False, "label": "", "reason": ""}


def scan_content(text):
    findings, seen, total_score = [], set(), 0
    lines = text.split("\n")

    for category, patterns in CONTENT_THREAT_PATTERNS.items():
        for pattern in patterns:
            try:
                m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                if m and category not in seen:
                    seen.add(category)
                    line_no = text[:m.start()].count("\n") + 1
                    snippet = lines[min(line_no-1, len(lines)-1)].strip()
                    weight  = CONTENT_WEIGHTS.get(category, 25)
                    total_score += weight
                    findings.append({
                        "category": category,
                        "line":     line_no,
                        "snippet":  snippet[:120] + ("..." if len(snippet) > 120 else ""),
                        "weight":   weight,
                        "mitre":    MITRE_MAP.get(category, "T1530"),
                    })
                    break
            except re.error:
                continue

    force_block = any(f["category"] in ALWAYS_BLOCK_CATEGORIES for f in findings)
    if force_block or total_score >= 50:  verdict = "BLOCK"
    elif total_score >= 25 or findings:   verdict = "WARN"
    else:                                  verdict = "PASS"

    return {"verdict": verdict, "findings": findings,
            "total_score": total_score, "blocked": verdict == "BLOCK"}


def run_file_guardrail(filename, file_bytes):
    stages, findings = [], []
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    # Stage 1 — Extension
    ext_r = check_extension(filename)
    stages.append({"name": "Extension Policy", "result": ext_r})
    if not ext_r["passed"]:
        return _blocked(stages, [], file_hash, f"Stage 1 BLOCKED — {ext_r['reason']}")

    # Stage 2 — Size
    size_r = check_size(file_bytes)
    stages.append({"name": "File Size", "result": size_r})
    if not size_r["passed"]:
        return _blocked(stages, [], file_hash, f"Stage 2 BLOCKED — {size_r['reason']}")

    # Stage 3 — Binary + Content-type mismatch
    bin_r = check_binary_and_mime(file_bytes, filename)
    stages.append({"name": "Binary / MIME Check", "result": bin_r})
    if bin_r.get("is_binary"):
        return _blocked(stages, [], file_hash, f"Stage 3 BLOCKED — {bin_r['reason']}")
    if bin_r.get("content_mismatch"):
        return _blocked(stages, [], file_hash, f"Stage 3 BLOCKED — {bin_r['reason']}",
                        attack_type=bin_r.get("attack_type","Content-Type Mismatch"))

    # Stage 4 — Deep content scan
    try:
        text = file_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = ""

    if text.strip():
        content_r = scan_content(text)
        stages.append({"name": "Content Scan", "result": content_r})
        findings = content_r["findings"]
        if content_r["blocked"]:
            return _blocked(stages, findings, file_hash,
                            f"Stage 4 BLOCKED — {len(findings)} threat(s) in file content.")
    else:
        stages.append({"name": "Content Scan",
                       "result": {"verdict": "SKIP", "reason": "Binary format"}})

    verdict = "WARN" if findings else "PASS"
    return {
        "verdict": verdict, "blocked": False, "stages": stages,
        "findings": findings,
        "summary": ("File passed all guardrail checks." if verdict == "PASS"
                    else f"File passed with {len(findings)} warning(s)."),
        "file_hash": file_hash, "text": text,
    }


def _blocked(stages, findings, file_hash, summary, attack_type=None):
    return {"verdict": "BLOCK", "blocked": True, "stages": stages,
            "findings": findings, "summary": summary,
            "attack_type": attack_type or "", "file_hash": file_hash, "text": ""}