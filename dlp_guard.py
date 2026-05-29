# # # # """
# # # # dlp_guard.py — Data Loss Prevention (DLP) Guard
# # # # Prevents users from uploading or pasting company code,
# # # # proprietary data, or sensitive file contents into the LLM.
# # # # """
# # # # import re

# # # # # =========================================================
# # # # # COMPANY CODE & PROPRIETARY DATA PATTERNS
# # # # # =========================================================

# # # # CODE_PATTERNS = {

# # # #     "Source Code — Function/Class Definition": [
# # # #         r"\bdef\s+[a-zA-Z_]\w*\s*\(",          # Python function
# # # #         r"\bclass\s+[A-Z][a-zA-Z0-9_]*\s*[:\(]", # Python class
# # # #         r"\bpublic\s+(static\s+)?(void|int|String|boolean|class)\b",  # Java
# # # #         r"\bprivate\s+(static\s+)?(void|int|String|boolean)\b",
# # # #         r"\bfunction\s+[a-zA-Z_]\w*\s*\(",      # JS/PHP function
# # # #         r"\bconst\s+[a-zA-Z_]\w*\s*=\s*\(.*\)\s*=>", # JS arrow func
# # # #         r"\bfunc\s+[a-zA-Z_]\w*\s*\(",          # Go/Swift
# # # #         r"\bfn\s+[a-zA-Z_]\w*\s*\(",            # Rust
# # # #         r"#include\s*<[a-zA-Z.]+>",             # C/C++
# # # #         r"\bnamespace\s+[A-Z][a-zA-Z0-9_.]+",   # C#/PHP
# # # #     ],

# # # #     "Source Code — Import Statements": [
# # # #         r"^\s*import\s+[a-zA-Z_][\w.]+",
# # # #         r"^\s*from\s+[a-zA-Z_][\w.]+\s+import",
# # # #         r"^\s*require\s*\(['\"][a-zA-Z]",        # Node.js
# # # #         r"^\s*#include\s*[<\"]",                 # C/C++
# # # #         r"^\s*using\s+[A-Z][a-zA-Z.]+;",        # C#
# # # #         r"^\s*import\s+[A-Z][a-zA-Z.]+;",       # Java
# # # #     ],

# # # #     "Database Schema / SQL DDL": [
# # # #         r"\bCREATE\s+TABLE\s+\w+",
# # # #         r"\bALTER\s+TABLE\s+\w+",
# # # #         r"\bDROP\s+TABLE\s+\w+",
# # # #         r"\bINSERT\s+INTO\s+\w+",
# # # #         r"\bCREATE\s+DATABASE\s+\w+",
# # # #         r"\bCREATE\s+INDEX\s+\w+",
# # # #         r"FOREIGN\s+KEY\s+REFERENCES",
# # # #         r"PRIMARY\s+KEY\s+AUTOINCREMENT",
# # # #     ],

# # # #     "Configuration / Environment File": [
# # # #         r"^\s*[A-Z_]{3,}\s*=\s*['\"]?[^\s'\"]{4,}",  # ENV vars like DB_HOST=xxx
# # # #         r"^\s*host\s*[:=]\s*['\"]?[\w.]+",
# # # #         r"^\s*port\s*[:=]\s*\d{2,5}",
# # # #         r"^\s*password\s*[:=]\s*['\"]?\S+",
# # # #         r"^\s*database\s*[:=]\s*['\"]?\w+",
# # # #         r"^\s*\[database\]|\[server\]|\[production\]|\[default\]",  # INI sections
# # # #         r"connection_string\s*[:=]",
# # # #         r"mongodb\+srv://",
# # # #         r"mysql://|postgresql://|sqlite:///",
# # # #     ],

# # # #     "API Endpoint / Internal URL": [
# # # #         r"https?://(?:api|internal|dev|staging|prod|admin|backend)\.[a-zA-Z0-9.\-]+",
# # # #         r"https?://(?:10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)",
# # # #         r"localhost:\d{4,5}/[a-zA-Z]",
# # # #         r"/api/v\d+/[a-zA-Z]",
# # # #         r"Authorization:\s*Bearer\s+\S+",
# # # #         r"X-API-Key:\s*\S+",
# # # #     ],

# # # #     "Proprietary Business Logic Keywords": [
# # # #         r"\b(internal_use_only|confidential|proprietary|trade_secret|do_not_share)\b",
# # # #         r"#\s*(TODO|FIXME|HACK|NOTE)\s*:.*(?:client|customer|prod|internal)",
# # # #         r"@(company|internal|private|confidential)\b",
# # # #     ],

# # # #     "Infrastructure / DevOps Config": [
# # # #         r"\bapiVersion:\s*[a-zA-Z]+/v\d",       # Kubernetes YAML
# # # #         r"\bkind:\s*(Deployment|Service|Pod|ConfigMap|Secret)\b",
# # # #         r"FROM\s+[a-zA-Z0-9.\-/]+:\d+\.",       # Dockerfile
# # # #         r"RUN\s+(apt|yum|pip|npm)\s+install",
# # # #         r"server_name\s+[a-zA-Z0-9.\-]+;",      # Nginx config
# # # #         r"VirtualHost|ProxyPass|RewriteRule",    # Apache config
# # # #         r"\bterraform\b|\bresource\s+\"aws_",    # Terraform
# # # #     ],

# # # #     "Compiled / Binary File Content": [
# # # #         r"^PK\x03\x04",                         # ZIP/JAR
# # # #         r"^\x7fELF",                             # ELF binary
# # # #         r"^MZ",                                  # Windows EXE
# # # #         r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}",  # Hex dump
# # # #         r"^H4sI|^UEsDB",                        # Base64 gzip/zip
# # # #     ],
# # # # }

# # # # FILE_EXTENSION_BLOCK = {
# # # #     ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cs", ".cpp", ".c",
# # # #     ".h", ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".scala",
# # # #     ".env", ".env.local", ".env.production", ".env.development",
# # # #     ".config", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml",
# # # #     ".sql", ".db", ".sqlite", ".sqlite3",
# # # #     ".pem", ".key", ".cert", ".crt", ".pfx", ".p12",
# # # #     ".tf", ".tfvars",                           # Terraform
# # # #     ".dockerfile", "dockerfile",
# # # #     ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
# # # #     ".jar", ".class", ".pyc", ".exe", ".dll", ".so",
# # # #     ".log",                                     # Server logs
# # # # }

# # # # ALLOWED_FILE_TYPES = {
# # # #     ".txt", ".pdf", ".docx", ".xlsx", ".csv", ".png", ".jpg", ".jpeg",
# # # #     ".gif", ".mp4", ".mp3", ".zip" , ".json",  # JSON allowed for non-code data
# # # # }

# # # # # Risk weight per category
# # # # CATEGORY_WEIGHTS = {
# # # #     "Source Code — Function/Class Definition": 40,
# # # #     "Source Code — Import Statements":         35,
# # # #     "Database Schema / SQL DDL":               35,
# # # #     "Configuration / Environment File":        45,
# # # #     "API Endpoint / Internal URL":             40,
# # # #     "Proprietary Business Logic Keywords":     30,
# # # #     "Infrastructure / DevOps Config":          35,
# # # #     "Compiled / Binary File Content":          50,
# # # # }


# # # # # =========================================================
# # # # # CORE SCANNER
# # # # # =========================================================

# # # # def scan_for_company_data(text: str) -> dict:
# # # #     """
# # # #     Scan pasted text for company code / proprietary data patterns.
# # # #     Returns detailed findings and a BLOCK/WARN/PASS verdict.
# # # #     """
# # # #     findings = []
# # # #     seen = set()
# # # #     lines = text.split("\n")
# # # #     total_score = 0

# # # #     for category, patterns in CODE_PATTERNS.items():
# # # #         for pattern in patterns:
# # # #             # Check full text and line-by-line
# # # #             matched_line = None
# # # #             try:
# # # #                 # Full text match
# # # #                 m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
# # # #                 if m:
# # # #                     # Find which line
# # # #                     pos = m.start()
# # # #                     matched_line = text[:pos].count("\n") + 1
# # # #             except re.error:
# # # #                 continue

# # # #             if matched_line and category not in seen:
# # # #                 seen.add(category)
# # # #                 snippet = lines[matched_line - 1].strip()[:80]
# # # #                 total_score += CATEGORY_WEIGHTS.get(category, 25)
# # # #                 findings.append({
# # # #                     "category":    category,
# # # #                     "line":        matched_line,
# # # #                     "snippet":     snippet + ("…" if len(lines[matched_line-1].strip()) > 80 else ""),
# # # #                     "weight":      CATEGORY_WEIGHTS.get(category, 25),
# # # #                 })
# # # #                 break

# # # #     # Determine verdict
# # # #     if total_score >= 40 or any(
# # # #         f["category"] in ("Configuration / Environment File",
# # # #                           "Compiled / Binary File Content",
# # # #                           "API Endpoint / Internal URL") for f in findings
# # # #     ):
# # # #         verdict = "BLOCK"
# # # #     elif total_score >= 20 or findings:
# # # #         verdict = "WARN"
# # # #     else:
# # # #         verdict = "PASS"

# # # #     # Count code lines (heuristic: lines starting with common code chars)
# # # #     code_line_count = sum(
# # # #         1 for l in lines
# # # #         if l.strip().startswith(("def ", "class ", "import ", "from ", "const ",
# # # #                                   "function ", "public ", "private ", "#include",
# # # #                                   "SELECT ", "INSERT ", "CREATE "))
# # # #     )

# # # #     return {
# # # #         "verdict":         verdict,
# # # #         "findings":        findings,
# # # #         "total_score":     total_score,
# # # #         "code_line_count": code_line_count,
# # # #         "category_count":  len(findings),
# # # #         "blocked":         verdict == "BLOCK",
# # # #     }


# # # # def check_file_extension(filename: str) -> dict:
# # # #     """
# # # #     Check if a file extension is allowed.
# # # #     Returns {allowed, extension, reason}
# # # #     """
# # # #     import os
# # # #     ext = os.path.splitext(filename.lower())[1]
# # # #     if not ext:
# # # #         # No extension — check if it's a known config filename
# # # #         base = filename.lower()
# # # #         if base in ("dockerfile", "makefile", "jenkinsfile", "vagrantfile",
# # # #                     ".env", ".gitignore", ".bashrc", ".zshrc"):
# # # #             return {
# # # #                 "allowed":    False,
# # # #                 "extension":  base,
# # # #                 "reason":     f"'{filename}' is a restricted configuration/build file.",
# # # #                 "category":   "Infrastructure / DevOps Config",
# # # #             }
# # # #         return {"allowed": True, "extension": "", "reason": "", "category": ""}

# # # #     if ext in FILE_EXTENSION_BLOCK:
# # # #         return {
# # # #             "allowed":    False,
# # # #             "extension":  ext,
# # # #             "reason":     f"Files with extension '{ext}' are not permitted — possible source code or sensitive config.",
# # # #             "category":   _ext_category(ext),
# # # #         }
# # # #     return {"allowed": True, "extension": ext, "reason": "", "category": ""}


# # # # def _ext_category(ext: str) -> str:
# # # #     code_exts    = {".py",".js",".ts",".jsx",".tsx",".java",".cs",".cpp",".c",".h",".go",".rs",".rb",".php",".swift",".kt",".scala"}
# # # #     config_exts  = {".env",".config",".conf",".cfg",".ini",".yaml",".yml",".toml",".tf",".tfvars"}
# # # #     db_exts      = {".sql",".db",".sqlite",".sqlite3"}
# # # #     key_exts     = {".pem",".key",".cert",".crt",".pfx",".p12"}
# # # #     script_exts  = {".sh",".bash",".zsh",".ps1",".bat",".cmd"}
# # # #     binary_exts  = {".jar",".class",".pyc",".exe",".dll",".so"}

# # # #     if ext in code_exts:    return "Source Code"
# # # #     if ext in config_exts:  return "Configuration / Environment File"
# # # #     if ext in db_exts:      return "Database File"
# # # #     if ext in key_exts:     return "Cryptographic Key / Certificate"
# # # #     if ext in script_exts:  return "Shell Script / Automation"
# # # #     if ext in binary_exts:  return "Compiled Binary"
# # # #     return "Restricted File Type"


# # # # def get_dlp_message(result: dict) -> str:
# # # #     """Return a user-facing block message."""
# # # #     cats = [f["category"] for f in result["findings"]]
# # # #     return (
# # # #         "🚫 **DLP Policy Violation — Submission Blocked**\n\n"
# # # #         "Your input appears to contain **company source code or proprietary data** "
# # # #         "which cannot be submitted to this system per your organisation's Data Loss Prevention policy.\n\n"
# # # #         f"**Detected:** {', '.join(cats)}\n\n"
# # # #         "**What you can do:**\n"
# # # #         "- Remove all code, configuration values, credentials, and internal URLs\n"
# # # #         "- Describe the problem in plain English instead of pasting code\n"
# # # #         "- Contact your security team if you believe this is a false positive\n\n"
# # # #         "*This attempt has been logged in the audit trail.*"
# # # #     )

# # # """
# # # dlp_guard.py — Data Loss Prevention (DLP) Guard
# # # Prevents users from uploading or pasting company code,
# # # proprietary data, or sensitive file contents into the LLM.
# # # """
# # # import re

# # # # =========================================================
# # # # COMPANY CODE & PROPRIETARY DATA PATTERNS
# # # # =========================================================

# # # CODE_PATTERNS = {

# # #     "Source Code — Function/Class Definition": [
# # #         r"\bdef\s+[a-zA-Z_]\w*\s*\(",          # Python function
# # #         r"\bclass\s+[A-Z][a-zA-Z0-9_]*\s*[:\(]", # Python class
# # #         r"\bpublic\s+(static\s+)?(void|int|String|boolean|class)\b",  # Java
# # #         r"\bprivate\s+(static\s+)?(void|int|String|boolean)\b",
# # #         r"\bfunction\s+[a-zA-Z_]\w*\s*\(",      # JS/PHP function
# # #         r"\bconst\s+[a-zA-Z_]\w*\s*=\s*\(.*\)\s*=>", # JS arrow func
# # #         r"\bfunc\s+[a-zA-Z_]\w*\s*\(",          # Go/Swift
# # #         r"\bfn\s+[a-zA-Z_]\w*\s*\(",            # Rust
# # #         r"#include\s*<[a-zA-Z.]+>",             # C/C++
# # #         r"\bnamespace\s+[A-Z][a-zA-Z0-9_.]+",   # C#/PHP
# # #     ],

# # #     "Source Code — Import Statements": [
# # #         r"^\s*import\s+[a-zA-Z_][\w.]+",
# # #         r"^\s*from\s+[a-zA-Z_][\w.]+\s+import",
# # #         r"^\s*require\s*\(['\"][a-zA-Z]",        # Node.js
# # #         r"^\s*#include\s*[<\"]",                 # C/C++
# # #         r"^\s*using\s+[A-Z][a-zA-Z.]+;",        # C#
# # #         r"^\s*import\s+[A-Z][a-zA-Z.]+;",       # Java
# # #     ],

# # #     "Database Schema / SQL DDL": [
# # #         r"\bCREATE\s+TABLE\s+\w+",
# # #         r"\bALTER\s+TABLE\s+\w+",
# # #         r"\bDROP\s+TABLE\s+\w+",
# # #         r"\bINSERT\s+INTO\s+\w+",
# # #         r"\bCREATE\s+DATABASE\s+\w+",
# # #         r"\bCREATE\s+INDEX\s+\w+",
# # #         r"FOREIGN\s+KEY\s+REFERENCES",
# # #         r"PRIMARY\s+KEY\s+AUTOINCREMENT",
# # #     ],

# # #     "Configuration / Environment File": [
# # #         r"^\s*[A-Z_]{3,}\s*=\s*['\"]?[^\s'\"]{4,}",  # ENV vars like DB_HOST=xxx
# # #         r"^\s*host\s*[:=]\s*['\"]?[\w.]+",
# # #         r"^\s*port\s*[:=]\s*\d{2,5}",
# # #         r"^\s*password\s*[:=]\s*['\"]?\S+",
# # #         r"^\s*database\s*[:=]\s*['\"]?\w+",
# # #         r"^\s*\[database\]|\[server\]|\[production\]|\[default\]",  # INI sections
# # #         r"connection_string\s*[:=]",
# # #         r"mongodb\+srv://",
# # #         r"mysql://|postgresql://|sqlite:///",
# # #     ],

# # #     "API Endpoint / Internal URL": [
# # #         r"https?://(?:api|internal|dev|staging|prod|admin|backend)\.[a-zA-Z0-9.\-]+",
# # #         r"https?://(?:10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)",
# # #         r"localhost:\d{4,5}/[a-zA-Z]",
# # #         r"/api/v\d+/[a-zA-Z]",
# # #         r"Authorization:\s*Bearer\s+\S+",
# # #         r"X-API-Key:\s*\S+",
# # #     ],

# # #     "Proprietary Business Logic Keywords": [
# # #         r"\b(internal_use_only|confidential|proprietary|trade_secret|do_not_share)\b",
# # #         r"#\s*(TODO|FIXME|HACK|NOTE)\s*:.*(?:client|customer|prod|internal)",
# # #         r"@(company|internal|private|confidential)\b",
# # #     ],

# # #     "Infrastructure / DevOps Config": [
# # #         r"\bapiVersion:\s*[a-zA-Z]+/v\d",       # Kubernetes YAML
# # #         r"\bkind:\s*(Deployment|Service|Pod|ConfigMap|Secret)\b",
# # #         r"FROM\s+[a-zA-Z0-9.\-/]+:\d+\.",       # Dockerfile
# # #         r"RUN\s+(apt|yum|pip|npm)\s+install",
# # #         r"server_name\s+[a-zA-Z0-9.\-]+;",      # Nginx config
# # #         r"VirtualHost|ProxyPass|RewriteRule",    # Apache config
# # #         r"\bterraform\b|\bresource\s+\"aws_",    # Terraform
# # #     ],

# # #     "Compiled / Binary File Content": [
# # #         r"^PK\x03\x04",                         # ZIP/JAR
# # #         r"^\x7fELF",                             # ELF binary
# # #         r"^MZ",                                  # Windows EXE
# # #         r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}",  # Hex dump
# # #         r"^H4sI|^UEsDB",                        # Base64 gzip/zip
# # #     ],
# # # }

# # # FILE_EXTENSION_BLOCK = {
# # #     ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cs", ".cpp", ".c",
# # #     ".h", ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".scala",
# # #     ".env", ".env.local", ".env.production", ".env.development",
# # #     ".config", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml",
# # #     ".sql", ".db", ".sqlite", ".sqlite3",
# # #     ".pem", ".key", ".cert", ".crt", ".pfx", ".p12",
# # #     ".tf", ".tfvars",                           # Terraform
# # #     ".dockerfile", "dockerfile",
# # #     ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
# # #     ".jar", ".class", ".pyc", ".exe", ".dll", ".so",
# # #     ".log",                                     # Server logs
# # # }

# # # ALLOWED_FILE_TYPES = {
# # #     ".txt", ".pdf", ".docx", ".xlsx", ".csv", ".png", ".jpg", ".jpeg",
# # #     ".gif", ".mp4", ".mp3", ".zip" , ".json",  # JSON allowed for non-code data
# # # }

# # # # Risk weight per category
# # # CATEGORY_WEIGHTS = {
# # #     "Source Code — Function/Class Definition": 40,
# # #     "Source Code — Import Statements":         35,
# # #     "Database Schema / SQL DDL":               35,
# # #     "Configuration / Environment File":        45,
# # #     "API Endpoint / Internal URL":             40,
# # #     "Proprietary Business Logic Keywords":     30,
# # #     "Infrastructure / DevOps Config":          35,
# # #     "Compiled / Binary File Content":          50,
# # # }


# # # # =========================================================
# # # # CORE SCANNER
# # # # =========================================================

# # # def scan_for_company_data(text: str) -> dict:
# # #     """
# # #     Scan pasted text for company code / proprietary data patterns.
# # #     Returns detailed findings and a BLOCK/WARN/PASS verdict.
# # #     """
# # #     findings = []
# # #     seen = set()
# # #     lines = text.split("\n")
# # #     total_score = 0

# # #     for category, patterns in CODE_PATTERNS.items():
# # #         for pattern in patterns:
# # #             # Check full text and line-by-line
# # #             matched_line = None
# # #             try:
# # #                 # Full text match
# # #                 m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
# # #                 if m:
# # #                     # Find which line
# # #                     pos = m.start()
# # #                     matched_line = text[:pos].count("\n") + 1
# # #             except re.error:
# # #                 continue

# # #             if matched_line and category not in seen:
# # #                 seen.add(category)
# # #                 snippet = lines[matched_line - 1].strip()[:80]
# # #                 total_score += CATEGORY_WEIGHTS.get(category, 25)
# # #                 findings.append({
# # #                     "category":    category,
# # #                     "line":        matched_line,
# # #                     "snippet":     snippet + ("…" if len(lines[matched_line-1].strip()) > 80 else ""),
# # #                     "weight":      CATEGORY_WEIGHTS.get(category, 25),
# # #                 })
# # #                 break

# # #     # Determine verdict
# # #     if total_score >= 40 or any(
# # #         f["category"] in ("Configuration / Environment File",
# # #                           "Compiled / Binary File Content",
# # #                           "API Endpoint / Internal URL") for f in findings
# # #     ):
# # #         verdict = "BLOCK"
# # #     elif total_score >= 20 or findings:
# # #         verdict = "WARN"
# # #     else:
# # #         verdict = "PASS"

# # #     # Count code lines (heuristic: lines starting with common code chars)
# # #     code_line_count = sum(
# # #         1 for l in lines
# # #         if l.strip().startswith(("def ", "class ", "import ", "from ", "const ",
# # #                                   "function ", "public ", "private ", "#include",
# # #                                   "SELECT ", "INSERT ", "CREATE "))
# # #     )

# # #     return {
# # #         "verdict":         verdict,
# # #         "findings":        findings,
# # #         "total_score":     total_score,
# # #         "code_line_count": code_line_count,
# # #         "category_count":  len(findings),
# # #         "blocked":         verdict == "BLOCK",
# # #     }


# # # def check_file_extension(filename: str) -> dict:
# # #     """
# # #     Check if a file extension is allowed.
# # #     Returns {allowed, extension, reason}
# # #     """
# # #     import os
# # #     ext = os.path.splitext(filename.lower())[1]
# # #     if not ext:
# # #         # No extension — check if it's a known config filename
# # #         base = filename.lower()
# # #         if base in ("dockerfile", "makefile", "jenkinsfile", "vagrantfile",
# # #                     ".env", ".gitignore", ".bashrc", ".zshrc"):
# # #             return {
# # #                 "allowed":    False,
# # #                 "extension":  base,
# # #                 "reason":     f"'{filename}' is a restricted configuration/build file.",
# # #                 "category":   "Infrastructure / DevOps Config",
# # #             }
# # #         return {"allowed": True, "extension": "", "reason": "", "category": ""}

# # #     if ext in FILE_EXTENSION_BLOCK:
# # #         return {
# # #             "allowed":    False,
# # #             "extension":  ext,
# # #             "reason":     f"Files with extension '{ext}' are not permitted — possible source code or sensitive config.",
# # #             "category":   _ext_category(ext),
# # #         }
# # #     return {"allowed": True, "extension": ext, "reason": "", "category": ""}


# # # def _ext_category(ext: str) -> str:
# # #     code_exts    = {".py",".js",".ts",".jsx",".tsx",".java",".cs",".cpp",".c",".h",".go",".rs",".rb",".php",".swift",".kt",".scala"}
# # #     config_exts  = {".env",".config",".conf",".cfg",".ini",".yaml",".yml",".toml",".tf",".tfvars"}
# # #     db_exts      = {".sql",".db",".sqlite",".sqlite3"}
# # #     key_exts     = {".pem",".key",".cert",".crt",".pfx",".p12"}
# # #     script_exts  = {".sh",".bash",".zsh",".ps1",".bat",".cmd"}
# # #     binary_exts  = {".jar",".class",".pyc",".exe",".dll",".so"}

# # #     if ext in code_exts:    return "Source Code"
# # #     if ext in config_exts:  return "Configuration / Environment File"
# # #     if ext in db_exts:      return "Database File"
# # #     if ext in key_exts:     return "Cryptographic Key / Certificate"
# # #     if ext in script_exts:  return "Shell Script / Automation"
# # #     if ext in binary_exts:  return "Compiled Binary"
# # #     return "Restricted File Type"


# # # def get_dlp_message(result: dict) -> str:
# # #     """Return a user-facing block message."""
# # #     cats = [f["category"] for f in result["findings"]]
# # #     return (
# # #         "🚫 **DLP Policy Violation — Submission Blocked**\n\n"
# # #         "Your input appears to contain **company source code or proprietary data** "
# # #         "which cannot be submitted to this system per your organisation's Data Loss Prevention policy.\n\n"
# # #         f"**Detected:** {', '.join(cats)}\n\n"
# # #         "**What you can do:**\n"
# # #         "- Remove all code, configuration values, credentials, and internal URLs\n"
# # #         "- Describe the problem in plain English instead of pasting code\n"
# # #         "- Contact your security team if you believe this is a false positive\n\n"
# # #         "*This attempt has been logged in the audit trail.*"
# # #     )

# # """
# # dlp_guard.py — Unified DLP + Threat Guard
# # Blocks: company code, proprietary data, prompt injection,
# # XSS, API keys, internal URLs, Dockerfile commands, jailbreaks.
# # """
# # import re

# # # =========================================================
# # # CATEGORY WEIGHTS
# # # =========================================================

# # CATEGORY_WEIGHTS = {
# #     # Company code
# #     "Source Code — Function/Class Definition":  40,
# #     "Source Code — Import Statements":          35,
# #     "Database Schema / SQL DDL":                35,
# #     "Configuration / Environment File":         45,
# #     "API Endpoint / Internal URL":              40,
# #     "Infrastructure / DevOps Config":           40,
# #     "Proprietary Business Logic Keywords":      30,
# #     "Compiled / Binary File Content":           50,
# #     # Secrets
# #     "Google API Key":                           50,
# #     "AWS Access Key":                           50,
# #     "GitHub Token":                             50,
# #     "Generic API Key / Token":                  45,
# #     "JWT Token":                                45,
# #     "Private Key Block":                        50,
# #     "Password in Text":                         40,
# #     # Attacks
# #     "Prompt Injection Attempt":                 45,
# #     "Jailbreak Attempt":                        45,
# #     "XSS / HTML Injection":                     40,
# #     "Command Injection":                        40,
# #     "Data Leakage Attempt":                     40,
# # }

# # # =========================================================
# # # ALL DETECTION PATTERNS
# # # =========================================================

# # CODE_PATTERNS = {

# #     # --- Company Source Code ---
# #     "Source Code — Function/Class Definition": [
# #         r"\bdef\s+[a-zA-Z_]\w*\s*\(",
# #         r"\bclass\s+[A-Z][a-zA-Z0-9_]*\s*[:\(]",
# #         r"\bpublic\s+(static\s+)?(void|int|String|boolean|class)\b",
# #         r"\bfunction\s+[a-zA-Z_]\w*\s*\(",
# #         r"\bconst\s+[a-zA-Z_]\w*\s*=\s*\(.*\)\s*=>",
# #         r"\bfunc\s+[a-zA-Z_]\w*\s*\(",
# #         r"\bfn\s+[a-zA-Z_]\w*\s*\(",
# #     ],
# #     "Source Code — Import Statements": [
# #         r"^\s*import\s+[a-zA-Z_][\w.]+",
# #         r"^\s*from\s+[a-zA-Z_][\w.]+\s+import",
# #         r"^\s*require\s*\(['\"][a-zA-Z]",
# #         r"^\s*#include\s*[<\"]",
# #         r"^\s*using\s+[A-Z][a-zA-Z.]+;",
# #     ],
# #     "Database Schema / SQL DDL": [
# #         r"\bCREATE\s+TABLE\s+\w+",
# #         r"\bALTER\s+TABLE\s+\w+",
# #         r"\bDROP\s+TABLE\s+\w+",
# #         r"\bCREATE\s+DATABASE\s+\w+",
# #         r"FOREIGN\s+KEY\s+REFERENCES",
# #         r"PRIMARY\s+KEY\s+AUTOINCREMENT",
# #     ],
# #     "Configuration / Environment File": [
# #         r"(?i)^\s*(DB_HOST|DB_PASSWORD|DATABASE_URL|SECRET_KEY|AWS_SECRET|REDIS_URL)\s*=\s*\S+",
# #         r"(?i)^\s*password\s*[:=]\s*['\"]?\S{4,}",
# #         r"(?i)^\s*host\s*[:=]\s*['\"]?[\w.\-]+",
# #         r"mongodb\+srv://",
# #         r"mysql://|postgresql://|redis://",
# #         r"connection_string\s*[:=]",
# #     ],
# #     "API Endpoint / Internal URL": [
# #         r"https?://(?:api|internal|dev|staging|prod|admin|backend|corp|intranet)\.[a-zA-Z0-9.\-]+",
# #         r"https?://(?:10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)\d+\.\d+",
# #         r"https?://(?:localhost|127\.0\.0\.1):\d+/[a-zA-Z]",
# #         r"https?://(?:[a-zA-Z0-9\-]+\.)*(?:local|internal|corp|lan|intranet)/",
# #         r"/api/v\d+/[a-zA-Z]",
# #         r"(?i)Authorization:\s*Bearer\s+\S+",
# #         r"(?i)X-API-Key:\s*\S+",
# #     ],
# #     "Infrastructure / DevOps Config": [
# #         r"\bapiVersion:\s*[a-zA-Z]+/v\d",
# #         r"\bkind:\s*(Deployment|Service|Pod|ConfigMap|Secret|Ingress)\b",
# #         r"(?i)^FROM\s+[a-zA-Z0-9.\-/]+",
# #         r"(?i)^RUN\s+(apt|yum|pip|npm|apk)\s+(install|update|get)",
# #         r"(?i)^EXPOSE\s+\d+",
# #         r"(?i)^ENTRYPOINT\s+[\[\"]",
# #         r"server_name\s+[a-zA-Z0-9.\-]+;",
# #         r"resource\s+\"aws_",
# #         r"\bterraform\s*\{",
# #     ],
# #     "Proprietary Business Logic Keywords": [
# #         r"\b(internal_use_only|confidential|proprietary|trade_secret|do_not_share|top_secret)\b",
# #         r"@(company|internal|private|confidential|awl)\b",
# #     ],
# #     "Compiled / Binary File Content": [
# #         r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}",
# #         r"^H4sI|^UEsDB",
# #     ],

# #     # --- Secrets & Credentials ---
# #     "Google API Key": [
# #         r"AIza[0-9A-Za-z\-_]{35}",
# #     ],
# #     "AWS Access Key": [
# #         r"AKIA[0-9A-Z]{16}",
# #         r"ASIA[0-9A-Z]{16}",
# #     ],
# #     "GitHub Token": [
# #         r"ghp_[0-9a-zA-Z]{36}",
# #         r"gho_[0-9a-zA-Z]{36}",
# #         r"github_pat_[0-9a-zA-Z_]{82}",
# #     ],
# #     "Generic API Key / Token": [
# #         r"(?i)(api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{20,}",
# #         r"sk_live_[0-9a-zA-Z]{24,}",
# #         r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
# #     ],
# #     "JWT Token": [
# #         r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+/=]{10,}",
# #     ],
# #     "Private Key Block": [
# #         r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
# #     ],
# #     "Password in Text": [
# #         r"(?i)\bpassword\s*[:=]\s*['\"]?\S{6,}",
# #         r"(?i)\bpasswd\s*[:=]\s*['\"]?\S{6,}",
# #         r"(?i)\bsecret\s*[:=]\s*['\"]?\S{6,}",
# #     ],

# #     # --- Prompt Attacks ---
# #     "Prompt Injection Attempt": [
# #         r"(?i)ignore\s+(all\s+)?(your\s+)?(previous|prior|above|earlier)\s+instructions",
# #         r"(?i)forget\s+(all\s+)?(your\s+)?(previous|prior|above|earlier)\s+instructions",
# #         r"(?i)disregard\s+(all\s+)?(your\s+)?instructions",
# #         r"(?i)override\s+(your\s+)?(safety|security|system|previous)\s*(settings|instructions|rules|constraints)?",
# #         r"(?i)bypass\s+(your\s+)?(safety|security|filter|guardrail|restriction)",
# #         r"(?i)you\s+are\s+now\s+(a\s+)?(?:unrestricted|jailbroken|free|evil|hacked|different)",
# #         r"(?i)act\s+as\s+(if\s+)?(you\s+are\s+)?(a\s+)?(?:human|admin|root|superuser|unrestricted|evil|different)",
# #         r"(?i)reveal\s+(your\s+)?(hidden\s+)?(system\s+)?(prompt|instructions|rules|context|configuration)",
# #         r"(?i)show\s+me\s+(your\s+)?(system\s+)?(prompt|instructions|configuration)",
# #         r"(?i)what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions|rules)",
# #         r"(?i)print\s+(your\s+)?(system\s+)?(prompt|instructions)",
# #         r"(?i)repeat\s+(everything|all)\s+(above|before|prior)",
# #         r"(?i)output\s+(your\s+)?(initial|original|system)\s+(prompt|instructions)",
# #         r"(?i)(system|developer|admin)\s+(override|mode|prompt|access)",
# #         r"(?i)new\s+instructions?\s*:",
# #         r"(?i)\[system\]|\[admin\]|\[override\]|\[instructions?\]",
# #     ],
# #     "Jailbreak Attempt": [
# #         r"(?i)jailbreak",
# #         r"(?i)pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(?:evil|unrestricted|human|different|hacked)",
# #         r"(?i)roleplay\s+as\s+(an?\s+)?(?:evil|unrestricted|hacker|admin)",
# #         r"(?i)dan\s+mode",
# #         r"(?i)evil\s+mode",
# #         r"(?i)developer\s+mode",
# #         r"(?i)no\s+restrictions?",
# #         r"(?i)without\s+(any\s+)?(restrictions?|filters?|limits?|guardrails?)",
# #         r"(?i)break\s+(the\s+)?(rules|ethical|restrictions?|guidelines)",
# #         r"(?i)disable\s+(your\s+)?(safety|security|filter|moderation|guardrail)",
# #         r"(?i)unrestricted\s+(ai|mode|access)",
# #         r"(?i)do\s+anything\s+now",
# #     ],
# #     "XSS / HTML Injection": [
# #         r"<script[^>]*>",
# #         r"</script>",
# #         r"(?i)javascript\s*:",
# #         r"(?i)on(error|load|click|mouseover|focus|blur|change|submit)\s*=",
# #         r"(?i)alert\s*\(",
# #         r"document\.cookie",
# #         r"<iframe[^>]*>",
# #         r"(?i)<img[^>]+on\w+\s*=",
# #         r"eval\s*\(",
# #         r"(?i)document\.write\s*\(",
# #         r"(?i)innerHTML\s*=",
# #         r"(?i)window\.location",
# #     ],
# #     "Command Injection": [
# #         r"(?i)(;|\||\|\|)\s*(rm|del|format|shutdown|reboot|kill|wget|curl|nc|bash|sh|cmd|powershell)",
# #         r"`[^`]{3,}`",
# #         r"\$\([^)]{3,}\)",
# #         r"(?i)(rm\s+-rf|del\s+/f|format\s+c:)",
# #         r"(?i)(wget|curl)\s+https?://",
# #         r"(?i)/bin/(bash|sh|zsh|ksh)",
# #         r"(?i)cmd\.exe",
# #     ],
# #     "Data Leakage Attempt": [
# #         r"(?i)(show|display|print|output|dump|leak|expose|send|email|exfiltrate)\s+(me\s+)?(all\s+)?(the\s+)?(user|customer|employee|database|confidential|private|secret|password|credential|key|token|log)",
# #         r"(?i)export\s+(all\s+)?(user|customer|data|database|record)",
# #         r"(?i)give\s+me\s+(all\s+)?(user|customer|employee|password|credential|secret)",
# #         r"(?i)list\s+all\s+(user|customer|password|credential|employee|admin)",
# #     ],
# # }

# # # =========================================================
# # # FILE EXTENSIONS
# # # =========================================================

# # FILE_EXTENSION_BLOCK = {
# #     ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cs", ".cpp", ".c",
# #     ".h", ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".scala",
# #     ".env", ".env.local", ".env.production", ".env.development",
# #     ".config", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml",
# #     ".sql", ".db", ".sqlite", ".sqlite3",
# #     ".pem", ".key", ".cert", ".crt", ".pfx", ".p12",
# #     ".tf", ".tfvars",
# #     ".dockerfile", "dockerfile",
# #     ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
# #     ".jar", ".class", ".pyc", ".exe", ".dll", ".so",
# #     ".log",
# # }

# # # =========================================================
# # # SCANNER
# # # =========================================================

# # def scan_for_company_data(text: str) -> dict:
# #     findings = []
# #     seen = set()
# #     lines = text.split("\n")
# #     total_score = 0

# #     for category, patterns in CODE_PATTERNS.items():
# #         for pattern in patterns:
# #             try:
# #                 m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
# #                 if m and category not in seen:
# #                     seen.add(category)
# #                     line_no = text[:m.start()].count("\n") + 1
# #                     snippet = lines[line_no - 1].strip()[:80]
# #                     weight = CATEGORY_WEIGHTS.get(category, 25)
# #                     total_score += weight
# #                     findings.append({
# #                         "category": category,
# #                         "line":     line_no,
# #                         "snippet":  snippet + ("..." if len(lines[line_no-1].strip()) > 80 else ""),
# #                         "weight":   weight,
# #                     })
# #                     break
# #             except re.error:
# #                 continue

# #     # Verdict logic
# #     high_risk_cats = {
# #         "Google API Key", "AWS Access Key", "GitHub Token", "Generic API Key / Token",
# #         "JWT Token", "Private Key Block", "Password in Text",
# #         "Prompt Injection Attempt", "Jailbreak Attempt", "XSS / HTML Injection",
# #         "Command Injection", "Data Leakage Attempt",
# #         "Configuration / Environment File", "API Endpoint / Internal URL",
# #         "Infrastructure / DevOps Config", "Compiled / Binary File Content",
# #     }

# #     has_high_risk = any(f["category"] in high_risk_cats for f in findings)

# #     if has_high_risk or total_score >= 40:
# #         verdict = "BLOCK"
# #     elif total_score >= 20 or findings:
# #         verdict = "WARN"
# #     else:
# #         verdict = "PASS"

# #     return {
# #         "verdict":        verdict,
# #         "findings":       findings,
# #         "total_score":    total_score,
# #         "code_line_count": sum(1 for l in lines if l.strip().startswith(
# #             ("def ", "class ", "import ", "from ", "const ", "function ", "public "))),
# #         "category_count": len(findings),
# #         "blocked":        verdict == "BLOCK",
# #     }


# # def check_file_extension(filename: str) -> dict:
# #     import os
# #     ext = os.path.splitext(filename.lower())[1]
# #     base = filename.lower()
# #     if base in ("dockerfile", "makefile", "jenkinsfile", "vagrantfile", ".env",
# #                 ".gitignore", ".bashrc", ".zshrc"):
# #         return {"allowed": False, "extension": base,
# #                 "reason": f"'{filename}' is a restricted configuration/build file.",
# #                 "category": "Infrastructure / DevOps Config"}
# #     if ext in FILE_EXTENSION_BLOCK:
# #         return {"allowed": False, "extension": ext,
# #                 "reason": f"Files with extension '{ext}' are not permitted.",
# #                 "category": "Restricted File Type"}
# #     return {"allowed": True, "extension": ext, "reason": "", "category": ""}


# # def get_dlp_message(result: dict) -> str:
# #     cats = [f["category"] for f in result["findings"]]

# #     # Customise message by threat type
# #     if any(c in ("Prompt Injection Attempt", "Jailbreak Attempt") for c in cats):
# #         header = "Prompt Injection / Jailbreak Blocked"
# #         body   = "Your input contains patterns that attempt to override system instructions or bypass security guardrails."
# #     elif any(c in ("Google API Key", "AWS Access Key", "GitHub Token",
# #                    "Generic API Key / Token", "JWT Token", "Private Key Block",
# #                    "Password in Text") for c in cats):
# #         header = "Secret / Credential Detected — Blocked"
# #         body   = "Your input contains API keys, tokens, or passwords. Never submit credentials to an AI system."
# #     elif any(c == "XSS / HTML Injection" for c in cats):
# #         header = "XSS / Injection Attack Blocked"
# #         body   = "Your input contains HTML/JavaScript injection patterns."
# #     elif any(c == "Command Injection" for c in cats):
# #         header = "Command Injection Blocked"
# #         body   = "Your input contains OS command injection patterns."
# #     elif any(c == "API Endpoint / Internal URL" for c in cats):
# #         header = "Internal URL Disclosure Blocked"
# #         body   = "Your input contains internal API endpoints or private network addresses."
# #     elif any(c == "Infrastructure / DevOps Config" for c in cats):
# #         header = "Infrastructure Config Blocked"
# #         body   = "Your input contains Dockerfile, Kubernetes, or Terraform configuration."
# #     else:
# #         header = "DLP Policy Violation — Submission Blocked"
# #         body   = "Your input contains company source code or proprietary data."

# #     return (
# #         f"🚫 **{header}**\n\n"
# #         f"{body}\n\n"
# #         f"**Detected:** {', '.join(cats)}\n\n"
# #         "**What you can do:**\n"
# #         "- Describe your problem in plain English\n"
# #         "- Remove all code, credentials, and internal URLs\n"
# #         "- Contact your security team if this is a false positive\n\n"
# #         "*This attempt has been logged in the audit trail.*"
# #     )

# """
# dlp_guard.py — Unified DLP + Threat Guard
# Blocks: company code, proprietary data, prompt injection,
# XSS, API keys, internal URLs, Dockerfile commands, jailbreaks.
# """
# import re

# # =========================================================
# # CATEGORY WEIGHTS
# # =========================================================

# CATEGORY_WEIGHTS = {
#     # Company code
#     "Source Code — Function/Class Definition":  40,
#     "Source Code — Import Statements":          35,
#     "Database Schema / SQL DDL":                35,
#     "Configuration / Environment File":         45,
#     "API Endpoint / Internal URL":              40,
#     "Infrastructure / DevOps Config":           40,
#     "Proprietary Business Logic Keywords":      40,
#     "Company / Project Name Leak":              40,
#     "Compiled / Binary File Content":           50,
#     # Secrets
#     "Google API Key":                           50,
#     "AWS Access Key":                           50,
#     "GitHub Token":                             50,
#     "Generic API Key / Token":                  45,
#     "JWT Token":                                45,
#     "Private Key Block":                        50,
#     "Password in Text":                         40,
#     # Attacks
#     "Prompt Injection Attempt":                 45,
#     "Jailbreak Attempt":                        45,
#     "XSS / HTML Injection":                     40,
#     "Command Injection":                        40,
#     "Data Leakage Attempt":                     40,
# }

# # =========================================================
# # ALL DETECTION PATTERNS
# # =========================================================

# CODE_PATTERNS = {

#     # --- Company Source Code ---
#     "Source Code — Function/Class Definition": [
#         r"\bdef\s+[a-zA-Z_]\w*\s*\(",
#         r"\bclass\s+[A-Z][a-zA-Z0-9_]*\s*[:\(]",
#         r"\bpublic\s+(static\s+)?(void|int|String|boolean|class)\b",
#         r"\bfunction\s+[a-zA-Z_]\w*\s*\(",
#         r"\bconst\s+[a-zA-Z_]\w*\s*=\s*\(.*\)\s*=>",
#         r"\bfunc\s+[a-zA-Z_]\w*\s*\(",
#         r"\bfn\s+[a-zA-Z_]\w*\s*\(",
#     ],
#     "Source Code — Import Statements": [
#         r"^\s*import\s+[a-zA-Z_][\w.]+",
#         r"^\s*from\s+[a-zA-Z_][\w.]+\s+import",
#         r"^\s*require\s*\(['\"][a-zA-Z]",
#         r"^\s*#include\s*[<\"]",
#         r"^\s*using\s+[A-Z][a-zA-Z.]+;",
#     ],
#     "Database Schema / SQL DDL": [
#         r"\bCREATE\s+TABLE\s+\w+",
#         r"\bALTER\s+TABLE\s+\w+",
#         r"\bDROP\s+TABLE\s+\w+",
#         r"\bCREATE\s+DATABASE\s+\w+",
#         r"FOREIGN\s+KEY\s+REFERENCES",
#         r"PRIMARY\s+KEY\s+AUTOINCREMENT",
#     ],
#     "Configuration / Environment File": [
#         r"(?i)^\s*(DB_HOST|DB_PASSWORD|DATABASE_URL|SECRET_KEY|AWS_SECRET|REDIS_URL)\s*=\s*\S+",
#         r"(?i)^\s*password\s*[:=]\s*['\"]?\S{4,}",
#         r"(?i)^\s*host\s*[:=]\s*['\"]?[\w.\-]+",
#         r"mongodb\+srv://",
#         r"mysql://|postgresql://|redis://",
#         r"connection_string\s*[:=]",
#     ],
#     "API Endpoint / Internal URL": [
#         r"https?://(?:api|internal|dev|staging|prod|admin|backend|corp|intranet)\.[a-zA-Z0-9.\-]+",
#         r"https?://(?:10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)\d+\.\d+",
#         r"https?://(?:localhost|127\.0\.0\.1):\d+/[a-zA-Z]",
#         r"https?://(?:[a-zA-Z0-9\-]+\.)*(?:local|internal|corp|lan|intranet)/",
#         r"/api/v\d+/[a-zA-Z]",
#         r"(?i)Authorization:\s*Bearer\s+\S+",
#         r"(?i)X-API-Key:\s*\S+",
#     ],
#     "Infrastructure / DevOps Config": [
#         r"\bapiVersion:\s*[a-zA-Z]+/v\d",
#         r"\bkind:\s*(Deployment|Service|Pod|ConfigMap|Secret|Ingress)\b",
#         r"(?i)^FROM\s+[a-zA-Z0-9.\-/]+",
#         r"(?i)^RUN\s+(apt|yum|pip|npm|apk)\s+(install|update|get)",
#         r"(?i)^EXPOSE\s+\d+",
#         r"(?i)^ENTRYPOINT\s+[\[\"]",
#         r"server_name\s+[a-zA-Z0-9.\-]+;",
#         r"resource\s+\"aws_",
#         r"\bterraform\s*\{",
#     ],
#     "Proprietary Business Logic Keywords": [
#         r"\b(internal_use_only|confidential|proprietary|trade_secret|do_not_share|top_secret|restricted|classified)\b",
#         r"@(company|internal|private|confidential)\b",
#         r"(?i)\bcompany\s+(confidential|secret|internal|data|code|project|system)\b",
#         r"(?i)not\s+for\s+(external|public|distribution|disclosure)\b",
#         r"(?i)privileged\s+and\s+confidential",
#     ],
#     "Company / Project Name Leak": [
#         # Add your real company abbreviations and project names here
#         # These block internal names from being submitted to AI systems
#         r"(?i)\b(AWL|adani\s+wilmar|adani\s+group)\b",
#         r"(?i)\b(ONGC|BPCL|HPCL|IOCL|GAIL)\b",   # common enterprise names
#         r"(?i)\b(project\s+[A-Z]{2,10})\b",        # Project ALPHA, Project XYZ etc
#         r"(?i)\binternal\s+project\b",
#         r"(?i)\bconfidential\s+project\b",
#     ],
#     "Compiled / Binary File Content": [
#         r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}",
#         r"^H4sI|^UEsDB",
#     ],

#     # --- Secrets & Credentials ---
#     "Google API Key": [
#         r"AIza[0-9A-Za-z\-_]{35}",
#     ],
#     "AWS Access Key": [
#         r"AKIA[0-9A-Z]{16}",
#         r"ASIA[0-9A-Z]{16}",
#     ],
#     "GitHub Token": [
#         r"ghp_[0-9a-zA-Z]{36}",
#         r"gho_[0-9a-zA-Z]{36}",
#         r"github_pat_[0-9a-zA-Z_]{82}",
#     ],
#     "Generic API Key / Token": [
#         r"(?i)(api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{20,}",
#         r"sk_live_[0-9a-zA-Z]{24,}",
#         r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
#     ],
#     "JWT Token": [
#         r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+/=]{10,}",
#     ],
#     "Private Key Block": [
#         r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
#     ],
#     "Password in Text": [
#         r"(?i)\bpassword\s*[:=]\s*['\"]?\S{6,}",
#         r"(?i)\bpasswd\s*[:=]\s*['\"]?\S{6,}",
#         r"(?i)\bsecret\s*[:=]\s*['\"]?\S{6,}",
#     ],

#     # --- Prompt Attacks ---
#     "Prompt Injection Attempt": [
#         r"(?i)\bignore\b.{0,30}\binstructions?\b",
#         r"(?i)\bignore\b.{0,30}\brules?\b",
#         r"(?i)\bignore\b.{0,30}\bconstraints?\b",
#         r"(?i)\bdisregard\b.{0,30}\binstructions?\b",
#         r"(?i)\bforget\b.{0,30}\binstructions?\b",
#         r"(?i)\bforget\b.{0,30}\brules?\b",
#         r"(?i)\bre+v[e3]?[a4]?l\b.{0,40}\b(system|prompt|identity|instructions?|rules?|config|key|secret|password)\b",
#         r"(?i)\br[e3]+v[e3]+[a4]?l\b",
#         r"(?i)\brev[\-\s]?e?al\b.{0,30}\b(identity|system|prompt|instructions?)\b",
#         r"(?i)\b(show|print|output|display|leak|expose|dump|give|tell|share)\b.{0,30}\b(system\s+prompt|your\s+prompt|your\s+instructions?|your\s+rules?|your\s+identity|your\s+config)\b",
#         r"(?i)\b(what|tell\s+me).{0,20}\b(your\s+)?(instructions?|rules?|system\s+prompt|constraints?)\b",
#         r"(?i)\bbypass\b.{0,30}\b(safety|filter|rule|restriction|guardrail|moderation)\b",
#         r"(?i)\boverride\b.{0,30}\b(programming|instruction|rule|filter|safety|system)\b",
#         r"(?i)\bact\s+as\b.{0,40}\b(unrestricted|no\s+rules?|no\s+limits?|no\s+filter|jailbreak|evil|dan)\b",
#         r"(?i)\byou\s+are\s+now\b.{0,30}\b(dan|evil|unrestricted|free|jailbreak)\b",
#         r"(?i)\bpretend\b.{0,40}\b(no\s+rules?|no\s+limits?|unrestricted|evil|dan)\b",
#         r"(?i)\[system\]|\[instructions?\]|\[admin\]|\[override\]|\[new\s+task\]",
#         r"(?i)###\s+(instruction|system|prompt|task)\s*:",
#         r"(?i)---\s*(new\s+)?(prompt|instruction|system)\s*---",
#         r"(?i)new\s+(task|instruction|prompt|directive)\s*:",
#         r"(?i)\brepeat\b.{0,30}\b(everything|all)\b.{0,20}\b(above|before|prior)\b",
#         r"(?i)\bno\s+(restrictions?|limits?|filters?|guardrails?|rules?)\b",
#         r"(?i)\bwithout\s+(any\s+)?(restrictions?|limits?|filters?|safety)\b",
#     ],
#     "Jailbreak Attempt": [
#         r"(?i)jailbreak",
#         r"(?i)pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(?:evil|unrestricted|human|different|hacked)",
#         r"(?i)roleplay\s+as\s+(an?\s+)?(?:evil|unrestricted|hacker|admin)",
#         r"(?i)dan\s+mode",
#         r"(?i)evil\s+mode",
#         r"(?i)developer\s+mode",
#         r"(?i)no\s+restrictions?",
#         r"(?i)without\s+(any\s+)?(restrictions?|filters?|limits?|guardrails?)",
#         r"(?i)break\s+(the\s+)?(rules|ethical|restrictions?|guidelines)",
#         r"(?i)disable\s+(your\s+)?(safety|security|filter|moderation|guardrail)",
#         r"(?i)unrestricted\s+(ai|mode|access)",
#         r"(?i)do\s+anything\s+now",
#     ],
#     "XSS / HTML Injection": [
#         r"<script[^>]*>",
#         r"</script>",
#         r"(?i)javascript\s*:",
#         r"(?i)on(error|load|click|mouseover|focus|blur|change|submit)\s*=",
#         r"(?i)alert\s*\(",
#         r"document\.cookie",
#         r"<iframe[^>]*>",
#         r"(?i)<img[^>]+on\w+\s*=",
#         r"eval\s*\(",
#         r"(?i)document\.write\s*\(",
#         r"(?i)innerHTML\s*=",
#         r"(?i)window\.location",
#     ],
#     "Command Injection": [
#         r"(?i)(;|\||\|\|)\s*(rm|del|format|shutdown|reboot|kill|wget|curl|nc|bash|sh|cmd|powershell)",
#         r"`[^`]{3,}`",
#         r"\$\([^)]{3,}\)",
#         r"(?i)(rm\s+-rf|del\s+/f|format\s+c:)",
#         r"(?i)(wget|curl)\s+https?://",
#         r"(?i)/bin/(bash|sh|zsh|ksh)",
#         r"(?i)cmd\.exe",
#     ],
#     "Data Leakage Attempt": [
#         r"(?i)(show|display|print|output|dump|leak|expose|send|email|exfiltrate)\s+(me\s+)?(all\s+)?(the\s+)?(user|customer|employee|database|confidential|private|secret|password|credential|key|token|log)",
#         r"(?i)export\s+(all\s+)?(user|customer|data|database|record)",
#         r"(?i)give\s+me\s+(all\s+)?(user|customer|employee|password|credential|secret)",
#         r"(?i)list\s+all\s+(user|customer|password|credential|employee|admin)",
#     ],
# }

# # =========================================================
# # FILE EXTENSIONS
# # =========================================================

# FILE_EXTENSION_BLOCK = {
#     ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cs", ".cpp", ".c",
#     ".h", ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".scala",
#     ".env", ".env.local", ".env.production", ".env.development",
#     ".config", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml",
#     ".sql", ".db", ".sqlite", ".sqlite3",
#     ".pem", ".key", ".cert", ".crt", ".pfx", ".p12",
#     ".tf", ".tfvars",
#     ".dockerfile", "dockerfile",
#     ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
#     ".jar", ".class", ".pyc", ".exe", ".dll", ".so",
#     ".log",
# }

# # =========================================================
# # SCANNER
# # =========================================================

# def scan_for_company_data(text: str) -> dict:
#     findings = []
#     seen = set()
#     lines = text.split("\n")
#     total_score = 0

#     for category, patterns in CODE_PATTERNS.items():
#         for pattern in patterns:
#             try:
#                 m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
#                 if m and category not in seen:
#                     seen.add(category)
#                     line_no = text[:m.start()].count("\n") + 1
#                     snippet = lines[line_no - 1].strip()[:80]
#                     weight = CATEGORY_WEIGHTS.get(category, 25)
#                     total_score += weight
#                     findings.append({
#                         "category": category,
#                         "line":     line_no,
#                         "snippet":  snippet + ("..." if len(lines[line_no-1].strip()) > 80 else ""),
#                         "weight":   weight,
#                     })
#                     break
#             except re.error:
#                 continue

#     # Verdict logic
#     high_risk_cats = {
#         "Google API Key", "AWS Access Key", "GitHub Token", "Generic API Key / Token",
#         "JWT Token", "Private Key Block", "Password in Text",
#         "Prompt Injection Attempt", "Jailbreak Attempt", "XSS / HTML Injection",
#         "Command Injection", "Data Leakage Attempt",
#         "Configuration / Environment File", "API Endpoint / Internal URL",
#         "Infrastructure / DevOps Config", "Compiled / Binary File Content",
#     }

#     has_high_risk = any(f["category"] in high_risk_cats for f in findings)

#     if has_high_risk or total_score >= 40:
#         verdict = "BLOCK"
#     elif total_score >= 20 or findings:
#         verdict = "WARN"
#     else:
#         verdict = "PASS"

#     return {
#         "verdict":        verdict,
#         "findings":       findings,
#         "total_score":    total_score,
#         "code_line_count": sum(1 for l in lines if l.strip().startswith(
#             ("def ", "class ", "import ", "from ", "const ", "function ", "public "))),
#         "category_count": len(findings),
#         "blocked":        verdict == "BLOCK",
#     }


# def check_file_extension(filename: str) -> dict:
#     import os
#     ext = os.path.splitext(filename.lower())[1]
#     base = filename.lower()
#     if base in ("dockerfile", "makefile", "jenkinsfile", "vagrantfile", ".env",
#                 ".gitignore", ".bashrc", ".zshrc"):
#         return {"allowed": False, "extension": base,
#                 "reason": f"'{filename}' is a restricted configuration/build file.",
#                 "category": "Infrastructure / DevOps Config"}
#     if ext in FILE_EXTENSION_BLOCK:
#         return {"allowed": False, "extension": ext,
#                 "reason": f"Files with extension '{ext}' are not permitted.",
#                 "category": "Restricted File Type"}
#     return {"allowed": True, "extension": ext, "reason": "", "category": ""}


# def get_dlp_message(result: dict) -> str:
#     cats = [f["category"] for f in result["findings"]]

#     # Customise message by threat type
#     if any(c in ("Prompt Injection Attempt", "Jailbreak Attempt") for c in cats):
#         header = "Prompt Injection / Jailbreak Blocked"
#         body   = "Your input contains patterns that attempt to override system instructions or bypass security guardrails."
#     elif any(c in ("Google API Key", "AWS Access Key", "GitHub Token",
#                    "Generic API Key / Token", "JWT Token", "Private Key Block",
#                    "Password in Text") for c in cats):
#         header = "Secret / Credential Detected — Blocked"
#         body   = "Your input contains API keys, tokens, or passwords. Never submit credentials to an AI system."
#     elif any(c == "XSS / HTML Injection" for c in cats):
#         header = "XSS / Injection Attack Blocked"
#         body   = "Your input contains HTML/JavaScript injection patterns."
#     elif any(c == "Command Injection" for c in cats):
#         header = "Command Injection Blocked"
#         body   = "Your input contains OS command injection patterns."
#     elif any(c == "API Endpoint / Internal URL" for c in cats):
#         header = "Internal URL Disclosure Blocked"
#         body   = "Your input contains internal API endpoints or private network addresses."
#     elif any(c == "Infrastructure / DevOps Config" for c in cats):
#         header = "Infrastructure Config Blocked"
#         body   = "Your input contains Dockerfile, Kubernetes, or Terraform configuration."
#     else:
#         header = "DLP Policy Violation — Submission Blocked"
#         body   = "Your input contains company source code or proprietary data."

#     return (
#         f"🚫 **{header}**\n\n"
#         f"{body}\n\n"
#         f"**Detected:** {', '.join(cats)}\n\n"
#         "**What you can do:**\n"
#         "- Describe your problem in plain English\n"
#         "- Remove all code, credentials, and internal URLs\n"
#         "- Contact your security team if this is a false positive\n\n"
#         "*This attempt has been logged in the audit trail.*"
#     )

"""
dlp_guard.py — Unified DLP + Threat Guard
Blocks: company code, proprietary data, prompt injection,
XSS, API keys, internal URLs, Dockerfile commands, jailbreaks.
"""
import re

# =========================================================
# CATEGORY WEIGHTS
# =========================================================

CATEGORY_WEIGHTS = {
    # Company code
    "Source Code — Function/Class Definition":  40,
    "Source Code — Import Statements":          35,
    "Database Schema / SQL DDL":                35,
    "Configuration / Environment File":         45,
    "API Endpoint / Internal URL":              40,
    "Infrastructure / DevOps Config":           40,
    "Proprietary Business Logic Keywords":      40,
    "Company / Project Name Leak":              40,
    "Compiled / Binary File Content":           50,
    # Secrets
    "Google API Key":                           50,
    "AWS Access Key":                           50,
    "GitHub Token":                             50,
    "Generic API Key / Token":                  45,
    "JWT Token":                                45,
    "Private Key Block":                        50,
    "Password in Text":                         40,
    # Attacks
    "Prompt Injection Attempt":                 45,
    "Jailbreak Attempt":                        45,
    "XSS / HTML Injection":                     40,
    "Command Injection":                        40,
    "Data Leakage Attempt":                     40,
}

# =========================================================
# ALL DETECTION PATTERNS
# =========================================================

CODE_PATTERNS = {

    # --- Company Source Code ---
    "Source Code — Function/Class Definition": [
        r"\bdef\s+[a-zA-Z_]\w*\s*\(",
        r"\bclass\s+[A-Z][a-zA-Z0-9_]*\s*[:\(]",
        r"\bpublic\s+(static\s+)?(void|int|String|boolean|class)\b",
        r"\bfunction\s+[a-zA-Z_]\w*\s*\(",
        r"\bconst\s+[a-zA-Z_]\w*\s*=\s*\(.*\)\s*=>",
        r"\bfunc\s+[a-zA-Z_]\w*\s*\(",
        r"\bfn\s+[a-zA-Z_]\w*\s*\(",
    ],
    "Source Code — Import Statements": [
        r"^\s*import\s+[a-zA-Z_][\w.]+",
        r"^\s*from\s+[a-zA-Z_][\w.]+\s+import",
        r"^\s*require\s*\(['\"][a-zA-Z]",
        r"^\s*#include\s*[<\"]",
        r"^\s*using\s+[A-Z][a-zA-Z.]+;",
    ],
    "Database Schema / SQL DDL": [
        r"\bCREATE\s+TABLE\s+\w+",
        r"\bALTER\s+TABLE\s+\w+",
        r"\bDROP\s+TABLE\s+\w+",
        r"\bCREATE\s+DATABASE\s+\w+",
        r"FOREIGN\s+KEY\s+REFERENCES",
        r"PRIMARY\s+KEY\s+AUTOINCREMENT",
    ],
    "Configuration / Environment File": [
        r"(?i)^\s*(DB_HOST|DB_PASSWORD|DATABASE_URL|SECRET_KEY|AWS_SECRET|REDIS_URL)\s*=\s*\S+",
        r"(?i)^\s*password\s*[:=]\s*['\"]?\S{4,}",
        r"(?i)^\s*host\s*[:=]\s*['\"]?[\w.\-]+",
        r"mongodb\+srv://",
        r"mysql://|postgresql://|redis://",
        r"connection_string\s*[:=]",
    ],
    "API Endpoint / Internal URL": [
        r"https?://(?:api|internal|dev|staging|prod|admin|backend|corp|intranet)\.[a-zA-Z0-9.\-]+",
        r"https?://(?:10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)\d+\.\d+",
        r"https?://(?:localhost|127\.0\.0\.1):\d+/[a-zA-Z]",
        r"https?://(?:[a-zA-Z0-9\-]+\.)*(?:local|internal|corp|lan|intranet)/",
        r"/api/v\d+/[a-zA-Z]",
        r"(?i)Authorization:\s*Bearer\s+\S+",
        r"(?i)X-API-Key:\s*\S+",
    ],
    "Infrastructure / DevOps Config": [
        r"\bapiVersion:\s*[a-zA-Z]+/v\d",
        r"\bkind:\s*(Deployment|Service|Pod|ConfigMap|Secret|Ingress)\b",
        r"(?i)^FROM\s+[a-zA-Z0-9.\-/]+",
        r"(?i)^RUN\s+(apt|yum|pip|npm|apk)\s+(install|update|get)",
        r"(?i)^EXPOSE\s+\d+",
        r"(?i)^ENTRYPOINT\s+[\[\"]",
        r"server_name\s+[a-zA-Z0-9.\-]+;",
        r"resource\s+\"aws_",
        r"\bterraform\s*\{",
    ],
    "Proprietary Business Logic Keywords": [
        r"\b(internal_use_only|confidential|proprietary|trade_secret|do_not_share|top_secret|restricted|classified)\b",
        r"@(company|internal|private|confidential)\b",
        r"(?i)\bcompany\s+(confidential|secret|internal|data|code|project|system)\b",
        r"(?i)not\s+for\s+(external|public|distribution|disclosure)\b",
        r"(?i)privileged\s+and\s+confidential",
    ],
    "Company / Project Name Leak": [
        # Add your real company abbreviations and project names here
        # These block internal names from being submitted to AI systems
        r"(?i)\b(AWL|adani\s+wilmar|adani\s+group)\b",
        r"(?i)\b(ONGC|BPCL|HPCL|IOCL|GAIL)\b",   # common enterprise names
        r"(?i)\b(project\s+[A-Z]{2,10})\b",        # Project ALPHA, Project XYZ etc
        r"(?i)\binternal\s+project\b",
        r"(?i)\bconfidential\s+project\b",
    ],
    "Compiled / Binary File Content": [
        r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}",
        r"^H4sI|^UEsDB",
    ],

    # --- Secrets & Credentials ---
    "Google API Key": [
        r"AIza[0-9A-Za-z\-_]{35}",
    ],
    "AWS Access Key": [
        r"AKIA[0-9A-Z]{16}",
        r"ASIA[0-9A-Z]{16}",
    ],
    "GitHub Token": [
        r"ghp_[0-9a-zA-Z]{36}",
        r"gho_[0-9a-zA-Z]{36}",
        r"github_pat_[0-9a-zA-Z_]{82}",
    ],
    "Generic API Key / Token": [
        r"(?i)(api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{20,}",
        r"sk_live_[0-9a-zA-Z]{24,}",
        r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    ],
    "JWT Token": [
        r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+/=]{10,}",
    ],
    "Private Key Block": [
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    ],
    "Password in Text": [
        r"(?i)\bpassword\s*[:=]\s*['\"]?\S{6,}",
        r"(?i)\bpasswd\s*[:=]\s*['\"]?\S{6,}",
        r"(?i)\bsecret\s*[:=]\s*['\"]?\S{6,}",
    ],

    # --- Prompt Attacks ---
    "Prompt Injection Attempt": [
        r"(?i)\bignore\b.{0,30}\binstructions?\b",
        r"(?i)\bignore\b.{0,30}\brules?\b",
        r"(?i)\bignore\b.{0,30}\bconstraints?\b",
        r"(?i)\bdisregard\b.{0,30}\binstructions?\b",
        r"(?i)\bforget\b.{0,30}\binstructions?\b",
        r"(?i)\bforget\b.{0,30}\brules?\b",
        r"(?i)\bre+v[e3]?[a4]?l\b.{0,40}\b(system|prompt|identity|instructions?|rules?|config|key|secret|password)\b",
        r"(?i)\br[e3]+v[e3]+[a4]?l\b",
        r"(?i)\brev[\-\s]?e?al\b.{0,30}\b(identity|system|prompt|instructions?)\b",
        r"(?i)\b(show|print|output|display|leak|expose|dump|give|tell|share)\b.{0,30}\b(system\s+prompt|your\s+prompt|your\s+instructions?|your\s+rules?|your\s+identity|your\s+config)\b",
        r"(?i)\b(what|tell\s+me).{0,20}\b(your\s+)?(instructions?|rules?|system\s+prompt|constraints?)\b",
        r"(?i)\bbypass\b.{0,30}\b(safety|filter|rule|restriction|guardrail|moderation)\b",
        r"(?i)\boverride\b.{0,30}\b(programming|instruction|rule|filter|safety|system)\b",
        r"(?i)\bact\s+as\b.{0,40}\b(unrestricted|no\s+rules?|no\s+limits?|no\s+filter|jailbreak|evil|dan)\b",
        r"(?i)\byou\s+are\s+now\b.{0,30}\b(dan|evil|unrestricted|free|jailbreak)\b",
        r"(?i)\bpretend\b.{0,40}\b(no\s+rules?|no\s+limits?|unrestricted|evil|dan)\b",
        r"(?i)\[system\]|\[instructions?\]|\[admin\]|\[override\]|\[new\s+task\]",
        r"(?i)###\s+(instruction|system|prompt|task)\s*:",
        r"(?i)---\s*(new\s+)?(prompt|instruction|system)\s*---",
        r"(?i)new\s+(task|instruction|prompt|directive)\s*:",
        r"(?i)\brepeat\b.{0,30}\b(everything|all)\b.{0,20}\b(above|before|prior)\b",
        r"(?i)\bno\s+(restrictions?|limits?|filters?|guardrails?|rules?)\b",
        r"(?i)\bwithout\s+(any\s+)?(restrictions?|limits?|filters?|safety)\b",
    ],
    "Jailbreak Attempt": [
        r"(?i)jailbreak",
        r"(?i)pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(?:evil|unrestricted|human|different|hacked)",
        r"(?i)roleplay\s+as\s+(an?\s+)?(?:evil|unrestricted|hacker|admin)",
        r"(?i)dan\s+mode",
        r"(?i)evil\s+mode",
        r"(?i)developer\s+mode",
        r"(?i)no\s+restrictions?",
        r"(?i)without\s+(any\s+)?(restrictions?|filters?|limits?|guardrails?)",
        r"(?i)break\s+(the\s+)?(rules|ethical|restrictions?|guidelines)",
        r"(?i)disable\s+(your\s+)?(safety|security|filter|moderation|guardrail)",
        r"(?i)unrestricted\s+(ai|mode|access)",
        r"(?i)do\s+anything\s+now",
    ],
    "XSS / HTML Injection": [
        r"<script[^>]*>",
        r"</script>",
        r"(?i)javascript\s*:",
        r"(?i)on(error|load|click|mouseover|focus|blur|change|submit)\s*=",
        r"(?i)alert\s*\(",
        r"document\.cookie",
        r"<iframe[^>]*>",
        r"(?i)<img[^>]+on\w+\s*=",
        r"eval\s*\(",
        r"(?i)document\.write\s*\(",
        r"(?i)innerHTML\s*=",
        r"(?i)window\.location",
    ],
    "Command Injection": [
        r"(?i)(;|\||\|\|)\s*(rm|del|format|shutdown|reboot|kill|wget|curl|nc|bash|sh|cmd|powershell)",
        r"`[^`]{3,}`",
        r"\$\([^)]{3,}\)",
        r"(?i)(rm\s+-rf|del\s+/f|format\s+c:)",
        r"(?i)(wget|curl)\s+https?://",
        r"(?i)/bin/(bash|sh|zsh|ksh)",
        r"(?i)cmd\.exe",
    ],
    "Data Leakage Attempt": [
        r"(?i)(show|display|print|output|dump|leak|expose|send|email|exfiltrate)\s+(me\s+)?(all\s+)?(the\s+)?(user|customer|employee|database|confidential|private|secret|password|credential|key|token|log)",
        r"(?i)export\s+(all\s+)?(user|customer|data|database|record)",
        r"(?i)give\s+me\s+(all\s+)?(user|customer|employee|password|credential|secret)",
        r"(?i)list\s+all\s+(user|customer|password|credential|employee|admin)",
    ],
}

# =========================================================
# FILE EXTENSIONS
# =========================================================

FILE_EXTENSION_BLOCK = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cs", ".cpp", ".c",
    ".h", ".go", ".rs", ".rb", ".php", ".swift", ".kt", ".scala",
    ".env", ".env.local", ".env.production", ".env.development",
    ".config", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml",
    ".sql", ".db", ".sqlite", ".sqlite3",
    ".pem", ".key", ".cert", ".crt", ".pfx", ".p12",
    ".tf", ".tfvars",
    ".dockerfile", "dockerfile",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".jar", ".class", ".pyc", ".exe", ".dll", ".so",
    ".log",
}

# =========================================================
# SCANNER
# =========================================================

def scan_for_company_data(text: str) -> dict:
    findings = []
    seen = set()
    lines = text.split("\n")
    total_score = 0

    for category, patterns in CODE_PATTERNS.items():
        for pattern in patterns:
            try:
                m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
                if m and category not in seen:
                    seen.add(category)
                    line_no = text[:m.start()].count("\n") + 1
                    snippet = lines[line_no - 1].strip()[:80]
                    weight = CATEGORY_WEIGHTS.get(category, 25)
                    total_score += weight
                    findings.append({
                        "category": category,
                        "line":     line_no,
                        "snippet":  snippet + ("..." if len(lines[line_no-1].strip()) > 80 else ""),
                        "weight":   weight,
                    })
                    break
            except re.error:
                continue

    # Verdict logic
    high_risk_cats = {
        "Google API Key", "AWS Access Key", "GitHub Token", "Generic API Key / Token",
        "JWT Token", "Private Key Block", "Password in Text",
        "Prompt Injection Attempt", "Jailbreak Attempt", "XSS / HTML Injection",
        "Command Injection", "Data Leakage Attempt",
        "Configuration / Environment File", "API Endpoint / Internal URL",
        "Infrastructure / DevOps Config", "Compiled / Binary File Content",
    }

    has_high_risk = any(f["category"] in high_risk_cats for f in findings)

    if has_high_risk or total_score >= 40:
        verdict = "BLOCK"
    elif total_score >= 20 or findings:
        verdict = "WARN"
    else:
        verdict = "PASS"

    return {
        "verdict":        verdict,
        "findings":       findings,
        "total_score":    total_score,
        "code_line_count": sum(1 for l in lines if l.strip().startswith(
            ("def ", "class ", "import ", "from ", "const ", "function ", "public "))),
        "category_count": len(findings),
        "blocked":        verdict == "BLOCK",
    }


def check_file_extension(filename: str) -> dict:
    import os
    ext = os.path.splitext(filename.lower())[1]
    base = filename.lower()
    if base in ("dockerfile", "makefile", "jenkinsfile", "vagrantfile", ".env",
                ".gitignore", ".bashrc", ".zshrc"):
        return {"allowed": False, "extension": base,
                "reason": f"'{filename}' is a restricted configuration/build file.",
                "category": "Infrastructure / DevOps Config"}
    if ext in FILE_EXTENSION_BLOCK:
        return {"allowed": False, "extension": ext,
                "reason": f"Files with extension '{ext}' are not permitted.",
                "category": "Restricted File Type"}
    return {"allowed": True, "extension": ext, "reason": "", "category": ""}


def get_dlp_message(result: dict) -> str:
    cats = [f["category"] for f in result["findings"]]

    # Customise message by threat type
    if any(c in ("Prompt Injection Attempt", "Jailbreak Attempt") for c in cats):
        header = "Prompt Injection / Jailbreak Blocked"
        body   = "Your input contains patterns that attempt to override system instructions or bypass security guardrails."
    elif any(c in ("Google API Key", "AWS Access Key", "GitHub Token",
                   "Generic API Key / Token", "JWT Token", "Private Key Block",
                   "Password in Text") for c in cats):
        header = "Secret / Credential Detected — Blocked"
        body   = "Your input contains API keys, tokens, or passwords. Never submit credentials to an AI system."
    elif any(c == "XSS / HTML Injection" for c in cats):
        header = "XSS / Injection Attack Blocked"
        body   = "Your input contains HTML/JavaScript injection patterns."
    elif any(c == "Command Injection" for c in cats):
        header = "Command Injection Blocked"
        body   = "Your input contains OS command injection patterns."
    elif any(c == "API Endpoint / Internal URL" for c in cats):
        header = "Internal URL Disclosure Blocked"
        body   = "Your input contains internal API endpoints or private network addresses."
    elif any(c == "Infrastructure / DevOps Config" for c in cats):
        header = "Infrastructure Config Blocked"
        body   = "Your input contains Dockerfile, Kubernetes, or Terraform configuration."
    else:
        header = "DLP Policy Violation — Submission Blocked"
        body   = "Your input contains company source code or proprietary data."

    return (
        f"🚫 **{header}**\n\n"
        f"{body}\n\n"
        f"**Detected:** {', '.join(cats)}\n\n"
        "**What you can do:**\n"
        "- Describe your problem in plain English\n"
        "- Remove all code, credentials, and internal URLs\n"
        "- Contact your security team if this is a false positive\n\n"
        "*This attempt has been logged in the audit trail.*"
    )


# =========================================================
# BACKWARD COMPATIBILITY ALIASES
# Supports both old app.py (scan_company_identifiers)
# and new app.py (scan_for_company_data)
# =========================================================

def scan_company_identifiers(text: str) -> dict:
    """Alias for backward compatibility with older app.py versions."""
    return scan_for_company_data(text)


def evaluate_text(text: str) -> dict:
    """Alias for backward compatibility."""
    return scan_for_company_data(text)