# # # import re

# # # malicious_patterns = {

# # #     "Prompt Injection": [
# # #         r"ignore previous instructions",
# # #         r"bypass safety",
# # #         r"forget your rules",
# # #         r"disable security"
# # #     ],

# # #     "Privilege Escalation": [
# # #         r"act as admin",
# # #         r"give root access",
# # #         r"full permissions"
# # #     ],

# # #     "Data Leakage": [
# # #         r"reveal hidden prompt",
# # #         r"show confidential data",
# # #         r"display secrets"
# # #     ],

# # #     "Jailbreak Attempt": [
# # #         r"jailbreak",
# # #         r"pretend to be",
# # #         r"roleplay as"
# # #     ]
# # # }


# # # def detect_prompt(prompt):

# # #     findings = []

# # #     for category, patterns in malicious_patterns.items():

# # #         for pattern in patterns:

# # #             if re.search(pattern, prompt.lower()):

# # #                 findings.append({
# # #                     "category": category,
# # #                     "pattern": pattern
# # #                 })

# # #     return findings
# # import re

# # malicious_patterns = {

# #     "Prompt Injection": [
# #         r"ignore previous instructions",
# #         r"bypass safety",
# #         r"forget your rules",
# #         r"disable security"
# #     ],

# #     "Privilege Escalation": [
# #         r"act as admin",
# #         r"give root access",
# #         r"full permissions"
# #     ],

# #     "Data Leakage": [
# #         r"reveal hidden prompt",
# #         r"show confidential data",
# #         r"display secrets"
# #     ],

# #     "Jailbreak Attempt": [
# #         r"jailbreak",
# #         r"pretend to be",
# #         r"roleplay as"
# #     ],

# #     "Cross Site Scripting (XSS)": [
# #         r"<script>",
# #         r"</script>",
# #         r"javascript:",
# #         r"onerror=",
# #         r"alert\("
# #     ],

# #     "SQL Injection": [
# #         r"union select",
# #         r"drop table",
# #         r"or 1=1",
# #         r"'--",
# #         r"insert into",
# #         r"delete from"
# #     ],

# #     "Command Injection": [
# #         r"cmd.exe",
# #         r"/bin/bash",
# #         r"powershell",
# #         r"whoami",
# #         r"nc -e"
# #     ]
# # }


# # def detect_prompt(prompt):

# #     findings = []

# #     for category, patterns in malicious_patterns.items():

# #         for pattern in patterns:

# #             if re.search(pattern, prompt.lower()):

# #                 findings.append({
# #                     "category": category,
# #                     "pattern": pattern
# #                 })

# #     return findings
# import re

# malicious_patterns = {

#     # =========================
#     # PROMPT INJECTION
#     # =========================
#     "Prompt Injection": [
#         r"ignore previous instructions",
#         r"bypass safety",
#         r"forget your rules",
#         r"disable security",
#         r"system override",
#         r"reveal prompt",
#         r"developer mode"
#     ],

#     # =========================
#     # JAILBREAK
#     # =========================
#     "Jailbreak Attempt": [
#         r"jailbreak",
#         r"pretend to be",
#         r"roleplay as",
#         r"unrestricted ai",
#         r"dan mode",
#         r"evil mode"
#     ],

#     # =========================
#     # PRIVILEGE ESCALATION
#     # =========================
#     "Privilege Escalation": [
#         r"act as admin",
#         r"give root access",
#         r"full permissions",
#         r"sudo su",
#         r"administrator access"
#     ],

#     # =========================
#     # DATA LEAKAGE
#     # =========================
#     "Data Leakage": [
#         r"show confidential data",
#         r"display secrets",
#         r"reveal hidden prompt",
#         r"show api key",
#         r"access tokens"
#     ],

#     # =========================
#     # XSS
#     # =========================
#     "Cross Site Scripting (XSS)": [
#         r"<script>",
#         r"</script>",
#         r"javascript:",
#         r"onerror=",
#         r"onload=",
#         r"alert\(",
#         r"document.cookie",
#         r"<iframe",
#         r"<svg",
#         r"eval\(",
#         r"innerhtml"
#     ],

#     # =========================
#     # CSRF
#     # =========================
#     "Cross Site Request Forgery (CSRF)": [
#         r"<form",
#         r"method=['\"]post['\"]",
#         r"document.forms",
#         r"csrf",
#         r"hidden",
#         r"submit\(",
#         r"action="
#     ],

#     # =========================
#     # SQL INJECTION
#     # =========================
#     "SQL Injection": [
#         r"union select",
#         r"drop table",
#         r"or 1=1",
#         r"'--",
#         r"insert into",
#         r"delete from",
#         r"update users",
#         r"select \* from",
#         r"xp_cmdshell"
#     ],

#     # =========================
#     # COMMAND INJECTION
#     # =========================
#     "Command Injection": [
#         r"cmd.exe",
#         r"/bin/bash",
#         r"powershell",
#         r"whoami",
#         r"nc -e",
#         r"bash -i",
#         r"net user",
#         r"chmod 777",
#         r"curl http",
#         r"wget http"
#     ],

#     # =========================
#     # PATH TRAVERSAL
#     # =========================
#     "Path Traversal": [
#         r"\.\./",
#         r"\.\.\\",
#         r"/etc/passwd",
#         r"boot.ini",
#         r"system32"
#     ],

#     # =========================
#     # SSRF
#     # =========================
#     "Server Side Request Forgery (SSRF)": [
#         r"127\.0\.0\.1",
#         r"localhost",
#         r"metadata.google.internal",
#         r"169\.254\.169\.254",
#         r"file://",
#         r"gopher://"
#     ],

#     # =========================
#     # XXE
#     # =========================
#     "XML External Entity (XXE)": [
#         r"<!DOCTYPE",
#         r"<!ENTITY",
#         r"SYSTEM",
#         r"file:///"
#     ],

#     # =========================
#     # SSTI
#     # =========================
#     "Server Side Template Injection (SSTI)": [
#         r"\{\{.*\}\}",
#         r"\$\{.*\}",
#         r"<%.*%>",
#         r"#{.*}"
#     ],

#     # =========================
#     # LDAP Injection
#     # =========================
#     "LDAP Injection": [
#         r"\*\)\(",
#         r"\|\(",
#         r"&\(",
#         r"uid=",
#         r"cn="
#     ]
# }


# def detect_prompt(prompt):

#     findings = []

#     for category, patterns in malicious_patterns.items():

#         for pattern in patterns:

#             if re.search(pattern, prompt.lower()):

#                 findings.append({
#                     "category": category,
#                     "pattern": pattern
#                 })

#     return findings
import re

# =========================================================
# MALICIOUS PATTERN DATABASE
# =========================================================

malicious_patterns = {

    # =====================================================
    # PROMPT INJECTION
    # =====================================================

    "Prompt Injection": [

        r"ignore previous instructions",
        r"bypass safety",
        r"forget your rules",
        r"disable security",
        r"system override",
        r"reveal prompt",
        r"developer mode",
        r"ignore all safeguards",
        r"ignore policy",
        r"jailbreak system"

    ],

    # =====================================================
    # JAILBREAK ATTEMPTS
    # =====================================================

    "Jailbreak Attempt": [

        r"jailbreak",
        r"pretend to be",
        r"roleplay as",
        r"unrestricted ai",
        r"dan mode",
        r"evil mode",
        r"no restrictions",
        r"break ethical rules",
        r"disable moderation"

    ],

    # =====================================================
    # PRIVILEGE ESCALATION
    # =====================================================

    "Privilege Escalation": [

        r"act as admin",
        r"give root access",
        r"full permissions",
        r"sudo su",
        r"administrator access",
        r"elevated privileges",
        r"gain admin access"

    ],

    # =====================================================
    # DATA LEAKAGE
    # =====================================================

    "Data Leakage": [

        r"show confidential data",
        r"display secrets",
        r"reveal hidden prompt",
        r"show api key",
        r"access tokens",
        r"dump database",
        r"show credentials",
        r"export secrets"

    ],

    # =====================================================
    # CROSS SITE SCRIPTING (XSS)
    # =====================================================

    "Cross Site Scripting (XSS)": [

        r"<script>",
        r"</script>",
        r"javascript:",
        r"onerror=",
        r"onload=",
        r"alert\(",
        r"document.cookie",
        r"<iframe",
        r"<svg",
        r"eval\(",
        r"innerhtml",

        # ADVANCED JAVASCRIPT ATTACKS
        r"xmlhttprequest",
        r"fetch\(",
        r"localstorage",
        r"sessionstorage",
        r"csrf-token",
        r"beacon",
        r"window\.location",
        r"document\.write",
        r"settimeout\(",
        r"setinterval\("

    ],

    # =====================================================
    # CSRF
    # =====================================================

    "Cross Site Request Forgery (CSRF)": [

        r"<form",
        r"method=['\"]post['\"]",
        r"document.forms",
        r"csrf",
        r"csrf-token",
        r"hidden",
        r"submit\(",
        r"action=",
        r"xmlhttprequest",
        r"fetch\(",
        r"credentials:",
        r"same-origin"

    ],

    # =====================================================
    # SQL INJECTION
    # =====================================================

    "SQL Injection": [

        r"union select",
        r"drop table",
        r"or 1=1",
        r"'--",
        r"insert into",
        r"delete from",
        r"update users",
        r"select \* from",
        r"xp_cmdshell",
        r"information_schema",
        r"sleep\(",
        r"benchmark\("

    ],

    # =====================================================
    # COMMAND INJECTION
    # =====================================================

    "Command Injection": [

        r"cmd.exe",
        r"/bin/bash",
        r"powershell",
        r"whoami",
        r"nc -e",
        r"bash -i",
        r"net user",
        r"chmod 777",
        r"curl http",
        r"wget http",
        r"rm -rf",
        r"ping -c"

    ],

    # =====================================================
    # PATH TRAVERSAL
    # =====================================================

    "Path Traversal": [

        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"boot.ini",
        r"system32",
        r"win.ini"

    ],

    # =====================================================
    # SSRF
    # =====================================================

    "Server Side Request Forgery (SSRF)": [

        r"127\.0\.0\.1",
        r"localhost",
        r"metadata.google.internal",
        r"169\.254\.169\.254",
        r"file://",
        r"gopher://",
        r"internal-api"

    ],

    # =====================================================
    # XXE
    # =====================================================

    "XML External Entity (XXE)": [

        r"<!DOCTYPE",
        r"<!ENTITY",
        r"SYSTEM",
        r"file:///",
        r"PUBLIC"

    ],

    # =====================================================
    # SSTI
    # =====================================================

    "Server Side Template Injection (SSTI)": [

        r"\{\{.*\}\}",
        r"\$\{.*\}",
        r"<%.*%>",
        r"#\{.*\}"

    ],

    # =====================================================
    # LDAP INJECTION
    # =====================================================

    "LDAP Injection": [

        r"\*\)\(",
        r"\|\(",
        r"&\(",
        r"uid=",
        r"cn="

    ]

}

# =========================================================
# DETECTION ENGINE
# =========================================================

def detect_prompt(prompt):

    findings = []

    lower_prompt = prompt.lower()

    for category, patterns in malicious_patterns.items():

        for pattern in patterns:

            if re.search(pattern, lower_prompt):

                findings.append({

                    "category": category,
                    "pattern": pattern

                })

    return findings