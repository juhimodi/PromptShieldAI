# # # # # import google.generativeai as genai

# # # # # # ============================================
# # # # # # CONFIGURE GEMINI API
# # # # # # ============================================

# # # # # API_KEY = "AIzaSyBetiTuQgi9NUadNkVFQfYP_XFSn0NDF1U"

# # # # # genai.configure(api_key=API_KEY)

# # # # # model = genai.GenerativeModel("gemini-1.5-flash")

# # # # # # ============================================
# # # # # # AI CHAT FUNCTION
# # # # # # ============================================

# # # # # def ask_ai(question):

# # # # #     cybersecurity_prompt = f"""
# # # # # You are an expert SOC Analyst and Cybersecurity AI Assistant.

# # # # # Answer cybersecurity questions professionally.

# # # # # Question:
# # # # # {question}

# # # # # Provide:
# # # # # - explanation
# # # # # - risks
# # # # # - attack flow
# # # # # - mitigation
# # # # # - best practices

# # # # # Keep response concise and professional.
# # # # # """

# # # # #     response = model.generate_content(cybersecurity_prompt)

# # # # #     return response.text
# # # # import google.generativeai as genai

# # # # # ==========================================
# # # # # CONFIGURE GEMINI API
# # # # # ==========================================

# # # # genai.configure(
# # # #     api_key="AIzaSyBetiTuQgi9NUadNkVFQfYP_XFSn0NDF1U"
# # # # )

# # # # # ==========================================
# # # # # LOAD MODEL
# # # # # ==========================================

# # # # model = genai.GenerativeModel("gemini-1.5-flash")

# # # # # ==========================================
# # # # # ASK AI FUNCTION
# # # # # ==========================================

# # # # def ask_ai(question):

# # # #     try:

# # # #         response = model.generate_content(question)

# # # #         return response.text

# # # #     except Exception as e:

# # # #         return f"Gemini Error: {e}"
# # # import os
# # # import time
# # # from google import genai
# # # from google.genai import types

# # # _API_KEY = os.getenv("GEMINI_API_KEY", "")
# # # _client  = genai.Client(api_key=_API_KEY) if _API_KEY else None

# # # _SYSTEM_PROMPT = (
# # #     "You are an expert SOC Analyst and Cybersecurity AI Assistant. "
# # #     "Answer questions about cybersecurity threats professionally and concisely. "
# # #     "Structure your answer with: a brief explanation, the key risks, "
# # #     "and 2-3 recommended mitigations. "
# # #     "If the question is unrelated to cybersecurity, politely redirect the user."
# # # )

# # # _STATIC_ANSWERS = {
# # #     "kali": (
# # #         "**Kali Linux**\n\nKali is a Debian-based distro built for penetration testing "
# # #         "and digital forensics, maintained by Offensive Security.\n\n"
# # #         "**Key Tools:** Metasploit, Nmap, Burp Suite, Wireshark, Aircrack-ng.\n\n"
# # #         "**Mitigations (defender side):**\n"
# # #         "- Patch systems regularly to reduce attack surface\n"
# # #         "- Monitor for port scans and recon activity in your SIEM\n"
# # #         "- Use network segmentation to limit blast radius"
# # #     ),
# # #     "xss": (
# # #         "**Cross-Site Scripting (XSS)**\n\nInjects malicious scripts into pages viewed by users.\n\n"
# # #         "**Key Risks:** Session hijacking, credential theft, malware delivery.\n\n"
# # #         "**Mitigations:**\n"
# # #         "- Encode all user output (HTML entities)\n"
# # #         "- Implement a strict Content Security Policy (CSP)\n"
# # #         "- Use HttpOnly + Secure cookie flags"
# # #     ),
# # #     "sql injection": (
# # #         "**SQL Injection**\n\nMalicious SQL inserted into input fields to manipulate queries.\n\n"
# # #         "**Key Risks:** Data exfiltration, auth bypass, data destruction.\n\n"
# # #         "**Mitigations:**\n"
# # #         "- Parameterized queries / prepared statements\n"
# # #         "- Least-privilege DB accounts\n"
# # #         "- WAF with SQL injection ruleset"
# # #     ),
# # #     "prompt injection": (
# # #         "**Prompt Injection**\n\nOverrides LLM system instructions via crafted user input.\n\n"
# # #         "**Key Risks:** Data leakage, policy bypass, unauthorized actions.\n\n"
# # #         "**Mitigations:**\n"
# # #         "- Input guardrails (like PromptShield)\n"
# # #         "- Privilege separation — LLM must not have direct system access\n"
# # #         "- Output filtering and logging"
# # #     ),
# # #     "jailbreak": (
# # #         "**Jailbreak Attacks**\n\nBypass LLM safety training via roleplay or social engineering.\n\n"
# # #         "**Key Risks:** Harmful output, policy violation, reputational damage.\n\n"
# # #         "**Mitigations:**\n"
# # #         "- Pattern-based detection for known jailbreak phrases\n"
# # #         "- Output content moderation layer\n"
# # #         "- Audit all LLM interactions"
# # #     ),
# # #     "firewall": (
# # #         "**Firewalls**\n\nControl network traffic based on rules.\n\n"
# # #         "**Key Risks without one:** Unauthorized access, lateral movement, data exfiltration.\n\n"
# # #         "**Mitigations:**\n"
# # #         "- Deploy network + host-based firewalls\n"
# # #         "- Use WAF for HTTP/S traffic\n"
# # #         "- Audit firewall rules quarterly"
# # #     ),
# # # }


# # # def _static_fallback(question: str) -> str | None:
# # #     q = question.lower()
# # #     for keyword, answer in _STATIC_ANSWERS.items():
# # #         if keyword in q:
# # #             return answer + "\n\n*⚠ Offline answer — Gemini quota reached. Try again shortly.*"
# # #     return None


# # # def ask_ai(question: str, retries: int = 2) -> str:
# # #     if not _client:
# # #         return (
# # #             "⚠ **Gemini API key not configured.**\n\n"
# # #             "In your PowerShell terminal run:\n"
# # #             "```powershell\n"
# # #             '$env:GEMINI_API_KEY="your-key-here"\n'
# # #             "python -m streamlit run app.py\n"
# # #             "```"
# # #         )

# # #     for attempt in range(retries + 1):
# # #         try:
# # #             response = _client.models.generate_content(
# # #                 model="gemini-2.0-flash",
# # #                 contents=f"{_SYSTEM_PROMPT}\n\nQuestion: {question}",
# # #             )
# # #             return response.text.strip()

# # #         except Exception as e:
# # #             err = str(e)
# # #             if "429" in err or "quota" in err.lower() or "rate" in err.lower():
# # #                 if attempt < retries:
# # #                     time.sleep((attempt + 1) * 12)
# # #                     continue
# # #                 static = _static_fallback(question)
# # #                 if static:
# # #                     return static
# # #                 return (
# # #                     "⏳ **Gemini API quota reached.**\n\n"
# # #                     "- Wait a few minutes and try again\n"
# # #                     "- Or get a new key at https://aistudio.google.com/app/apikey"
# # #                 )
# # #             return f"⚠ AI Error: {err}"

# # #     return "⚠ Could not get a response after retries. Please try again."
# # import os
# # import time
# # from google import genai
# # from google.genai import types

# # _API_KEY = os.getenv("GEMINI_API_KEY", "")
# # _client  = genai.Client(api_key=_API_KEY) if _API_KEY else None

# # _SYSTEM_PROMPT = (
# #     "You are an expert SOC Analyst and Cybersecurity AI Assistant. "
# #     "Answer questions about cybersecurity threats professionally and concisely. "
# #     "Structure your answer with: a brief explanation, the key risks, "
# #     "and 2-3 recommended mitigations. "
# #     "If the question is unrelated to cybersecurity, politely redirect the user."
# # )

# # _STATIC_ANSWERS = {
# #     "kali": (
# #         "**Kali Linux**\n\nKali is a Debian-based distro built for penetration testing "
# #         "and digital forensics, maintained by Offensive Security.\n\n"
# #         "**Key Tools:** Metasploit, Nmap, Burp Suite, Wireshark, Aircrack-ng.\n\n"
# #         "**Mitigations (defender side):**\n"
# #         "- Patch systems regularly to reduce attack surface\n"
# #         "- Monitor for port scans and recon activity in your SIEM\n"
# #         "- Use network segmentation to limit blast radius"
# #     ),
# #     "xss": (
# #         "**Cross-Site Scripting (XSS)**\n\nInjects malicious scripts into pages viewed by users.\n\n"
# #         "**Key Risks:** Session hijacking, credential theft, malware delivery.\n\n"
# #         "**Mitigations:**\n"
# #         "- Encode all user output (HTML entities)\n"
# #         "- Implement a strict Content Security Policy (CSP)\n"
# #         "- Use HttpOnly + Secure cookie flags"
# #     ),
# #     "sql injection": (
# #         "**SQL Injection**\n\nMalicious SQL inserted into input fields to manipulate queries.\n\n"
# #         "**Key Risks:** Data exfiltration, auth bypass, data destruction.\n\n"
# #         "**Mitigations:**\n"
# #         "- Parameterized queries / prepared statements\n"
# #         "- Least-privilege DB accounts\n"
# #         "- WAF with SQL injection ruleset"
# #     ),
# #     "prompt injection": (
# #         "**Prompt Injection**\n\nOverrides LLM system instructions via crafted user input.\n\n"
# #         "**Key Risks:** Data leakage, policy bypass, unauthorized actions.\n\n"
# #         "**Mitigations:**\n"
# #         "- Input guardrails (like PromptShield)\n"
# #         "- Privilege separation — LLM must not have direct system access\n"
# #         "- Output filtering and logging"
# #     ),
# #     "jailbreak": (
# #         "**Jailbreak Attacks**\n\nBypass LLM safety training via roleplay or social engineering.\n\n"
# #         "**Key Risks:** Harmful output, policy violation, reputational damage.\n\n"
# #         "**Mitigations:**\n"
# #         "- Pattern-based detection for known jailbreak phrases\n"
# #         "- Output content moderation layer\n"
# #         "- Audit all LLM interactions"
# #     ),
# #     "firewall": (
# #         "**Firewalls**\n\nControl network traffic based on rules.\n\n"
# #         "**Key Risks without one:** Unauthorized access, lateral movement, data exfiltration.\n\n"
# #         "**Mitigations:**\n"
# #         "- Deploy network + host-based firewalls\n"
# #         "- Use WAF for HTTP/S traffic\n"
# #         "- Audit firewall rules quarterly"
# #     ),
# # }


# # def _static_fallback(question: str) -> str | None:
# #     q = question.lower()
# #     for keyword, answer in _STATIC_ANSWERS.items():
# #         if keyword in q:
# #             return answer + "\n\n*⚠ Offline answer — Gemini quota reached. Try again shortly.*"
# #     return None


# # def ask_ai(question: str, retries: int = 2) -> str:
# #     if not _client:
# #         return (
# #             "⚠ **Gemini API key not configured.**\n\n"
# #             "In your PowerShell terminal run:\n"
# #             "```powershell\n"
# #             '$env:GEMINI_API_KEY="your-key-here"\n'
# #             "python -m streamlit run app.py\n"
# #             "```"
# #         )

# #     for attempt in range(retries + 1):
# #         try:
# #             response = _client.models.generate_content(
# #                 model="gemini-2.0-flash",
# #                 contents=f"{_SYSTEM_PROMPT}\n\nQuestion: {question}",
# #             )
# #             return response.text.strip()

# #         except Exception as e:
# #             err = str(e)
# #             if "429" in err or "quota" in err.lower() or "rate" in err.lower():
# #                 if attempt < retries:
# #                     time.sleep((attempt + 1) * 12)
# #                     continue
# #                 static = _static_fallback(question)
# #                 if static:
# #                     return static
# #                 return (
# #                     "⏳ **Gemini API quota reached.**\n\n"
# #                     "- Wait a few minutes and try again\n"
# #                     "- Or get a new key at https://aistudio.google.com/app/apikey"
# #                 )
# #             return f"⚠ AI Error: {err}"

# #     return "⚠ Could not get a response after retries. Please try again."

# import os
# import time
# from google import genai

# _API_KEY = os.getenv("GEMINI_API_KEY", "")
# _client  = genai.Client(api_key=_API_KEY) if _API_KEY else None

# _SYSTEM_PROMPT = (
#     "You are an expert SOC Analyst and Cybersecurity AI Assistant. "
#     "Answer questions about cybersecurity threats professionally and concisely. "
#     "Structure your answer with: a brief explanation, the key risks, "
#     "and 2-3 recommended mitigations. "
#     "If the question is unrelated to cybersecurity, politely redirect the user."
# )

# # =========================================================
# # COMPREHENSIVE STATIC KNOWLEDGE BASE
# # Used when Gemini quota is reached — covers all common topics
# # =========================================================
# _STATIC_ANSWERS = {

#     # Kali Linux
#     "kali": (
#         "**Kali Linux**\n\n"
#         "Kali Linux is a Debian-based distribution built for penetration testing and digital forensics, "
#         "maintained by Offensive Security. It comes pre-loaded with 600+ security tools.\n\n"
#         "**Key Tools:** Metasploit, Nmap, Burp Suite, Wireshark, John the Ripper, Aircrack-ng, Hydra, SQLMap.\n\n"
#         "**Mitigations (defender side):**\n"
#         "- Patch all systems regularly to reduce attack surface\n"
#         "- Monitor for port scans and recon activity in your SIEM\n"
#         "- Use network segmentation to limit blast radius"
#     ),

#     # XSS
#     "xss": (
#         "**Cross-Site Scripting (XSS)**\n\n"
#         "XSS is a web vulnerability where attackers inject malicious scripts into pages viewed by other users. "
#         "It exploits the trust a user has in a website.\n\n"
#         "**Types:** Stored XSS (persisted in DB), Reflected XSS (in URL), DOM-based XSS.\n\n"
#         "**Key Risks:** Session hijacking, credential theft, malware delivery, defacement.\n\n"
#         "**Mitigations:**\n"
#         "- Encode all user output (HTML entity encoding)\n"
#         "- Implement a strict Content Security Policy (CSP)\n"
#         "- Use HttpOnly and Secure cookie flags"
#     ),

#     # SQL Injection
#     "sql injection": (
#         "**SQL Injection (SQLi)**\n\n"
#         "SQL injection occurs when an attacker inserts malicious SQL code into input fields, "
#         "manipulating the database query logic.\n\n"
#         "**Key Risks:** Data exfiltration, authentication bypass, data destruction, server compromise.\n\n"
#         "**Mitigations:**\n"
#         "- Use parameterized queries / prepared statements (never string concatenation)\n"
#         "- Apply least-privilege DB accounts\n"
#         "- Deploy a WAF with SQL injection ruleset"
#     ),

#     # Prompt Injection
#     "prompt injection": (
#         "**Prompt Injection**\n\n"
#         "Prompt injection is an attack where malicious user input overrides an LLM's system instructions, "
#         "hijacking its behavior. It's the AI equivalent of SQL injection.\n\n"
#         "**Key Risks:** Data leakage, policy bypass, unauthorized LLM actions, jailbreaking.\n\n"
#         "**Mitigations:**\n"
#         "- Input guardrails that scan prompts before they reach the LLM (like PromptShield)\n"
#         "- Privilege separation — LLM must not have direct system/DB access\n"
#         "- Output filtering and comprehensive audit logging"
#     ),

#     # Jailbreak
#     "jailbreak": (
#         "**LLM Jailbreak Attacks**\n\n"
#         "Jailbreaks bypass an LLM's safety training using roleplay, fictional framing, "
#         "or social engineering to make it ignore ethical constraints.\n\n"
#         "**Common techniques:** DAN mode, roleplay-as-evil-AI, hypothetical framing, token smuggling.\n\n"
#         "**Key Risks:** Harmful content generation, policy violation, data leakage, reputational damage.\n\n"
#         "**Mitigations:**\n"
#         "- Pattern-based detection for known jailbreak phrases\n"
#         "- Output content moderation layer in addition to input filtering\n"
#         "- Audit all LLM interactions with anomaly detection"
#     ),

#     # DLP
#     "dlp": (
#         "**Data Loss Prevention (DLP)**\n\n"
#         "DLP is a set of tools and policies that detect and prevent unauthorized transmission, "
#         "access, or leakage of sensitive data — whether through email, uploads, or AI systems.\n\n"
#         "**Key Capabilities:** PII detection, credential scanning, content inspection, policy enforcement, audit logging.\n\n"
#         "**Key Risks without DLP:** Accidental data leakage, credential exposure, regulatory violations (GDPR, DPDP).\n\n"
#         "**Mitigations:**\n"
#         "- Implement DLP at all data egress points (email, cloud storage, AI inputs)\n"
#         "- Define clear classification policies (Public, Internal, Confidential, Restricted)\n"
#         "- Regularly audit and tune DLP rules to reduce false positives"
#     ),

#     # SSRF
#     "ssrf": (
#         "**Server-Side Request Forgery (SSRF)**\n\n"
#         "SSRF tricks a server into making HTTP requests to internal resources — "
#         "cloud metadata endpoints, internal APIs, or private network services.\n\n"
#         "**Key Risks:** Cloud credential theft (AWS metadata at 169.254.169.254), "
#         "internal network pivoting, data exfiltration.\n\n"
#         "**Mitigations:**\n"
#         "- Allowlist outbound destinations — deny all private IP ranges\n"
#         "- Block access to cloud metadata endpoints at the network level\n"
#         "- Validate and sanitize all user-supplied URLs"
#     ),

#     # Firewall
#     "firewall": (
#         "**Firewalls**\n\n"
#         "Firewalls monitor and control network traffic based on security rules, "
#         "acting as a barrier between trusted and untrusted networks.\n\n"
#         "**Types:** Network firewall, host-based firewall, WAF (Web Application Firewall), NGFW.\n\n"
#         "**Key Risks without one:** Unauthorized access, lateral movement, direct server attacks.\n\n"
#         "**Mitigations:**\n"
#         "- Deploy network + host-based firewalls (defence in depth)\n"
#         "- Use a WAF specifically for HTTP/S application traffic\n"
#         "- Review and audit firewall rules quarterly"
#     ),

#     # Ransomware
#     "ransomware": (
#         "**Ransomware**\n\n"
#         "Ransomware is malware that encrypts victim files and demands payment for decryption. "
#         "Modern ransomware also exfiltrates data before encrypting (double extortion).\n\n"
#         "**Key Risks:** Business disruption, financial loss, data exposure, reputational damage.\n\n"
#         "**Mitigations:**\n"
#         "- Maintain offline backups following the 3-2-1 rule\n"
#         "- Patch and update all systems — most ransomware exploits known CVEs\n"
#         "- Deploy EDR and email filtering — most ransomware enters via phishing"
#     ),

#     # Phishing
#     "phishing": (
#         "**Phishing Attacks**\n\n"
#         "Phishing tricks users into revealing credentials or installing malware via "
#         "deceptive emails, SMS (smishing), or voice calls (vishing).\n\n"
#         "**Key Risks:** Credential theft, malware installation, BEC (Business Email Compromise), financial fraud.\n\n"
#         "**Mitigations:**\n"
#         "- Enable MFA on all accounts — credentials alone aren't enough\n"
#         "- Deploy email filtering with SPF, DKIM, and DMARC\n"
#         "- Run regular phishing simulation training for employees"
#     ),

#     # Zero Day
#     "zero day": (
#         "**Zero-Day Vulnerabilities**\n\n"
#         "A zero-day is a software vulnerability unknown to the vendor, "
#         "meaning no patch exists. Attackers exploit it before defenders can respond.\n\n"
#         "**Key Risks:** Full system compromise, undetectable exploitation, supply chain attacks.\n\n"
#         "**Mitigations:**\n"
#         "- Apply defence-in-depth — assume breach, limit blast radius\n"
#         "- Use behavioural detection (EDR/XDR) rather than signature-based detection only\n"
#         "- Subscribe to threat intelligence feeds for early warning"
#     ),

#     # CVE
#     "cve": (
#         "**CVE — Common Vulnerabilities and Exposures**\n\n"
#         "CVE is a standardised database of publicly disclosed cybersecurity vulnerabilities, "
#         "each assigned a unique ID (e.g. CVE-2024-12345) and a CVSS severity score (0-10).\n\n"
#         "**CVSS Score Ranges:** Critical (9-10), High (7-8.9), Medium (4-6.9), Low (0-3.9).\n\n"
#         "**Best Practices:**\n"
#         "- Subscribe to CVE feeds (NVD, CISA KEV) for your technology stack\n"
#         "- Prioritise patching Critical and High CVEs within 24-72 hours\n"
#         "- Use vulnerability scanners (Nessus, OpenVAS) to track exposure"
#     ),

#     # MITRE ATT&CK
#     "mitre": (
#         "**MITRE ATT&CK Framework**\n\n"
#         "MITRE ATT&CK is a globally accessible knowledge base of adversary tactics, "
#         "techniques, and procedures (TTPs) based on real-world observations.\n\n"
#         "**Structure:** 14 Tactics (e.g. Initial Access, Execution, Persistence, Exfiltration) "
#         "each containing numbered Techniques (T1xxx).\n\n"
#         "**Uses:**\n"
#         "- Map detected threats to known TTPs for context\n"
#         "- Identify detection gaps in your security controls\n"
#         "- Build threat-informed detection rules in your SIEM"
#     ),

#     # SOC
#     "soc": (
#         "**Security Operations Center (SOC)**\n\n"
#         "A SOC is a team of security analysts who monitor, detect, investigate, "
#         "and respond to cybersecurity incidents around the clock.\n\n"
#         "**Key Functions:** SIEM monitoring, incident response, threat hunting, vulnerability management.\n\n"
#         "**SOC Tiers:**\n"
#         "- Tier 1: Alert triage and initial investigation\n"
#         "- Tier 2: Deep-dive incident analysis\n"
#         "- Tier 3: Threat hunting and advanced forensics"
#     ),

#     # SIEM
#     "siem": (
#         "**SIEM — Security Information and Event Management**\n\n"
#         "SIEM aggregates and correlates security logs from across your infrastructure "
#         "to detect threats, generate alerts, and support compliance.\n\n"
#         "**Popular SIEMs:** Splunk, Microsoft Sentinel, IBM QRadar, Elastic SIEM.\n\n"
#         "**Key Capabilities:** Real-time monitoring, correlation rules, dashboards, compliance reporting.\n\n"
#         "**Best Practices:**\n"
#         "- Ensure all critical systems send logs to SIEM\n"
#         "- Build detection rules aligned to MITRE ATT&CK TTPs\n"
#         "- Review and tune rules monthly to reduce alert fatigue"
#     ),

#     # MFA
#     "mfa": (
#         "**Multi-Factor Authentication (MFA)**\n\n"
#         "MFA requires users to verify identity using two or more factors: "
#         "something you know (password), something you have (OTP/token), something you are (biometric).\n\n"
#         "**Key Risks without MFA:** Single credential compromise leads to full account takeover.\n\n"
#         "**Mitigations:**\n"
#         "- Enforce MFA on all privileged accounts and remote access\n"
#         "- Prefer hardware tokens or authenticator apps over SMS OTP\n"
#         "- Implement phishing-resistant MFA (FIDO2/WebAuthn) for critical systems"
#     ),

#     # Penetration Testing
#     "penetration": (
#         "**Penetration Testing (Pen Testing)**\n\n"
#         "Penetration testing is an authorised, simulated cyberattack on a system "
#         "to identify security weaknesses before real attackers do.\n\n"
#         "**Phases:** Reconnaissance → Scanning → Exploitation → Post-Exploitation → Reporting.\n\n"
#         "**Types:** Black box (no prior knowledge), White box (full access), Grey box (partial info).\n\n"
#         "**Best Practices:**\n"
#         "- Conduct pen tests at least annually and after major changes\n"
#         "- Use findings to drive a prioritised remediation plan\n"
#         "- Always get written authorisation before testing"
#     ),

#     # OWASP
#     "owasp": (
#         "**OWASP Top 10**\n\n"
#         "OWASP (Open Web Application Security Project) publishes the Top 10 most critical "
#         "web application security risks, updated every few years.\n\n"
#         "**Current Top 10 (2021):**\n"
#         "1. Broken Access Control\n"
#         "2. Cryptographic Failures\n"
#         "3. Injection (SQLi, XSS, etc.)\n"
#         "4. Insecure Design\n"
#         "5. Security Misconfiguration\n"
#         "6. Vulnerable & Outdated Components\n"
#         "7. Identification & Authentication Failures\n"
#         "8. Software & Data Integrity Failures\n"
#         "9. Security Logging & Monitoring Failures\n"
#         "10. Server-Side Request Forgery (SSRF)"
#     ),

#     # Encryption
#     "encryption": (
#         "**Encryption**\n\n"
#         "Encryption converts plaintext into ciphertext using an algorithm and key, "
#         "making data unreadable without the decryption key.\n\n"
#         "**Types:** Symmetric (AES-256 — same key for encrypt/decrypt), "
#         "Asymmetric (RSA/ECC — public key encrypts, private key decrypts).\n\n"
#         "**Key Risks without encryption:** Data breach exposure, compliance violations, MITM attacks.\n\n"
#         "**Mitigations:**\n"
#         "- Encrypt data at rest (AES-256) and in transit (TLS 1.3)\n"
#         "- Manage keys securely using a KMS (Key Management Service)\n"
#         "- Never store encryption keys alongside the data they protect"
#     ),

#     # IDS/IPS
#     "ids": (
#         "**IDS/IPS — Intrusion Detection/Prevention Systems**\n\n"
#         "IDS monitors network traffic for suspicious activity and alerts; "
#         "IPS goes further and actively blocks detected threats.\n\n"
#         "**Types:** Network-based (NIDS/NIPS), Host-based (HIDS/HIPS), Signature-based, Anomaly-based.\n\n"
#         "**Mitigations:**\n"
#         "- Deploy IPS at network perimeter and between network segments\n"
#         "- Keep signature databases updated daily\n"
#         "- Tune rules to balance detection rate vs false positives"
#     ),

#     # VPN
#     "vpn": (
#         "**Virtual Private Network (VPN)**\n\n"
#         "A VPN creates an encrypted tunnel between a user and a network, "
#         "protecting data in transit and masking the user's real IP address.\n\n"
#         "**Key Risks:** Poorly configured VPNs can become attack vectors (e.g. CVE exploits on VPN appliances).\n\n"
#         "**Mitigations:**\n"
#         "- Keep VPN software patched — VPN CVEs are frequently exploited\n"
#         "- Enforce MFA on VPN access\n"
#         "- Consider Zero Trust Network Access (ZTNA) as a more secure alternative"
#     ),

#     # AWL / company specific
#     "awl": (
#         "⚠️ **Company Name Detected — Blocked by DLP Policy**\n\n"
#         "Your question contains an internal company name or abbreviation (AWL). "
#         "Submitting internal company identifiers to AI systems is restricted by your organisation's "
#         "Data Loss Prevention policy.\n\n"
#         "**Why this is blocked:**\n"
#         "- Company names in AI prompts can be logged and used in model training\n"
#         "- Internal project names can reveal confidential business strategy\n"
#         "- This reduces the risk of competitive intelligence leakage\n\n"
#         "**What to do instead:**\n"
#         "- Rephrase your question without the company name\n"
#         "- Use generic terms: 'our company', 'my organisation', 'the system'\n"
#         "- Contact your security team if you need an exception"
#     ),
# }


# def _static_fallback(question: str) -> str | None:
#     q = question.lower()
#     for keyword, answer in _STATIC_ANSWERS.items():
#         if keyword in q:
#             return answer + "\n\n*ℹ Offline answer — Gemini API quota reached. Try again in a few minutes.*"
#     return None


# def ask_ai(question: str, retries: int = 2) -> str:
#     if not _client:
#         # Still try static fallback even without API key
#         static = _static_fallback(question)
#         if static:
#             return static
#         return (
#             "⚠ **Gemini API key not configured.**\n\n"
#             "Set `GEMINI_API_KEY` environment variable and restart the app.\n"
#             "```powershell\n$env:GEMINI_API_KEY='your-key-here'\npython -m streamlit run app.py\n```"
#         )

#     for attempt in range(retries + 1):
#         try:
#             response = _client.models.generate_content(
#                 model="gemini-2.0-flash",
#                 contents=f"{_SYSTEM_PROMPT}\n\nQuestion: {question}",
#             )
#             return response.text.strip()

#         except Exception as e:
#             err = str(e)

#             if "429" in err or "quota" in err.lower() or "rate" in err.lower():
#                 if attempt < retries:
#                     time.sleep((attempt + 1) * 10)
#                     continue
#                 # Quota exhausted — use static fallback
#                 static = _static_fallback(question)
#                 if static:
#                     return static
#                 return (
#                     "⏳ **Gemini API quota reached.**\n\n"
#                     "**Quick fixes:**\n"
#                     "- Wait 1-2 minutes and try again (per-minute limit)\n"
#                     "- The daily quota resets at midnight\n"
#                     "- Get a new key at https://aistudio.google.com/app/apikey\n\n"
#                     "**Common cybersecurity topics I can answer offline:**\n"
#                     "XSS, SQL Injection, Prompt Injection, Jailbreak, DLP, SSRF, Firewall, "
#                     "Ransomware, Phishing, Zero Day, CVE, MITRE ATT&CK, SOC, SIEM, MFA, "
#                     "Penetration Testing, OWASP, Encryption, IDS/IPS, VPN"
#                 )

#             if "404" in err or "not found" in err.lower():
#                 return (
#                     "⚠ **Model not found.** Check that `chatbot.py` uses `gemini-2.0-flash`."
#                 )

#             if "10051" in err or "unreachable" in err.lower() or "socket" in err.lower():
#                 static = _static_fallback(question)
#                 if static:
#                     return static
#                 return (
#                     "⚠ **Network Error — Cannot reach Gemini API.**\n\n"
#                     "Your network is blocking outbound API requests (WinError 10051).\n\n"
#                     "**Solutions:**\n"
#                     "- Switch to mobile hotspot\n"
#                     "- Use a VPN\n"
#                     "- Check if your network blocks google APIs\n\n"
#                     "**I can still answer these topics offline:** XSS, SQL Injection, "
#                     "Prompt Injection, DLP, SSRF, Firewall, Ransomware, Phishing, "
#                     "CVE, MITRE ATT&CK, SOC, SIEM, MFA, OWASP, Encryption, VPN"
#                 )

#             return f"⚠ AI Error: {err}"

#     return "⚠ Could not get a response. Please try again."

import os
import time
from google import genai

_API_KEY = os.getenv("GEMINI_API_KEY", "")
_client  = genai.Client(api_key=_API_KEY) if _API_KEY else None

_SYSTEM_PROMPT = (
    "You are an expert SOC Analyst and Cybersecurity AI Assistant. "
    "Answer questions about cybersecurity threats professionally and concisely. "
    "Structure your answer with: a brief explanation, the key risks, "
    "and 2-3 recommended mitigations. "
    "If the question is unrelated to cybersecurity, politely redirect the user."
)

# =========================================================
# COMPREHENSIVE STATIC KNOWLEDGE BASE
# Used when Gemini quota is reached — covers all common topics
# =========================================================
_STATIC_ANSWERS = {

    # Kali Linux
    "kali": (
        "**Kali Linux**\n\n"
        "Kali Linux is a Debian-based distribution built for penetration testing and digital forensics, "
        "maintained by Offensive Security. It comes pre-loaded with 600+ security tools.\n\n"
        "**Key Tools:** Metasploit, Nmap, Burp Suite, Wireshark, John the Ripper, Aircrack-ng, Hydra, SQLMap.\n\n"
        "**Mitigations (defender side):**\n"
        "- Patch all systems regularly to reduce attack surface\n"
        "- Monitor for port scans and recon activity in your SIEM\n"
        "- Use network segmentation to limit blast radius"
    ),

    # XSS
    "xss": (
        "**Cross-Site Scripting (XSS)**\n\n"
        "XSS is a web vulnerability where attackers inject malicious scripts into pages viewed by other users. "
        "It exploits the trust a user has in a website.\n\n"
        "**Types:** Stored XSS (persisted in DB), Reflected XSS (in URL), DOM-based XSS.\n\n"
        "**Key Risks:** Session hijacking, credential theft, malware delivery, defacement.\n\n"
        "**Mitigations:**\n"
        "- Encode all user output (HTML entity encoding)\n"
        "- Implement a strict Content Security Policy (CSP)\n"
        "- Use HttpOnly and Secure cookie flags"
    ),

    # SQL Injection
    "sql injection": (
        "**SQL Injection (SQLi)**\n\n"
        "SQL injection occurs when an attacker inserts malicious SQL code into input fields, "
        "manipulating the database query logic.\n\n"
        "**Key Risks:** Data exfiltration, authentication bypass, data destruction, server compromise.\n\n"
        "**Mitigations:**\n"
        "- Use parameterized queries / prepared statements (never string concatenation)\n"
        "- Apply least-privilege DB accounts\n"
        "- Deploy a WAF with SQL injection ruleset"
    ),

    # Prompt Injection
    "prompt injection": (
        "**Prompt Injection**\n\n"
        "Prompt injection is an attack where malicious user input overrides an LLM's system instructions, "
        "hijacking its behavior. It's the AI equivalent of SQL injection.\n\n"
        "**Key Risks:** Data leakage, policy bypass, unauthorized LLM actions, jailbreaking.\n\n"
        "**Mitigations:**\n"
        "- Input guardrails that scan prompts before they reach the LLM (like PromptShield)\n"
        "- Privilege separation — LLM must not have direct system/DB access\n"
        "- Output filtering and comprehensive audit logging"
    ),

    # Jailbreak
    "jailbreak": (
        "**LLM Jailbreak Attacks**\n\n"
        "Jailbreaks bypass an LLM's safety training using roleplay, fictional framing, "
        "or social engineering to make it ignore ethical constraints.\n\n"
        "**Common techniques:** DAN mode, roleplay-as-evil-AI, hypothetical framing, token smuggling.\n\n"
        "**Key Risks:** Harmful content generation, policy violation, data leakage, reputational damage.\n\n"
        "**Mitigations:**\n"
        "- Pattern-based detection for known jailbreak phrases\n"
        "- Output content moderation layer in addition to input filtering\n"
        "- Audit all LLM interactions with anomaly detection"
    ),

    # DLP
    "dlp": (
        "**Data Loss Prevention (DLP)**\n\n"
        "DLP is a set of tools and policies that detect and prevent unauthorized transmission, "
        "access, or leakage of sensitive data — whether through email, uploads, or AI systems.\n\n"
        "**Key Capabilities:** PII detection, credential scanning, content inspection, policy enforcement, audit logging.\n\n"
        "**Key Risks without DLP:** Accidental data leakage, credential exposure, regulatory violations (GDPR, DPDP).\n\n"
        "**Mitigations:**\n"
        "- Implement DLP at all data egress points (email, cloud storage, AI inputs)\n"
        "- Define clear classification policies (Public, Internal, Confidential, Restricted)\n"
        "- Regularly audit and tune DLP rules to reduce false positives"
    ),

    # SSRF
    "ssrf": (
        "**Server-Side Request Forgery (SSRF)**\n\n"
        "SSRF tricks a server into making HTTP requests to internal resources — "
        "cloud metadata endpoints, internal APIs, or private network services.\n\n"
        "**Key Risks:** Cloud credential theft (AWS metadata at 169.254.169.254), "
        "internal network pivoting, data exfiltration.\n\n"
        "**Mitigations:**\n"
        "- Allowlist outbound destinations — deny all private IP ranges\n"
        "- Block access to cloud metadata endpoints at the network level\n"
        "- Validate and sanitize all user-supplied URLs"
    ),

    # Firewall
    "firewall": (
        "**Firewalls**\n\n"
        "Firewalls monitor and control network traffic based on security rules, "
        "acting as a barrier between trusted and untrusted networks.\n\n"
        "**Types:** Network firewall, host-based firewall, WAF (Web Application Firewall), NGFW.\n\n"
        "**Key Risks without one:** Unauthorized access, lateral movement, direct server attacks.\n\n"
        "**Mitigations:**\n"
        "- Deploy network + host-based firewalls (defence in depth)\n"
        "- Use a WAF specifically for HTTP/S application traffic\n"
        "- Review and audit firewall rules quarterly"
    ),

    # Ransomware
    "ransomware": (
        "**Ransomware**\n\n"
        "Ransomware is malware that encrypts victim files and demands payment for decryption. "
        "Modern ransomware also exfiltrates data before encrypting (double extortion).\n\n"
        "**Key Risks:** Business disruption, financial loss, data exposure, reputational damage.\n\n"
        "**Mitigations:**\n"
        "- Maintain offline backups following the 3-2-1 rule\n"
        "- Patch and update all systems — most ransomware exploits known CVEs\n"
        "- Deploy EDR and email filtering — most ransomware enters via phishing"
    ),

    # Phishing
    "phishing": (
        "**Phishing Attacks**\n\n"
        "Phishing tricks users into revealing credentials or installing malware via "
        "deceptive emails, SMS (smishing), or voice calls (vishing).\n\n"
        "**Key Risks:** Credential theft, malware installation, BEC (Business Email Compromise), financial fraud.\n\n"
        "**Mitigations:**\n"
        "- Enable MFA on all accounts — credentials alone aren't enough\n"
        "- Deploy email filtering with SPF, DKIM, and DMARC\n"
        "- Run regular phishing simulation training for employees"
    ),

    # Zero Day
    "zero day": (
        "**Zero-Day Vulnerabilities**\n\n"
        "A zero-day is a software vulnerability unknown to the vendor, "
        "meaning no patch exists. Attackers exploit it before defenders can respond.\n\n"
        "**Key Risks:** Full system compromise, undetectable exploitation, supply chain attacks.\n\n"
        "**Mitigations:**\n"
        "- Apply defence-in-depth — assume breach, limit blast radius\n"
        "- Use behavioural detection (EDR/XDR) rather than signature-based detection only\n"
        "- Subscribe to threat intelligence feeds for early warning"
    ),

    # CVE
    "cve": (
        "**CVE — Common Vulnerabilities and Exposures**\n\n"
        "CVE is a standardised database of publicly disclosed cybersecurity vulnerabilities, "
        "each assigned a unique ID (e.g. CVE-2024-12345) and a CVSS severity score (0-10).\n\n"
        "**CVSS Score Ranges:** Critical (9-10), High (7-8.9), Medium (4-6.9), Low (0-3.9).\n\n"
        "**Best Practices:**\n"
        "- Subscribe to CVE feeds (NVD, CISA KEV) for your technology stack\n"
        "- Prioritise patching Critical and High CVEs within 24-72 hours\n"
        "- Use vulnerability scanners (Nessus, OpenVAS) to track exposure"
    ),

    # MITRE ATT&CK
    "mitre": (
        "**MITRE ATT&CK Framework**\n\n"
        "MITRE ATT&CK is a globally accessible knowledge base of adversary tactics, "
        "techniques, and procedures (TTPs) based on real-world observations.\n\n"
        "**Structure:** 14 Tactics (e.g. Initial Access, Execution, Persistence, Exfiltration) "
        "each containing numbered Techniques (T1xxx).\n\n"
        "**Uses:**\n"
        "- Map detected threats to known TTPs for context\n"
        "- Identify detection gaps in your security controls\n"
        "- Build threat-informed detection rules in your SIEM"
    ),

    # SOC
    "soc": (
        "**Security Operations Center (SOC)**\n\n"
        "A SOC is a team of security analysts who monitor, detect, investigate, "
        "and respond to cybersecurity incidents around the clock.\n\n"
        "**Key Functions:** SIEM monitoring, incident response, threat hunting, vulnerability management.\n\n"
        "**SOC Tiers:**\n"
        "- Tier 1: Alert triage and initial investigation\n"
        "- Tier 2: Deep-dive incident analysis\n"
        "- Tier 3: Threat hunting and advanced forensics"
    ),

    # SIEM
    "siem": (
        "**SIEM — Security Information and Event Management**\n\n"
        "SIEM aggregates and correlates security logs from across your infrastructure "
        "to detect threats, generate alerts, and support compliance.\n\n"
        "**Popular SIEMs:** Splunk, Microsoft Sentinel, IBM QRadar, Elastic SIEM.\n\n"
        "**Key Capabilities:** Real-time monitoring, correlation rules, dashboards, compliance reporting.\n\n"
        "**Best Practices:**\n"
        "- Ensure all critical systems send logs to SIEM\n"
        "- Build detection rules aligned to MITRE ATT&CK TTPs\n"
        "- Review and tune rules monthly to reduce alert fatigue"
    ),

    # MFA
    "mfa": (
        "**Multi-Factor Authentication (MFA)**\n\n"
        "MFA requires users to verify identity using two or more factors: "
        "something you know (password), something you have (OTP/token), something you are (biometric).\n\n"
        "**Key Risks without MFA:** Single credential compromise leads to full account takeover.\n\n"
        "**Mitigations:**\n"
        "- Enforce MFA on all privileged accounts and remote access\n"
        "- Prefer hardware tokens or authenticator apps over SMS OTP\n"
        "- Implement phishing-resistant MFA (FIDO2/WebAuthn) for critical systems"
    ),

    # Penetration Testing
    "penetration": (
        "**Penetration Testing (Pen Testing)**\n\n"
        "Penetration testing is an authorised, simulated cyberattack on a system "
        "to identify security weaknesses before real attackers do.\n\n"
        "**Phases:** Reconnaissance → Scanning → Exploitation → Post-Exploitation → Reporting.\n\n"
        "**Types:** Black box (no prior knowledge), White box (full access), Grey box (partial info).\n\n"
        "**Best Practices:**\n"
        "- Conduct pen tests at least annually and after major changes\n"
        "- Use findings to drive a prioritised remediation plan\n"
        "- Always get written authorisation before testing"
    ),

    # OWASP
    "owasp": (
        "**OWASP Top 10**\n\n"
        "OWASP (Open Web Application Security Project) publishes the Top 10 most critical "
        "web application security risks, updated every few years.\n\n"
        "**Current Top 10 (2021):**\n"
        "1. Broken Access Control\n"
        "2. Cryptographic Failures\n"
        "3. Injection (SQLi, XSS, etc.)\n"
        "4. Insecure Design\n"
        "5. Security Misconfiguration\n"
        "6. Vulnerable & Outdated Components\n"
        "7. Identification & Authentication Failures\n"
        "8. Software & Data Integrity Failures\n"
        "9. Security Logging & Monitoring Failures\n"
        "10. Server-Side Request Forgery (SSRF)"
    ),

    # Encryption
    "encryption": (
        "**Encryption**\n\n"
        "Encryption converts plaintext into ciphertext using an algorithm and key, "
        "making data unreadable without the decryption key.\n\n"
        "**Types:** Symmetric (AES-256 — same key for encrypt/decrypt), "
        "Asymmetric (RSA/ECC — public key encrypts, private key decrypts).\n\n"
        "**Key Risks without encryption:** Data breach exposure, compliance violations, MITM attacks.\n\n"
        "**Mitigations:**\n"
        "- Encrypt data at rest (AES-256) and in transit (TLS 1.3)\n"
        "- Manage keys securely using a KMS (Key Management Service)\n"
        "- Never store encryption keys alongside the data they protect"
    ),

    # IDS/IPS
    "ids": (
        "**IDS/IPS — Intrusion Detection/Prevention Systems**\n\n"
        "IDS monitors network traffic for suspicious activity and alerts; "
        "IPS goes further and actively blocks detected threats.\n\n"
        "**Types:** Network-based (NIDS/NIPS), Host-based (HIDS/HIPS), Signature-based, Anomaly-based.\n\n"
        "**Mitigations:**\n"
        "- Deploy IPS at network perimeter and between network segments\n"
        "- Keep signature databases updated daily\n"
        "- Tune rules to balance detection rate vs false positives"
    ),

    # VPN
    "vpn": (
        "**Virtual Private Network (VPN)**\n\n"
        "A VPN creates an encrypted tunnel between a user and a network, "
        "protecting data in transit and masking the user's real IP address.\n\n"
        "**Key Risks:** Poorly configured VPNs can become attack vectors (e.g. CVE exploits on VPN appliances).\n\n"
        "**Mitigations:**\n"
        "- Keep VPN software patched — VPN CVEs are frequently exploited\n"
        "- Enforce MFA on VPN access\n"
        "- Consider Zero Trust Network Access (ZTNA) as a more secure alternative"
    ),

    # AWL / company specific
    "awl": (
        "⚠️ **Company Name Detected — Blocked by DLP Policy**\n\n"
        "Your question contains an internal company name or abbreviation (AWL). "
        "Submitting internal company identifiers to AI systems is restricted by your organisation's "
        "Data Loss Prevention policy.\n\n"
        "**Why this is blocked:**\n"
        "- Company names in AI prompts can be logged and used in model training\n"
        "- Internal project names can reveal confidential business strategy\n"
        "- This reduces the risk of competitive intelligence leakage\n\n"
        "**What to do instead:**\n"
        "- Rephrase your question without the company name\n"
        "- Use generic terms: 'our company', 'my organisation', 'the system'\n"
        "- Contact your security team if you need an exception"
    ),
}


def _static_fallback(question: str) -> str | None:
    q = question.lower()
    for keyword, answer in _STATIC_ANSWERS.items():
        if keyword in q:
            return answer + "\n\n*ℹ Offline answer — Gemini API quota reached. Try again in a few minutes.*"
    return None


def ask_ai(question: str, retries: int = 3) -> str:
    if not _client:
        # Still try static fallback even without API key
        static = _static_fallback(question)
        if static:
            return static
        return (
            "⚠ **Gemini API key not configured.**\n\n"
            "Set `GEMINI_API_KEY` environment variable and restart the app.\n"
            "```powershell\n$env:GEMINI_API_KEY='your-key-here'\npython -m streamlit run app.py\n```"
        )

    for attempt in range(retries + 1):
        try:
            response = _client.models.generate_content(
                model="gemini-2.0-flash",
                contents=f"{_SYSTEM_PROMPT}\n\nQuestion: {question}",
            )
            return response.text.strip()

        except Exception as e:
            err = str(e)

            if "429" in err or "quota" in err.lower() or "rate" in err.lower():
                if attempt < retries:
                    time.sleep((attempt + 1) * 15)  # 15s, 30s, 45s
                    continue
                # Quota exhausted — use static fallback
                static = _static_fallback(question)
                if static:
                    return static
                return (
                    "⏳ **Gemini API quota reached.**\n\n"
                    "**Quick fixes:**\n"
                    "- Wait 1-2 minutes and try again (per-minute limit)\n"
                    "- The daily quota resets at midnight\n"
                    "- Get a new key at https://aistudio.google.com/app/apikey\n\n"
                    "**Common cybersecurity topics I can answer offline:**\n"
                    "XSS, SQL Injection, Prompt Injection, Jailbreak, DLP, SSRF, Firewall, "
                    "Ransomware, Phishing, Zero Day, CVE, MITRE ATT&CK, SOC, SIEM, MFA, "
                    "Penetration Testing, OWASP, Encryption, IDS/IPS, VPN"
                )

            if "404" in err or "not found" in err.lower():
                return (
                    "⚠ **Model not found.** Check that `chatbot.py` uses `gemini-2.0-flash`."
                )

            if "10051" in err or "unreachable" in err.lower() or "socket" in err.lower():
                static = _static_fallback(question)
                if static:
                    return static
                return (
                    "⚠ **Network Error — Cannot reach Gemini API.**\n\n"
                    "Your network is blocking outbound API requests (WinError 10051).\n\n"
                    "**Solutions:**\n"
                    "- Switch to mobile hotspot\n"
                    "- Use a VPN\n"
                    "- Check if your network blocks google APIs\n\n"
                    "**I can still answer these topics offline:** XSS, SQL Injection, "
                    "Prompt Injection, DLP, SSRF, Firewall, Ransomware, Phishing, "
                    "CVE, MITRE ATT&CK, SOC, SIEM, MFA, OWASP, Encryption, VPN"
                )

            return f"⚠ AI Error: {err}"

    return "⚠ Could not get a response. Please try again." 