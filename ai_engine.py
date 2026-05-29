# # def generate_ai_explanation(findings):

# #     explanations = []

# #     for item in findings:

# #         category = item['category']

# #         if category == "Prompt Injection":

# #             explanations.append(
# #                 "This prompt attempts to override system instructions and manipulate LLM behavior."
# #             )

# #         elif category == "Privilege Escalation":

# #             explanations.append(
# #                 "This prompt attempts unauthorized privilege escalation or admin-level access."
# #             )

# #         elif category == "Data Leakage":

# #             explanations.append(
# #                 "Potential attempt to extract confidential or hidden information."
# #             )

# #         elif category == "Jailbreak Attempt":

# #             explanations.append(
# #                 "This prompt attempts to bypass AI safety and ethical controls."
# #             )

# #         elif category == "Cross Site Scripting (XSS)":

# #             explanations.append(
# #                 "Detected possible XSS payload capable of executing malicious client-side scripts."
# #             )

# #         elif category == "SQL Injection":

# #             explanations.append(
# #                 "Detected SQL Injection pattern attempting database manipulation."
# #             )

# #         elif category == "Command Injection":

# #             explanations.append(
# #                 "Detected operating system command injection attempt."
# #             )

# #     return explanations

# # def generate_ai_explanation(findings):

# #     explanations = []

# #     for item in findings:

# #         category = item['category']

# #         if category == "Prompt Injection":

# #             explanations.append(
# #                 "This prompt attempts to override system instructions and manipulate LLM behavior."
# #             )

# #         elif category == "Privilege Escalation":

# #             explanations.append(
# #                 "This prompt attempts unauthorized privilege escalation or admin-level access."
# #             )

# #         elif category == "Data Leakage":

# #             explanations.append(
# #                 "Potential attempt to extract confidential or hidden information."
# #             )

# #         elif category == "Jailbreak Attempt":

# #             explanations.append(
# #                 "This prompt attempts to bypass AI safety and ethical controls."
# #             )

# #         elif category == "Cross Site Scripting (XSS)":

# #             explanations.append(
# #                 "Detected possible XSS payload capable of executing malicious client-side scripts."
# #             )

# #         elif category == "SQL Injection":

# #             explanations.append(
# #                 "Detected SQL Injection pattern attempting database manipulation."
# #             )

# #         elif category == "Command Injection":

# #             explanations.append(
# #                 "Detected operating system command injection attempt."
# #             )

# #     return explanations
# def generate_ai_explanation(findings):

#     explanations = []

#     processed_categories = set()

#     for item in findings:

#         category = item['category']

#         # Prevent duplicate explanations
#         if category in processed_categories:
#             continue

#         processed_categories.add(category)

#         if category == "Prompt Injection":

#             explanations.append(
#                 "This prompt attempts to override system instructions and manipulate LLM behavior."
#             )

#         elif category == "Privilege Escalation":

#             explanations.append(
#                 "This prompt attempts unauthorized privilege escalation or admin-level access."
#             )

#         elif category == "Data Leakage":

#             explanations.append(
#                 "Potential attempt to extract confidential or hidden information."
#             )

#         elif category == "Jailbreak Attempt":

#             explanations.append(
#                 "This prompt attempts to bypass AI safety and ethical controls."
#             )

#         elif category == "Cross Site Scripting (XSS)":

#             explanations.append(
#                 "Detected possible XSS payload capable of executing malicious client-side scripts."
#             )

#         elif category == "SQL Injection":

#             explanations.append(
#                 "Detected SQL Injection pattern attempting database manipulation."
#             )

#         elif category == "Command Injection":

#             explanations.append(
#                 "Detected operating system command injection attempt."
#             )

#     return explanations
import os
import time
from google import genai

_API_KEY = os.getenv("GEMINI_API_KEY", "")
_client  = genai.Client(api_key=_API_KEY) if _API_KEY else None

_static_explanations = {
    "Prompt Injection":                       "The prompt attempts to override the LLM's system instructions. An attacker is trying to hijack model behavior by injecting new directives.",
    "Jailbreak Attempt":                      "This prompt tries to bypass the AI's safety guardrails by convincing it to adopt an unrestricted persona or ignore ethical constraints.",
    "Privilege Escalation":                   "The prompt requests elevated system-level access or admin privileges that should not be granted to an end user.",
    "Data Leakage":                           "The prompt attempts to extract confidential information such as API keys, system prompts, credentials, or database contents.",
    "Cross Site Scripting (XSS)":            "A JavaScript or HTML injection payload was detected. If rendered in a browser, this could execute malicious client-side scripts.",
    "Cross Site Request Forgery (CSRF)":     "A CSRF pattern was detected. This could trick a user's browser into submitting unauthorized requests to a trusted site.",
    "SQL Injection":                          "A SQL injection pattern was detected. This could allow an attacker to read, modify, or delete database records.",
    "Command Injection":                      "An OS command injection pattern was detected. If executed, this could allow an attacker to run arbitrary system commands on the server.",
    "Path Traversal":                         "A path traversal sequence was detected. This could allow an attacker to access files outside the intended directory.",
    "Server Side Request Forgery (SSRF)":    "An SSRF pattern was detected. An attacker may be trying to make the server issue requests to internal services or cloud metadata endpoints.",
    "XML External Entity (XXE)":             "An XXE payload was detected. This could allow reading local files or triggering SSRF via XML parsing.",
    "Server Side Template Injection (SSTI)": "A template injection pattern was detected. If processed by a templating engine, this could lead to remote code execution.",
    "LDAP Injection":                         "An LDAP injection pattern was detected. This could allow an attacker to manipulate directory queries and access unauthorized user records.",
    "PII Detected":                           "Personally Identifiable Information such as email addresses, phone numbers, or SSNs was detected in the prompt.",
    "Secret / API Key Detected":              "A potential API key, token, or credential pattern was detected. Submitting secrets to an LLM risks them being logged or leaked.",
}


def generate_ai_explanation(findings: list[dict]) -> list[str]:
    explanations = []
    seen = set()

    for item in findings:
        category = item["category"]
        if category in seen:
            continue
        seen.add(category)

        if _client:
            for attempt in range(2):
                try:
                    prompt = (
                        f"You are a cybersecurity SOC analyst. "
                        f"A threat of type '{category}' was detected in a user prompt. "
                        f"The matched pattern was: {item['pattern']}. "
                        f"In 2-3 concise sentences, explain what this attack is, "
                        f"what the attacker is trying to achieve, and the key risk. "
                        f"Be professional and direct."
                    )
                    response = _client.models.generate_content(
                        model="gemini-2.0-flash",
                        contents=prompt,
                    )
                    explanations.append(response.text.strip())
                    break
                except Exception as e:
                    err = str(e)
                    if ("429" in err or "quota" in err.lower()) and attempt == 0:
                        time.sleep(10)
                        continue
                    explanations.append(
                        _static_explanations.get(category, f"Threat detected: {category}.")
                    )
                    break
            continue

        explanations.append(
            _static_explanations.get(category, f"Threat detected: {category}.")
        )

    return explanations