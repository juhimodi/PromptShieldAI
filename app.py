# # # # # import streamlit as st
# # # # # import pandas as pd
# # # # # import sqlite3
# # # # # import plotly.express as px
# # # # # import requests

# # # # # from detector import detect_prompt
# # # # # from scorer import calculate_risk
# # # # # from database import init_db, insert_log
# # # # # from ai_engine import generate_ai_explanation
# # # # # from auth import login, logout
# # # # # from report_generator import generate_pdf
# # # # # from chatbot import ask_ai
# # # # # from pii_scanner import scan_all
# # # # # from dlp_guard import scan_for_company_data, check_file_extension, get_dlp_message

# # # # # REPORT_PATH = "PromptShield_Report.pdf"

# # # # # # =========================================================
# # # # # # BOOTSTRAP
# # # # # # =========================================================

# # # # # init_db()

# # # # # st.set_page_config(
# # # # #     page_title="PromptShield AI",
# # # # #     page_icon="🛡️",
# # # # #     layout="wide",
# # # # # )

# # # # # # =========================================================
# # # # # # AUTH GATE
# # # # # # =========================================================

# # # # # if "authenticated" not in st.session_state:
# # # # #     st.session_state["authenticated"] = False

# # # # # if not st.session_state["authenticated"]:
# # # # #     login()
# # # # #     st.stop()

# # # # # # =========================================================
# # # # # # CUSTOM THEME
# # # # # # =========================================================

# # # # # st.markdown("""
# # # # # <style>
# # # # # .main { background-color: #0E1117; color: white; }
# # # # # h1, h2, h3 { color: #00FFAA; }
# # # # # .stButton>button {
# # # # #     background-color: #00FFAA;
# # # # #     color: black;
# # # # #     font-weight: bold;
# # # # #     border-radius: 8px;
# # # # #     height: 46px;
# # # # #     min-width: 180px;
# # # # # }
# # # # # .stTextArea textarea { background-color: #1A1A2E; color: white; }
# # # # # </style>
# # # # # """, unsafe_allow_html=True)

# # # # # # =========================================================
# # # # # # HEADER
# # # # # # =========================================================

# # # # # col_title, col_logout = st.columns([5, 1])
# # # # # with col_title:
# # # # #     st.title("🛡️ PromptShield AI")
# # # # #     st.caption("LLM Guardrail Engine — Real-Time Threat Detection & Policy Enforcement")
# # # # # with col_logout:
# # # # #     st.write("")
# # # # #     if st.button("Logout"):
# # # # #         logout()

# # # # # st.divider()

# # # # # # =========================================================
# # # # # # SIDEBAR NAVIGATION
# # # # # # =========================================================

# # # # # st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
# # # # # st.sidebar.title("Navigation")

# # # # # menu = st.sidebar.radio(
# # # # #     "Select Module",
# # # # #     ["🔍 Prompt Analyzer", "🔏 PII & Secrets Scanner", "🚫 DLP Policy", "📊 Analytics Dashboard", "🤖 AI Security Assistant", "🌐 CVE Threat Feed"],
# # # # # )

# # # # # # =========================================================
# # # # # # HELPERS
# # # # # # =========================================================

# # # # # def load_logs() -> pd.DataFrame:
# # # # #     conn = sqlite3.connect("prompts.db")
# # # # #     df = pd.read_sql_query("SELECT * FROM logs ORDER BY id DESC", conn)
# # # # #     conn.close()
# # # # #     return df


# # # # # RISK_COLORS = {
# # # # #     "LOW":      "#00FFAA",
# # # # #     "MEDIUM":   "#FFD700",
# # # # #     "HIGH":     "#FF6B35",
# # # # #     "CRITICAL": "#FF3333",
# # # # # }


# # # # # def parse_cve(item: dict) -> dict:
# # # # #     if not isinstance(item, dict):
# # # # #         return {"cve_id": "Unknown CVE", "summary": "No summary available.", "cvss": None}

# # # # #     cve_id = (
# # # # #         item.get("id")
# # # # #         or item.get("cveId")
# # # # #         or (item.get("CVE_data_meta") or {}).get("ID")
# # # # #         or "Unknown CVE"
# # # # #     )

# # # # #     summary = item.get("summary") or ""
# # # # #     if not summary:
# # # # #         summary = item.get("details") or ""
# # # # #     if not summary:
# # # # #         desc_field = item.get("description")
# # # # #         if isinstance(desc_field, str):
# # # # #             summary = desc_field
# # # # #     if not summary:
# # # # #         descs = item.get("descriptions")
# # # # #         if not descs and isinstance(item.get("description"), dict):
# # # # #             descs = item["description"].get("description_data", [])
# # # # #         if isinstance(descs, list):
# # # # #             for d in descs:
# # # # #                 if isinstance(d, dict) and d.get("lang", "").startswith("en"):
# # # # #                     summary = d.get("value", "")
# # # # #                     break
# # # # #             if not summary and descs:
# # # # #                 first = descs[0]
# # # # #                 summary = first.get("value", "") if isinstance(first, dict) else str(first)
# # # # #     if not summary:
# # # # #         aliases = item.get("aliases", [])
# # # # #         if aliases and isinstance(aliases, list):
# # # # #             summary = f"See advisory: {', '.join(str(a) for a in aliases[:3])}"

# # # # #     summary = (summary or "No summary available.").strip()
# # # # #     if len(summary) > 450:
# # # # #         summary = summary[:447] + "..."

# # # # #     cvss = None
# # # # #     for field in ("cvss", "cvss3", "cvssScore", "baseScore", "score"):
# # # # #         val = item.get(field)
# # # # #         if val is not None:
# # # # #             try:
# # # # #                 cvss = float(val)
# # # # #                 break
# # # # #             except (ValueError, TypeError):
# # # # #                 pass

# # # # #     if cvss is None:
# # # # #         severity_list = item.get("severity") or []
# # # # #         if isinstance(severity_list, list):
# # # # #             for s in severity_list:
# # # # #                 if isinstance(s, dict):
# # # # #                     raw = s.get("score") or s.get("baseScore")
# # # # #                     try:
# # # # #                         cvss = float(raw); break
# # # # #                     except (ValueError, TypeError):
# # # # #                         pass
# # # # #         elif isinstance(severity_list, (int, float)):
# # # # #             try:
# # # # #                 cvss = float(severity_list)
# # # # #             except (ValueError, TypeError):
# # # # #                 pass

# # # # #     if cvss is None:
# # # # #         metrics = item.get("metrics") or {}
# # # # #         if isinstance(metrics, dict):
# # # # #             for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
# # # # #                 entries = metrics.get(key, [])
# # # # #                 if isinstance(entries, list) and entries:
# # # # #                     raw = (entries[0].get("cvssData") or {}).get("baseScore")
# # # # #                     try:
# # # # #                         cvss = float(raw); break
# # # # #                     except (ValueError, TypeError):
# # # # #                         pass

# # # # #     try:
# # # # #         cvss = float(cvss) if cvss is not None else None
# # # # #     except (ValueError, TypeError):
# # # # #         cvss = None

# # # # #     return {"cve_id": cve_id, "summary": summary, "cvss": cvss}


# # # # # # =========================================================
# # # # # # MODULE 1 — PROMPT ANALYZER
# # # # # # =========================================================

# # # # # if menu == "🔍 Prompt Analyzer":

# # # # #     st.header("Prompt Analyzer")
# # # # #     st.write("Paste any prompt below to scan it for injection, jailbreak, and other attack patterns.")

# # # # #     prompt = st.text_area("Enter Prompt to Analyze", height=200, placeholder="Paste suspicious prompt here...")

# # # # #     if st.button("🔎 Analyze Prompt"):

# # # # #         if not prompt.strip():
# # # # #             st.warning("Please enter a prompt before analyzing.")
# # # # #             st.stop()

# # # # #         dlp = scan_for_company_data(prompt)
# # # # #         if dlp["blocked"]:
# # # # #             st.error(get_dlp_message(dlp))
# # # # #             st.divider()
# # # # #             st.subheader("DLP Detection Details")
# # # # #             for f in dlp["findings"]:
# # # # #                 with st.expander(f"🚫 {f['category']}  (line {f['line']})"):
# # # # #                     st.code(f["snippet"], language="text")
# # # # #                     st.caption(f"Risk weight: {f['weight']} pts")
# # # # #             st.info("Tip: Describe your problem in plain English. Do not paste source code, config files, credentials, or internal URLs.")
# # # # #             st.stop()
# # # # #         elif dlp["verdict"] == "WARN":
# # # # #             st.warning(f"DLP Warning — {dlp['category_count']} suspicious pattern(s) detected (code-like content). Proceed only if this is intentional test data.")

# # # # #         with st.spinner("Scanning for threats..."):
# # # # #             findings = detect_prompt(prompt)
# # # # #             score, risk, severity, confidence = calculate_risk(findings)
# # # # #             insert_log(prompt, str(findings), score, risk)

# # # # #         st.divider()
# # # # #         st.subheader("Analysis Result")

# # # # #         c1, c2, c3, c4 = st.columns(4)
# # # # #         c1.metric("Risk Score",        score)
# # # # #         c2.metric("Risk Level",        risk)
# # # # #         c3.metric("Severity",          severity)
# # # # #         c4.metric("Threat Confidence", confidence)

# # # # #         st.divider()

# # # # #         if risk == "CRITICAL":
# # # # #             st.error("SOC ALERT — Critical malicious payload detected! Immediate action required.")
# # # # #         elif risk == "HIGH":
# # # # #             st.warning("HIGH RISK — Suspicious activity detected. Review and block.")
# # # # #         elif risk == "MEDIUM":
# # # # #             st.info("MEDIUM RISK — Potential threat activity observed. Monitor closely.")
# # # # #         else:
# # # # #             st.success("Prompt appears safe. No malicious patterns matched.")

# # # # #         if findings:
# # # # #             generate_pdf(prompt, findings, score, risk)
# # # # #             with open(REPORT_PATH, "rb") as f:
# # # # #                 st.download_button(
# # # # #                     "📄 Download Security Report (PDF)",
# # # # #                     data=f,
# # # # #                     file_name="PromptShield_Report.pdf",
# # # # #                     mime="application/pdf",
# # # # #                 )

# # # # #             st.divider()
# # # # #             st.subheader("AI Threat Analysis")
# # # # #             with st.spinner("Generating AI analysis..."):
# # # # #                 explanations = generate_ai_explanation(findings)
# # # # #             for exp in explanations:
# # # # #                 st.warning(exp)

# # # # #             st.divider()
# # # # #             st.subheader("Detected Threats")
# # # # #             for item in findings:
# # # # #                 with st.expander(f"🔴 {item['category']}"):
# # # # #                     st.write(f"**Matched Pattern:** `{item['pattern']}`")
# # # # #                     st.info(f"**MITRE ATT&CK:** {item.get('mitre', 'N/A')}")

# # # # #             st.divider()
# # # # #             st.subheader("Recommended Actions")
# # # # #             recs = [
# # # # #                 "Block this prompt from reaching the LLM immediately.",
# # # # #                 "Enable strict input validation and sanitization.",
# # # # #                 "Apply Web Application Firewall (WAF) rules.",
# # # # #                 "Alert the SOC team and create an incident ticket.",
# # # # #                 "Review recent logs for similar patterns.",
# # # # #                 "Rotate any secrets or credentials that may have been exposed.",
# # # # #             ]
# # # # #             for rec in recs:
# # # # #                 st.success(f"✔ {rec}")
# # # # #         else:
# # # # #             st.success("Prompt is Safe — no malicious patterns detected.")


# # # # # # =========================================================
# # # # # # MODULE 2 — PII & SECRETS SCANNER
# # # # # # =========================================================

# # # # # elif menu == "🔏 PII & Secrets Scanner":

# # # # #     st.header("PII & Secrets Scanner")
# # # # #     st.write("Detect Personally Identifiable Information (PII) and leaked credentials inside any text.")

# # # # #     text_input = st.text_area(
# # # # #         "Paste text to scan",
# # # # #         height=220,
# # # # #         placeholder="Paste any text here — emails, phone numbers, API keys, tokens, passwords, etc.",
# # # # #     )

# # # # #     col_scan, col_clear = st.columns([2, 1])
# # # # #     with col_scan:
# # # # #         scan_clicked = st.button("🔍 Scan for PII & Secrets", use_container_width=True)
# # # # #     with col_clear:
# # # # #         if st.button("Clear", use_container_width=True):
# # # # #             st.rerun()

# # # # #     if scan_clicked:
# # # # #         if not text_input.strip():
# # # # #             st.warning("Please paste some text to scan.")
# # # # #             st.stop()

# # # # #         dlp = scan_for_company_data(text_input)
# # # # #         if dlp["blocked"]:
# # # # #             st.error(get_dlp_message(dlp))
# # # # #             for f in dlp["findings"]:
# # # # #                 with st.expander(f"🚫 {f['category']}"):
# # # # #                     st.code(f["snippet"], language="text")
# # # # #             st.stop()

# # # # #         with st.spinner("Scanning for PII and secrets..."):
# # # # #             result = scan_all(text_input)

# # # # #         st.divider()

# # # # #         risk = result["risk"]
# # # # #         risk_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "CLEAN": "🟢"}
# # # # #         icon = risk_icons.get(risk, "⚪")

# # # # #         c1, c2, c3, c4 = st.columns(4)
# # # # #         c1.metric("PII Found",      result["pii_count"])
# # # # #         c2.metric("Secrets Found",  result["secret_count"])
# # # # #         c3.metric("Total Findings", result["total"])
# # # # #         c4.metric("Risk Level",     f"{icon} {risk}")

# # # # #         st.divider()

# # # # #         if risk == "CRITICAL":
# # # # #             st.error("CRITICAL — API keys or credentials detected! Rotate them immediately.")
# # # # #         elif risk == "HIGH":
# # # # #             st.warning("HIGH RISK — Multiple PII fields detected. Review before sharing.")
# # # # #         elif risk == "MEDIUM":
# # # # #             st.info("MEDIUM — PII detected. Ensure data handling complies with your policy.")
# # # # #         else:
# # # # #             st.success("CLEAN — No PII or secrets detected in this text.")

# # # # #         if result["pii"]:
# # # # #             st.subheader("PII Detections")
# # # # #             for item in result["pii"]:
# # # # #                 with st.expander(f"🟡 {item['category']}  x{item['count']} found"):
# # # # #                     st.write(f"**Sample (redacted):** `{item['matched_value']}`")
# # # # #                     st.info(f"**MITRE ATT&CK:** {item['mitre']}")

# # # # #         if result["secrets"]:
# # # # #             st.subheader("Credential / Secret Detections")
# # # # #             for item in result["secrets"]:
# # # # #                 with st.expander(f"🔴 {item['category']}  x{item['count']} found"):
# # # # #                     st.write(f"**Sample (redacted):** `{item['matched_value']}`")
# # # # #                     st.error(f"**MITRE ATT&CK:** {item['mitre']}")
# # # # #                     st.caption("Action required: Rotate this credential immediately.")

# # # # #         if result["total"] > 0:
# # # # #             st.divider()
# # # # #             st.subheader("Recommended Actions")
# # # # #             if result["secrets"]:
# # # # #                 st.error("Rotate all detected API keys and tokens immediately.")
# # # # #                 st.error("Check access logs for unauthorized use of these credentials.")
# # # # #                 st.error("Store secrets in environment variables — never in prompts.")
# # # # #             if result["pii"]:
# # # # #                 st.info("Apply data masking before sending text to any AI system.")
# # # # #                 st.info("Review your data retention policies for GDPR/DPDP compliance.")
# # # # #                 st.info("Implement a pre-processing filter to strip PII before it reaches the LLM.")


# # # # # # =========================================================
# # # # # # MODULE 3 — DLP POLICY MANAGER
# # # # # # =========================================================

# # # # # elif menu == "🚫 DLP Policy":

# # # # #     st.header("Data Loss Prevention (DLP) Policy")
# # # # #     st.write("Configure what types of content are blocked. All inputs pass through this policy engine before processing.")

# # # # #     st.divider()

# # # # #     c1, c2, c3 = st.columns(3)
# # # # #     c1.metric("DLP Status",           "ACTIVE")
# # # # #     c2.metric("Categories Monitored", "8")
# # # # #     c3.metric("File Types Blocked",   "30+")

# # # # #     st.divider()

# # # # #     st.subheader("Blocked Content Categories")
# # # # #     from dlp_guard import CODE_PATTERNS, FILE_EXTENSION_BLOCK, CATEGORY_WEIGHTS

# # # # #     blocked_cats = [
# # # # #         ("Source Code — Function/Class Definition", "Python, Java, JavaScript, C++, Go, Rust functions and classes", "🔴"),
# # # # #         ("Source Code — Import Statements",         "import/require/using statements from any language",            "🔴"),
# # # # #         ("Database Schema / SQL DDL",               "CREATE TABLE, ALTER TABLE, schema definitions",                "🔴"),
# # # # #         ("Configuration / Environment File",        ".env files, DB connection strings, host/port/password configs","🔴"),
# # # # #         ("API Endpoint / Internal URL",             "Internal API routes, private IPs, Bearer tokens in headers",  "🔴"),
# # # # #         ("Infrastructure / DevOps Config",          "Kubernetes YAML, Dockerfile, Terraform, Nginx/Apache config",  "🔴"),
# # # # #         ("Proprietary Business Logic Keywords",     "internal_use_only, confidential, proprietary markers",        "🟡"),
# # # # #         ("Compiled / Binary File Content",          "ELF binaries, PE executables, hex dumps, base64 archives",    "🔴"),
# # # # #     ]

# # # # #     for cat, desc, icon in blocked_cats:
# # # # #         weight = CATEGORY_WEIGHTS.get(cat, 25)
# # # # #         with st.expander(f"{icon} {cat}  —  Risk Weight: {weight}"):
# # # # #             st.write(desc)
# # # # #             st.caption("MITRE ATT&CK: T1213 – Data from Information Repositories")

# # # # #     st.divider()

# # # # #     st.subheader("Blocked File Extensions")
# # # # #     ext_cols = st.columns(6)
# # # # #     sorted_exts = sorted(FILE_EXTENSION_BLOCK)
# # # # #     per_col = len(sorted_exts) // 6 + 1
# # # # #     for i, col in enumerate(ext_cols):
# # # # #         chunk = sorted_exts[i*per_col:(i+1)*per_col]
# # # # #         for e in chunk:
# # # # #             col.markdown(f"`{e}`")

# # # # #     st.divider()

# # # # #     st.subheader("Live DLP Tester")
# # # # #     test_input = st.text_area("Paste text to test", height=150, placeholder="Paste some text to see if DLP would block it...")

# # # # #     if st.button("Test DLP Policy", use_container_width=True):
# # # # #         if test_input.strip():
# # # # #             result = scan_for_company_data(test_input)
# # # # #             if result["verdict"] == "BLOCK":
# # # # #                 st.error(f"BLOCKED — Score: {result['total_score']}  |  Categories: {result['category_count']}")
# # # # #                 for f in result["findings"]:
# # # # #                     with st.expander(f"🚫 {f['category']}  (line {f['line']})"):
# # # # #                         st.code(f["snippet"], language="text")
# # # # #                         st.caption(f"Risk weight: {f['weight']}")
# # # # #             elif result["verdict"] == "WARN":
# # # # #                 st.warning(f"WARNING — Score: {result['total_score']}  |  Code-like content detected.")
# # # # #                 for f in result["findings"]:
# # # # #                     with st.expander(f"⚠ {f['category']}"):
# # # # #                         st.code(f["snippet"], language="text")
# # # # #             else:
# # # # #                 st.success("PASS — No policy violations detected. This text would be allowed.")

# # # # #     st.divider()

# # # # #     st.subheader("Policy Rules Summary")
# # # # #     st.info(
# # # # #         "Enforcement Points:\n"
# # # # #         "- Prompt Analyzer — DLP checked before every scan\n"
# # # # #         "- PII & Secrets Scanner — DLP checked before every scan\n"
# # # # #         "- AI Security Assistant — DLP checked before sending to Gemini\n\n"
# # # # #         "On violation: Input is blocked, user sees a policy message, event is logged."
# # # # #     )

# # # # #     with st.expander("What users CAN submit"):
# # # # #         st.markdown("""
# # # # # - Plain English descriptions of security problems
# # # # # - Anonymised log snippets (no credentials, no internal IPs)
# # # # # - Public CVE IDs or vulnerability names
# # # # # - Generic attack patterns for testing
# # # # # - Cybersecurity questions
# # # # #         """)

# # # # #     with st.expander("What users CANNOT submit"):
# # # # #         st.markdown("""
# # # # # - Source code files (.py, .js, .java, .cs, .go, etc.)
# # # # # - Database schemas or SQL DDL statements
# # # # # - .env files or configuration with real credentials
# # # # # - Internal API endpoints or private IP addresses
# # # # # - Kubernetes / Docker / Terraform infrastructure files
# # # # # - Compiled binaries or hex dumps
# # # # #         """)


# # # # # # =========================================================
# # # # # # MODULE 4 — ANALYTICS DASHBOARD
# # # # # # =========================================================

# # # # # elif menu == "📊 Analytics Dashboard":

# # # # #     st.header("Threat Analytics Dashboard")

# # # # #     df = load_logs()

# # # # #     if df.empty:
# # # # #         st.info("No scan logs yet. Run some prompts through the Prompt Analyzer first.")
# # # # #         st.stop()

# # # # #     total      = len(df)
# # # # #     critical   = len(df[df["risk"] == "CRITICAL"])
# # # # #     high       = len(df[df["risk"] == "HIGH"])
# # # # #     safe_count = len(df[df["risk"] == "LOW"])

# # # # #     c1, c2, c3, c4 = st.columns(4)
# # # # #     c1.metric("Total Scans",      total)
# # # # #     c2.metric("Critical Threats", critical)
# # # # #     c3.metric("High Risk",        high)
# # # # #     c4.metric("Safe Prompts",     safe_count)

# # # # #     st.divider()

# # # # #     col_a, col_b = st.columns(2)

# # # # #     with col_a:
# # # # #         st.subheader("Risk Distribution")
# # # # #         risk_counts = df["risk"].value_counts().reset_index()
# # # # #         risk_counts.columns = ["Risk Level", "Count"]
# # # # #         fig_pie = px.pie(
# # # # #             risk_counts,
# # # # #             names="Risk Level",
# # # # #             values="Count",
# # # # #             color="Risk Level",
# # # # #             color_discrete_map=RISK_COLORS,
# # # # #             hole=0.4,
# # # # #         )
# # # # #         fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
# # # # #         st.plotly_chart(fig_pie, use_container_width=True)

# # # # #     with col_b:
# # # # #         st.subheader("Threat Category Frequency")
# # # # #         categories = ["XSS", "SQL Injection", "CSRF", "Prompt Injection", "Jailbreak", "SSRF", "Command Injection"]
# # # # #         kw_map     = ["XSS", "SQL", "CSRF", "Prompt Injection", "Jailbreak", "SSRF", "Command"]
# # # # #         counts = [len(df[df["findings"].str.contains(kw, case=False, na=False)]) for kw in kw_map]
# # # # #         bar_df = pd.DataFrame({"Threat": categories, "Count": counts})
# # # # #         fig_bar = px.bar(bar_df, x="Threat", y="Count", color="Count",
# # # # #                          color_continuous_scale="Reds", text="Count")
# # # # #         fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white", showlegend=False)
# # # # #         st.plotly_chart(fig_bar, use_container_width=True)

# # # # #     st.divider()

# # # # #     st.subheader("Recent Attack Stream (last 10 scans)")
# # # # #     for _, row in df.head(10).iterrows():
# # # # #         ft  = str(row["findings"])
# # # # #         ts  = row.get("timestamp", "")
# # # # #         pfx = f"[{ts}] Prompt #{row['id']}"

# # # # #         if "Prompt Injection" in ft:  st.error(f"Prompt Injection -> {pfx}")
# # # # #         elif "Jailbreak"      in ft:  st.error(f"Jailbreak Attempt -> {pfx}")
# # # # #         elif "XSS"            in ft:  st.error(f"XSS Attack -> {pfx}")
# # # # #         elif "SQL"            in ft:  st.error(f"SQL Injection -> {pfx}")
# # # # #         elif "CSRF"           in ft:  st.warning(f"CSRF Pattern -> {pfx}")
# # # # #         elif "SSRF"           in ft:  st.warning(f"SSRF Activity -> {pfx}")
# # # # #         elif ft == "[]":              st.success(f"Safe Request -> {pfx}")
# # # # #         else:                         st.warning(f"Threat Detected -> {pfx}")

# # # # #     st.divider()

# # # # #     st.subheader("Full Scan Logs")
# # # # #     st.dataframe(df, use_container_width=True)
# # # # #     csv = df.to_csv(index=False)
# # # # #     st.download_button("Download Logs (CSV)", data=csv,
# # # # #                        file_name="promptshield_logs.csv", mime="text/csv")


# # # # # # =========================================================
# # # # # # MODULE 5 — AI SECURITY ASSISTANT
# # # # # # =========================================================

# # # # # elif menu == "🤖 AI Security Assistant":

# # # # #     st.header("AI Security Assistant")
# # # # #     st.write("Ask any cybersecurity question. Powered by Gemini AI.")

# # # # #     question = st.text_input("Your Question", placeholder="e.g. What is a prompt injection attack?")

# # # # #     if st.button("Ask AI"):
# # # # #         if not question.strip():
# # # # #             st.warning("Please enter a question.")
# # # # #         else:
# # # # #             dlp = scan_for_company_data(question)
# # # # #             if dlp["blocked"]:
# # # # #                 st.error(get_dlp_message(dlp))
# # # # #                 st.stop()
# # # # #             with st.spinner("AI is analyzing..."):
# # # # #                 answer = ask_ai(question)
# # # # #             st.markdown("### AI Response")
# # # # #             st.success(answer)


# # # # # # =========================================================
# # # # # # MODULE 6 — LIVE CVE THREAT FEED
# # # # # # =========================================================

# # # # # elif menu == "🌐 CVE Threat Feed":

# # # # #     st.header("Live CVE Threat Intelligence Feed")
# # # # #     st.write("Latest Common Vulnerabilities and Exposures — sourced from CIRCL vulnerability-lookup.")

# # # # #     if st.button("Refresh Feed"):
# # # # #         st.rerun()

# # # # #     CIRCL_ENDPOINTS = [
# # # # #         "https://cve.circl.lu/api/last",
# # # # #         "https://vulnerability.circl.lu/api/last",
# # # # #         "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=15",
# # # # #     ]

# # # # #     cves = None
# # # # #     error_msg = None

# # # # #     def _extract_list(data):
# # # # #         if isinstance(data, list):
# # # # #             return data if data else None
# # # # #         if isinstance(data, dict):
# # # # #             for key in ("results", "data", "cves"):
# # # # #                 val = data.get(key)
# # # # #                 if isinstance(val, list) and val:
# # # # #                     return val
# # # # #             nvd_vulns = data.get("vulnerabilities")
# # # # #             if isinstance(nvd_vulns, list) and nvd_vulns:
# # # # #                 return [v.get("cve", v) for v in nvd_vulns]
# # # # #             for val in data.values():
# # # # #                 if isinstance(val, list) and val:
# # # # #                     return val
# # # # #         return None

# # # # #     with st.spinner("Fetching latest CVEs..."):
# # # # #         for url in CIRCL_ENDPOINTS:
# # # # #             try:
# # # # #                 resp = requests.get(url, timeout=12, headers={"Accept": "application/json"})
# # # # #                 if resp.status_code == 200:
# # # # #                     cves = _extract_list(resp.json())
# # # # #                     if cves:
# # # # #                         break
# # # # #             except Exception as e:
# # # # #                 error_msg = str(e)
# # # # #                 continue

# # # # #     if cves:
# # # # #         shown = 0
# # # # #         for raw in cves:
# # # # #             if shown >= 15:
# # # # #                 break
# # # # #             entry = parse_cve(raw)
# # # # #             if entry["cve_id"] == "Unknown CVE" and entry["summary"] == "No summary available.":
# # # # #                 continue

# # # # #             cvss  = entry["cvss"]
# # # # #             label = f"**{entry['cve_id']}**"
# # # # #             label += f" | CVSS: {cvss:.1f}" if cvss is not None else " | CVSS: N/A"
# # # # #             text  = f"{label}\n\n{entry['summary']}"

# # # # #             if cvss is not None and cvss >= 9.0:   st.error(f"🚨 {text}")
# # # # #             elif cvss is not None and cvss >= 7.0: st.warning(f"⚠️ {text}")
# # # # #             elif cvss is not None and cvss >= 4.0: st.info(f"🔵 {text}")
# # # # #             else:                                   st.info(f"ℹ️ {text}")
# # # # #             shown += 1

# # # # #         if shown == 0:
# # # # #             st.warning("Feed returned data but no readable CVE entries could be parsed.")
# # # # #             with st.expander("Raw API response (first entry)"):
# # # # #                 st.json(cves[0] if cves else {})
# # # # #         else:
# # # # #             with st.expander("Debug: raw first entry"):
# # # # #                 st.json(cves[0] if cves else {})
# # # # #     else:
# # # # #         st.warning("Live CVE feed could not be reached. Showing recent notable CVEs instead.")
# # # # #         st.divider()
# # # # #         st.subheader("Recent Notable CVEs (static reference)")

# # # # #         static_cves = [
# # # # #             {"id": "CVE-2025-21413", "cvss": 9.8, "color": "error",
# # # # #              "desc": "Windows Telephony Service RCE — attacker can execute arbitrary code remotely without authentication.",
# # # # #              "mitre": "T1190 – Exploit Public-Facing Application"},
# # # # #             {"id": "CVE-2025-21418", "cvss": 7.8, "color": "warning",
# # # # #              "desc": "Windows Ancillary Function Driver privilege escalation — local attacker gains SYSTEM privileges.",
# # # # #              "mitre": "T1068 – Exploitation for Privilege Escalation"},
# # # # #             {"id": "CVE-2024-49138", "cvss": 7.8, "color": "warning",
# # # # #              "desc": "Windows CLFS Driver heap buffer overflow enabling local privilege escalation. Actively exploited.",
# # # # #              "mitre": "T1068 – Exploitation for Privilege Escalation"},
# # # # #             {"id": "CVE-2024-38812", "cvss": 9.8, "color": "error",
# # # # #              "desc": "VMware vCenter Server heap overflow via DCERPC — unauthenticated remote code execution.",
# # # # #              "mitre": "T1190 – Exploit Public-Facing Application"},
# # # # #             {"id": "CVE-2024-6387 (regreSSHion)", "cvss": 8.1, "color": "warning",
# # # # #              "desc": "OpenSSH race condition allowing unauthenticated RCE as root on glibc-based Linux systems.",
# # # # #              "mitre": "T1190 – Exploit Public-Facing Application"},
# # # # #         ]

# # # # #         for cve in static_cves:
# # # # #             msg = f"**{cve['id']}** | CVSS: {cve['cvss']}\n\n{cve['desc']}\n\nMITRE: {cve['mitre']}"
# # # # #             if cve["color"] == "error":
# # # # #                 st.error(msg)
# # # # #             else:
# # # # #                 st.warning(msg)

# # # # #         st.caption("Source: NVD / Microsoft MSRC / Apple Security. Refresh or check https://cve.circl.lu for live data.")

# # # # import streamlit as st
# # # # import pandas as pd
# # # # import sqlite3
# # # # import plotly.express as px
# # # # import requests

# # # # from detector import detect_prompt
# # # # from scorer import calculate_risk
# # # # from database import init_db, insert_log
# # # # from ai_engine import generate_ai_explanation
# # # # from auth import login, logout
# # # # from report_generator import generate_pdf
# # # # from chatbot import ask_ai
# # # # from pii_scanner import scan_all
# # # # from dlp_guard import scan_for_company_data, check_file_extension, get_dlp_message

# # # # REPORT_PATH = "PromptShield_Report.pdf"

# # # # # =========================================================
# # # # # BOOTSTRAP
# # # # # =========================================================

# # # # init_db()

# # # # st.set_page_config(
# # # #     page_title="PromptShield AI",
# # # #     page_icon="🛡️",
# # # #     layout="wide",
# # # # )

# # # # # =========================================================
# # # # # AUTH GATE
# # # # # =========================================================

# # # # if "authenticated" not in st.session_state:
# # # #     st.session_state["authenticated"] = False

# # # # if not st.session_state["authenticated"]:
# # # #     login()
# # # #     st.stop()

# # # # # =========================================================
# # # # # CUSTOM THEME
# # # # # =========================================================

# # # # st.markdown("""
# # # # <style>
# # # # .main { background-color: #0E1117; color: white; }
# # # # h1, h2, h3 { color: #00FFAA; }
# # # # .stButton>button {
# # # #     background-color: #00FFAA;
# # # #     color: black;
# # # #     font-weight: bold;
# # # #     border-radius: 8px;
# # # #     height: 46px;
# # # #     min-width: 180px;
# # # # }
# # # # .stTextArea textarea { background-color: #1A1A2E; color: white; }
# # # # </style>
# # # # """, unsafe_allow_html=True)

# # # # # =========================================================
# # # # # HEADER
# # # # # =========================================================

# # # # col_title, col_logout = st.columns([5, 1])
# # # # with col_title:
# # # #     st.title("🛡️ PromptShield AI")
# # # #     st.caption("LLM Guardrail Engine — Real-Time Threat Detection & Policy Enforcement")
# # # # with col_logout:
# # # #     st.write("")
# # # #     if st.button("Logout"):
# # # #         logout()

# # # # st.divider()

# # # # # =========================================================
# # # # # SIDEBAR NAVIGATION
# # # # # =========================================================

# # # # st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
# # # # st.sidebar.title("Navigation")

# # # # menu = st.sidebar.radio(
# # # #     "Select Module",
# # # #     ["🔍 Prompt Analyzer", "🔏 PII & Secrets Scanner", "🚫 DLP Policy", "📊 Analytics Dashboard", "🤖 AI Security Assistant", "🌐 CVE Threat Feed"],
# # # # )

# # # # # =========================================================
# # # # # HELPERS
# # # # # =========================================================

# # # # def load_logs() -> pd.DataFrame:
# # # #     conn = sqlite3.connect("prompts.db")
# # # #     df = pd.read_sql_query("SELECT * FROM logs ORDER BY id DESC", conn)
# # # #     conn.close()
# # # #     return df


# # # # RISK_COLORS = {
# # # #     "LOW":      "#00FFAA",
# # # #     "MEDIUM":   "#FFD700",
# # # #     "HIGH":     "#FF6B35",
# # # #     "CRITICAL": "#FF3333",
# # # # }


# # # # def parse_cve(item: dict) -> dict:
# # # #     if not isinstance(item, dict):
# # # #         return {"cve_id": "Unknown CVE", "summary": "No summary available.", "cvss": None}

# # # #     cve_id = (
# # # #         item.get("id")
# # # #         or item.get("cveId")
# # # #         or (item.get("CVE_data_meta") or {}).get("ID")
# # # #         or "Unknown CVE"
# # # #     )

# # # #     summary = item.get("summary") or ""
# # # #     if not summary:
# # # #         summary = item.get("details") or ""
# # # #     if not summary:
# # # #         desc_field = item.get("description")
# # # #         if isinstance(desc_field, str):
# # # #             summary = desc_field
# # # #     if not summary:
# # # #         descs = item.get("descriptions")
# # # #         if not descs and isinstance(item.get("description"), dict):
# # # #             descs = item["description"].get("description_data", [])
# # # #         if isinstance(descs, list):
# # # #             for d in descs:
# # # #                 if isinstance(d, dict) and d.get("lang", "").startswith("en"):
# # # #                     summary = d.get("value", "")
# # # #                     break
# # # #             if not summary and descs:
# # # #                 first = descs[0]
# # # #                 summary = first.get("value", "") if isinstance(first, dict) else str(first)
# # # #     if not summary:
# # # #         aliases = item.get("aliases", [])
# # # #         if aliases and isinstance(aliases, list):
# # # #             summary = f"See advisory: {', '.join(str(a) for a in aliases[:3])}"

# # # #     summary = (summary or "No summary available.").strip()
# # # #     if len(summary) > 450:
# # # #         summary = summary[:447] + "..."

# # # #     cvss = None
# # # #     for field in ("cvss", "cvss3", "cvssScore", "baseScore", "score"):
# # # #         val = item.get(field)
# # # #         if val is not None:
# # # #             try:
# # # #                 cvss = float(val)
# # # #                 break
# # # #             except (ValueError, TypeError):
# # # #                 pass

# # # #     if cvss is None:
# # # #         severity_list = item.get("severity") or []
# # # #         if isinstance(severity_list, list):
# # # #             for s in severity_list:
# # # #                 if isinstance(s, dict):
# # # #                     raw = s.get("score") or s.get("baseScore")
# # # #                     try:
# # # #                         cvss = float(raw); break
# # # #                     except (ValueError, TypeError):
# # # #                         pass
# # # #         elif isinstance(severity_list, (int, float)):
# # # #             try:
# # # #                 cvss = float(severity_list)
# # # #             except (ValueError, TypeError):
# # # #                 pass

# # # #     if cvss is None:
# # # #         metrics = item.get("metrics") or {}
# # # #         if isinstance(metrics, dict):
# # # #             for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
# # # #                 entries = metrics.get(key, [])
# # # #                 if isinstance(entries, list) and entries:
# # # #                     raw = (entries[0].get("cvssData") or {}).get("baseScore")
# # # #                     try:
# # # #                         cvss = float(raw); break
# # # #                     except (ValueError, TypeError):
# # # #                         pass

# # # #     try:
# # # #         cvss = float(cvss) if cvss is not None else None
# # # #     except (ValueError, TypeError):
# # # #         cvss = None

# # # #     return {"cve_id": cve_id, "summary": summary, "cvss": cvss}


# # # # # =========================================================
# # # # # MODULE 1 — PROMPT ANALYZER
# # # # # =========================================================

# # # # if menu == "🔍 Prompt Analyzer":

# # # #     st.header("Prompt Analyzer")
# # # #     st.write("Paste any prompt below to scan it for injection, jailbreak, and other attack patterns.")

# # # #     prompt = st.text_area("Enter Prompt to Analyze", height=200, placeholder="Paste suspicious prompt here...")

# # # #     if st.button("🔎 Analyze Prompt"):

# # # #         if not prompt.strip():
# # # #             st.warning("Please enter a prompt before analyzing.")
# # # #             st.stop()

# # # #         dlp = scan_for_company_data(prompt)
# # # #         if dlp["blocked"]:
# # # #             st.error(get_dlp_message(dlp))
# # # #             st.divider()
# # # #             st.subheader("DLP Detection Details")
# # # #             for f in dlp["findings"]:
# # # #                 with st.expander(f"🚫 {f['category']}  (line {f['line']})"):
# # # #                     st.code(f["snippet"], language="text")
# # # #                     st.caption(f"Risk weight: {f['weight']} pts")
# # # #             st.info("Tip: Describe your problem in plain English. Do not paste source code, config files, credentials, or internal URLs.")
# # # #             st.stop()
# # # #         elif dlp["verdict"] == "WARN":
# # # #             st.warning(f"DLP Warning — {dlp['category_count']} suspicious pattern(s) detected (code-like content). Proceed only if this is intentional test data.")

# # # #         with st.spinner("Scanning for threats..."):
# # # #             findings = detect_prompt(prompt)
# # # #             score, risk, severity, confidence = calculate_risk(findings)
# # # #             insert_log(prompt, str(findings), score, risk)

# # # #         st.divider()
# # # #         st.subheader("Analysis Result")

# # # #         c1, c2, c3, c4 = st.columns(4)
# # # #         c1.metric("Risk Score",        score)
# # # #         c2.metric("Risk Level",        risk)
# # # #         c3.metric("Severity",          severity)
# # # #         c4.metric("Threat Confidence", confidence)

# # # #         st.divider()

# # # #         if risk == "CRITICAL":
# # # #             st.error("SOC ALERT — Critical malicious payload detected! Immediate action required.")
# # # #         elif risk == "HIGH":
# # # #             st.warning("HIGH RISK — Suspicious activity detected. Review and block.")
# # # #         elif risk == "MEDIUM":
# # # #             st.info("MEDIUM RISK — Potential threat activity observed. Monitor closely.")
# # # #         else:
# # # #             st.success("Prompt appears safe. No malicious patterns matched.")

# # # #         if findings:
# # # #             generate_pdf(prompt, findings, score, risk)
# # # #             with open(REPORT_PATH, "rb") as f:
# # # #                 st.download_button(
# # # #                     "📄 Download Security Report (PDF)",
# # # #                     data=f,
# # # #                     file_name="PromptShield_Report.pdf",
# # # #                     mime="application/pdf",
# # # #                 )

# # # #             st.divider()
# # # #             st.subheader("AI Threat Analysis")
# # # #             with st.spinner("Generating AI analysis..."):
# # # #                 explanations = generate_ai_explanation(findings)
# # # #             for exp in explanations:
# # # #                 st.warning(exp)

# # # #             st.divider()
# # # #             st.subheader("Detected Threats")
# # # #             for item in findings:
# # # #                 with st.expander(f"🔴 {item['category']}"):
# # # #                     st.write(f"**Matched Pattern:** `{item['pattern']}`")
# # # #                     st.info(f"**MITRE ATT&CK:** {item.get('mitre', 'N/A')}")

# # # #             st.divider()
# # # #             st.subheader("Recommended Actions")
# # # #             recs = [
# # # #                 "Block this prompt from reaching the LLM immediately.",
# # # #                 "Enable strict input validation and sanitization.",
# # # #                 "Apply Web Application Firewall (WAF) rules.",
# # # #                 "Alert the SOC team and create an incident ticket.",
# # # #                 "Review recent logs for similar patterns.",
# # # #                 "Rotate any secrets or credentials that may have been exposed.",
# # # #             ]
# # # #             for rec in recs:
# # # #                 st.success(f"✔ {rec}")
# # # #         else:
# # # #             st.success("Prompt is Safe — no malicious patterns detected.")


# # # # # =========================================================
# # # # # MODULE 2 — PII & SECRETS SCANNER
# # # # # =========================================================

# # # # elif menu == "🔏 PII & Secrets Scanner":

# # # #     st.header("PII & Secrets Scanner")
# # # #     st.write("Detect Personally Identifiable Information (PII) and leaked credentials inside any text.")

# # # #     text_input = st.text_area(
# # # #         "Paste text to scan",
# # # #         height=220,
# # # #         placeholder="Paste any text here — emails, phone numbers, API keys, tokens, passwords, etc.",
# # # #     )

# # # #     col_scan, col_clear = st.columns([2, 1])
# # # #     with col_scan:
# # # #         scan_clicked = st.button("🔍 Scan for PII & Secrets", use_container_width=True)
# # # #     with col_clear:
# # # #         if st.button("Clear", use_container_width=True):
# # # #             st.rerun()

# # # #     if scan_clicked:
# # # #         if not text_input.strip():
# # # #             st.warning("Please paste some text to scan.")
# # # #             st.stop()

# # # #         dlp = scan_for_company_data(text_input)
# # # #         if dlp["blocked"]:
# # # #             st.error(get_dlp_message(dlp))
# # # #             for f in dlp["findings"]:
# # # #                 with st.expander(f"🚫 {f['category']}"):
# # # #                     st.code(f["snippet"], language="text")
# # # #             st.stop()

# # # #         with st.spinner("Scanning for PII and secrets..."):
# # # #             result = scan_all(text_input)

# # # #         st.divider()

# # # #         risk = result["risk"]
# # # #         risk_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "CLEAN": "🟢"}
# # # #         icon = risk_icons.get(risk, "⚪")

# # # #         c1, c2, c3, c4 = st.columns(4)
# # # #         c1.metric("PII Found",      result["pii_count"])
# # # #         c2.metric("Secrets Found",  result["secret_count"])
# # # #         c3.metric("Total Findings", result["total"])
# # # #         c4.metric("Risk Level",     f"{icon} {risk}")

# # # #         st.divider()

# # # #         if risk == "CRITICAL":
# # # #             st.error("CRITICAL — API keys or credentials detected! Rotate them immediately.")
# # # #         elif risk == "HIGH":
# # # #             st.warning("HIGH RISK — Multiple PII fields detected. Review before sharing.")
# # # #         elif risk == "MEDIUM":
# # # #             st.info("MEDIUM — PII detected. Ensure data handling complies with your policy.")
# # # #         else:
# # # #             st.success("CLEAN — No PII or secrets detected in this text.")

# # # #         if result["pii"]:
# # # #             st.subheader("PII Detections")
# # # #             for item in result["pii"]:
# # # #                 with st.expander(f"🟡 {item['category']}  x{item['count']} found"):
# # # #                     st.write(f"**Sample (redacted):** `{item['matched_value']}`")
# # # #                     st.info(f"**MITRE ATT&CK:** {item['mitre']}")

# # # #         if result["secrets"]:
# # # #             st.subheader("Credential / Secret Detections")
# # # #             for item in result["secrets"]:
# # # #                 with st.expander(f"🔴 {item['category']}  x{item['count']} found"):
# # # #                     st.write(f"**Sample (redacted):** `{item['matched_value']}`")
# # # #                     st.error(f"**MITRE ATT&CK:** {item['mitre']}")
# # # #                     st.caption("Action required: Rotate this credential immediately.")

# # # #         if result["total"] > 0:
# # # #             st.divider()
# # # #             st.subheader("Recommended Actions")
# # # #             if result["secrets"]:
# # # #                 st.error("Rotate all detected API keys and tokens immediately.")
# # # #                 st.error("Check access logs for unauthorized use of these credentials.")
# # # #                 st.error("Store secrets in environment variables — never in prompts.")
# # # #             if result["pii"]:
# # # #                 st.info("Apply data masking before sending text to any AI system.")
# # # #                 st.info("Review your data retention policies for GDPR/DPDP compliance.")
# # # #                 st.info("Implement a pre-processing filter to strip PII before it reaches the LLM.")


# # # # # =========================================================
# # # # # MODULE 3 — DLP POLICY MANAGER
# # # # # =========================================================

# # # # elif menu == "🚫 DLP Policy":

# # # #     st.header("Data Loss Prevention (DLP) Policy")
# # # #     st.write("Configure what types of content are blocked. All inputs pass through this policy engine before processing.")

# # # #     st.divider()

# # # #     c1, c2, c3 = st.columns(3)
# # # #     c1.metric("DLP Status",           "ACTIVE")
# # # #     c2.metric("Categories Monitored", "8")
# # # #     c3.metric("File Types Blocked",   "30+")

# # # #     st.divider()

# # # #     st.subheader("Blocked Content Categories")
# # # #     from dlp_guard import CODE_PATTERNS, FILE_EXTENSION_BLOCK, CATEGORY_WEIGHTS

# # # #     blocked_cats = [
# # # #         ("Source Code — Function/Class Definition", "Python, Java, JavaScript, C++, Go, Rust functions and classes", "🔴"),
# # # #         ("Source Code — Import Statements",         "import/require/using statements from any language",            "🔴"),
# # # #         ("Database Schema / SQL DDL",               "CREATE TABLE, ALTER TABLE, schema definitions",                "🔴"),
# # # #         ("Configuration / Environment File",        ".env files, DB connection strings, host/port/password configs","🔴"),
# # # #         ("API Endpoint / Internal URL",             "Internal API routes, private IPs, Bearer tokens in headers",  "🔴"),
# # # #         ("Infrastructure / DevOps Config",          "Kubernetes YAML, Dockerfile, Terraform, Nginx/Apache config",  "🔴"),
# # # #         ("Proprietary Business Logic Keywords",     "internal_use_only, confidential, proprietary markers",        "🟡"),
# # # #         ("Compiled / Binary File Content",          "ELF binaries, PE executables, hex dumps, base64 archives",    "🔴"),
# # # #     ]

# # # #     for cat, desc, icon in blocked_cats:
# # # #         weight = CATEGORY_WEIGHTS.get(cat, 25)
# # # #         with st.expander(f"{icon} {cat}  —  Risk Weight: {weight}"):
# # # #             st.write(desc)
# # # #             st.caption("MITRE ATT&CK: T1213 – Data from Information Repositories")

# # # #     st.divider()

# # # #     st.subheader("Blocked File Extensions")
# # # #     ext_cols = st.columns(6)
# # # #     sorted_exts = sorted(FILE_EXTENSION_BLOCK)
# # # #     per_col = len(sorted_exts) // 6 + 1
# # # #     for i, col in enumerate(ext_cols):
# # # #         chunk = sorted_exts[i*per_col:(i+1)*per_col]
# # # #         for e in chunk:
# # # #             col.markdown(f"`{e}`")

# # # #     st.divider()

# # # #     st.subheader("Live DLP Tester")
# # # #     test_input = st.text_area("Paste text to test", height=150, placeholder="Paste some text to see if DLP would block it...")

# # # #     if st.button("Test DLP Policy", use_container_width=True):
# # # #         if test_input.strip():
# # # #             result = scan_for_company_data(test_input)
# # # #             if result["verdict"] == "BLOCK":
# # # #                 st.error(f"BLOCKED — Score: {result['total_score']}  |  Categories: {result['category_count']}")
# # # #                 for f in result["findings"]:
# # # #                     with st.expander(f"🚫 {f['category']}  (line {f['line']})"):
# # # #                         st.code(f["snippet"], language="text")
# # # #                         st.caption(f"Risk weight: {f['weight']}")
# # # #             elif result["verdict"] == "WARN":
# # # #                 st.warning(f"WARNING — Score: {result['total_score']}  |  Code-like content detected.")
# # # #                 for f in result["findings"]:
# # # #                     with st.expander(f"⚠ {f['category']}"):
# # # #                         st.code(f["snippet"], language="text")
# # # #             else:
# # # #                 st.success("PASS — No policy violations detected. This text would be allowed.")

# # # #     st.divider()

# # # #     st.subheader("Policy Rules Summary")
# # # #     st.info(
# # # #         "Enforcement Points:\n"
# # # #         "- Prompt Analyzer — DLP checked before every scan\n"
# # # #         "- PII & Secrets Scanner — DLP checked before every scan\n"
# # # #         "- AI Security Assistant — DLP checked before sending to Gemini\n\n"
# # # #         "On violation: Input is blocked, user sees a policy message, event is logged."
# # # #     )

# # # #     with st.expander("What users CAN submit"):
# # # #         st.markdown("""
# # # # - Plain English descriptions of security problems
# # # # - Anonymised log snippets (no credentials, no internal IPs)
# # # # - Public CVE IDs or vulnerability names
# # # # - Generic attack patterns for testing
# # # # - Cybersecurity questions
# # # #         """)

# # # #     with st.expander("What users CANNOT submit"):
# # # #         st.markdown("""
# # # # - Source code files (.py, .js, .java, .cs, .go, etc.)
# # # # - Database schemas or SQL DDL statements
# # # # - .env files or configuration with real credentials
# # # # - Internal API endpoints or private IP addresses
# # # # - Kubernetes / Docker / Terraform infrastructure files
# # # # - Compiled binaries or hex dumps
# # # #         """)


# # # # # =========================================================
# # # # # MODULE 4 — ANALYTICS DASHBOARD
# # # # # =========================================================

# # # # elif menu == "📊 Analytics Dashboard":

# # # #     st.header("Threat Analytics Dashboard")

# # # #     df = load_logs()

# # # #     if df.empty:
# # # #         st.info("No scan logs yet. Run some prompts through the Prompt Analyzer first.")
# # # #         st.stop()

# # # #     total      = len(df)
# # # #     critical   = len(df[df["risk"] == "CRITICAL"])
# # # #     high       = len(df[df["risk"] == "HIGH"])
# # # #     safe_count = len(df[df["risk"] == "LOW"])

# # # #     c1, c2, c3, c4 = st.columns(4)
# # # #     c1.metric("Total Scans",      total)
# # # #     c2.metric("Critical Threats", critical)
# # # #     c3.metric("High Risk",        high)
# # # #     c4.metric("Safe Prompts",     safe_count)

# # # #     st.divider()

# # # #     col_a, col_b = st.columns(2)

# # # #     with col_a:
# # # #         st.subheader("Risk Distribution")
# # # #         risk_counts = df["risk"].value_counts().reset_index()
# # # #         risk_counts.columns = ["Risk Level", "Count"]
# # # #         fig_pie = px.pie(
# # # #             risk_counts,
# # # #             names="Risk Level",
# # # #             values="Count",
# # # #             color="Risk Level",
# # # #             color_discrete_map=RISK_COLORS,
# # # #             hole=0.4,
# # # #         )
# # # #         fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
# # # #         st.plotly_chart(fig_pie, use_container_width=True)

# # # #     with col_b:
# # # #         st.subheader("Threat Category Frequency")
# # # #         categories = ["XSS", "SQL Injection", "CSRF", "Prompt Injection", "Jailbreak", "SSRF", "Command Injection"]
# # # #         kw_map     = ["XSS", "SQL", "CSRF", "Prompt Injection", "Jailbreak", "SSRF", "Command"]
# # # #         counts = [len(df[df["findings"].str.contains(kw, case=False, na=False)]) for kw in kw_map]
# # # #         bar_df = pd.DataFrame({"Threat": categories, "Count": counts})
# # # #         fig_bar = px.bar(bar_df, x="Threat", y="Count", color="Count",
# # # #                          color_continuous_scale="Reds", text="Count")
# # # #         fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white", showlegend=False)
# # # #         st.plotly_chart(fig_bar, use_container_width=True)

# # # #     st.divider()

# # # #     st.subheader("Recent Attack Stream (last 10 scans)")
# # # #     for _, row in df.head(10).iterrows():
# # # #         ft  = str(row["findings"])
# # # #         ts  = row.get("timestamp", "")
# # # #         pfx = f"[{ts}] Prompt #{row['id']}"

# # # #         if "Prompt Injection" in ft:  st.error(f"Prompt Injection -> {pfx}")
# # # #         elif "Jailbreak"      in ft:  st.error(f"Jailbreak Attempt -> {pfx}")
# # # #         elif "XSS"            in ft:  st.error(f"XSS Attack -> {pfx}")
# # # #         elif "SQL"            in ft:  st.error(f"SQL Injection -> {pfx}")
# # # #         elif "CSRF"           in ft:  st.warning(f"CSRF Pattern -> {pfx}")
# # # #         elif "SSRF"           in ft:  st.warning(f"SSRF Activity -> {pfx}")
# # # #         elif ft == "[]":              st.success(f"Safe Request -> {pfx}")
# # # #         else:                         st.warning(f"Threat Detected -> {pfx}")

# # # #     st.divider()

# # # #     st.subheader("Full Scan Logs")
# # # #     st.dataframe(df, use_container_width=True)
# # # #     csv = df.to_csv(index=False)
# # # #     st.download_button("Download Logs (CSV)", data=csv,
# # # #                        file_name="promptshield_logs.csv", mime="text/csv")


# # # # # =========================================================
# # # # # MODULE 5 — AI SECURITY ASSISTANT (Enterprise Guardrail Pipeline)
# # # # # =========================================================

# # # # elif menu == "🤖 AI Security Assistant":

# # # #     # ---- Import the file guardrail ----
# # # #     from file_guardrail import run_file_guardrail, BLOCKED_EXTENSIONS, ALLOWED_EXTENSIONS

# # # #     st.header("AI Security Assistant")
# # # #     st.caption("Enterprise LLM Guardrail — File Upload + DLP + PII + Content Scan before every AI call")

# # # #     # ---- Policy notice ----
# # # #     st.info(
# # # #         "All inputs pass through a 5-stage guardrail pipeline before reaching the AI:\n"
# # # #         "**Stage 1** Extension Policy  →  **Stage 2** File Size  →  "
# # # #         "**Stage 3** Binary Detection  →  **Stage 4** Content Scan (secrets, PII, code, injection)  →  "
# # # #         "**Stage 5** Final Verdict\n\n"
# # # #         "Blocked uploads are logged. The AI never sees blocked content."
# # # #     )

# # # #     st.divider()

# # # #     # =========================================================
# # # #     # INPUT MODE SELECTOR
# # # #     # =========================================================

# # # #     input_mode = st.radio(
# # # #         "Input Mode",
# # # #         ["💬 Text Question", "📎 File Upload + Question"],
# # # #         horizontal=True,
# # # #     )

# # # #     st.divider()

# # # #     # =========================================================
# # # #     # MODE A — TEXT QUESTION
# # # #     # =========================================================

# # # #     if input_mode == "💬 Text Question":

# # # #         question = st.text_area(
# # # #             "Your Question",
# # # #             height=120,
# # # #             placeholder="e.g. What is a prompt injection attack? How does SSRF work?",
# # # #         )

# # # #         if st.button("Ask AI", use_container_width=False):
# # # #             if not question.strip():
# # # #                 st.warning("Please enter a question.")
# # # #                 st.stop()

# # # #             # Run DLP on text question too
# # # #             from dlp_guard import scan_for_company_data, get_dlp_message
# # # #             from pii_scanner import scan_all as pii_scan_all

# # # #             with st.spinner("Running guardrail checks on your input..."):
# # # #                 dlp_result = scan_for_company_data(question)
# # # #                 pii_result = pii_scan_all(question)

# # # #             # Show guardrail pipeline status
# # # #             st.subheader("Guardrail Pipeline Result")
# # # #             g1, g2, g3 = st.columns(3)

# # # #             dlp_pass = not dlp_result["blocked"]
# # # #             pii_pass = pii_result["risk"] in ("CLEAN", "MEDIUM")

# # # #             g1.metric("DLP Policy", "PASS" if dlp_pass else "BLOCK",
# # # #                       delta=None)
# # # #             g2.metric("Secret Scan", "PASS" if pii_result["secret_count"] == 0 else "BLOCK",
# # # #                       delta=None)
# # # #             g3.metric("PII Scan", f"{pii_result['pii_count']} found",
# # # #                       delta=None)

# # # #             # Block if DLP or secrets detected
# # # #             if dlp_result["blocked"]:
# # # #                 st.error(get_dlp_message(dlp_result))
# # # #                 with st.expander("DLP Detection Details"):
# # # #                     for f in dlp_result["findings"]:
# # # #                         st.write(f"**{f['category']}** — Line {f['line']}: `{f['snippet']}`")
# # # #                 st.stop()

# # # #             if pii_result["secret_count"] > 0:
# # # #                 st.error(
# # # #                     "🚫 **Secret / Credential Detected — Blocked**\n\n"
# # # #                     "Your question contains API keys, tokens, or passwords. "
# # # #                     "Never submit credentials to an AI system.\n\n"
# # # #                     f"**Detected:** {', '.join(s['category'] for s in pii_result['secrets'])}\n\n"
# # # #                     "*This attempt has been logged.*"
# # # #                 )
# # # #                 st.stop()

# # # #             if pii_result["pii_count"] > 0:
# # # #                 st.warning(
# # # #                     f"⚠️ PII detected in your question ({pii_result['pii_count']} type(s)). "
# # # #                     "The question will be sent to AI but please avoid including personal data."
# # # #                 )

# # # #             st.success("✅ All guardrail checks passed — sending to AI...")
# # # #             st.divider()

# # # #             with st.spinner("AI is analyzing..."):
# # # #                 answer = ask_ai(question)

# # # #             st.subheader("AI Response")
# # # #             st.success(answer)


# # # #     # =========================================================
# # # #     # MODE B — FILE UPLOAD + QUESTION
# # # #     # =========================================================

# # # #     else:

# # # #         # ---- Allowed / Blocked extension info ----
# # # #         with st.expander("📋 File Upload Policy — What is allowed?"):
# # # #             col_allow, col_block = st.columns(2)
# # # #             with col_allow:
# # # #                 st.markdown("**✅ Allowed Extensions**")
# # # #                 for ext in sorted(ALLOWED_EXTENSIONS):
# # # #                     st.markdown(f"- `{ext}`")
# # # #                 st.caption("Content is still scanned even for allowed types.")
# # # #             with col_block:
# # # #                 st.markdown("**🚫 Blocked Extensions (examples)**")
# # # #                 sample_blocked = sorted(list(BLOCKED_EXTENSIONS))[:20]
# # # #                 for ext in sample_blocked:
# # # #                     st.markdown(f"- `{ext}`")
# # # #                 st.caption(f"...and {len(BLOCKED_EXTENSIONS) - 20} more. No source code, config, or binary files.")

# # # #         st.divider()

# # # #         # ---- File uploader ----
# # # #         uploaded_file = st.file_uploader(
# # # #             "Upload a file to analyze with AI",
# # # #             type=None,   # We do manual extension validation
# # # #             help=f"Max size: 5 MB. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
# # # #         )

# # # #         question = st.text_area(
# # # #             "Your question about this file",
# # # #             height=100,
# # # #             placeholder="e.g. Summarize this document. What are the key risks mentioned?",
# # # #         )

# # # #         analyze_btn = st.button("🔍 Run Guardrail & Analyze", use_container_width=True)

# # # #         if analyze_btn:

# # # #             if uploaded_file is None:
# # # #                 st.warning("Please upload a file first.")
# # # #                 st.stop()

# # # #             if not question.strip():
# # # #                 st.warning("Please enter a question about the file.")
# # # #                 st.stop()

# # # #             file_bytes = uploaded_file.read()
# # # #             filename   = uploaded_file.name

# # # #             # ============================================================
# # # #             # ENTERPRISE GUARDRAIL PIPELINE
# # # #             # ============================================================

# # # #             st.divider()
# # # #             st.subheader("🔒 Guardrail Pipeline Executing...")

# # # #             with st.spinner("Running 5-stage enterprise security scan..."):
# # # #                 result = run_file_guardrail(filename, file_bytes)

# # # #             # ---- Stage-by-stage status display ----
# # # #             st.subheader("Pipeline Stages")

# # # #             stage_icons = {
# # # #                 "PASS": "✅", "BLOCK": "🚫", "WARN": "⚠️", "SKIP": "⏭️"
# # # #             }

# # # #             cols = st.columns(len(result["stages"]))
# # # #             for i, stage in enumerate(result["stages"]):
# # # #                 s = stage["result"]
# # # #                 verdict_key = (
# # # #                     "BLOCK" if s.get("passed") == False or s.get("is_binary") or s.get("blocked")
# # # #                     else "WARN" if s.get("verdict") == "WARN"
# # # #                     else "SKIP" if s.get("verdict") == "SKIP"
# # # #                     else "PASS"
# # # #                 )
# # # #                 icon = stage_icons.get(verdict_key, "✅")
# # # #                 with cols[i]:
# # # #                     st.metric(
# # # #                         label=stage["name"],
# # # #                         value=f"{icon} {verdict_key}",
# # # #                     )

# # # #             st.divider()

# # # #             # ---- BLOCKED ----
# # # #             if result["blocked"]:
# # # #                 st.error(
# # # #                     f"🚫 **FILE BLOCKED — DLP Policy Violation**\n\n"
# # # #                     f"{result['summary']}\n\n"
# # # #                     f"**File:** `{filename}`\n"
# # # #                     f"**SHA-256:** `{result['file_hash'][:16]}...`\n\n"
# # # #                     f"*This upload attempt has been logged in the audit trail.*"
# # # #                 )

# # # #                 if result["findings"]:
# # # #                     st.subheader("Detected Violations")
# # # #                     for f in result["findings"]:
# # # #                         with st.expander(f"🚫 {f['category']}  (Line {f['line']})"):
# # # #                             st.code(f["snippet"], language="text")
# # # #                             st.caption(f"Risk Weight: {f['weight']} pts  |  MITRE: {f['mitre']}")

# # # #                 st.divider()
# # # #                 st.subheader("What you can do instead")
# # # #                 st.info(
# # # #                     "- **Describe the problem in plain English** — do not upload the file\n"
# # # #                     "- **Remove all credentials, internal URLs, and code** from the file first\n"
# # # #                     "- **Use an anonymised version** with real values replaced by placeholders\n"
# # # #                     "- **Contact your security team** if you believe this is a false positive"
# # # #                 )
# # # #                 st.stop()

# # # #             # ---- WARNINGS (pass but with notices) ----
# # # #             if result["verdict"] == "WARN" and result["findings"]:
# # # #                 st.warning(
# # # #                     f"⚠️ **File passed with {len(result['findings'])} warning(s)** — "
# # # #                     f"review findings below before proceeding."
# # # #                 )
# # # #                 for f in result["findings"]:
# # # #                     with st.expander(f"⚠️ {f['category']}  (Line {f['line']})"):
# # # #                         st.code(f["snippet"], language="text")
# # # #                         st.caption(f"Risk Weight: {f['weight']} pts  |  MITRE: {f['mitre']}")
# # # #                 st.divider()

# # # #             # ---- PASS — send to Gemini ----
# # # #             st.success(f"✅ File cleared all guardrail stages — sending to AI")

# # # #             # Show file metadata
# # # #             size_kb = len(file_bytes) / 1024
# # # #             m1, m2, m3, m4 = st.columns(4)
# # # #             m1.metric("File",      filename)
# # # #             m2.metric("Size",      f"{size_kb:.1f} KB")
# # # #             m3.metric("Hash",      result["file_hash"][:8] + "...")
# # # #             m4.metric("Status",    "CLEARED")

# # # #             st.divider()
# # # #             st.subheader("AI Analysis")

# # # #             # Build prompt for Gemini — include file content summary
# # # #             file_text = result.get("text", "")
# # # #             if file_text:
# # # #                 char_limit = 8000
# # # #                 content_preview = file_text[:char_limit]
# # # #                 if len(file_text) > char_limit:
# # # #                     content_preview += f"\n\n[File truncated — showing first {char_limit} chars of {len(file_text)} total]"

# # # #                 gemini_prompt = (
# # # #                     f"The user has uploaded a file named '{filename}'.\n"
# # # #                     f"File contents:\n---\n{content_preview}\n---\n\n"
# # # #                     f"User question: {question}"
# # # #                 )
# # # #             else:
# # # #                 gemini_prompt = (
# # # #                     f"The user has uploaded a binary/image file named '{filename}' "
# # # #                     f"({size_kb:.1f} KB). They ask: {question}"
# # # #                 )

# # # #             with st.spinner("AI is reading and analyzing the file..."):
# # # #                 answer = ask_ai(gemini_prompt)

# # # #             st.success(answer)

# # # #             # Audit entry
# # # #             with st.expander("Audit Trail"):
# # # #                 st.json({
# # # #                     "filename":    filename,
# # # #                     "file_hash":   result["file_hash"],
# # # #                     "size_bytes":  len(file_bytes),
# # # #                     "verdict":     result["verdict"],
# # # #                     "stages":      [s["name"] for s in result["stages"]],
# # # #                     "warnings":    len(result["findings"]),
# # # #                     "question":    question[:100] + "..." if len(question) > 100 else question,
# # # #                 })

# # # # # # MODULE 6 — LIVE CVE THREAT FEED
# # # # # =========================================================

# # # # elif menu == "🌐 CVE Threat Feed":

# # # #     st.header("Live CVE Threat Intelligence Feed")
# # # #     st.write("Latest Common Vulnerabilities and Exposures — sourced from CIRCL vulnerability-lookup.")

# # # #     if st.button("Refresh Feed"):
# # # #         st.rerun()

# # # #     CIRCL_ENDPOINTS = [
# # # #         "https://cve.circl.lu/api/last",
# # # #         "https://vulnerability.circl.lu/api/last",
# # # #         "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=15",
# # # #     ]

# # # #     cves = None
# # # #     error_msg = None

# # # #     def _extract_list(data):
# # # #         if isinstance(data, list):
# # # #             return data if data else None
# # # #         if isinstance(data, dict):
# # # #             for key in ("results", "data", "cves"):
# # # #                 val = data.get(key)
# # # #                 if isinstance(val, list) and val:
# # # #                     return val
# # # #             nvd_vulns = data.get("vulnerabilities")
# # # #             if isinstance(nvd_vulns, list) and nvd_vulns:
# # # #                 return [v.get("cve", v) for v in nvd_vulns]
# # # #             for val in data.values():
# # # #                 if isinstance(val, list) and val:
# # # #                     return val
# # # #         return None

# # # #     with st.spinner("Fetching latest CVEs..."):
# # # #         for url in CIRCL_ENDPOINTS:
# # # #             try:
# # # #                 resp = requests.get(url, timeout=12, headers={"Accept": "application/json"})
# # # #                 if resp.status_code == 200:
# # # #                     cves = _extract_list(resp.json())
# # # #                     if cves:
# # # #                         break
# # # #             except Exception as e:
# # # #                 error_msg = str(e)
# # # #                 continue

# # # #     if cves:
# # # #         shown = 0
# # # #         for raw in cves:
# # # #             if shown >= 15:
# # # #                 break
# # # #             entry = parse_cve(raw)
# # # #             if entry["cve_id"] == "Unknown CVE" and entry["summary"] == "No summary available.":
# # # #                 continue

# # # #             cvss  = entry["cvss"]
# # # #             label = f"**{entry['cve_id']}**"
# # # #             label += f" | CVSS: {cvss:.1f}" if cvss is not None else " | CVSS: N/A"
# # # #             text  = f"{label}\n\n{entry['summary']}"

# # # #             if cvss is not None and cvss >= 9.0:   st.error(f"🚨 {text}")
# # # #             elif cvss is not None and cvss >= 7.0: st.warning(f"⚠️ {text}")
# # # #             elif cvss is not None and cvss >= 4.0: st.info(f"🔵 {text}")
# # # #             else:                                   st.info(f"ℹ️ {text}")
# # # #             shown += 1

# # # #         if shown == 0:
# # # #             st.warning("Feed returned data but no readable CVE entries could be parsed.")
# # # #             with st.expander("Raw API response (first entry)"):
# # # #                 st.json(cves[0] if cves else {})
# # # #         else:
# # # #             with st.expander("Debug: raw first entry"):
# # # #                 st.json(cves[0] if cves else {})
# # # #     else:
# # # #         st.warning("Live CVE feed could not be reached. Showing recent notable CVEs instead.")
# # # #         st.divider()
# # # #         st.subheader("Recent Notable CVEs (static reference)")

# # # #         static_cves = [
# # # #             {"id": "CVE-2025-21413", "cvss": 9.8, "color": "error",
# # # #              "desc": "Windows Telephony Service RCE — attacker can execute arbitrary code remotely without authentication.",
# # # #              "mitre": "T1190 – Exploit Public-Facing Application"},
# # # #             {"id": "CVE-2025-21418", "cvss": 7.8, "color": "warning",
# # # #              "desc": "Windows Ancillary Function Driver privilege escalation — local attacker gains SYSTEM privileges.",
# # # #              "mitre": "T1068 – Exploitation for Privilege Escalation"},
# # # #             {"id": "CVE-2024-49138", "cvss": 7.8, "color": "warning",
# # # #              "desc": "Windows CLFS Driver heap buffer overflow enabling local privilege escalation. Actively exploited.",
# # # #              "mitre": "T1068 – Exploitation for Privilege Escalation"},
# # # #             {"id": "CVE-2024-38812", "cvss": 9.8, "color": "error",
# # # #              "desc": "VMware vCenter Server heap overflow via DCERPC — unauthenticated remote code execution.",
# # # #              "mitre": "T1190 – Exploit Public-Facing Application"},
# # # #             {"id": "CVE-2024-6387 (regreSSHion)", "cvss": 8.1, "color": "warning",
# # # #              "desc": "OpenSSH race condition allowing unauthenticated RCE as root on glibc-based Linux systems.",
# # # #              "mitre": "T1190 – Exploit Public-Facing Application"},
# # # #         ]

# # # #         for cve in static_cves:
# # # #             msg = f"**{cve['id']}** | CVSS: {cve['cvss']}\n\n{cve['desc']}\n\nMITRE: {cve['mitre']}"
# # # #             if cve["color"] == "error":
# # # #                 st.error(msg)
# # # #             else:
# # # #                 st.warning(msg)

# # # #         st.caption("Source: NVD / Microsoft MSRC / Apple Security. Refresh or check https://cve.circl.lu for live data.")
# # # import streamlit as st
# # # import pandas as pd
# # # import sqlite3
# # # import plotly.express as px
# # # import requests

# # # from detector import detect_prompt
# # # from scorer import calculate_risk
# # # from database import init_db, insert_log
# # # from ai_engine import generate_ai_explanation
# # # from auth import login, logout
# # # from report_generator import generate_pdf
# # # from chatbot import ask_ai
# # # from pii_scanner import scan_all
# # # from dlp_guard import scan_for_company_data, check_file_extension, get_dlp_message

# # # REPORT_PATH = "PromptShield_Report.pdf"

# # # # =========================================================
# # # # BOOTSTRAP
# # # # =========================================================

# # # init_db()

# # # st.set_page_config(
# # #     page_title="PromptShield AI",
# # #     page_icon="🛡️",
# # #     layout="wide",
# # # )

# # # # =========================================================
# # # # AUTH GATE
# # # # =========================================================

# # # if "authenticated" not in st.session_state:
# # #     st.session_state["authenticated"] = False

# # # if not st.session_state["authenticated"]:
# # #     login()
# # #     st.stop()

# # # # =========================================================
# # # # CUSTOM THEME
# # # # =========================================================

# # # st.markdown("""
# # # <style>
# # # .main { background-color: #0E1117; color: white; }
# # # h1, h2, h3 { color: #00FFAA; }
# # # .stButton>button {
# # #     background-color: #00FFAA;
# # #     color: black;
# # #     font-weight: bold;
# # #     border-radius: 8px;
# # #     height: 46px;
# # #     min-width: 180px;
# # # }
# # # .stTextArea textarea { background-color: #1A1A2E; color: white; }
# # # </style>
# # # """, unsafe_allow_html=True)

# # # # =========================================================
# # # # HEADER
# # # # =========================================================

# # # col_title, col_logout = st.columns([5, 1])
# # # with col_title:
# # #     st.title("🛡️ PromptShield AI")
# # #     st.caption("LLM Guardrail Engine — Real-Time Threat Detection & Policy Enforcement")
# # # with col_logout:
# # #     st.write("")
# # #     if st.button("Logout"):
# # #         logout()

# # # st.divider()

# # # # =========================================================
# # # # SIDEBAR NAVIGATION
# # # # =========================================================

# # # st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
# # # st.sidebar.title("Navigation")

# # # menu = st.sidebar.radio(
# # #     "Select Module",
# # #     ["🔍 Prompt Analyzer", "🔏 PII & Secrets Scanner", "🚫 DLP Policy", "📊 Analytics Dashboard", "🤖 AI Security Assistant", "🌐 CVE Threat Feed"],
# # # )

# # # # =========================================================
# # # # HELPERS
# # # # =========================================================

# # # def load_logs() -> pd.DataFrame:
# # #     conn = sqlite3.connect("prompts.db")
# # #     df = pd.read_sql_query("SELECT * FROM logs ORDER BY id DESC", conn)
# # #     conn.close()
# # #     return df


# # # RISK_COLORS = {
# # #     "LOW":      "#00FFAA",
# # #     "MEDIUM":   "#FFD700",
# # #     "HIGH":     "#FF6B35",
# # #     "CRITICAL": "#FF3333",
# # # }


# # # def parse_cve(item: dict) -> dict:
# # #     if not isinstance(item, dict):
# # #         return {"cve_id": "Unknown CVE", "summary": "No summary available.", "cvss": None}

# # #     cve_id = (
# # #         item.get("id")
# # #         or item.get("cveId")
# # #         or (item.get("CVE_data_meta") or {}).get("ID")
# # #         or "Unknown CVE"
# # #     )

# # #     summary = item.get("summary") or ""
# # #     if not summary:
# # #         summary = item.get("details") or ""
# # #     if not summary:
# # #         desc_field = item.get("description")
# # #         if isinstance(desc_field, str):
# # #             summary = desc_field
# # #     if not summary:
# # #         descs = item.get("descriptions")
# # #         if not descs and isinstance(item.get("description"), dict):
# # #             descs = item["description"].get("description_data", [])
# # #         if isinstance(descs, list):
# # #             for d in descs:
# # #                 if isinstance(d, dict) and d.get("lang", "").startswith("en"):
# # #                     summary = d.get("value", "")
# # #                     break
# # #             if not summary and descs:
# # #                 first = descs[0]
# # #                 summary = first.get("value", "") if isinstance(first, dict) else str(first)
# # #     if not summary:
# # #         aliases = item.get("aliases", [])
# # #         if aliases and isinstance(aliases, list):
# # #             summary = f"See advisory: {', '.join(str(a) for a in aliases[:3])}"

# # #     summary = (summary or "No summary available.").strip()
# # #     if len(summary) > 450:
# # #         summary = summary[:447] + "..."

# # #     cvss = None
# # #     for field in ("cvss", "cvss3", "cvssScore", "baseScore", "score"):
# # #         val = item.get(field)
# # #         if val is not None:
# # #             try:
# # #                 cvss = float(val)
# # #                 break
# # #             except (ValueError, TypeError):
# # #                 pass

# # #     if cvss is None:
# # #         severity_list = item.get("severity") or []
# # #         if isinstance(severity_list, list):
# # #             for s in severity_list:
# # #                 if isinstance(s, dict):
# # #                     raw = s.get("score") or s.get("baseScore")
# # #                     try:
# # #                         cvss = float(raw); break
# # #                     except (ValueError, TypeError):
# # #                         pass
# # #         elif isinstance(severity_list, (int, float)):
# # #             try:
# # #                 cvss = float(severity_list)
# # #             except (ValueError, TypeError):
# # #                 pass

# # #     if cvss is None:
# # #         metrics = item.get("metrics") or {}
# # #         if isinstance(metrics, dict):
# # #             for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
# # #                 entries = metrics.get(key, [])
# # #                 if isinstance(entries, list) and entries:
# # #                     raw = (entries[0].get("cvssData") or {}).get("baseScore")
# # #                     try:
# # #                         cvss = float(raw); break
# # #                     except (ValueError, TypeError):
# # #                         pass

# # #     try:
# # #         cvss = float(cvss) if cvss is not None else None
# # #     except (ValueError, TypeError):
# # #         cvss = None

# # #     return {"cve_id": cve_id, "summary": summary, "cvss": cvss}


# # # # =========================================================
# # # # MODULE 1 — PROMPT ANALYZER
# # # # =========================================================

# # # if menu == "🔍 Prompt Analyzer":

# # #     st.header("Prompt Analyzer")
# # #     st.write("Paste any prompt below to scan it for injection, jailbreak, and other attack patterns.")

# # #     prompt = st.text_area("Enter Prompt to Analyze", height=200, placeholder="Paste suspicious prompt here...")

# # #     if st.button("🔎 Analyze Prompt"):

# # #         if not prompt.strip():
# # #             st.warning("Please enter a prompt before analyzing.")
# # #             st.stop()

# # #         dlp = scan_for_company_data(prompt)
# # #         if dlp["blocked"]:
# # #             st.error(get_dlp_message(dlp))
# # #             st.divider()
# # #             st.subheader("DLP Detection Details")
# # #             for f in dlp["findings"]:
# # #                 with st.expander(f"🚫 {f['category']}  (line {f['line']})"):
# # #                     st.code(f["snippet"], language="text")
# # #                     st.caption(f"Risk weight: {f['weight']} pts")
# # #             st.info("Tip: Describe your problem in plain English. Do not paste source code, config files, credentials, or internal URLs.")
# # #             st.stop()
# # #         elif dlp["verdict"] == "WARN":
# # #             st.warning(f"DLP Warning — {dlp['category_count']} suspicious pattern(s) detected (code-like content). Proceed only if this is intentional test data.")

# # #         with st.spinner("Scanning for threats..."):
# # #             findings = detect_prompt(prompt)
# # #             score, risk, severity, confidence = calculate_risk(findings)
# # #             insert_log(prompt, str(findings), score, risk)

# # #         st.divider()
# # #         st.subheader("Analysis Result")

# # #         c1, c2, c3, c4 = st.columns(4)
# # #         c1.metric("Risk Score",        score)
# # #         c2.metric("Risk Level",        risk)
# # #         c3.metric("Severity",          severity)
# # #         c4.metric("Threat Confidence", confidence)

# # #         st.divider()

# # #         if risk == "CRITICAL":
# # #             st.error("SOC ALERT — Critical malicious payload detected! Immediate action required.")
# # #         elif risk == "HIGH":
# # #             st.warning("HIGH RISK — Suspicious activity detected. Review and block.")
# # #         elif risk == "MEDIUM":
# # #             st.info("MEDIUM RISK — Potential threat activity observed. Monitor closely.")
# # #         else:
# # #             st.success("Prompt appears safe. No malicious patterns matched.")

# # #         if findings:
# # #             generate_pdf(prompt, findings, score, risk)
# # #             with open(REPORT_PATH, "rb") as f:
# # #                 st.download_button(
# # #                     "📄 Download Security Report (PDF)",
# # #                     data=f,
# # #                     file_name="PromptShield_Report.pdf",
# # #                     mime="application/pdf",
# # #                 )

# # #             st.divider()
# # #             st.subheader("AI Threat Analysis")
# # #             with st.spinner("Generating AI analysis..."):
# # #                 explanations = generate_ai_explanation(findings)
# # #             for exp in explanations:
# # #                 st.warning(exp)

# # #             st.divider()
# # #             st.subheader("Detected Threats")
# # #             for item in findings:
# # #                 with st.expander(f"🔴 {item['category']}"):
# # #                     st.write(f"**Matched Pattern:** `{item['pattern']}`")
# # #                     st.info(f"**MITRE ATT&CK:** {item.get('mitre', 'N/A')}")

# # #             st.divider()
# # #             st.subheader("Recommended Actions")
# # #             recs = [
# # #                 "Block this prompt from reaching the LLM immediately.",
# # #                 "Enable strict input validation and sanitization.",
# # #                 "Apply Web Application Firewall (WAF) rules.",
# # #                 "Alert the SOC team and create an incident ticket.",
# # #                 "Review recent logs for similar patterns.",
# # #                 "Rotate any secrets or credentials that may have been exposed.",
# # #             ]
# # #             for rec in recs:
# # #                 st.success(f"✔ {rec}")
# # #         else:
# # #             st.success("Prompt is Safe — no malicious patterns detected.")


# # # # =========================================================
# # # # MODULE 2 — PII & SECRETS SCANNER
# # # # =========================================================

# # # elif menu == "🔏 PII & Secrets Scanner":

# # #     st.header("PII & Secrets Scanner")
# # #     st.write("Detect Personally Identifiable Information (PII) and leaked credentials inside any text.")

# # #     text_input = st.text_area(
# # #         "Paste text to scan",
# # #         height=220,
# # #         placeholder="Paste any text here — emails, phone numbers, API keys, tokens, passwords, etc.",
# # #     )

# # #     col_scan, col_clear = st.columns([2, 1])
# # #     with col_scan:
# # #         scan_clicked = st.button("🔍 Scan for PII & Secrets", use_container_width=True)
# # #     with col_clear:
# # #         if st.button("Clear", use_container_width=True):
# # #             st.rerun()

# # #     if scan_clicked:
# # #         if not text_input.strip():
# # #             st.warning("Please paste some text to scan.")
# # #             st.stop()

# # #         dlp = scan_for_company_data(text_input)
# # #         if dlp["blocked"]:
# # #             st.error(get_dlp_message(dlp))
# # #             for f in dlp["findings"]:
# # #                 with st.expander(f"🚫 {f['category']}"):
# # #                     st.code(f["snippet"], language="text")
# # #             st.stop()

# # #         with st.spinner("Scanning for PII and secrets..."):
# # #             result = scan_all(text_input)

# # #         st.divider()

# # #         risk = result["risk"]
# # #         risk_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "CLEAN": "🟢"}
# # #         icon = risk_icons.get(risk, "⚪")

# # #         c1, c2, c3, c4 = st.columns(4)
# # #         c1.metric("PII Found",      result["pii_count"])
# # #         c2.metric("Secrets Found",  result["secret_count"])
# # #         c3.metric("Total Findings", result["total"])
# # #         c4.metric("Risk Level",     f"{icon} {risk}")

# # #         st.divider()

# # #         if risk == "CRITICAL":
# # #             st.error("CRITICAL — API keys or credentials detected! Rotate them immediately.")
# # #         elif risk == "HIGH":
# # #             st.warning("HIGH RISK — Multiple PII fields detected. Review before sharing.")
# # #         elif risk == "MEDIUM":
# # #             st.info("MEDIUM — PII detected. Ensure data handling complies with your policy.")
# # #         else:
# # #             st.success("CLEAN — No PII or secrets detected in this text.")

# # #         if result["pii"]:
# # #             st.subheader("PII Detections")
# # #             for item in result["pii"]:
# # #                 with st.expander(f"🟡 {item['category']}  x{item['count']} found"):
# # #                     st.write(f"**Sample (redacted):** `{item['matched_value']}`")
# # #                     st.info(f"**MITRE ATT&CK:** {item['mitre']}")

# # #         if result["secrets"]:
# # #             st.subheader("Credential / Secret Detections")
# # #             for item in result["secrets"]:
# # #                 with st.expander(f"🔴 {item['category']}  x{item['count']} found"):
# # #                     st.write(f"**Sample (redacted):** `{item['matched_value']}`")
# # #                     st.error(f"**MITRE ATT&CK:** {item['mitre']}")
# # #                     st.caption("Action required: Rotate this credential immediately.")

# # #         if result["total"] > 0:
# # #             st.divider()
# # #             st.subheader("Recommended Actions")
# # #             if result["secrets"]:
# # #                 st.error("Rotate all detected API keys and tokens immediately.")
# # #                 st.error("Check access logs for unauthorized use of these credentials.")
# # #                 st.error("Store secrets in environment variables — never in prompts.")
# # #             if result["pii"]:
# # #                 st.info("Apply data masking before sending text to any AI system.")
# # #                 st.info("Review your data retention policies for GDPR/DPDP compliance.")
# # #                 st.info("Implement a pre-processing filter to strip PII before it reaches the LLM.")


# # # # =========================================================
# # # # MODULE 3 — DLP POLICY MANAGER
# # # # =========================================================

# # # elif menu == "🚫 DLP Policy":

# # #     st.header("Data Loss Prevention (DLP) Policy")
# # #     st.write("Configure what types of content are blocked. All inputs pass through this policy engine before processing.")

# # #     st.divider()

# # #     c1, c2, c3 = st.columns(3)
# # #     c1.metric("DLP Status",           "ACTIVE")
# # #     c2.metric("Categories Monitored", "8")
# # #     c3.metric("File Types Blocked",   "30+")

# # #     st.divider()

# # #     st.subheader("Blocked Content Categories")
# # #     from dlp_guard import CODE_PATTERNS, FILE_EXTENSION_BLOCK, CATEGORY_WEIGHTS

# # #     blocked_cats = [
# # #         ("Source Code — Function/Class Definition", "Python, Java, JavaScript, C++, Go, Rust functions and classes", "🔴"),
# # #         ("Source Code — Import Statements",         "import/require/using statements from any language",            "🔴"),
# # #         ("Database Schema / SQL DDL",               "CREATE TABLE, ALTER TABLE, schema definitions",                "🔴"),
# # #         ("Configuration / Environment File",        ".env files, DB connection strings, host/port/password configs","🔴"),
# # #         ("API Endpoint / Internal URL",             "Internal API routes, private IPs, Bearer tokens in headers",  "🔴"),
# # #         ("Infrastructure / DevOps Config",          "Kubernetes YAML, Dockerfile, Terraform, Nginx/Apache config",  "🔴"),
# # #         ("Proprietary Business Logic Keywords",     "internal_use_only, confidential, proprietary markers",        "🟡"),
# # #         ("Compiled / Binary File Content",          "ELF binaries, PE executables, hex dumps, base64 archives",    "🔴"),
# # #     ]

# # #     for cat, desc, icon in blocked_cats:
# # #         weight = CATEGORY_WEIGHTS.get(cat, 25)
# # #         with st.expander(f"{icon} {cat}  —  Risk Weight: {weight}"):
# # #             st.write(desc)
# # #             st.caption("MITRE ATT&CK: T1213 – Data from Information Repositories")

# # #     st.divider()

# # #     st.subheader("Blocked File Extensions")
# # #     ext_cols = st.columns(6)
# # #     sorted_exts = sorted(FILE_EXTENSION_BLOCK)
# # #     per_col = len(sorted_exts) // 6 + 1
# # #     for i, col in enumerate(ext_cols):
# # #         chunk = sorted_exts[i*per_col:(i+1)*per_col]
# # #         for e in chunk:
# # #             col.markdown(f"`{e}`")

# # #     st.divider()

# # #     st.subheader("Live DLP Tester")
# # #     test_input = st.text_area("Paste text to test", height=150, placeholder="Paste some text to see if DLP would block it...")

# # #     if st.button("Test DLP Policy", use_container_width=True):
# # #         if test_input.strip():
# # #             result = scan_for_company_data(test_input)
# # #             if result["verdict"] == "BLOCK":
# # #                 st.error(f"BLOCKED — Score: {result['total_score']}  |  Categories: {result['category_count']}")
# # #                 for f in result["findings"]:
# # #                     with st.expander(f"🚫 {f['category']}  (line {f['line']})"):
# # #                         st.code(f["snippet"], language="text")
# # #                         st.caption(f"Risk weight: {f['weight']}")
# # #             elif result["verdict"] == "WARN":
# # #                 st.warning(f"WARNING — Score: {result['total_score']}  |  Code-like content detected.")
# # #                 for f in result["findings"]:
# # #                     with st.expander(f"⚠ {f['category']}"):
# # #                         st.code(f["snippet"], language="text")
# # #             else:
# # #                 st.success("PASS — No policy violations detected. This text would be allowed.")

# # #     st.divider()

# # #     st.subheader("Policy Rules Summary")
# # #     st.info(
# # #         "Enforcement Points:\n"
# # #         "- Prompt Analyzer — DLP checked before every scan\n"
# # #         "- PII & Secrets Scanner — DLP checked before every scan\n"
# # #         "- AI Security Assistant — DLP checked before sending to Gemini\n\n"
# # #         "On violation: Input is blocked, user sees a policy message, event is logged."
# # #     )

# # #     with st.expander("What users CAN submit"):
# # #         st.markdown("""
# # # - Plain English descriptions of security problems
# # # - Anonymised log snippets (no credentials, no internal IPs)
# # # - Public CVE IDs or vulnerability names
# # # - Generic attack patterns for testing
# # # - Cybersecurity questions
# # #         """)

# # #     with st.expander("What users CANNOT submit"):
# # #         st.markdown("""
# # # - Source code files (.py, .js, .java, .cs, .go, etc.)
# # # - Database schemas or SQL DDL statements
# # # - .env files or configuration with real credentials
# # # - Internal API endpoints or private IP addresses
# # # - Kubernetes / Docker / Terraform infrastructure files
# # # - Compiled binaries or hex dumps
# # #         """)


# # # # =========================================================
# # # # MODULE 4 — ANALYTICS DASHBOARD
# # # # =========================================================

# # # elif menu == "📊 Analytics Dashboard":

# # #     st.header("Threat Analytics Dashboard")

# # #     df = load_logs()

# # #     if df.empty:
# # #         st.info("No scan logs yet. Run some prompts through the Prompt Analyzer first.")
# # #         st.stop()

# # #     total      = len(df)
# # #     critical   = len(df[df["risk"] == "CRITICAL"])
# # #     high       = len(df[df["risk"] == "HIGH"])
# # #     safe_count = len(df[df["risk"] == "LOW"])

# # #     c1, c2, c3, c4 = st.columns(4)
# # #     c1.metric("Total Scans",      total)
# # #     c2.metric("Critical Threats", critical)
# # #     c3.metric("High Risk",        high)
# # #     c4.metric("Safe Prompts",     safe_count)

# # #     st.divider()

# # #     col_a, col_b = st.columns(2)

# # #     with col_a:
# # #         st.subheader("Risk Distribution")
# # #         risk_counts = df["risk"].value_counts().reset_index()
# # #         risk_counts.columns = ["Risk Level", "Count"]
# # #         fig_pie = px.pie(
# # #             risk_counts,
# # #             names="Risk Level",
# # #             values="Count",
# # #             color="Risk Level",
# # #             color_discrete_map=RISK_COLORS,
# # #             hole=0.4,
# # #         )
# # #         fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
# # #         st.plotly_chart(fig_pie, use_container_width=True)

# # #     with col_b:
# # #         st.subheader("Threat Category Frequency")
# # #         categories = ["XSS", "SQL Injection", "CSRF", "Prompt Injection", "Jailbreak", "SSRF", "Command Injection"]
# # #         kw_map     = ["XSS", "SQL", "CSRF", "Prompt Injection", "Jailbreak", "SSRF", "Command"]
# # #         counts = [len(df[df["findings"].str.contains(kw, case=False, na=False)]) for kw in kw_map]
# # #         bar_df = pd.DataFrame({"Threat": categories, "Count": counts})
# # #         fig_bar = px.bar(bar_df, x="Threat", y="Count", color="Count",
# # #                          color_continuous_scale="Reds", text="Count")
# # #         fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white", showlegend=False)
# # #         st.plotly_chart(fig_bar, use_container_width=True)

# # #     st.divider()

# # #     st.subheader("Recent Attack Stream (last 10 scans)")
# # #     for _, row in df.head(10).iterrows():
# # #         ft  = str(row["findings"])
# # #         ts  = row.get("timestamp", "")
# # #         pfx = f"[{ts}] Prompt #{row['id']}"

# # #         if "Prompt Injection" in ft:  st.error(f"Prompt Injection -> {pfx}")
# # #         elif "Jailbreak"      in ft:  st.error(f"Jailbreak Attempt -> {pfx}")
# # #         elif "XSS"            in ft:  st.error(f"XSS Attack -> {pfx}")
# # #         elif "SQL"            in ft:  st.error(f"SQL Injection -> {pfx}")
# # #         elif "CSRF"           in ft:  st.warning(f"CSRF Pattern -> {pfx}")
# # #         elif "SSRF"           in ft:  st.warning(f"SSRF Activity -> {pfx}")
# # #         elif ft == "[]":              st.success(f"Safe Request -> {pfx}")
# # #         else:                         st.warning(f"Threat Detected -> {pfx}")

# # #     st.divider()

# # #     st.subheader("Full Scan Logs")
# # #     st.dataframe(df, use_container_width=True)
# # #     csv = df.to_csv(index=False)
# # #     st.download_button("Download Logs (CSV)", data=csv,
# # #                        file_name="promptshield_logs.csv", mime="text/csv")


# # # # =========================================================
# # # # MODULE 5 — AI SECURITY ASSISTANT
# # # # =========================================================

# # # elif menu == "🤖 AI Security Assistant":

# # #     st.header("AI Security Assistant")
# # #     st.write("Ask any cybersecurity question. Powered by Gemini AI.")

# # #     question = st.text_input("Your Question", placeholder="e.g. What is a prompt injection attack?")

# # #     if st.button("Ask AI"):
# # #         if not question.strip():
# # #             st.warning("Please enter a question.")
# # #         else:
# # #             dlp = scan_for_company_data(question)
# # #             if dlp["blocked"]:
# # #                 st.error(get_dlp_message(dlp))
# # #                 st.stop()
# # #             with st.spinner("AI is analyzing..."):
# # #                 answer = ask_ai(question)
# # #             st.markdown("### AI Response")
# # #             st.success(answer)


# # # # =========================================================
# # # # MODULE 6 — LIVE CVE THREAT FEED
# # # # =========================================================

# # # elif menu == "🌐 CVE Threat Feed":

# # #     st.header("Live CVE Threat Intelligence Feed")
# # #     st.write("Latest Common Vulnerabilities and Exposures — sourced from CIRCL vulnerability-lookup.")

# # #     if st.button("Refresh Feed"):
# # #         st.rerun()

# # #     CIRCL_ENDPOINTS = [
# # #         "https://cve.circl.lu/api/last",
# # #         "https://vulnerability.circl.lu/api/last",
# # #         "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=15",
# # #     ]

# # #     cves = None
# # #     error_msg = None

# # #     def _extract_list(data):
# # #         if isinstance(data, list):
# # #             return data if data else None
# # #         if isinstance(data, dict):
# # #             for key in ("results", "data", "cves"):
# # #                 val = data.get(key)
# # #                 if isinstance(val, list) and val:
# # #                     return val
# # #             nvd_vulns = data.get("vulnerabilities")
# # #             if isinstance(nvd_vulns, list) and nvd_vulns:
# # #                 return [v.get("cve", v) for v in nvd_vulns]
# # #             for val in data.values():
# # #                 if isinstance(val, list) and val:
# # #                     return val
# # #         return None

# # #     with st.spinner("Fetching latest CVEs..."):
# # #         for url in CIRCL_ENDPOINTS:
# # #             try:
# # #                 resp = requests.get(url, timeout=12, headers={"Accept": "application/json"})
# # #                 if resp.status_code == 200:
# # #                     cves = _extract_list(resp.json())
# # #                     if cves:
# # #                         break
# # #             except Exception as e:
# # #                 error_msg = str(e)
# # #                 continue

# # #     if cves:
# # #         shown = 0
# # #         for raw in cves:
# # #             if shown >= 15:
# # #                 break
# # #             entry = parse_cve(raw)
# # #             if entry["cve_id"] == "Unknown CVE" and entry["summary"] == "No summary available.":
# # #                 continue

# # #             cvss  = entry["cvss"]
# # #             label = f"**{entry['cve_id']}**"
# # #             label += f" | CVSS: {cvss:.1f}" if cvss is not None else " | CVSS: N/A"
# # #             text  = f"{label}\n\n{entry['summary']}"

# # #             if cvss is not None and cvss >= 9.0:   st.error(f"🚨 {text}")
# # #             elif cvss is not None and cvss >= 7.0: st.warning(f"⚠️ {text}")
# # #             elif cvss is not None and cvss >= 4.0: st.info(f"🔵 {text}")
# # #             else:                                   st.info(f"ℹ️ {text}")
# # #             shown += 1

# # #         if shown == 0:
# # #             st.warning("Feed returned data but no readable CVE entries could be parsed.")
# # #             with st.expander("Raw API response (first entry)"):
# # #                 st.json(cves[0] if cves else {})
# # #         else:
# # #             with st.expander("Debug: raw first entry"):
# # #                 st.json(cves[0] if cves else {})
# # #     else:
# # #         st.warning("Live CVE feed could not be reached. Showing recent notable CVEs instead.")
# # #         st.divider()
# # #         st.subheader("Recent Notable CVEs (static reference)")

# # #         static_cves = [
# # #             {"id": "CVE-2025-21413", "cvss": 9.8, "color": "error",
# # #              "desc": "Windows Telephony Service RCE — attacker can execute arbitrary code remotely without authentication.",
# # #              "mitre": "T1190 – Exploit Public-Facing Application"},
# # #             {"id": "CVE-2025-21418", "cvss": 7.8, "color": "warning",
# # #              "desc": "Windows Ancillary Function Driver privilege escalation — local attacker gains SYSTEM privileges.",
# # #              "mitre": "T1068 – Exploitation for Privilege Escalation"},
# # #             {"id": "CVE-2024-49138", "cvss": 7.8, "color": "warning",
# # #              "desc": "Windows CLFS Driver heap buffer overflow enabling local privilege escalation. Actively exploited.",
# # #              "mitre": "T1068 – Exploitation for Privilege Escalation"},
# # #             {"id": "CVE-2024-38812", "cvss": 9.8, "color": "error",
# # #              "desc": "VMware vCenter Server heap overflow via DCERPC — unauthenticated remote code execution.",
# # #              "mitre": "T1190 – Exploit Public-Facing Application"},
# # #             {"id": "CVE-2024-6387 (regreSSHion)", "cvss": 8.1, "color": "warning",
# # #              "desc": "OpenSSH race condition allowing unauthenticated RCE as root on glibc-based Linux systems.",
# # #              "mitre": "T1190 – Exploit Public-Facing Application"},
# # #         ]

# # #         for cve in static_cves:
# # #             msg = f"**{cve['id']}** | CVSS: {cve['cvss']}\n\n{cve['desc']}\n\nMITRE: {cve['mitre']}"
# # #             if cve["color"] == "error":
# # #                 st.error(msg)
# # #             else:
# # #                 st.warning(msg)

# # #         st.caption("Source: NVD / Microsoft MSRC / Apple Security. Refresh or check https://cve.circl.lu for live data.")

# # import streamlit as st
# # import pandas as pd
# # import sqlite3
# # import plotly.express as px
# # import requests

# # from detector import detect_prompt
# # from scorer import calculate_risk
# # from database import init_db, insert_log
# # from ai_engine import generate_ai_explanation
# # from auth import login, logout
# # from report_generator import generate_pdf
# # from chatbot import ask_ai
# # from pii_scanner import scan_all
# # from dlp_guard import scan_for_company_data, check_file_extension, get_dlp_message

# # REPORT_PATH = "PromptShield_Report.pdf"

# # # =========================================================
# # # BOOTSTRAP
# # # =========================================================

# # init_db()

# # st.set_page_config(
# #     page_title="PromptShield AI",
# #     page_icon="🛡️",
# #     layout="wide",
# # )

# # # =========================================================
# # # AUTH GATE
# # # =========================================================

# # if "authenticated" not in st.session_state:
# #     st.session_state["authenticated"] = False

# # if not st.session_state["authenticated"]:
# #     login()
# #     st.stop()

# # # =========================================================
# # # CUSTOM THEME
# # # =========================================================

# # st.markdown("""
# # <style>
# # .main { background-color: #0E1117; color: white; }
# # h1, h2, h3 { color: #00FFAA; }
# # .stButton>button {
# #     background-color: #00FFAA;
# #     color: black;
# #     font-weight: bold;
# #     border-radius: 8px;
# #     height: 46px;
# #     min-width: 180px;
# # }
# # .stTextArea textarea { background-color: #1A1A2E; color: white; }
# # </style>
# # """, unsafe_allow_html=True)

# # # =========================================================
# # # HEADER
# # # =========================================================

# # col_title, col_logout = st.columns([5, 1])
# # with col_title:
# #     st.title("🛡️ PromptShield AI")
# #     st.caption("LLM Guardrail Engine — Real-Time Threat Detection & Policy Enforcement")
# # with col_logout:
# #     st.write("")
# #     if st.button("Logout"):
# #         logout()

# # st.divider()

# # # =========================================================
# # # SIDEBAR NAVIGATION
# # # =========================================================

# # st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
# # st.sidebar.title("Navigation")

# # menu = st.sidebar.radio(
# #     "Select Module",
# #     ["🔍 Prompt Analyzer", "🔏 PII & Secrets Scanner", "🚫 DLP Policy", "📊 Analytics Dashboard", "🤖 AI Security Assistant", "🌐 CVE Threat Feed"],
# # )

# # # =========================================================
# # # HELPERS
# # # =========================================================

# # def load_logs() -> pd.DataFrame:
# #     conn = sqlite3.connect("prompts.db")
# #     df = pd.read_sql_query("SELECT * FROM logs ORDER BY id DESC", conn)
# #     conn.close()
# #     return df


# # RISK_COLORS = {
# #     "LOW":      "#00FFAA",
# #     "MEDIUM":   "#FFD700",
# #     "HIGH":     "#FF6B35",
# #     "CRITICAL": "#FF3333",
# # }


# # def parse_cve(item: dict) -> dict:
# #     if not isinstance(item, dict):
# #         return {"cve_id": "Unknown CVE", "summary": "No summary available.", "cvss": None}

# #     cve_id = (
# #         item.get("id")
# #         or item.get("cveId")
# #         or (item.get("CVE_data_meta") or {}).get("ID")
# #         or "Unknown CVE"
# #     )

# #     summary = item.get("summary") or ""
# #     if not summary:
# #         summary = item.get("details") or ""
# #     if not summary:
# #         desc_field = item.get("description")
# #         if isinstance(desc_field, str):
# #             summary = desc_field
# #     if not summary:
# #         descs = item.get("descriptions")
# #         if not descs and isinstance(item.get("description"), dict):
# #             descs = item["description"].get("description_data", [])
# #         if isinstance(descs, list):
# #             for d in descs:
# #                 if isinstance(d, dict) and d.get("lang", "").startswith("en"):
# #                     summary = d.get("value", "")
# #                     break
# #             if not summary and descs:
# #                 first = descs[0]
# #                 summary = first.get("value", "") if isinstance(first, dict) else str(first)
# #     if not summary:
# #         aliases = item.get("aliases", [])
# #         if aliases and isinstance(aliases, list):
# #             summary = f"See advisory: {', '.join(str(a) for a in aliases[:3])}"

# #     summary = (summary or "No summary available.").strip()
# #     if len(summary) > 450:
# #         summary = summary[:447] + "..."

# #     cvss = None
# #     for field in ("cvss", "cvss3", "cvssScore", "baseScore", "score"):
# #         val = item.get(field)
# #         if val is not None:
# #             try:
# #                 cvss = float(val)
# #                 break
# #             except (ValueError, TypeError):
# #                 pass

# #     if cvss is None:
# #         severity_list = item.get("severity") or []
# #         if isinstance(severity_list, list):
# #             for s in severity_list:
# #                 if isinstance(s, dict):
# #                     raw = s.get("score") or s.get("baseScore")
# #                     try:
# #                         cvss = float(raw); break
# #                     except (ValueError, TypeError):
# #                         pass
# #         elif isinstance(severity_list, (int, float)):
# #             try:
# #                 cvss = float(severity_list)
# #             except (ValueError, TypeError):
# #                 pass

# #     if cvss is None:
# #         metrics = item.get("metrics") or {}
# #         if isinstance(metrics, dict):
# #             for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
# #                 entries = metrics.get(key, [])
# #                 if isinstance(entries, list) and entries:
# #                     raw = (entries[0].get("cvssData") or {}).get("baseScore")
# #                     try:
# #                         cvss = float(raw); break
# #                     except (ValueError, TypeError):
# #                         pass

# #     try:
# #         cvss = float(cvss) if cvss is not None else None
# #     except (ValueError, TypeError):
# #         cvss = None

# #     return {"cve_id": cve_id, "summary": summary, "cvss": cvss}


# # # =========================================================
# # # MODULE 1 — PROMPT ANALYZER
# # # =========================================================

# # if menu == "🔍 Prompt Analyzer":

# #     st.header("Prompt Analyzer")
# #     st.write("Paste any prompt below to scan it for injection, jailbreak, and other attack patterns.")

# #     prompt = st.text_area("Enter Prompt to Analyze", height=200, placeholder="Paste suspicious prompt here...")

# #     if st.button("🔎 Analyze Prompt"):

# #         if not prompt.strip():
# #             st.warning("Please enter a prompt before analyzing.")
# #             st.stop()

# #         dlp = scan_for_company_data(prompt)
# #         if dlp["blocked"]:
# #             st.error(get_dlp_message(dlp))
# #             st.divider()
# #             st.subheader("DLP Detection Details")
# #             for f in dlp["findings"]:
# #                 with st.expander(f"🚫 {f['category']}  (line {f['line']})"):
# #                     st.code(f["snippet"], language="text")
# #                     st.caption(f"Risk weight: {f['weight']} pts")
# #             st.info("Tip: Describe your problem in plain English. Do not paste source code, config files, credentials, or internal URLs.")
# #             st.stop()
# #         elif dlp["verdict"] == "WARN":
# #             st.warning(f"DLP Warning — {dlp['category_count']} suspicious pattern(s) detected (code-like content). Proceed only if this is intentional test data.")

# #         with st.spinner("Scanning for threats..."):
# #             findings = detect_prompt(prompt)
# #             score, risk, severity, confidence = calculate_risk(findings)
# #             insert_log(prompt, str(findings), score, risk)

# #         st.divider()
# #         st.subheader("Analysis Result")

# #         c1, c2, c3, c4 = st.columns(4)
# #         c1.metric("Risk Score",        score)
# #         c2.metric("Risk Level",        risk)
# #         c3.metric("Severity",          severity)
# #         c4.metric("Threat Confidence", confidence)

# #         st.divider()

# #         if risk == "CRITICAL":
# #             st.error("SOC ALERT — Critical malicious payload detected! Immediate action required.")
# #         elif risk == "HIGH":
# #             st.warning("HIGH RISK — Suspicious activity detected. Review and block.")
# #         elif risk == "MEDIUM":
# #             st.info("MEDIUM RISK — Potential threat activity observed. Monitor closely.")
# #         else:
# #             st.success("Prompt appears safe. No malicious patterns matched.")

# #         if findings:
# #             generate_pdf(prompt, findings, score, risk)
# #             with open(REPORT_PATH, "rb") as f:
# #                 st.download_button(
# #                     "📄 Download Security Report (PDF)",
# #                     data=f,
# #                     file_name="PromptShield_Report.pdf",
# #                     mime="application/pdf",
# #                 )

# #             st.divider()
# #             st.subheader("AI Threat Analysis")
# #             with st.spinner("Generating AI analysis..."):
# #                 explanations = generate_ai_explanation(findings)
# #             for exp in explanations:
# #                 st.warning(exp)

# #             st.divider()
# #             st.subheader("Detected Threats")
# #             for item in findings:
# #                 with st.expander(f"🔴 {item['category']}"):
# #                     st.write(f"**Matched Pattern:** `{item['pattern']}`")
# #                     st.info(f"**MITRE ATT&CK:** {item.get('mitre', 'N/A')}")

# #             st.divider()
# #             st.subheader("Recommended Actions")
# #             recs = [
# #                 "Block this prompt from reaching the LLM immediately.",
# #                 "Enable strict input validation and sanitization.",
# #                 "Apply Web Application Firewall (WAF) rules.",
# #                 "Alert the SOC team and create an incident ticket.",
# #                 "Review recent logs for similar patterns.",
# #                 "Rotate any secrets or credentials that may have been exposed.",
# #             ]
# #             for rec in recs:
# #                 st.success(f"✔ {rec}")
# #         else:
# #             st.success("Prompt is Safe — no malicious patterns detected.")


# # # =========================================================
# # # MODULE 2 — PII & SECRETS SCANNER
# # # =========================================================

# # elif menu == "🔏 PII & Secrets Scanner":

# #     st.header("PII & Secrets Scanner")
# #     st.write("Detect Personally Identifiable Information (PII) and leaked credentials inside any text.")

# #     text_input = st.text_area(
# #         "Paste text to scan",
# #         height=220,
# #         placeholder="Paste any text here — emails, phone numbers, API keys, tokens, passwords, etc.",
# #     )

# #     col_scan, col_clear = st.columns([2, 1])
# #     with col_scan:
# #         scan_clicked = st.button("🔍 Scan for PII & Secrets", use_container_width=True)
# #     with col_clear:
# #         if st.button("Clear", use_container_width=True):
# #             st.rerun()

# #     if scan_clicked:
# #         if not text_input.strip():
# #             st.warning("Please paste some text to scan.")
# #             st.stop()

# #         dlp = scan_for_company_data(text_input)
# #         if dlp["blocked"]:
# #             st.error(get_dlp_message(dlp))
# #             for f in dlp["findings"]:
# #                 with st.expander(f"🚫 {f['category']}"):
# #                     st.code(f["snippet"], language="text")
# #             st.stop()

# #         with st.spinner("Scanning for PII and secrets..."):
# #             result = scan_all(text_input)

# #         st.divider()

# #         risk = result["risk"]
# #         risk_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "CLEAN": "🟢"}
# #         icon = risk_icons.get(risk, "⚪")

# #         c1, c2, c3, c4 = st.columns(4)
# #         c1.metric("PII Found",      result["pii_count"])
# #         c2.metric("Secrets Found",  result["secret_count"])
# #         c3.metric("Total Findings", result["total"])
# #         c4.metric("Risk Level",     f"{icon} {risk}")

# #         st.divider()

# #         if risk == "CRITICAL":
# #             st.error("CRITICAL — API keys or credentials detected! Rotate them immediately.")
# #         elif risk == "HIGH":
# #             st.warning("HIGH RISK — Multiple PII fields detected. Review before sharing.")
# #         elif risk == "MEDIUM":
# #             st.info("MEDIUM — PII detected. Ensure data handling complies with your policy.")
# #         else:
# #             st.success("CLEAN — No PII or secrets detected in this text.")

# #         if result["pii"]:
# #             st.subheader("PII Detections")
# #             for item in result["pii"]:
# #                 with st.expander(f"🟡 {item['category']}  x{item['count']} found"):
# #                     st.write(f"**Sample (redacted):** `{item['matched_value']}`")
# #                     st.info(f"**MITRE ATT&CK:** {item['mitre']}")

# #         if result["secrets"]:
# #             st.subheader("Credential / Secret Detections")
# #             for item in result["secrets"]:
# #                 with st.expander(f"🔴 {item['category']}  x{item['count']} found"):
# #                     st.write(f"**Sample (redacted):** `{item['matched_value']}`")
# #                     st.error(f"**MITRE ATT&CK:** {item['mitre']}")
# #                     st.caption("Action required: Rotate this credential immediately.")

# #         if result["total"] > 0:
# #             st.divider()
# #             st.subheader("Recommended Actions")
# #             if result["secrets"]:
# #                 st.error("Rotate all detected API keys and tokens immediately.")
# #                 st.error("Check access logs for unauthorized use of these credentials.")
# #                 st.error("Store secrets in environment variables — never in prompts.")
# #             if result["pii"]:
# #                 st.info("Apply data masking before sending text to any AI system.")
# #                 st.info("Review your data retention policies for GDPR/DPDP compliance.")
# #                 st.info("Implement a pre-processing filter to strip PII before it reaches the LLM.")


# # # =========================================================
# # # MODULE 3 — DLP POLICY MANAGER
# # # =========================================================

# # elif menu == "🚫 DLP Policy":

# #     st.header("Data Loss Prevention (DLP) Policy")
# #     st.write("Configure what types of content are blocked. All inputs pass through this policy engine before processing.")

# #     st.divider()

# #     c1, c2, c3 = st.columns(3)
# #     c1.metric("DLP Status",           "ACTIVE")
# #     c2.metric("Categories Monitored", "8")
# #     c3.metric("File Types Blocked",   "30+")

# #     st.divider()

# #     st.subheader("Blocked Content Categories")
# #     from dlp_guard import CODE_PATTERNS, FILE_EXTENSION_BLOCK, CATEGORY_WEIGHTS

# #     blocked_cats = [
# #         ("Source Code — Function/Class Definition", "Python, Java, JavaScript, C++, Go, Rust functions and classes", "🔴"),
# #         ("Source Code — Import Statements",         "import/require/using statements from any language",            "🔴"),
# #         ("Database Schema / SQL DDL",               "CREATE TABLE, ALTER TABLE, schema definitions",                "🔴"),
# #         ("Configuration / Environment File",        ".env files, DB connection strings, host/port/password configs","🔴"),
# #         ("API Endpoint / Internal URL",             "Internal API routes, private IPs, Bearer tokens in headers",  "🔴"),
# #         ("Infrastructure / DevOps Config",          "Kubernetes YAML, Dockerfile, Terraform, Nginx/Apache config",  "🔴"),
# #         ("Proprietary Business Logic Keywords",     "internal_use_only, confidential, proprietary markers",        "🟡"),
# #         ("Compiled / Binary File Content",          "ELF binaries, PE executables, hex dumps, base64 archives",    "🔴"),
# #     ]

# #     for cat, desc, icon in blocked_cats:
# #         weight = CATEGORY_WEIGHTS.get(cat, 25)
# #         with st.expander(f"{icon} {cat}  —  Risk Weight: {weight}"):
# #             st.write(desc)
# #             st.caption("MITRE ATT&CK: T1213 – Data from Information Repositories")

# #     st.divider()

# #     st.subheader("Blocked File Extensions")
# #     ext_cols = st.columns(6)
# #     sorted_exts = sorted(FILE_EXTENSION_BLOCK)
# #     per_col = len(sorted_exts) // 6 + 1
# #     for i, col in enumerate(ext_cols):
# #         chunk = sorted_exts[i*per_col:(i+1)*per_col]
# #         for e in chunk:
# #             col.markdown(f"`{e}`")

# #     st.divider()

# #     st.subheader("Live DLP Tester")
# #     test_input = st.text_area("Paste text to test", height=150, placeholder="Paste some text to see if DLP would block it...")

# #     if st.button("Test DLP Policy", use_container_width=True):
# #         if test_input.strip():
# #             result = scan_for_company_data(test_input)
# #             if result["verdict"] == "BLOCK":
# #                 st.error(f"BLOCKED — Score: {result['total_score']}  |  Categories: {result['category_count']}")
# #                 for f in result["findings"]:
# #                     with st.expander(f"🚫 {f['category']}  (line {f['line']})"):
# #                         st.code(f["snippet"], language="text")
# #                         st.caption(f"Risk weight: {f['weight']}")
# #             elif result["verdict"] == "WARN":
# #                 st.warning(f"WARNING — Score: {result['total_score']}  |  Code-like content detected.")
# #                 for f in result["findings"]:
# #                     with st.expander(f"⚠ {f['category']}"):
# #                         st.code(f["snippet"], language="text")
# #             else:
# #                 st.success("PASS — No policy violations detected. This text would be allowed.")

# #     st.divider()

# #     st.subheader("Policy Rules Summary")
# #     st.info(
# #         "Enforcement Points:\n"
# #         "- Prompt Analyzer — DLP checked before every scan\n"
# #         "- PII & Secrets Scanner — DLP checked before every scan\n"
# #         "- AI Security Assistant — DLP checked before sending to Gemini\n\n"
# #         "On violation: Input is blocked, user sees a policy message, event is logged."
# #     )

# #     with st.expander("What users CAN submit"):
# #         st.markdown("""
# # - Plain English descriptions of security problems
# # - Anonymised log snippets (no credentials, no internal IPs)
# # - Public CVE IDs or vulnerability names
# # - Generic attack patterns for testing
# # - Cybersecurity questions
# #         """)

# #     with st.expander("What users CANNOT submit"):
# #         st.markdown("""
# # - Source code files (.py, .js, .java, .cs, .go, etc.)
# # - Database schemas or SQL DDL statements
# # - .env files or configuration with real credentials
# # - Internal API endpoints or private IP addresses
# # - Kubernetes / Docker / Terraform infrastructure files
# # - Compiled binaries or hex dumps
# #         """)


# # # =========================================================
# # # MODULE 4 — ANALYTICS DASHBOARD
# # # =========================================================

# # elif menu == "📊 Analytics Dashboard":

# #     st.header("Threat Analytics Dashboard")

# #     df = load_logs()

# #     if df.empty:
# #         st.info("No scan logs yet. Run some prompts through the Prompt Analyzer first.")
# #         st.stop()

# #     total      = len(df)
# #     critical   = len(df[df["risk"] == "CRITICAL"])
# #     high       = len(df[df["risk"] == "HIGH"])
# #     safe_count = len(df[df["risk"] == "LOW"])

# #     c1, c2, c3, c4 = st.columns(4)
# #     c1.metric("Total Scans",      total)
# #     c2.metric("Critical Threats", critical)
# #     c3.metric("High Risk",        high)
# #     c4.metric("Safe Prompts",     safe_count)

# #     st.divider()

# #     col_a, col_b = st.columns(2)

# #     with col_a:
# #         st.subheader("Risk Distribution")
# #         risk_counts = df["risk"].value_counts().reset_index()
# #         risk_counts.columns = ["Risk Level", "Count"]
# #         fig_pie = px.pie(
# #             risk_counts,
# #             names="Risk Level",
# #             values="Count",
# #             color="Risk Level",
# #             color_discrete_map=RISK_COLORS,
# #             hole=0.4,
# #         )
# #         fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
# #         st.plotly_chart(fig_pie, use_container_width=True)

# #     with col_b:
# #         st.subheader("Threat Category Frequency")
# #         categories = ["XSS", "SQL Injection", "CSRF", "Prompt Injection", "Jailbreak", "SSRF", "Command Injection"]
# #         kw_map     = ["XSS", "SQL", "CSRF", "Prompt Injection", "Jailbreak", "SSRF", "Command"]
# #         counts = [len(df[df["findings"].str.contains(kw, case=False, na=False)]) for kw in kw_map]
# #         bar_df = pd.DataFrame({"Threat": categories, "Count": counts})
# #         fig_bar = px.bar(bar_df, x="Threat", y="Count", color="Count",
# #                          color_continuous_scale="Reds", text="Count")
# #         fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white", showlegend=False)
# #         st.plotly_chart(fig_bar, use_container_width=True)

# #     st.divider()

# #     st.subheader("Recent Attack Stream (last 10 scans)")
# #     for _, row in df.head(10).iterrows():
# #         ft  = str(row["findings"])
# #         ts  = row.get("timestamp", "")
# #         pfx = f"[{ts}] Prompt #{row['id']}"

# #         if "Prompt Injection" in ft:  st.error(f"Prompt Injection -> {pfx}")
# #         elif "Jailbreak"      in ft:  st.error(f"Jailbreak Attempt -> {pfx}")
# #         elif "XSS"            in ft:  st.error(f"XSS Attack -> {pfx}")
# #         elif "SQL"            in ft:  st.error(f"SQL Injection -> {pfx}")
# #         elif "CSRF"           in ft:  st.warning(f"CSRF Pattern -> {pfx}")
# #         elif "SSRF"           in ft:  st.warning(f"SSRF Activity -> {pfx}")
# #         elif ft == "[]":              st.success(f"Safe Request -> {pfx}")
# #         else:                         st.warning(f"Threat Detected -> {pfx}")

# #     st.divider()

# #     st.subheader("Full Scan Logs")
# #     st.dataframe(df, use_container_width=True)
# #     csv = df.to_csv(index=False)
# #     st.download_button("Download Logs (CSV)", data=csv,
# #                        file_name="promptshield_logs.csv", mime="text/csv")


# # # =========================================================
# # # MODULE 5 — AI SECURITY ASSISTANT
# # # =========================================================

# # elif menu == "🤖 AI Security Assistant":

# #     from file_guardrail import run_file_guardrail, BLOCKED_EXTENSIONS, ALLOWED_EXTENSIONS

# #     st.header("🤖 AI Security Assistant")
# #     st.caption("Enterprise LLM Guardrail — Every input screened before reaching AI")

# #     st.info(
# #         "**5-Stage Guardrail Pipeline** runs on every submission:\n"
# #         "Stage 1: Extension Policy → Stage 2: File Size → "
# #         "Stage 3: Binary + Content-Type Mismatch Detection → "
# #         "Stage 4: Deep Content Scan (XSS, SQLi, Prompt Injection, Secrets, PII) → "
# #         "Stage 5: Final Verdict\n\n"
# #         "Blocked inputs are never sent to AI."
# #     )

# #     st.divider()

# #     input_mode = st.radio(
# #         "Input Mode",
# #         ["💬 Text Question", "📎 File Upload + Question"],
# #         horizontal=True,
# #     )

# #     st.divider()

# #     # ── MODE A: TEXT QUESTION ──────────────────────────────
# #     if input_mode == "💬 Text Question":

# #         question = st.text_area(
# #             "Your Question",
# #             height=120,
# #             placeholder="e.g. What is a prompt injection attack? How does SSRF work?",
# #         )

# #         if st.button("🔍 Run Guardrail & Ask AI", use_container_width=True):
# #             if not question.strip():
# #                 st.warning("Please enter a question.")
# #                 st.stop()

# #             with st.spinner("Running guardrail checks..."):
# #                 dlp = scan_for_company_data(question)
# #                 from pii_scanner import scan_all as pii_scan
# #                 pii = pii_scan(question)

# #             # Pipeline status
# #             st.subheader("Guardrail Pipeline Result")
# #             g1, g2, g3, g4 = st.columns(4)
# #             g1.metric("DLP Policy",    "🚫 BLOCK" if dlp["blocked"] else "✅ PASS")
# #             g2.metric("Secret Scan",   "🚫 BLOCK" if pii["secret_count"] > 0 else "✅ PASS")
# #             g3.metric("PII Scan",      f"⚠️ {pii['pii_count']} found" if pii["pii_count"] > 0 else "✅ PASS")
# #             g4.metric("Prompt Safety", "🚫 BLOCK" if dlp["blocked"] else "✅ PASS")

# #             if dlp["blocked"]:
# #                 st.error(get_dlp_message(dlp))
# #                 for f in dlp["findings"]:
# #                     with st.expander(f"🚫 {f['category']}  (line {f['line']})"):
# #                         st.code(f["snippet"], language="text")
# #                         st.caption(f"Risk weight: {f['weight']} pts")
# #                 st.stop()

# #             if pii["secret_count"] > 0:
# #                 st.error(
# #                     "🚫 **Credential Detected — Blocked**\n\n"
# #                     "Your question contains API keys or passwords. Never submit credentials to AI.\n\n"
# #                     f"Detected: {', '.join(s['category'] for s in pii['secrets'])}"
# #                 )
# #                 st.stop()

# #             if pii["pii_count"] > 0:
# #                 st.warning(f"⚠️ PII detected ({pii['pii_count']} type(s)). Proceeding but avoid sending personal data.")

# #             st.success("✅ All guardrail checks passed — sending to AI...")
# #             st.divider()

# #             with st.spinner("AI is analyzing..."):
# #                 answer = ask_ai(question)
# #             st.subheader("AI Response")
# #             st.success(answer)

# #     # ── MODE B: FILE UPLOAD + QUESTION ────────────────────
# #     else:

# #         with st.expander("📋 File Upload Policy — What is allowed?"):
# #             col_a, col_b = st.columns(2)
# #             with col_a:
# #                 st.markdown("**✅ Allowed Extensions**")
# #                 for ext in sorted(ALLOWED_EXTENSIONS):
# #                     st.markdown(f"- `{ext}`")
# #                 st.caption("Content is still scanned even for allowed types.")
# #             with col_b:
# #                 st.markdown("**🚫 Blocked Extensions (sample)**")
# #                 for ext in sorted(list(BLOCKED_EXTENSIONS))[:20]:
# #                     st.markdown(f"- `{ext}`")
# #                 st.caption(f"...and {len(BLOCKED_EXTENSIONS)-20} more.")

# #         st.divider()

# #         uploaded_file = st.file_uploader(
# #             "Upload a file to analyze with AI",
# #             type=None,
# #             help=f"Max 5 MB. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
# #         )

# #         question = st.text_area(
# #             "Your question about this file",
# #             height=100,
# #             placeholder="e.g. Summarize this document. What are the key risks?",
# #         )

# #         if st.button("🔍 Run Guardrail & Analyze", use_container_width=True):

# #             if uploaded_file is None:
# #                 st.warning("Please upload a file first.")
# #                 st.stop()

# #             if not question.strip():
# #                 st.warning("Please enter a question about the file.")
# #                 st.stop()

# #             file_bytes = uploaded_file.read()
# #             filename   = uploaded_file.name

# #             st.divider()
# #             st.subheader("🔒 Guardrail Pipeline Executing...")

# #             with st.spinner("Running 5-stage enterprise security scan..."):
# #                 result = run_file_guardrail(filename, file_bytes)

# #             # Stage status display
# #             st.subheader("Pipeline Stages")
# #             cols = st.columns(len(result["stages"]))
# #             for i, stage in enumerate(result["stages"]):
# #                 s = stage["result"]
# #                 if s.get("passed") == False or s.get("is_binary") or s.get("blocked"):
# #                     verdict_key, icon = "BLOCK", "🚫"
# #                 elif s.get("verdict") == "WARN":
# #                     verdict_key, icon = "WARN", "⚠️"
# #                 elif s.get("verdict") == "SKIP":
# #                     verdict_key, icon = "SKIP", "⏭️"
# #                 else:
# #                     verdict_key, icon = "PASS", "✅"
# #                 with cols[i]:
# #                     st.metric(stage["name"], f"{icon} {verdict_key}")

# #             st.divider()

# #             # BLOCKED
# #             if result["blocked"]:
# #                 st.error(
# #                     f"🚫 **FILE BLOCKED — Security Policy Violation**\n\n"
# #                     f"{result['summary']}\n\n"
# #                     f"**File:** `{filename}`  |  "
# #                     f"**SHA-256:** `{result['file_hash'][:16]}...`\n\n"
# #                     f"*This upload has been logged in the audit trail.*"
# #                 )
# #                 if result.get("attack_type"):
# #                     st.error(f"**Attack Type:** {result['attack_type']}")

# #                 if result["findings"]:
# #                     st.subheader("Detected Violations")
# #                     for f in result["findings"]:
# #                         with st.expander(f"🚫 {f['category']}  (Line {f['line']})"):
# #                             st.code(f["snippet"], language="text")
# #                             st.caption(f"Risk Weight: {f['weight']} pts  |  MITRE: {f['mitre']}")

# #                 st.divider()
# #                 st.info(
# #                     "**What you can do instead:**\n"
# #                     "- Describe the problem in plain English\n"
# #                     "- Remove all credentials, code, and internal URLs first\n"
# #                     "- Use anonymised data with placeholders\n"
# #                     "- Contact your security team if this is a false positive"
# #                 )
# #                 st.stop()

# #             # WARNINGS
# #             if result["verdict"] == "WARN" and result["findings"]:
# #                 st.warning(f"⚠️ File passed with {len(result['findings'])} warning(s).")
# #                 for f in result["findings"]:
# #                     with st.expander(f"⚠️ {f['category']}  (Line {f['line']})"):
# #                         st.code(f["snippet"], language="text")
# #                         st.caption(f"MITRE: {f['mitre']}")
# #                 st.divider()

# #             # PASS — send to AI
# #             st.success("✅ File cleared all guardrail stages — sending to AI")
# #             size_kb = len(file_bytes) / 1024
# #             m1, m2, m3, m4 = st.columns(4)
# #             m1.metric("File",   filename)
# #             m2.metric("Size",   f"{size_kb:.1f} KB")
# #             m3.metric("Hash",   result["file_hash"][:8] + "...")
# #             m4.metric("Status", "CLEARED")

# #             st.divider()
# #             st.subheader("AI Analysis")

# #             file_text = result.get("text", "")
# #             if file_text:
# #                 preview = file_text[:8000]
# #                 if len(file_text) > 8000:
# #                     preview += f"\n\n[Truncated — showing first 8000 of {len(file_text)} chars]"
# #                 gemini_prompt = (
# #                     f"The user uploaded '{filename}'.\nFile contents:\n---\n{preview}\n---\n\n"
# #                     f"User question: {question}"
# #                 )
# #             else:
# #                 gemini_prompt = (
# #                     f"The user uploaded a binary/image file '{filename}' ({size_kb:.1f} KB). "
# #                     f"They ask: {question}"
# #                 )

# #             with st.spinner("AI is reading and analyzing the file..."):
# #                 answer = ask_ai(gemini_prompt)
# #             st.success(answer)

# #             with st.expander("📋 Audit Trail"):
# #                 st.json({
# #                     "filename":   filename,
# #                     "file_hash":  result["file_hash"],
# #                     "size_bytes": len(file_bytes),
# #                     "verdict":    result["verdict"],
# #                     "warnings":   len(result["findings"]),
# #                     "question":   question[:100],
# #                 })


# # # =========================================================
# # # MODULE 6 — LIVE CVE THREAT FEED
# # # =========================================================

# # elif menu == "🌐 CVE Threat Feed":

# #     st.header("Live CVE Threat Intelligence Feed")
# #     st.write("Latest Common Vulnerabilities and Exposures — sourced from CIRCL vulnerability-lookup.")

# #     if st.button("Refresh Feed"):
# #         st.rerun()

# #     CIRCL_ENDPOINTS = [
# #         "https://cve.circl.lu/api/last",
# #         "https://vulnerability.circl.lu/api/last",
# #         "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=15",
# #     ]

# #     cves = None
# #     error_msg = None

# #     def _extract_list(data):
# #         if isinstance(data, list):
# #             return data if data else None
# #         if isinstance(data, dict):
# #             for key in ("results", "data", "cves"):
# #                 val = data.get(key)
# #                 if isinstance(val, list) and val:
# #                     return val
# #             nvd_vulns = data.get("vulnerabilities")
# #             if isinstance(nvd_vulns, list) and nvd_vulns:
# #                 return [v.get("cve", v) for v in nvd_vulns]
# #             for val in data.values():
# #                 if isinstance(val, list) and val:
# #                     return val
# #         return None

# #     with st.spinner("Fetching latest CVEs..."):
# #         for url in CIRCL_ENDPOINTS:
# #             try:
# #                 resp = requests.get(url, timeout=12, headers={"Accept": "application/json"})
# #                 if resp.status_code == 200:
# #                     cves = _extract_list(resp.json())
# #                     if cves:
# #                         break
# #             except Exception as e:
# #                 error_msg = str(e)
# #                 continue

# #     if cves:
# #         shown = 0
# #         for raw in cves:
# #             if shown >= 15:
# #                 break
# #             entry = parse_cve(raw)
# #             if entry["cve_id"] == "Unknown CVE" and entry["summary"] == "No summary available.":
# #                 continue

# #             cvss  = entry["cvss"]
# #             label = f"**{entry['cve_id']}**"
# #             label += f" | CVSS: {cvss:.1f}" if cvss is not None else " | CVSS: N/A"
# #             text  = f"{label}\n\n{entry['summary']}"

# #             if cvss is not None and cvss >= 9.0:   st.error(f"🚨 {text}")
# #             elif cvss is not None and cvss >= 7.0: st.warning(f"⚠️ {text}")
# #             elif cvss is not None and cvss >= 4.0: st.info(f"🔵 {text}")
# #             else:                                   st.info(f"ℹ️ {text}")
# #             shown += 1

# #         if shown == 0:
# #             st.warning("Feed returned data but no readable CVE entries could be parsed.")
# #             with st.expander("Raw API response (first entry)"):
# #                 st.json(cves[0] if cves else {})
# #         else:
# #             with st.expander("Debug: raw first entry"):
# #                 st.json(cves[0] if cves else {})
# #     else:
# #         st.warning("Live CVE feed could not be reached. Showing recent notable CVEs instead.")
# #         st.divider()
# #         st.subheader("Recent Notable CVEs (static reference)")

# #         static_cves = [
# #             {"id": "CVE-2025-21413", "cvss": 9.8, "color": "error",
# #              "desc": "Windows Telephony Service RCE — attacker can execute arbitrary code remotely without authentication.",
# #              "mitre": "T1190 – Exploit Public-Facing Application"},
# #             {"id": "CVE-2025-21418", "cvss": 7.8, "color": "warning",
# #              "desc": "Windows Ancillary Function Driver privilege escalation — local attacker gains SYSTEM privileges.",
# #              "mitre": "T1068 – Exploitation for Privilege Escalation"},
# #             {"id": "CVE-2024-49138", "cvss": 7.8, "color": "warning",
# #              "desc": "Windows CLFS Driver heap buffer overflow enabling local privilege escalation. Actively exploited.",
# #              "mitre": "T1068 – Exploitation for Privilege Escalation"},
# #             {"id": "CVE-2024-38812", "cvss": 9.8, "color": "error",
# #              "desc": "VMware vCenter Server heap overflow via DCERPC — unauthenticated remote code execution.",
# #              "mitre": "T1190 – Exploit Public-Facing Application"},
# #             {"id": "CVE-2024-6387 (regreSSHion)", "cvss": 8.1, "color": "warning",
# #              "desc": "OpenSSH race condition allowing unauthenticated RCE as root on glibc-based Linux systems.",
# #              "mitre": "T1190 – Exploit Public-Facing Application"},
# #         ]

# #         for cve in static_cves:
# #             msg = f"**{cve['id']}** | CVSS: {cve['cvss']}\n\n{cve['desc']}\n\nMITRE: {cve['mitre']}"
# #             if cve["color"] == "error":
# #                 st.error(msg)
# #             else:
# #                 st.warning(msg)

# #         st.caption("Source: NVD / Microsoft MSRC / Apple Security. Refresh or check https://cve.circl.lu for live data.")

# import os
# import streamlit as st
# import pandas as pd
# import sqlite3
# import plotly.express as px
# import requests

# from detector import detect_prompt
# from scorer import calculate_risk
# from database import init_db, insert_log
# from ai_engine import generate_ai_explanation
# from auth import login, logout
# from report_generator import generate_pdf
# from chatbot import ask_ai
# from pii_scanner import scan_all
# from dlp_guard import scan_for_company_data, check_file_extension, get_dlp_message

# REPORT_PATH = "PromptShield_Report.pdf"

# # =========================================================
# # BOOTSTRAP
# # =========================================================

# init_db()

# st.set_page_config(
#     page_title="PromptShield AI",
#     page_icon="🛡️",
#     layout="wide",
# )

# # =========================================================
# # AUTH GATE
# # =========================================================

# if "authenticated" not in st.session_state:
#     st.session_state["authenticated"] = False

# if not st.session_state["authenticated"]:
#     login()
#     st.stop()

# # =========================================================
# # CUSTOM THEME
# # =========================================================

# st.markdown("""
# <style>
# .main { background-color: #0E1117; color: white; }
# h1, h2, h3 { color: #00FFAA; }
# .stButton>button {
#     background-color: #00FFAA;
#     color: black;
#     font-weight: bold;
#     border-radius: 8px;
#     height: 46px;
#     min-width: 180px;
# }
# .stTextArea textarea { background-color: #1A1A2E; color: white; }
# </style>
# """, unsafe_allow_html=True)

# # =========================================================
# # HEADER
# # =========================================================

# col_title, col_logout = st.columns([5, 1])
# with col_title:
#     st.title("🛡️ PromptShield AI")
#     st.caption("LLM Guardrail Engine — Real-Time Threat Detection & Policy Enforcement")
# with col_logout:
#     st.write("")
#     if st.button("Logout"):
#         logout()

# st.divider()

# # =========================================================
# # SIDEBAR NAVIGATION
# # =========================================================

# st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
# st.sidebar.title("Navigation")

# menu = st.sidebar.radio(
#     "Select Module",
#     ["🔍 Prompt Analyzer", "🔏 PII & Secrets Scanner", "🚫 DLP Policy", "📊 Analytics Dashboard", "🤖 AI Security Assistant", "🌐 CVE Threat Feed"],
# )

# # =========================================================
# # HELPERS
# # =========================================================

# def load_logs() -> pd.DataFrame:
#     conn = sqlite3.connect("prompts.db")
#     df = pd.read_sql_query("SELECT * FROM logs ORDER BY id DESC", conn)
#     conn.close()
#     return df


# RISK_COLORS = {
#     "LOW":      "#00FFAA",
#     "MEDIUM":   "#FFD700",
#     "HIGH":     "#FF6B35",
#     "CRITICAL": "#FF3333",
# }


# def parse_cve(item: dict) -> dict:
#     if not isinstance(item, dict):
#         return {"cve_id": "Unknown CVE", "summary": "No summary available.", "cvss": None}

#     cve_id = (
#         item.get("id")
#         or item.get("cveId")
#         or (item.get("CVE_data_meta") or {}).get("ID")
#         or "Unknown CVE"
#     )

#     summary = item.get("summary") or ""
#     if not summary:
#         summary = item.get("details") or ""
#     if not summary:
#         desc_field = item.get("description")
#         if isinstance(desc_field, str):
#             summary = desc_field
#     if not summary:
#         descs = item.get("descriptions")
#         if not descs and isinstance(item.get("description"), dict):
#             descs = item["description"].get("description_data", [])
#         if isinstance(descs, list):
#             for d in descs:
#                 if isinstance(d, dict) and d.get("lang", "").startswith("en"):
#                     summary = d.get("value", "")
#                     break
#             if not summary and descs:
#                 first = descs[0]
#                 summary = first.get("value", "") if isinstance(first, dict) else str(first)
#     if not summary:
#         aliases = item.get("aliases", [])
#         if aliases and isinstance(aliases, list):
#             summary = f"See advisory: {', '.join(str(a) for a in aliases[:3])}"

#     summary = (summary or "No summary available.").strip()
#     if len(summary) > 450:
#         summary = summary[:447] + "..."

#     cvss = None
#     for field in ("cvss", "cvss3", "cvssScore", "baseScore", "score"):
#         val = item.get(field)
#         if val is not None:
#             try:
#                 cvss = float(val)
#                 break
#             except (ValueError, TypeError):
#                 pass

#     if cvss is None:
#         severity_list = item.get("severity") or []
#         if isinstance(severity_list, list):
#             for s in severity_list:
#                 if isinstance(s, dict):
#                     raw = s.get("score") or s.get("baseScore")
#                     try:
#                         cvss = float(raw); break
#                     except (ValueError, TypeError):
#                         pass
#         elif isinstance(severity_list, (int, float)):
#             try:
#                 cvss = float(severity_list)
#             except (ValueError, TypeError):
#                 pass

#     if cvss is None:
#         metrics = item.get("metrics") or {}
#         if isinstance(metrics, dict):
#             for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
#                 entries = metrics.get(key, [])
#                 if isinstance(entries, list) and entries:
#                     raw = (entries[0].get("cvssData") or {}).get("baseScore")
#                     try:
#                         cvss = float(raw); break
#                     except (ValueError, TypeError):
#                         pass

#     try:
#         cvss = float(cvss) if cvss is not None else None
#     except (ValueError, TypeError):
#         cvss = None

#     return {"cve_id": cve_id, "summary": summary, "cvss": cvss}


# # =========================================================
# # MODULE 1 — PROMPT ANALYZER
# # =========================================================

# if menu == "🔍 Prompt Analyzer":

#     st.header("Prompt Analyzer")
#     st.write("Paste any prompt below to scan it for injection, jailbreak, and other attack patterns.")

#     prompt = st.text_area("Enter Prompt to Analyze", height=200, placeholder="Paste suspicious prompt here...")

#     if st.button("🔎 Analyze Prompt"):

#         if not prompt.strip():
#             st.warning("Please enter a prompt before analyzing.")
#             st.stop()

#         dlp = scan_for_company_data(prompt)
#         if dlp["blocked"]:
#             st.error(get_dlp_message(dlp))
#             st.divider()
#             st.subheader("DLP Detection Details")
#             for f in dlp["findings"]:
#                 with st.expander(f"🚫 {f['category']}  (line {f['line']})"):
#                     st.code(f["snippet"], language="text")
#                     st.caption(f"Risk weight: {f['weight']} pts")
#             st.info("Tip: Describe your problem in plain English. Do not paste source code, config files, credentials, or internal URLs.")
#             st.stop()
#         elif dlp["verdict"] == "WARN":
#             st.warning(f"DLP Warning — {dlp['category_count']} suspicious pattern(s) detected (code-like content). Proceed only if this is intentional test data.")

#         with st.spinner("Scanning for threats..."):
#             findings = detect_prompt(prompt)
#             score, risk, severity, confidence = calculate_risk(findings)
#             insert_log(prompt, str(findings), score, risk)

#         st.divider()
#         st.subheader("Analysis Result")

#         c1, c2, c3, c4 = st.columns(4)
#         c1.metric("Risk Score",        score)
#         c2.metric("Risk Level",        risk)
#         c3.metric("Severity",          severity)
#         c4.metric("Threat Confidence", confidence)

#         st.divider()

#         if risk == "CRITICAL":
#             st.error("SOC ALERT — Critical malicious payload detected! Immediate action required.")
#         elif risk == "HIGH":
#             st.warning("HIGH RISK — Suspicious activity detected. Review and block.")
#         elif risk == "MEDIUM":
#             st.info("MEDIUM RISK — Potential threat activity observed. Monitor closely.")
#         else:
#             st.success("Prompt appears safe. No malicious patterns matched.")

#         if findings:
#             generate_pdf(prompt, findings, score, risk)
#             with open(REPORT_PATH, "rb") as f:
#                 st.download_button(
#                     "📄 Download Security Report (PDF)",
#                     data=f,
#                     file_name="PromptShield_Report.pdf",
#                     mime="application/pdf",
#                 )

#             st.divider()
#             st.subheader("AI Threat Analysis")
#             with st.spinner("Generating AI analysis..."):
#                 explanations = generate_ai_explanation(findings)
#             for exp in explanations:
#                 st.warning(exp)

#             st.divider()
#             st.subheader("Detected Threats")
#             for item in findings:
#                 with st.expander(f"🔴 {item['category']}"):
#                     st.write(f"**Matched Pattern:** `{item['pattern']}`")
#                     st.info(f"**MITRE ATT&CK:** {item.get('mitre', 'N/A')}")

#             st.divider()
#             st.subheader("Recommended Actions")
#             recs = [
#                 "Block this prompt from reaching the LLM immediately.",
#                 "Enable strict input validation and sanitization.",
#                 "Apply Web Application Firewall (WAF) rules.",
#                 "Alert the SOC team and create an incident ticket.",
#                 "Review recent logs for similar patterns.",
#                 "Rotate any secrets or credentials that may have been exposed.",
#             ]
#             for rec in recs:
#                 st.success(f"✔ {rec}")
#         else:
#             st.success("Prompt is Safe — no malicious patterns detected.")


# # =========================================================
# # MODULE 2 — PII & SECRETS SCANNER
# # =========================================================

# elif menu == "🔏 PII & Secrets Scanner":

#     st.header("PII & Secrets Scanner")
#     st.write("Detect Personally Identifiable Information (PII) and leaked credentials inside any text.")

#     text_input = st.text_area(
#         "Paste text to scan",
#         height=220,
#         placeholder="Paste any text here — emails, phone numbers, API keys, tokens, passwords, etc.",
#     )

#     col_scan, col_clear = st.columns([2, 1])
#     with col_scan:
#         scan_clicked = st.button("🔍 Scan for PII & Secrets", use_container_width=True)
#     with col_clear:
#         if st.button("Clear", use_container_width=True):
#             st.rerun()

#     if scan_clicked:
#         if not text_input.strip():
#             st.warning("Please paste some text to scan.")
#             st.stop()

#         dlp = scan_for_company_data(text_input)
#         if dlp["blocked"]:
#             st.error(get_dlp_message(dlp))
#             for f in dlp["findings"]:
#                 with st.expander(f"🚫 {f['category']}"):
#                     st.code(f["snippet"], language="text")
#             st.stop()

#         with st.spinner("Scanning for PII and secrets..."):
#             result = scan_all(text_input)

#         st.divider()

#         risk = result["risk"]
#         risk_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "CLEAN": "🟢"}
#         icon = risk_icons.get(risk, "⚪")

#         c1, c2, c3, c4 = st.columns(4)
#         c1.metric("PII Found",      result["pii_count"])
#         c2.metric("Secrets Found",  result["secret_count"])
#         c3.metric("Total Findings", result["total"])
#         c4.metric("Risk Level",     f"{icon} {risk}")

#         st.divider()

#         if risk == "CRITICAL":
#             st.error("CRITICAL — API keys or credentials detected! Rotate them immediately.")
#         elif risk == "HIGH":
#             st.warning("HIGH RISK — Multiple PII fields detected. Review before sharing.")
#         elif risk == "MEDIUM":
#             st.info("MEDIUM — PII detected. Ensure data handling complies with your policy.")
#         else:
#             st.success("CLEAN — No PII or secrets detected in this text.")

#         if result["pii"]:
#             st.subheader("PII Detections")
#             for item in result["pii"]:
#                 with st.expander(f"🟡 {item['category']}  x{item['count']} found"):
#                     st.write(f"**Sample (redacted):** `{item['matched_value']}`")
#                     st.info(f"**MITRE ATT&CK:** {item['mitre']}")

#         if result["secrets"]:
#             st.subheader("Credential / Secret Detections")
#             for item in result["secrets"]:
#                 with st.expander(f"🔴 {item['category']}  x{item['count']} found"):
#                     st.write(f"**Sample (redacted):** `{item['matched_value']}`")
#                     st.error(f"**MITRE ATT&CK:** {item['mitre']}")
#                     st.caption("Action required: Rotate this credential immediately.")

#         if result["total"] > 0:
#             st.divider()
#             st.subheader("Recommended Actions")
#             if result["secrets"]:
#                 st.error("Rotate all detected API keys and tokens immediately.")
#                 st.error("Check access logs for unauthorized use of these credentials.")
#                 st.error("Store secrets in environment variables — never in prompts.")
#             if result["pii"]:
#                 st.info("Apply data masking before sending text to any AI system.")
#                 st.info("Review your data retention policies for GDPR/DPDP compliance.")
#                 st.info("Implement a pre-processing filter to strip PII before it reaches the LLM.")


# # =========================================================
# # MODULE 3 — DLP POLICY MANAGER
# # =========================================================

# elif menu == "🚫 DLP Policy":

#     st.header("Data Loss Prevention (DLP) Policy")
#     st.write("Configure what types of content are blocked. All inputs pass through this policy engine before processing.")

#     st.divider()

#     c1, c2, c3 = st.columns(3)
#     c1.metric("DLP Status",           "ACTIVE")
#     c2.metric("Categories Monitored", "8")
#     c3.metric("File Types Blocked",   "30+")

#     st.divider()

#     st.subheader("Blocked Content Categories")
#     from dlp_guard import CODE_PATTERNS, FILE_EXTENSION_BLOCK, CATEGORY_WEIGHTS

#     blocked_cats = [
#         ("Source Code — Function/Class Definition", "Python, Java, JavaScript, C++, Go, Rust functions and classes", "🔴"),
#         ("Source Code — Import Statements",         "import/require/using statements from any language",            "🔴"),
#         ("Database Schema / SQL DDL",               "CREATE TABLE, ALTER TABLE, schema definitions",                "🔴"),
#         ("Configuration / Environment File",        ".env files, DB connection strings, host/port/password configs","🔴"),
#         ("API Endpoint / Internal URL",             "Internal API routes, private IPs, Bearer tokens in headers",  "🔴"),
#         ("Infrastructure / DevOps Config",          "Kubernetes YAML, Dockerfile, Terraform, Nginx/Apache config",  "🔴"),
#         ("Proprietary Business Logic Keywords",     "internal_use_only, confidential, proprietary markers",        "🟡"),
#         ("Compiled / Binary File Content",          "ELF binaries, PE executables, hex dumps, base64 archives",    "🔴"),
#     ]

#     for cat, desc, icon in blocked_cats:
#         weight = CATEGORY_WEIGHTS.get(cat, 25)
#         with st.expander(f"{icon} {cat}  —  Risk Weight: {weight}"):
#             st.write(desc)
#             st.caption("MITRE ATT&CK: T1213 – Data from Information Repositories")

#     st.divider()

#     st.subheader("Blocked File Extensions")
#     ext_cols = st.columns(6)
#     sorted_exts = sorted(FILE_EXTENSION_BLOCK)
#     per_col = len(sorted_exts) // 6 + 1
#     for i, col in enumerate(ext_cols):
#         chunk = sorted_exts[i*per_col:(i+1)*per_col]
#         for e in chunk:
#             col.markdown(f"`{e}`")

#     st.divider()

#     st.subheader("Live DLP Tester")
#     test_input = st.text_area("Paste text to test", height=150, placeholder="Paste some text to see if DLP would block it...")

#     if st.button("Test DLP Policy", use_container_width=True):
#         if test_input.strip():
#             result = scan_for_company_data(test_input)
#             if result["verdict"] == "BLOCK":
#                 st.error(f"BLOCKED — Score: {result['total_score']}  |  Categories: {result['category_count']}")
#                 for f in result["findings"]:
#                     with st.expander(f"🚫 {f['category']}  (line {f['line']})"):
#                         st.code(f["snippet"], language="text")
#                         st.caption(f"Risk weight: {f['weight']}")
#             elif result["verdict"] == "WARN":
#                 st.warning(f"WARNING — Score: {result['total_score']}  |  Code-like content detected.")
#                 for f in result["findings"]:
#                     with st.expander(f"⚠ {f['category']}"):
#                         st.code(f["snippet"], language="text")
#             else:
#                 st.success("PASS — No policy violations detected. This text would be allowed.")

#     st.divider()

#     st.subheader("Policy Rules Summary")
#     st.info(
#         "Enforcement Points:\n"
#         "- Prompt Analyzer — DLP checked before every scan\n"
#         "- PII & Secrets Scanner — DLP checked before every scan\n"
#         "- AI Security Assistant — DLP checked before sending to Gemini\n\n"
#         "On violation: Input is blocked, user sees a policy message, event is logged."
#     )

#     with st.expander("What users CAN submit"):
#         st.markdown("""
# - Plain English descriptions of security problems
# - Anonymised log snippets (no credentials, no internal IPs)
# - Public CVE IDs or vulnerability names
# - Generic attack patterns for testing
# - Cybersecurity questions
#         """)

#     with st.expander("What users CANNOT submit"):
#         st.markdown("""
# - Source code files (.py, .js, .java, .cs, .go, etc.)
# - Database schemas or SQL DDL statements
# - .env files or configuration with real credentials
# - Internal API endpoints or private IP addresses
# - Kubernetes / Docker / Terraform infrastructure files
# - Compiled binaries or hex dumps
#         """)


# # =========================================================
# # MODULE 4 — ANALYTICS DASHBOARD
# # =========================================================

# elif menu == "📊 Analytics Dashboard":

#     st.header("Threat Analytics Dashboard")

#     df = load_logs()

#     if df.empty:
#         st.info("No scan logs yet. Run some prompts through the Prompt Analyzer first.")
#         st.stop()

#     total      = len(df)
#     critical   = len(df[df["risk"] == "CRITICAL"])
#     high       = len(df[df["risk"] == "HIGH"])
#     safe_count = len(df[df["risk"] == "LOW"])

#     c1, c2, c3, c4 = st.columns(4)
#     c1.metric("Total Scans",      total)
#     c2.metric("Critical Threats", critical)
#     c3.metric("High Risk",        high)
#     c4.metric("Safe Prompts",     safe_count)

#     st.divider()

#     col_a, col_b = st.columns(2)

#     with col_a:
#         st.subheader("Risk Distribution")
#         risk_counts = df["risk"].value_counts().reset_index()
#         risk_counts.columns = ["Risk Level", "Count"]
#         fig_pie = px.pie(
#             risk_counts,
#             names="Risk Level",
#             values="Count",
#             color="Risk Level",
#             color_discrete_map=RISK_COLORS,
#             hole=0.4,
#         )
#         fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
#         st.plotly_chart(fig_pie, use_container_width=True)

#     with col_b:
#         st.subheader("Threat Category Frequency")
#         categories = ["XSS", "SQL Injection", "CSRF", "Prompt Injection", "Jailbreak", "SSRF", "Command Injection"]
#         kw_map     = ["XSS", "SQL", "CSRF", "Prompt Injection", "Jailbreak", "SSRF", "Command"]
#         counts = [len(df[df["findings"].str.contains(kw, case=False, na=False)]) for kw in kw_map]
#         bar_df = pd.DataFrame({"Threat": categories, "Count": counts})
#         fig_bar = px.bar(bar_df, x="Threat", y="Count", color="Count",
#                          color_continuous_scale="Reds", text="Count")
#         fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white", showlegend=False)
#         st.plotly_chart(fig_bar, use_container_width=True)

#     st.divider()

#     st.subheader("Recent Attack Stream (last 10 scans)")
#     for _, row in df.head(10).iterrows():
#         ft  = str(row["findings"])
#         ts  = row.get("timestamp", "")
#         pfx = f"[{ts}] Prompt #{row['id']}"

#         if "Prompt Injection" in ft:  st.error(f"Prompt Injection -> {pfx}")
#         elif "Jailbreak"      in ft:  st.error(f"Jailbreak Attempt -> {pfx}")
#         elif "XSS"            in ft:  st.error(f"XSS Attack -> {pfx}")
#         elif "SQL"            in ft:  st.error(f"SQL Injection -> {pfx}")
#         elif "CSRF"           in ft:  st.warning(f"CSRF Pattern -> {pfx}")
#         elif "SSRF"           in ft:  st.warning(f"SSRF Activity -> {pfx}")
#         elif ft == "[]":              st.success(f"Safe Request -> {pfx}")
#         else:                         st.warning(f"Threat Detected -> {pfx}")

#     st.divider()

#     st.subheader("Full Scan Logs")
#     st.dataframe(df, use_container_width=True)
#     csv = df.to_csv(index=False)
#     st.download_button("Download Logs (CSV)", data=csv,
#                        file_name="promptshield_logs.csv", mime="text/csv")


# # =========================================================
# # MODULE 5 — AI SECURITY ASSISTANT (Enterprise Guardrail Pipeline)
# # =========================================================

# elif menu == "🤖 AI Security Assistant":

#     # ---- Import the file guardrail ----
#     from file_guardrail import run_file_guardrail, BLOCKED_EXTENSIONS, ALLOWED_EXTENSIONS

#     st.header("AI Security Assistant")
#     st.caption("Enterprise LLM Guardrail — File Upload + DLP + PII + Content Scan before every AI call")

#     # ---- Policy notice ----
#     st.info(
#         "All inputs pass through a 5-stage guardrail pipeline before reaching the AI:\n"
#         "**Stage 1** Extension Policy  →  **Stage 2** File Size  →  "
#         "**Stage 3** Binary Detection  →  **Stage 4** Content Scan (secrets, PII, code, injection)  →  "
#         "**Stage 5** Final Verdict\n\n"
#         "Blocked uploads are logged. The AI never sees blocked content."
#     )

#     st.divider()

#     # =========================================================
#     # INPUT MODE SELECTOR
#     # =========================================================

#     input_mode = st.radio(
#         "Input Mode",
#         ["💬 Text Question", "📎 File Upload + Question"],
#         horizontal=True,
#     )

#     st.divider()

#     # =========================================================
#     # MODE A — TEXT QUESTION
#     # =========================================================

#     if input_mode == "💬 Text Question":

#         question = st.text_area(
#             "Your Question",
#             height=120,
#             placeholder="e.g. What is a prompt injection attack? How does SSRF work?",
#         )

#         if st.button("Ask AI", use_container_width=False):
#             if not question.strip():
#                 st.warning("Please enter a question.")
#                 st.stop()

#             # Run DLP on text question too
#             from dlp_guard import scan_for_company_data, get_dlp_message
#             from pii_scanner import scan_all as pii_scan_all

#             with st.spinner("Running guardrail checks on your input..."):
#                 dlp_result = scan_for_company_data(question)
#                 pii_result = pii_scan_all(question)

#             # Show guardrail pipeline status
#             st.subheader("Guardrail Pipeline Result")
#             g1, g2, g3 = st.columns(3)

#             dlp_pass = not dlp_result["blocked"]
#             pii_pass = pii_result["risk"] in ("CLEAN", "MEDIUM")

#             g1.metric("DLP Policy", "PASS" if dlp_pass else "BLOCK",
#                       delta=None)
#             g2.metric("Secret Scan", "PASS" if pii_result["secret_count"] == 0 else "BLOCK",
#                       delta=None)
#             g3.metric("PII Scan", f"{pii_result['pii_count']} found",
#                       delta=None)

#             # Block if DLP or secrets detected
#             if dlp_result["blocked"]:
#                 st.error(get_dlp_message(dlp_result))
#                 with st.expander("DLP Detection Details"):
#                     for f in dlp_result["findings"]:
#                         st.write(f"**{f['category']}** — Line {f['line']}: `{f['snippet']}`")
#                 st.stop()

#             if pii_result["secret_count"] > 0:
#                 st.error(
#                     "🚫 **Secret / Credential Detected — Blocked**\n\n"
#                     "Your question contains API keys, tokens, or passwords. "
#                     "Never submit credentials to an AI system.\n\n"
#                     f"**Detected:** {', '.join(s['category'] for s in pii_result['secrets'])}\n\n"
#                     "*This attempt has been logged.*"
#                 )
#                 st.stop()

#             if pii_result["pii_count"] > 0:
#                 st.warning(
#                     f"⚠️ PII detected in your question ({pii_result['pii_count']} type(s)). "
#                     "The question will be sent to AI but please avoid including personal data."
#                 )

#             st.success("✅ All guardrail checks passed — sending to AI...")
#             st.divider()

#             with st.spinner("AI is analyzing..."):
#                 answer = ask_ai(question)

#             st.subheader("AI Response")
#             st.success(answer)


#     # =========================================================
#     # MODE B — FILE UPLOAD + QUESTION
#     # =========================================================

#     else:

#         # ---- Allowed / Blocked extension info ----
#         with st.expander("📋 File Upload Policy — What is allowed?"):
#             col_allow, col_block = st.columns(2)
#             with col_allow:
#                 st.markdown("**✅ Allowed Extensions**")
#                 for ext in sorted(ALLOWED_EXTENSIONS):
#                     st.markdown(f"- `{ext}`")
#                 st.caption("Content is still scanned even for allowed types.")
#             with col_block:
#                 st.markdown("**🚫 Blocked Extensions (examples)**")
#                 sample_blocked = sorted(list(BLOCKED_EXTENSIONS))[:20]
#                 for ext in sample_blocked:
#                     st.markdown(f"- `{ext}`")
#                 st.caption(f"...and {len(BLOCKED_EXTENSIONS) - 20} more. No source code, config, or binary files.")

#         st.divider()

#         # ---- File uploader ----
#         uploaded_file = st.file_uploader(
#             "Upload a file to analyze with AI",
#             type=None,   # We do manual extension validation
#             help=f"Max size: 5 MB. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
#         )

#         question = st.text_area(
#             "Your question about this file",
#             height=100,
#             placeholder="e.g. Summarize this document. What are the key risks mentioned?",
#         )

#         analyze_btn = st.button("🔍 Run Guardrail & Analyze", use_container_width=True)

#         if analyze_btn:

#             if uploaded_file is None:
#                 st.warning("Please upload a file first.")
#                 st.stop()

#             if not question.strip():
#                 st.warning("Please enter a question about the file.")
#                 st.stop()

#             file_bytes = uploaded_file.read()
#             filename   = uploaded_file.name

#             # ============================================================
#             # ENTERPRISE GUARDRAIL PIPELINE
#             # ============================================================

#             st.divider()
#             st.subheader("🔒 Guardrail Pipeline Executing...")

#             with st.spinner("Running 5-stage enterprise security scan..."):
#                 result = run_file_guardrail(filename, file_bytes)

#             # ---- Stage-by-stage status display ----
#             st.subheader("Pipeline Stages")

#             stage_icons = {
#                 "PASS": "✅", "BLOCK": "🚫", "WARN": "⚠️", "SKIP": "⏭️"
#             }

#             cols = st.columns(len(result["stages"]))
#             for i, stage in enumerate(result["stages"]):
#                 s = stage["result"]
#                 verdict_key = (
#                     "BLOCK" if s.get("passed") == False or s.get("is_binary") or s.get("blocked")
#                     else "WARN" if s.get("verdict") == "WARN"
#                     else "SKIP" if s.get("verdict") == "SKIP"
#                     else "PASS"
#                 )
#                 icon = stage_icons.get(verdict_key, "✅")
#                 with cols[i]:
#                     st.metric(
#                         label=stage["name"],
#                         value=f"{icon} {verdict_key}",
#                     )

#             st.divider()

#             # ---- BLOCKED ----
#             if result["blocked"]:

#                 # Pull true-type info from the binary/mime stage if present
#                 true_type    = ""
#                 claimed_ext  = ""
#                 attack_type  = result.get("attack_type", "")
#                 magic_hex    = ""
#                 for stage in result["stages"]:
#                     sr = stage.get("result", {})
#                     if "true_type" in sr:
#                         true_type   = sr.get("true_type", "")
#                         claimed_ext = sr.get("claimed_ext", "")
#                         magic_hex   = sr.get("magic_hex", "")
#                         break

#                 # Build block message
#                 block_lines = [
#                     f"🚫 **FILE BLOCKED — Security Policy Violation**\n",
#                     f"{result['summary']}\n",
#                     f"**Uploaded filename:** `{filename}`",
#                     f"**SHA-256:** `{result['file_hash'][:16]}...`",
#                 ]
#                 if true_type:
#                     block_lines.append(f"**Real file type detected:** `{true_type}`")
#                 if claimed_ext:
#                     block_lines.append(f"**Claimed extension:** `{claimed_ext}`")
#                 if magic_hex:
#                     block_lines.append(f"**Magic bytes (hex):** `0x{magic_hex.upper()[:16]}`")
#                 if attack_type:
#                     block_lines.append(f"**Attack classification:** `{attack_type}`")
#                 block_lines.append("\n*This upload attempt has been logged in the audit trail.*")

#                 st.error("\n".join(block_lines))

#                 if result["findings"]:
#                     st.subheader("Detected Violations")
#                     for f in result["findings"]:
#                         with st.expander(f"🚫 {f['category']}  (Line {f['line']})"):
#                             st.code(f["snippet"], language="text")
#                             st.caption(f"Risk Weight: {f['weight']} pts  |  MITRE: {f['mitre']}")

#                 # Audit trail shown even on block
#                 with st.expander("Audit Trail (Blocked Attempt)"):
#                     st.json({
#                         "event":          "FILE_UPLOAD_BLOCKED",
#                         "filename":       filename,
#                         "file_hash":      result["file_hash"],
#                         "size_bytes":     len(file_bytes),
#                         "claimed_ext":    claimed_ext or os.path.splitext(filename)[1],
#                         "true_type_detected": true_type or "N/A",
#                         "magic_bytes_hex":    magic_hex or "N/A",
#                         "attack_type":    attack_type or "Policy Violation",
#                         "verdict":        "BLOCK",
#                         "stages_run":     [s["name"] for s in result["stages"]],
#                         "block_reason":   result["summary"],
#                     })

#                 st.divider()
#                 st.subheader("What you can do instead")
#                 st.info(
#                     "- **Describe the problem in plain English** — do not upload the file\n"
#                     "- **Remove all credentials, internal URLs, and code** from the file first\n"
#                     "- **Use an anonymised version** with real values replaced by placeholders\n"
#                     "- **Contact your security team** if you believe this is a false positive"
#                 )
#                 st.stop()

#             # ---- WARNINGS (pass but with notices) ----
#             if result["verdict"] == "WARN" and result["findings"]:
#                 st.warning(
#                     f"⚠️ **File passed with {len(result['findings'])} warning(s)** — "
#                     f"review findings below before proceeding."
#                 )
#                 for f in result["findings"]:
#                     with st.expander(f"⚠️ {f['category']}  (Line {f['line']})"):
#                         st.code(f["snippet"], language="text")
#                         st.caption(f"Risk Weight: {f['weight']} pts  |  MITRE: {f['mitre']}")
#                 st.divider()

#             # ---- PASS — send to Gemini ----
#             st.success(f"✅ File cleared all guardrail stages — sending to AI")

#             # Show file metadata
#             size_kb = len(file_bytes) / 1024
#             m1, m2, m3, m4 = st.columns(4)
#             m1.metric("File",      filename)
#             m2.metric("Size",      f"{size_kb:.1f} KB")
#             m3.metric("Hash",      result["file_hash"][:8] + "...")
#             m4.metric("Status",    "CLEARED")

#             st.divider()
#             st.subheader("AI Analysis")

#             # Build prompt for Gemini — include file content summary
#             file_text = result.get("text", "")
#             if file_text:
#                 char_limit = 8000
#                 content_preview = file_text[:char_limit]
#                 if len(file_text) > char_limit:
#                     content_preview += f"\n\n[File truncated — showing first {char_limit} chars of {len(file_text)} total]"

#                 gemini_prompt = (
#                     f"The user has uploaded a file named '{filename}'.\n"
#                     f"File contents:\n---\n{content_preview}\n---\n\n"
#                     f"User question: {question}"
#                 )
#             else:
#                 gemini_prompt = (
#                     f"The user has uploaded a binary/image file named '{filename}' "
#                     f"({size_kb:.1f} KB). They ask: {question}"
#                 )

#             with st.spinner("AI is reading and analyzing the file..."):
#                 answer = ask_ai(gemini_prompt)

#             st.success(answer)

#             # Audit entry — always show for passing files too
#             true_type_pass = ""
#             magic_hex_pass = ""
#             for stage in result["stages"]:
#                 sr = stage.get("result", {})
#                 if "true_type" in sr:
#                     true_type_pass = sr.get("true_type", "")
#                     magic_hex_pass = sr.get("magic_hex", "")
#                     break

#             with st.expander("Audit Trail"):
#                 st.json({
#                     "event":              "FILE_UPLOAD_CLEARED",
#                     "filename":           filename,
#                     "file_hash":          result["file_hash"],
#                     "size_bytes":         len(file_bytes),
#                     "claimed_ext":        os.path.splitext(filename)[1],
#                     "true_type_detected": true_type_pass or "Plain Text / Unknown",
#                     "magic_bytes_hex":    magic_hex_pass or "N/A",
#                     "verdict":            result["verdict"],
#                     "stages_run":         [s["name"] for s in result["stages"]],
#                     "warnings":           len(result["findings"]),
#                     "question_preview":   question[:100] + "..." if len(question) > 100 else question,
#                 })

# # # MODULE 6 — LIVE CVE THREAT FEED
# # =========================================================

# elif menu == "🌐 CVE Threat Feed":

#     st.header("Live CVE Threat Intelligence Feed")
#     st.write("Latest Common Vulnerabilities and Exposures — sourced from CIRCL vulnerability-lookup.")

#     if st.button("Refresh Feed"):
#         st.rerun()

#     CIRCL_ENDPOINTS = [
#         "https://cve.circl.lu/api/last",
#         "https://vulnerability.circl.lu/api/last",
#         "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=15",
#     ]

#     cves = None
#     error_msg = None

#     def _extract_list(data):
#         if isinstance(data, list):
#             return data if data else None
#         if isinstance(data, dict):
#             for key in ("results", "data", "cves"):
#                 val = data.get(key)
#                 if isinstance(val, list) and val:
#                     return val
#             nvd_vulns = data.get("vulnerabilities")
#             if isinstance(nvd_vulns, list) and nvd_vulns:
#                 return [v.get("cve", v) for v in nvd_vulns]
#             for val in data.values():
#                 if isinstance(val, list) and val:
#                     return val
#         return None

#     with st.spinner("Fetching latest CVEs..."):
#         for url in CIRCL_ENDPOINTS:
#             try:
#                 resp = requests.get(url, timeout=12, headers={"Accept": "application/json"})
#                 if resp.status_code == 200:
#                     cves = _extract_list(resp.json())
#                     if cves:
#                         break
#             except Exception as e:
#                 error_msg = str(e)
#                 continue

#     if cves:
#         shown = 0
#         for raw in cves:
#             if shown >= 15:
#                 break
#             entry = parse_cve(raw)
#             if entry["cve_id"] == "Unknown CVE" and entry["summary"] == "No summary available.":
#                 continue

#             cvss  = entry["cvss"]
#             label = f"**{entry['cve_id']}**"
#             label += f" | CVSS: {cvss:.1f}" if cvss is not None else " | CVSS: N/A"
#             text  = f"{label}\n\n{entry['summary']}"

#             if cvss is not None and cvss >= 9.0:   st.error(f"🚨 {text}")
#             elif cvss is not None and cvss >= 7.0: st.warning(f"⚠️ {text}")
#             elif cvss is not None and cvss >= 4.0: st.info(f"🔵 {text}")
#             else:                                   st.info(f"ℹ️ {text}")
#             shown += 1

#         if shown == 0:
#             st.warning("Feed returned data but no readable CVE entries could be parsed.")
#             with st.expander("Raw API response (first entry)"):
#                 st.json(cves[0] if cves else {})
#         else:
#             with st.expander("Debug: raw first entry"):
#                 st.json(cves[0] if cves else {})
#     else:
#         st.warning("Live CVE feed could not be reached. Showing recent notable CVEs instead.")
#         st.divider()
#         st.subheader("Recent Notable CVEs (static reference)")

#         static_cves = [
#             {"id": "CVE-2025-21413", "cvss": 9.8, "color": "error",
#              "desc": "Windows Telephony Service RCE — attacker can execute arbitrary code remotely without authentication.",
#              "mitre": "T1190 – Exploit Public-Facing Application"},
#             {"id": "CVE-2025-21418", "cvss": 7.8, "color": "warning",
#              "desc": "Windows Ancillary Function Driver privilege escalation — local attacker gains SYSTEM privileges.",
#              "mitre": "T1068 – Exploitation for Privilege Escalation"},
#             {"id": "CVE-2024-49138", "cvss": 7.8, "color": "warning",
#              "desc": "Windows CLFS Driver heap buffer overflow enabling local privilege escalation. Actively exploited.",
#              "mitre": "T1068 – Exploitation for Privilege Escalation"},
#             {"id": "CVE-2024-38812", "cvss": 9.8, "color": "error",
#              "desc": "VMware vCenter Server heap overflow via DCERPC — unauthenticated remote code execution.",
#              "mitre": "T1190 – Exploit Public-Facing Application"},
#             {"id": "CVE-2024-6387 (regreSSHion)", "cvss": 8.1, "color": "warning",
#              "desc": "OpenSSH race condition allowing unauthenticated RCE as root on glibc-based Linux systems.",
#              "mitre": "T1190 – Exploit Public-Facing Application"},
#         ]

#         for cve in static_cves:
#             msg = f"**{cve['id']}** | CVSS: {cve['cvss']}\n\n{cve['desc']}\n\nMITRE: {cve['mitre']}"
#             if cve["color"] == "error":
#                 st.error(msg)
#             else:
#                 st.warning(msg)

#         st.caption("Source: NVD / Microsoft MSRC / Apple Security. Refresh or check https://cve.circl.lu for live data.")

import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
import requests

from detector import detect_prompt
from scorer import calculate_risk
from database import init_db, insert_log
from ai_engine import generate_ai_explanation
from auth import login, logout
from report_generator import generate_pdf
from chatbot import ask_ai
from pii_scanner import scan_all
from dlp_guard import scan_for_company_data, check_file_extension, get_dlp_message

REPORT_PATH = "PromptShield_Report.pdf"

# =========================================================
# BOOTSTRAP
# =========================================================

init_db()

st.set_page_config(
    page_title="PromptShield AI",
    page_icon="🛡️",
    layout="wide",
)

# =========================================================
# AUTH GATE
# =========================================================

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if not st.session_state["authenticated"]:
    login()
    st.stop()

# =========================================================
# CUSTOM THEME
# =========================================================

st.markdown("""
<style>
.main { background-color: #0E1117; color: white; }
h1, h2, h3 { color: #00FFAA; }
.stButton>button {
    background-color: #00FFAA;
    color: black;
    font-weight: bold;
    border-radius: 8px;
    height: 46px;
    min-width: 180px;
}
.stTextArea textarea { background-color: #1A1A2E; color: white; }
</style>
""", unsafe_allow_html=True)

# =========================================================
# HEADER
# =========================================================

col_title, col_logout = st.columns([5, 1])
with col_title:
    st.title("🛡️ PromptShield AI")
    st.caption("LLM Guardrail Engine — Real-Time Threat Detection & Policy Enforcement")
with col_logout:
    st.write("")
    if st.button("Logout"):
        logout()

st.divider()

# =========================================================
# SIDEBAR NAVIGATION
# =========================================================

st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
st.sidebar.title("Navigation")

menu = st.sidebar.radio(
    "Select Module",
    ["🔍 Prompt Analyzer", "🔏 PII & Secrets Scanner", "🚫 DLP Policy", "📊 Analytics Dashboard", "🤖 AI Security Assistant", "🌐 CVE Threat Feed"],
)

# =========================================================
# HELPERS
# =========================================================

def load_logs() -> pd.DataFrame:
    conn = sqlite3.connect("prompts.db")
    df = pd.read_sql_query("SELECT * FROM logs ORDER BY id DESC", conn)
    conn.close()
    return df


RISK_COLORS = {
    "LOW":      "#00FFAA",
    "MEDIUM":   "#FFD700",
    "HIGH":     "#FF6B35",
    "CRITICAL": "#FF3333",
}


def parse_cve(item: dict) -> dict:
    if not isinstance(item, dict):
        return {"cve_id": "Unknown CVE", "summary": "No summary available.", "cvss": None}

    cve_id = (
        item.get("id")
        or item.get("cveId")
        or (item.get("CVE_data_meta") or {}).get("ID")
        or "Unknown CVE"
    )

    summary = item.get("summary") or ""
    if not summary:
        summary = item.get("details") or ""
    if not summary:
        desc_field = item.get("description")
        if isinstance(desc_field, str):
            summary = desc_field
    if not summary:
        descs = item.get("descriptions")
        if not descs and isinstance(item.get("description"), dict):
            descs = item["description"].get("description_data", [])
        if isinstance(descs, list):
            for d in descs:
                if isinstance(d, dict) and d.get("lang", "").startswith("en"):
                    summary = d.get("value", "")
                    break
            if not summary and descs:
                first = descs[0]
                summary = first.get("value", "") if isinstance(first, dict) else str(first)
    if not summary:
        aliases = item.get("aliases", [])
        if aliases and isinstance(aliases, list):
            summary = f"See advisory: {', '.join(str(a) for a in aliases[:3])}"

    summary = (summary or "No summary available.").strip()
    if len(summary) > 450:
        summary = summary[:447] + "..."

    cvss = None
    for field in ("cvss", "cvss3", "cvssScore", "baseScore", "score"):
        val = item.get(field)
        if val is not None:
            try:
                cvss = float(val)
                break
            except (ValueError, TypeError):
                pass

    if cvss is None:
        severity_list = item.get("severity") or []
        if isinstance(severity_list, list):
            for s in severity_list:
                if isinstance(s, dict):
                    raw = s.get("score") or s.get("baseScore")
                    try:
                        cvss = float(raw); break
                    except (ValueError, TypeError):
                        pass
        elif isinstance(severity_list, (int, float)):
            try:
                cvss = float(severity_list)
            except (ValueError, TypeError):
                pass

    if cvss is None:
        metrics = item.get("metrics") or {}
        if isinstance(metrics, dict):
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if isinstance(entries, list) and entries:
                    raw = (entries[0].get("cvssData") or {}).get("baseScore")
                    try:
                        cvss = float(raw); break
                    except (ValueError, TypeError):
                        pass

    try:
        cvss = float(cvss) if cvss is not None else None
    except (ValueError, TypeError):
        cvss = None

    return {"cve_id": cve_id, "summary": summary, "cvss": cvss}


# =========================================================
# MODULE 1 — PROMPT ANALYZER
# =========================================================

if menu == "🔍 Prompt Analyzer":

    st.header("Prompt Analyzer")
    st.write("Paste any prompt below to scan it for injection, jailbreak, and other attack patterns.")

    prompt = st.text_area("Enter Prompt to Analyze", height=200, placeholder="Paste suspicious prompt here...")

    if st.button("🔎 Analyze Prompt"):

        if not prompt.strip():
            st.warning("Please enter a prompt before analyzing.")
            st.stop()

        dlp = scan_for_company_data(prompt)
        if dlp["blocked"]:
            st.error(get_dlp_message(dlp))
            st.divider()
            st.subheader("DLP Detection Details")
            for f in dlp["findings"]:
                with st.expander(f"🚫 {f['category']}  (line {f['line']})"):
                    st.code(f["snippet"], language="text")
                    st.caption(f"Risk weight: {f['weight']} pts")
            st.info("Tip: Describe your problem in plain English. Do not paste source code, config files, credentials, or internal URLs.")
            st.stop()
        elif dlp["verdict"] == "WARN":
            st.warning(f"DLP Warning — {dlp['category_count']} suspicious pattern(s) detected (code-like content). Proceed only if this is intentional test data.")

        with st.spinner("Scanning for threats..."):
            findings = detect_prompt(prompt)
            score, risk, severity, confidence = calculate_risk(findings)
            insert_log(prompt, str(findings), score, risk)

        st.divider()
        st.subheader("Analysis Result")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Risk Score",        score)
        c2.metric("Risk Level",        risk)
        c3.metric("Severity",          severity)
        c4.metric("Threat Confidence", confidence)

        st.divider()

        if risk == "CRITICAL":
            st.error("SOC ALERT — Critical malicious payload detected! Immediate action required.")
        elif risk == "HIGH":
            st.warning("HIGH RISK — Suspicious activity detected. Review and block.")
        elif risk == "MEDIUM":
            st.info("MEDIUM RISK — Potential threat activity observed. Monitor closely.")
        else:
            st.success("Prompt appears safe. No malicious patterns matched.")

        if findings:
            generate_pdf(prompt, findings, score, risk)
            with open(REPORT_PATH, "rb") as f:
                st.download_button(
                    "📄 Download Security Report (PDF)",
                    data=f,
                    file_name="PromptShield_Report.pdf",
                    mime="application/pdf",
                )

            st.divider()
            st.subheader("AI Threat Analysis")
            with st.spinner("Generating AI analysis..."):
                explanations = generate_ai_explanation(findings)
            for exp in explanations:
                st.warning(exp)

            st.divider()
            st.subheader("Detected Threats")
            for item in findings:
                with st.expander(f"🔴 {item['category']}"):
                    st.write(f"**Matched Pattern:** `{item['pattern']}`")
                    st.info(f"**MITRE ATT&CK:** {item.get('mitre', 'N/A')}")

            st.divider()
            st.subheader("Recommended Actions")
            recs = [
                "Block this prompt from reaching the LLM immediately.",
                "Enable strict input validation and sanitization.",
                "Apply Web Application Firewall (WAF) rules.",
                "Alert the SOC team and create an incident ticket.",
                "Review recent logs for similar patterns.",
                "Rotate any secrets or credentials that may have been exposed.",
            ]
            for rec in recs:
                st.success(f"✔ {rec}")
        else:
            st.success("Prompt is Safe — no malicious patterns detected.")


# =========================================================
# MODULE 2 — PII & SECRETS SCANNER
# =========================================================

elif menu == "🔏 PII & Secrets Scanner":

    st.header("PII & Secrets Scanner")
    st.write("Detect Personally Identifiable Information (PII) and leaked credentials inside any text.")

    text_input = st.text_area(
        "Paste text to scan",
        height=220,
        placeholder="Paste any text here — emails, phone numbers, API keys, tokens, passwords, etc.",
    )

    col_scan, col_clear = st.columns([2, 1])
    with col_scan:
        scan_clicked = st.button("🔍 Scan for PII & Secrets", use_container_width=True)
    with col_clear:
        if st.button("Clear", use_container_width=True):
            st.rerun()

    if scan_clicked:
        if not text_input.strip():
            st.warning("Please paste some text to scan.")
            st.stop()

        dlp = scan_for_company_data(text_input)
        if dlp["blocked"]:
            st.error(get_dlp_message(dlp))
            for f in dlp["findings"]:
                with st.expander(f"🚫 {f['category']}"):
                    st.code(f["snippet"], language="text")
            st.stop()

        with st.spinner("Scanning for PII and secrets..."):
            result = scan_all(text_input)

        st.divider()

        risk = result["risk"]
        risk_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "CLEAN": "🟢"}
        icon = risk_icons.get(risk, "⚪")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("PII Found",      result["pii_count"])
        c2.metric("Secrets Found",  result["secret_count"])
        c3.metric("Total Findings", result["total"])
        c4.metric("Risk Level",     f"{icon} {risk}")

        st.divider()

        if risk == "CRITICAL":
            st.error("CRITICAL — API keys or credentials detected! Rotate them immediately.")
        elif risk == "HIGH":
            st.warning("HIGH RISK — Multiple PII fields detected. Review before sharing.")
        elif risk == "MEDIUM":
            st.info("MEDIUM — PII detected. Ensure data handling complies with your policy.")
        else:
            st.success("CLEAN — No PII or secrets detected in this text.")

        if result["pii"]:
            st.subheader("PII Detections")
            for item in result["pii"]:
                with st.expander(f"🟡 {item['category']}  x{item['count']} found"):
                    st.write(f"**Sample (redacted):** `{item['matched_value']}`")
                    st.info(f"**MITRE ATT&CK:** {item['mitre']}")

        if result["secrets"]:
            st.subheader("Credential / Secret Detections")
            for item in result["secrets"]:
                with st.expander(f"🔴 {item['category']}  x{item['count']} found"):
                    st.write(f"**Sample (redacted):** `{item['matched_value']}`")
                    st.error(f"**MITRE ATT&CK:** {item['mitre']}")
                    st.caption("Action required: Rotate this credential immediately.")

        if result["total"] > 0:
            st.divider()
            st.subheader("Recommended Actions")
            if result["secrets"]:
                st.error("Rotate all detected API keys and tokens immediately.")
                st.error("Check access logs for unauthorized use of these credentials.")
                st.error("Store secrets in environment variables — never in prompts.")
            if result["pii"]:
                st.info("Apply data masking before sending text to any AI system.")
                st.info("Review your data retention policies for GDPR/DPDP compliance.")
                st.info("Implement a pre-processing filter to strip PII before it reaches the LLM.")


# =========================================================
# MODULE 3 — DLP POLICY MANAGER
# =========================================================

elif menu == "🚫 DLP Policy":

    st.header("Data Loss Prevention (DLP) Policy")
    st.write("Configure what types of content are blocked. All inputs pass through this policy engine before processing.")

    st.divider()

    c1, c2, c3 = st.columns(3)
    c1.metric("DLP Status",           "ACTIVE")
    c2.metric("Categories Monitored", "8")
    c3.metric("File Types Blocked",   "30+")

    st.divider()

    st.subheader("Blocked Content Categories")
    from dlp_guard import CODE_PATTERNS, FILE_EXTENSION_BLOCK, CATEGORY_WEIGHTS

    blocked_cats = [
        ("Source Code — Function/Class Definition", "Python, Java, JavaScript, C++, Go, Rust functions and classes", "🔴"),
        ("Source Code — Import Statements",         "import/require/using statements from any language",            "🔴"),
        ("Database Schema / SQL DDL",               "CREATE TABLE, ALTER TABLE, schema definitions",                "🔴"),
        ("Configuration / Environment File",        ".env files, DB connection strings, host/port/password configs","🔴"),
        ("API Endpoint / Internal URL",             "Internal API routes, private IPs, Bearer tokens in headers",  "🔴"),
        ("Infrastructure / DevOps Config",          "Kubernetes YAML, Dockerfile, Terraform, Nginx/Apache config",  "🔴"),
        ("Proprietary Business Logic Keywords",     "internal_use_only, confidential, proprietary markers",        "🟡"),
        ("Compiled / Binary File Content",          "ELF binaries, PE executables, hex dumps, base64 archives",    "🔴"),
    ]

    for cat, desc, icon in blocked_cats:
        weight = CATEGORY_WEIGHTS.get(cat, 25)
        with st.expander(f"{icon} {cat}  —  Risk Weight: {weight}"):
            st.write(desc)
            st.caption("MITRE ATT&CK: T1213 – Data from Information Repositories")

    st.divider()

    st.subheader("Blocked File Extensions")
    ext_cols = st.columns(6)
    sorted_exts = sorted(FILE_EXTENSION_BLOCK)
    per_col = len(sorted_exts) // 6 + 1
    for i, col in enumerate(ext_cols):
        chunk = sorted_exts[i*per_col:(i+1)*per_col]
        for e in chunk:
            col.markdown(f"`{e}`")

    st.divider()

    st.subheader("Live DLP Tester")
    test_input = st.text_area("Paste text to test", height=150, placeholder="Paste some text to see if DLP would block it...")

    if st.button("Test DLP Policy", use_container_width=True):
        if test_input.strip():
            result = scan_for_company_data(test_input)
            if result["verdict"] == "BLOCK":
                st.error(f"BLOCKED — Score: {result['total_score']}  |  Categories: {result['category_count']}")
                for f in result["findings"]:
                    with st.expander(f"🚫 {f['category']}  (line {f['line']})"):
                        st.code(f["snippet"], language="text")
                        st.caption(f"Risk weight: {f['weight']}")
            elif result["verdict"] == "WARN":
                st.warning(f"WARNING — Score: {result['total_score']}  |  Code-like content detected.")
                for f in result["findings"]:
                    with st.expander(f"⚠ {f['category']}"):
                        st.code(f["snippet"], language="text")
            else:
                st.success("PASS — No policy violations detected. This text would be allowed.")

    st.divider()

    st.subheader("Policy Rules Summary")
    st.info(
        "Enforcement Points:\n"
        "- Prompt Analyzer — DLP checked before every scan\n"
        "- PII & Secrets Scanner — DLP checked before every scan\n"
        "- AI Security Assistant — DLP checked before sending to Gemini\n\n"
        "On violation: Input is blocked, user sees a policy message, event is logged."
    )

    with st.expander("What users CAN submit"):
        st.markdown("""
- Plain English descriptions of security problems
- Anonymised log snippets (no credentials, no internal IPs)
- Public CVE IDs or vulnerability names
- Generic attack patterns for testing
- Cybersecurity questions
        """)

    with st.expander("What users CANNOT submit"):
        st.markdown("""
- Source code files (.py, .js, .java, .cs, .go, etc.)
- Database schemas or SQL DDL statements
- .env files or configuration with real credentials
- Internal API endpoints or private IP addresses
- Kubernetes / Docker / Terraform infrastructure files
- Compiled binaries or hex dumps
        """)


# =========================================================
# MODULE 4 — ANALYTICS DASHBOARD
# =========================================================

elif menu == "📊 Analytics Dashboard":

    st.header("Threat Analytics Dashboard")

    df = load_logs()

    if df.empty:
        st.info("No scan logs yet. Run some prompts through the Prompt Analyzer first.")
        st.stop()

    total      = len(df)
    critical   = len(df[df["risk"] == "CRITICAL"])
    high       = len(df[df["risk"] == "HIGH"])
    safe_count = len(df[df["risk"] == "LOW"])

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Scans",      total)
    c2.metric("Critical Threats", critical)
    c3.metric("High Risk",        high)
    c4.metric("Safe Prompts",     safe_count)

    st.divider()

    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("Risk Distribution")
        risk_counts = df["risk"].value_counts().reset_index()
        risk_counts.columns = ["Risk Level", "Count"]
        fig_pie = px.pie(
            risk_counts,
            names="Risk Level",
            values="Count",
            color="Risk Level",
            color_discrete_map=RISK_COLORS,
            hole=0.4,
        )
        fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
        st.plotly_chart(fig_pie, use_container_width=True)

    with col_b:
        st.subheader("Threat Category Frequency")
        categories = ["XSS", "SQL Injection", "CSRF", "Prompt Injection", "Jailbreak", "SSRF", "Command Injection"]
        kw_map     = ["XSS", "SQL", "CSRF", "Prompt Injection", "Jailbreak", "SSRF", "Command"]
        counts = [len(df[df["findings"].str.contains(kw, case=False, na=False)]) for kw in kw_map]
        bar_df = pd.DataFrame({"Threat": categories, "Count": counts})
        fig_bar = px.bar(bar_df, x="Threat", y="Count", color="Count",
                         color_continuous_scale="Reds", text="Count")
        fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white", showlegend=False)
        st.plotly_chart(fig_bar, use_container_width=True)

    st.divider()

    st.subheader("Recent Attack Stream (last 10 scans)")
    for _, row in df.head(10).iterrows():
        ft  = str(row["findings"])
        ts  = row.get("timestamp", "")
        pfx = f"[{ts}] Prompt #{row['id']}"

        if "Prompt Injection" in ft:  st.error(f"Prompt Injection -> {pfx}")
        elif "Jailbreak"      in ft:  st.error(f"Jailbreak Attempt -> {pfx}")
        elif "XSS"            in ft:  st.error(f"XSS Attack -> {pfx}")
        elif "SQL"            in ft:  st.error(f"SQL Injection -> {pfx}")
        elif "CSRF"           in ft:  st.warning(f"CSRF Pattern -> {pfx}")
        elif "SSRF"           in ft:  st.warning(f"SSRF Activity -> {pfx}")
        elif ft == "[]":              st.success(f"Safe Request -> {pfx}")
        else:                         st.warning(f"Threat Detected -> {pfx}")

    st.divider()

    st.subheader("Full Scan Logs")
    st.dataframe(df, use_container_width=True)
    csv = df.to_csv(index=False)
    st.download_button("Download Logs (CSV)", data=csv,
                       file_name="promptshield_logs.csv", mime="text/csv")


# =========================================================
# MODULE 5 — AI SECURITY ASSISTANT
# =========================================================

elif menu == "🤖 AI Security Assistant":

    from file_guardrail import run_file_guardrail, BLOCKED_EXTENSIONS, ALLOWED_EXTENSIONS

    st.header("🤖 AI Security Assistant")
    st.caption("Enterprise LLM Guardrail — Every input screened before reaching AI")

    st.info(
        "**5-Stage Guardrail Pipeline** runs on every submission:\n"
        "Stage 1: Extension Policy → Stage 2: File Size → "
        "Stage 3: Binary + Content-Type Mismatch Detection → "
        "Stage 4: Deep Content Scan (XSS, SQLi, Prompt Injection, Secrets, PII) → "
        "Stage 5: Final Verdict\n\n"
        "Blocked inputs are never sent to AI."
    )

    st.divider()

    input_mode = st.radio(
        "Input Mode",
        ["💬 Text Question", "📎 File Upload + Question"],
        horizontal=True,
    )

    st.divider()

    # ── MODE A: TEXT QUESTION ──────────────────────────────
    if input_mode == "💬 Text Question":

        question = st.text_area(
            "Your Question",
            height=120,
            placeholder="e.g. What is a prompt injection attack? How does SSRF work?",
        )

        if st.button("🔍 Run Guardrail & Ask AI", use_container_width=True):
            if not question.strip():
                st.warning("Please enter a question.")
                st.stop()

            with st.spinner("Running guardrail checks..."):
                dlp = scan_for_company_data(question)
                from pii_scanner import scan_all as pii_scan
                pii = pii_scan(question)

            # Pipeline status
            st.subheader("Guardrail Pipeline Result")
            g1, g2, g3, g4 = st.columns(4)
            g1.metric("DLP Policy",    "🚫 BLOCK" if dlp["blocked"] else "✅ PASS")
            g2.metric("Secret Scan",   "🚫 BLOCK" if pii["secret_count"] > 0 else "✅ PASS")
            g3.metric("PII Scan",      f"⚠️ {pii['pii_count']} found" if pii["pii_count"] > 0 else "✅ PASS")
            g4.metric("Prompt Safety", "🚫 BLOCK" if dlp["blocked"] else "✅ PASS")

            if dlp["blocked"]:
                st.error(get_dlp_message(dlp))
                for f in dlp["findings"]:
                    with st.expander(f"🚫 {f['category']}  (line {f['line']})"):
                        st.code(f["snippet"], language="text")
                        st.caption(f"Risk weight: {f['weight']} pts")
                st.stop()

            if pii["secret_count"] > 0:
                st.error(
                    "🚫 **Credential Detected — Blocked**\n\n"
                    "Your question contains API keys or passwords. Never submit credentials to AI.\n\n"
                    f"Detected: {', '.join(s['category'] for s in pii['secrets'])}"
                )
                st.stop()

            if pii["pii_count"] > 0:
                st.warning(f"⚠️ PII detected ({pii['pii_count']} type(s)). Proceeding but avoid sending personal data.")

            st.success("✅ All guardrail checks passed — sending to AI...")
            st.divider()

            with st.spinner("AI is analyzing..."):
                answer = ask_ai(question)
            st.subheader("AI Response")
            st.success(answer)

    # ── MODE B: FILE UPLOAD + QUESTION ────────────────────
    else:

        with st.expander("📋 File Upload Policy — What is allowed?"):
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("**✅ Allowed Extensions**")
                for ext in sorted(ALLOWED_EXTENSIONS):
                    st.markdown(f"- `{ext}`")
                st.caption("Content is still scanned even for allowed types.")
            with col_b:
                st.markdown("**🚫 Blocked Extensions (sample)**")
                for ext in sorted(list(BLOCKED_EXTENSIONS))[:20]:
                    st.markdown(f"- `{ext}`")
                st.caption(f"...and {len(BLOCKED_EXTENSIONS)-20} more.")

        st.divider()

        uploaded_file = st.file_uploader(
            "Upload a file to analyze with AI",
            type=None,
            help=f"Max 5 MB. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

        question = st.text_area(
            "Your question about this file",
            height=100,
            placeholder="e.g. Summarize this document. What are the key risks?",
        )

        if st.button("🔍 Run Guardrail & Analyze", use_container_width=True):

            if uploaded_file is None:
                st.warning("Please upload a file first.")
                st.stop()

            if not question.strip():
                st.warning("Please enter a question about the file.")
                st.stop()

            file_bytes = uploaded_file.read()
            filename   = uploaded_file.name

            st.divider()
            st.subheader("🔒 Guardrail Pipeline Executing...")

            # Pre-check: scan filename itself for company names / suspicious patterns
            from dlp_guard import scan_for_company_data as dlp_scan
            filename_check = dlp_scan(filename.replace(".", " ").replace("_", " ").replace("-", " "))
            if filename_check["blocked"]:
                st.error(
                    f"🚫 **Filename Blocked — DLP Policy Violation**\n\n"
                    f"The filename `{filename}` contains restricted terms: "
                    f"{', '.join(f['category'] for f in filename_check['findings'])}\n\n"
                    f"Rename the file and try again."
                )
                st.stop()

            with st.spinner("Running 5-stage enterprise security scan..."):
                result = run_file_guardrail(filename, file_bytes)

            # Stage status display
            st.subheader("Pipeline Stages")
            cols = st.columns(len(result["stages"]))
            for i, stage in enumerate(result["stages"]):
                s = stage["result"]
                if s.get("passed") == False or s.get("is_binary") or s.get("blocked"):
                    verdict_key, icon = "BLOCK", "🚫"
                elif s.get("verdict") == "WARN":
                    verdict_key, icon = "WARN", "⚠️"
                elif s.get("verdict") == "SKIP":
                    verdict_key, icon = "SKIP", "⏭️"
                else:
                    verdict_key, icon = "PASS", "✅"
                with cols[i]:
                    st.metric(stage["name"], f"{icon} {verdict_key}")

            st.divider()

            # BLOCKED
            if result["blocked"]:
                st.error(
                    f"🚫 **FILE BLOCKED — Security Policy Violation**\n\n"
                    f"{result['summary']}\n\n"
                    f"**File:** `{filename}`  |  "
                    f"**SHA-256:** `{result['file_hash'][:16]}...`\n\n"
                    f"*This upload has been logged in the audit trail.*"
                )
                if result.get("attack_type"):
                    st.error(f"**Attack Type:** {result['attack_type']}")

                if result["findings"]:
                    st.subheader("Detected Violations")
                    for f in result["findings"]:
                        with st.expander(f"🚫 {f['category']}  (Line {f['line']})"):
                            st.code(f["snippet"], language="text")
                            st.caption(f"Risk Weight: {f['weight']} pts  |  MITRE: {f['mitre']}")

                st.divider()
                st.info(
                    "**What you can do instead:**\n"
                    "- Describe the problem in plain English\n"
                    "- Remove all credentials, code, and internal URLs first\n"
                    "- Use anonymised data with placeholders\n"
                    "- Contact your security team if this is a false positive"
                )
                st.stop()

            # WARNINGS
            if result["verdict"] == "WARN" and result["findings"]:
                st.warning(f"⚠️ File passed with {len(result['findings'])} warning(s).")
                for f in result["findings"]:
                    with st.expander(f"⚠️ {f['category']}  (Line {f['line']})"):
                        st.code(f["snippet"], language="text")
                        st.caption(f"MITRE: {f['mitre']}")
                st.divider()

            # PASS — send to AI
            st.success("✅ File cleared all guardrail stages — sending to AI")
            size_kb = len(file_bytes) / 1024
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("File",   filename)
            m2.metric("Size",   f"{size_kb:.1f} KB")
            m3.metric("Hash",   result["file_hash"][:8] + "...")
            m4.metric("Status", "CLEARED")

            st.divider()
            st.subheader("AI Analysis")

            file_text = result.get("text", "")
            if file_text:
                preview = file_text[:8000]
                if len(file_text) > 8000:
                    preview += f"\n\n[Truncated — showing first 8000 of {len(file_text)} chars]"
                gemini_prompt = (
                    f"The user uploaded '{filename}'.\nFile contents:\n---\n{preview}\n---\n\n"
                    f"User question: {question}"
                )
            else:
                gemini_prompt = (
                    f"The user uploaded a binary/image file '{filename}' ({size_kb:.1f} KB). "
                    f"They ask: {question}"
                )

            with st.spinner("AI is reading and analyzing the file..."):
                answer = ask_ai(gemini_prompt)
            st.success(answer)

            with st.expander("📋 Audit Trail"):
                st.json({
                    "filename":   filename,
                    "file_hash":  result["file_hash"],
                    "size_bytes": len(file_bytes),
                    "verdict":    result["verdict"],
                    "warnings":   len(result["findings"]),
                    "question":   question[:100],
                })


# =========================================================
# MODULE 6 — LIVE CVE THREAT FEED
# =========================================================

elif menu == "🌐 CVE Threat Feed":

    st.header("Live CVE Threat Intelligence Feed")
    st.write("Latest Common Vulnerabilities and Exposures — sourced from CIRCL vulnerability-lookup.")

    if st.button("Refresh Feed"):
        st.rerun()

    CIRCL_ENDPOINTS = [
        "https://cve.circl.lu/api/last",
        "https://vulnerability.circl.lu/api/last",
        "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=15",
    ]

    cves = None
    error_msg = None

    def _extract_list(data):
        if isinstance(data, list):
            return data if data else None
        if isinstance(data, dict):
            for key in ("results", "data", "cves"):
                val = data.get(key)
                if isinstance(val, list) and val:
                    return val
            nvd_vulns = data.get("vulnerabilities")
            if isinstance(nvd_vulns, list) and nvd_vulns:
                return [v.get("cve", v) for v in nvd_vulns]
            for val in data.values():
                if isinstance(val, list) and val:
                    return val
        return None

    with st.spinner("Fetching latest CVEs..."):
        for url in CIRCL_ENDPOINTS:
            try:
                resp = requests.get(url, timeout=12, headers={"Accept": "application/json"})
                if resp.status_code == 200:
                    cves = _extract_list(resp.json())
                    if cves:
                        break
            except Exception as e:
                error_msg = str(e)
                continue

    if cves:
        shown = 0
        for raw in cves:
            if shown >= 15:
                break
            entry = parse_cve(raw)
            if entry["cve_id"] == "Unknown CVE" and entry["summary"] == "No summary available.":
                continue

            cvss  = entry["cvss"]
            label = f"**{entry['cve_id']}**"
            label += f" | CVSS: {cvss:.1f}" if cvss is not None else " | CVSS: N/A"
            text  = f"{label}\n\n{entry['summary']}"

            if cvss is not None and cvss >= 9.0:   st.error(f"🚨 {text}")
            elif cvss is not None and cvss >= 7.0: st.warning(f"⚠️ {text}")
            elif cvss is not None and cvss >= 4.0: st.info(f"🔵 {text}")
            else:                                   st.info(f"ℹ️ {text}")
            shown += 1

        if shown == 0:
            st.warning("Feed returned data but no readable CVE entries could be parsed.")
            with st.expander("Raw API response (first entry)"):
                st.json(cves[0] if cves else {})
        else:
            with st.expander("Debug: raw first entry"):
                st.json(cves[0] if cves else {})
    else:
        st.warning("Live CVE feed could not be reached. Showing recent notable CVEs instead.")
        st.divider()
        st.subheader("Recent Notable CVEs (static reference)")

        static_cves = [
            {"id": "CVE-2025-21413", "cvss": 9.8, "color": "error",
             "desc": "Windows Telephony Service RCE — attacker can execute arbitrary code remotely without authentication.",
             "mitre": "T1190 – Exploit Public-Facing Application"},
            {"id": "CVE-2025-21418", "cvss": 7.8, "color": "warning",
             "desc": "Windows Ancillary Function Driver privilege escalation — local attacker gains SYSTEM privileges.",
             "mitre": "T1068 – Exploitation for Privilege Escalation"},
            {"id": "CVE-2024-49138", "cvss": 7.8, "color": "warning",
             "desc": "Windows CLFS Driver heap buffer overflow enabling local privilege escalation. Actively exploited.",
             "mitre": "T1068 – Exploitation for Privilege Escalation"},
            {"id": "CVE-2024-38812", "cvss": 9.8, "color": "error",
             "desc": "VMware vCenter Server heap overflow via DCERPC — unauthenticated remote code execution.",
             "mitre": "T1190 – Exploit Public-Facing Application"},
            {"id": "CVE-2024-6387 (regreSSHion)", "cvss": 8.1, "color": "warning",
             "desc": "OpenSSH race condition allowing unauthenticated RCE as root on glibc-based Linux systems.",
             "mitre": "T1190 – Exploit Public-Facing Application"},
        ]

        for cve in static_cves:
            msg = f"**{cve['id']}** | CVSS: {cve['cvss']}\n\n{cve['desc']}\n\nMITRE: {cve['mitre']}"
            if cve["color"] == "error":
                st.error(msg)
            else:
                st.warning(msg)

        st.caption("Source: NVD / Microsoft MSRC / Apple Security. Refresh or check https://cve.circl.lu for live data.")