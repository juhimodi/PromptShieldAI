from fpdf import FPDF

def generate_pdf(prompt, findings, risk_score, risk_level):

    pdf = FPDF()

    pdf.add_page()

    pdf.set_font("Arial", "B", 20)

    pdf.cell(200, 10, "PromptShield AI Report", ln=True)

    pdf.ln(10)

    # Prompt
    pdf.set_font("Arial", "B", 14)

    pdf.cell(200, 10, "Analyzed Prompt:", ln=True)

    pdf.set_font("Arial", "", 12)

    pdf.multi_cell(0, 10, prompt)

    pdf.ln(5)

    # Risk Info
    pdf.set_font("Arial", "B", 14)

    pdf.cell(200, 10, "Risk Assessment", ln=True)

    pdf.set_font("Arial", "", 12)

    pdf.cell(200, 10, f"Risk Score: {risk_score}", ln=True)

    pdf.cell(200, 10, f"Risk Level: {risk_level}", ln=True)

    pdf.ln(5)

    # Findings
    pdf.set_font("Arial", "B", 14)

    pdf.cell(200, 10, "Threat Findings", ln=True)

    pdf.set_font("Arial", "", 12)

    if findings:

        for item in findings:

            pdf.multi_cell(
                0,
                10,
                f"Category: {item['category']}"
            )

            pdf.multi_cell(
                0,
                10,
                f"Matched Pattern: {item['pattern']}"
            )

            pdf.ln(2)

    else:

        pdf.cell(
            200,
            10,
            "No malicious activity detected.",
            ln=True
        )

    pdf.ln(5)

    # Recommendations
    pdf.set_font("Arial", "B", 14)

    pdf.cell(200, 10, "Security Recommendations", ln=True)

    pdf.set_font("Arial", "", 12)

    recommendations = [

        "Enable WAF protection",
        "Apply input sanitization",
        "Monitor suspicious sessions",
        "Review SOC alerts regularly",
        "Block malicious payload execution",
        "Use secure authentication mechanisms"

    ]

    for rec in recommendations:

        pdf.multi_cell(0, 10, f"- {rec}")

    # Save PDF
    pdf.output("PromptShield_Report.pdf")