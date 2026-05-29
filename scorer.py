# def calculate_risk(findings):

#     score = len(findings) * 25

#     if score == 0:
#         level = "LOW"

#     elif score <= 25:
#         level = "MEDIUM"

#     elif score <= 50:
#         level = "HIGH"

#     else:
#         level = "CRITICAL"

#     return score, level
def calculate_risk(findings):

    score = len(findings) * 25

    # =========================
    # RISK LEVEL
    # =========================

    if score == 0:

        level = "LOW"
        severity = "Informational"
        confidence = "10%"

    elif score <= 25:

        level = "MEDIUM"
        severity = "Medium"
        confidence = "45%"

    elif score <= 50:

        level = "HIGH"
        severity = "High"
        confidence = "75%"

    else:

        level = "CRITICAL"
        severity = "Critical"
        confidence = "95%"

    return score, level, severity, confidence