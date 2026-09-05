def calculate_risk(phishing_prob: float, fraud_alert: dict = None) -> dict:
    risk_score = int(round(phishing_prob))

    is_fraud = fraud_alert and fraud_alert.get('is_fraud_or_illegal')

    if is_fraud:
        # Boost risk score to minimum 90 for illegal / fraud operations
        risk_score = max(risk_score, 92)

    risk_score = max(0, min(100, risk_score))

    if is_fraud:
        risk_level = 'CRITICAL'
        badge_color = 'darkred'
        recommendation = (
            f"ILLEGAL / FRAUD ALERT: This domain is associated with {fraud_alert.get('category', 'illegal activities')} "
            f"({fraud_alert.get('reason', '')}). Users frequently fall victim to financial extortion, cyber fraud, and fund freezing on such sites. "
            "DO NOT USE THIS LINK or deposit any money."
        )
    elif risk_score <= 20:
        risk_level = 'LOW'
        badge_color = 'green'
        recommendation = 'The website appears low risk based on analyzed URL characteristics. Continue to verify the domain before entering sensitive credentials.'
    elif risk_score <= 40:
        risk_level = 'MODERATE'
        badge_color = 'yellow'
        recommendation = 'Moderate risk indicators observed. Exercise standard caution and confirm domain authenticity before submitting information.'
    elif risk_score <= 60:
        risk_level = 'MEDIUM'
        badge_color = 'orange'
        recommendation = 'Suspicious elements detected in URL structure. Exercise caution; verify certificate and site identity.'
    elif risk_score <= 80:
        risk_level = 'HIGH'
        badge_color = 'red'
        recommendation = 'High probability of phishing or fraud. Do not input passwords, financial details, or OTP codes on this page.'
    else:
        risk_level = 'CRITICAL'
        badge_color = 'darkred'
        recommendation = 'CRITICAL ALERT: Strong indicators of a fraudulent phishing or scam website. Avoid entering any credentials, credit card numbers, or personal data.'

    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'badge_color': badge_color,
        'recommendation': recommendation
    }
