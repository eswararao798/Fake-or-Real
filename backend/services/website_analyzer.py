import os
import joblib
import numpy as np
from backend.services.feature_extractor import extract_features, features_to_vector
from backend.services.risk_engine import calculate_risk
from backend.services.xai_engine import explain_prediction
from backend.services.fraud_detector import detect_fraudulent_or_illegal_site
from backend.services.content_safety import evaluate_student_safety

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../models'))
MODEL_PATH = os.path.join(MODELS_DIR, 'phishing_model.pkl')

_model = None

def get_model():
    global _model
    if _model is None and os.path.exists(MODEL_PATH):
        _model = joblib.load(MODEL_PATH)
    return _model

def generate_security_review(features: dict, prediction: str, risk_info: dict, fraud_alert: dict = None, student_safety: dict = None) -> dict:
    detected_issues = []
    positive_indicators = []

    if student_safety and student_safety.get('is_blocked'):
        detected_issues.append(f"STUDENT SAFETY VIOLATION: {student_safety.get('reason')}")
        detected_issues.append("Unapproved domain for academic environments. Access restricted.")
    elif student_safety and student_safety.get('category') == 'EDUCATIONAL_RESOURCE':
        positive_indicators.append(f"STUDENT-FRIENDLY: {student_safety.get('reason')}")

    if fraud_alert and fraud_alert.get('is_fraud_or_illegal'):
        detected_issues.append(f"CRITICAL: {fraud_alert.get('reason', 'Domain flagged as high-risk illegal/fraudulent operation.')}")
        detected_issues.append("Unregulated betting/financial operation prone to sudden user fund freezing, cyber fraud, and credential compromise.")

    if features.get('has_ip'):
        detected_issues.append('URL hostname directly uses a numeric IP address instead of a registered domain.')
    if features.get('url_length', 0) > 75:
        detected_issues.append('Excessive URL length (' + str(features['url_length']) + ' characters).')
    if features.get('has_suspicious_keyword'):
        detected_issues.append('Detected ' + str(features.get('suspicious_keyword_count', 1)) + ' sensitive auth/banking verification keywords.')
    if features.get('num_subdomains', 0) >= 2:
        detected_issues.append('Unusually high subdomain count (' + str(features['num_subdomains']) + ' subdomains).')
    if features.get('suspicious_tld'):
        detected_issues.append('URL utilizes a top-level domain frequently abused by phishing campaigns.')
    if features.get('has_at_symbol'):
        detected_issues.append('URL contains an @ symbol which can obscure the real destination host.')
    if features.get('is_shortened'):
        detected_issues.append('URL uses a known shortening service to mask the real destination.')
    if features.get('domain_entropy', 0) > 3.8:
        detected_issues.append('High domain randomness/entropy (' + str(features['domain_entropy']) + ').')
    if features.get('has_port'):
        detected_issues.append('Non-standard HTTP port specified in hostname.')

    if features.get('has_https'):
        positive_indicators.append('HTTPS protocol detected.')
    if features.get('url_length', 0) <= 60:
        positive_indicators.append('Standard URL length observed.')
    if not features.get('has_suspicious_keyword'):
        positive_indicators.append('No suspicious credential-theft keywords detected.')
    if features.get('num_subdomains', 0) <= 1:
        positive_indicators.append('Standard domain hierarchy (low subdomain count).')
    if not features.get('has_ip'):
        positive_indicators.append('Standard registered domain name utilized (no direct IP).')

    if student_safety and student_safety.get('is_blocked'):
        overall_summary = f"BLOCKED FOR STUDENTS: {student_safety.get('category_label')}. {student_safety.get('action_advice')}"
    elif fraud_alert and fraud_alert.get('is_fraud_or_illegal'):
        overall_summary = f"WARNING: Website operates within high-risk prohibited category ({fraud_alert.get('category')}). Strong caution advised."
    elif prediction == 'phishing':
        overall_summary = 'The machine-learning classifier identified prominent deceptive patterns and structural abnormalities.'
    else:
        overall_summary = 'The machine-learning classifier evaluated standard lexical and domain traits characteristic of benign web destinations.'

    return {
        'overall_summary': overall_summary,
        'detected_issues': detected_issues,
        'positive_indicators': positive_indicators,
        'disclaimer': 'PhishNet Sentinel provides an AI-based risk assessment. It does not guarantee that a website is completely safe or malicious. Always verify the website independently before entering sensitive information.'
    }

def analyze_url(url: str) -> dict:
    features = extract_features(url)
    vector = features_to_vector(features)
    fraud_alert = detect_fraudulent_or_illegal_site(url)
    
    model = get_model()
    if model is None:
        raise RuntimeError('Trained ML model is not available in backend/models.')

    X = np.array([vector])
    probs = model.predict_proba(X)[0]
    legit_prob = round(float(probs[0]) * 100, 2)
    phish_prob = round(float(probs[1]) * 100, 2)
    
    # Check student content safety
    student_safety = evaluate_student_safety(url, is_phishing_predicted=(phish_prob >= 50.0))

    # If the domain is identified as an illegal/fraudulent/scam network or 18+ content, override ML safe prediction
    if fraud_alert.get('is_fraud_or_illegal') or student_safety.get('is_blocked'):
        phish_prob = max(phish_prob, 95.0)
        legit_prob = round(100.0 - phish_prob, 2)
        prediction = 'phishing'
    else:
        prediction = 'phishing' if phish_prob >= 50.0 else 'legitimate'

    confidence = max(phish_prob, legit_prob)
    
    risk_info = calculate_risk(phish_prob, fraud_alert=fraud_alert)
    if student_safety.get('is_blocked'):
        risk_info['risk_score'] = max(risk_info['risk_score'], 96)
        risk_info['risk_level'] = 'CRITICAL'
        risk_info['badge_color'] = 'darkred'
        risk_info['recommendation'] = f"STUDENT ACCESS BLOCKED: {student_safety.get('reason')} {student_safety.get('action_advice')}"

    explanations = explain_prediction(vector, features)
    review = generate_security_review(features, prediction, risk_info, fraud_alert=fraud_alert, student_safety=student_safety)
    
    return {
        'url': url,
        'prediction': prediction,
        'phishing_probability': phish_prob,
        'legitimate_probability': legit_prob,
        'confidence': confidence,
        'risk_score': risk_info['risk_score'],
        'risk_level': risk_info['risk_level'],
        'badge_color': risk_info['badge_color'],
        'recommendation': risk_info['recommendation'],
        'features': features,
        'explanation': explanations,
        'security_review': review,
        'fraud_alert': fraud_alert,
        'student_safety': student_safety
    }
