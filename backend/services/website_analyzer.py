import os
import joblib
import numpy as np
from backend.services.feature_extractor import extract_features, features_to_vector, unshorten_url
from backend.services.risk_engine import calculate_risk
from backend.services.xai_engine import explain_prediction
from backend.services.fraud_detector import detect_fraudulent_or_illegal_site
from backend.services.content_safety import evaluate_student_safety
from backend.services.html_inspector import inspect_page_dom

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../models'))
MODEL_PATH = os.path.join(MODELS_DIR, 'phishing_model.pkl')
CHAR_CNN_PATH = os.path.join(MODELS_DIR, 'char_cnn_model.keras')
DEEP_MLP_PATH = os.path.join(MODELS_DIR, 'deep_mlp_model.keras')
DL_SCALER_PATH = os.path.join(MODELS_DIR, 'dl_scaler.pkl')

_model = None
_char_cnn = None
_deep_mlp = None
_dl_scaler = None

def get_model():
    global _model
    if _model is None and os.path.exists(MODEL_PATH):
        _model = joblib.load(MODEL_PATH)
    return _model

def get_dl_models():
    global _char_cnn, _deep_mlp, _dl_scaler
    try:
        import tensorflow as tf
        if _char_cnn is None and os.path.exists(CHAR_CNN_PATH):
            _char_cnn = tf.keras.models.load_model(CHAR_CNN_PATH)
        if _deep_mlp is None and os.path.exists(DEEP_MLP_PATH):
            _deep_mlp = tf.keras.models.load_model(DEEP_MLP_PATH)
        if _dl_scaler is None and os.path.exists(DL_SCALER_PATH):
            _dl_scaler = joblib.load(DL_SCALER_PATH)
    except Exception as e:
        print(f"[DL Load Warning] Could not load DL models: {e}")
    return _char_cnn, _deep_mlp, _dl_scaler

def predict_deep_learning(raw_url: str, feature_vector: list) -> dict:
    char_cnn, deep_mlp, dl_scaler = get_dl_models()
    if char_cnn is None or deep_mlp is None:
        return {
            'enabled': False,
            'message': 'Deep Learning models not loaded'
        }
    try:
        from backend.ml.deep_learning_models import encode_url_sequence
        seq = np.array([encode_url_sequence(raw_url)], dtype=np.int32)
        cnn_prob = float(char_cnn.predict(seq, verbose=0)[0][0])
        
        feat_arr = np.array([feature_vector], dtype=np.float32)
        if dl_scaler:
            feat_arr = dl_scaler.transform(feat_arr)
        mlp_prob = float(deep_mlp.predict(feat_arr, verbose=0)[0][0])
        
        hybrid_prob = round((0.6 * cnn_prob + 0.4 * mlp_prob) * 100, 2)
        
        return {
            'enabled': True,
            'char_cnn_score': round(cnn_prob * 100, 2),
            'deep_mlp_score': round(mlp_prob * 100, 2),
            'dl_hybrid_score': hybrid_prob,
            'dl_prediction': 'phishing' if hybrid_prob >= 50.0 else 'legitimate',
            'model_types': ['Character-Level 1D-CNN', 'Deep MLP / ANN']
        }
    except Exception as e:
        return {
            'enabled': False,
            'error': str(e)
        }

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
    final_url, redirect_chain = unshorten_url(url)
    
    # Extract features from initial URL and target destination URL if redirected
    features = extract_features(final_url if final_url != url else url)
    if final_url != url:
        features['is_shortened'] = 1

    vector = features_to_vector(features)
    fraud_alert = detect_fraudulent_or_illegal_site(final_url)
    
    model = get_model()
    if model is None:
        raise RuntimeError('Trained ML model is not available in backend/models.')

    X = np.array([vector])
    probs = model.predict_proba(X)[0]
    legit_prob = round(float(probs[0]) * 100, 2)
    phish_prob = round(float(probs[1]) * 100, 2)
    
    # Check student content safety
    student_safety = evaluate_student_safety(final_url, is_phishing_predicted=(phish_prob >= 50.0))

    # Override ML safe prediction for betting apps, adult content, or fraud sites
    if student_safety.get('category') == 'BETTING_AND_GAMBLING':
        phish_prob = 99.0
        legit_prob = 1.0
        prediction = 'phishing'
    elif student_safety.get('category') == 'ADULT_18_PLUS':
        phish_prob = 99.0
        legit_prob = 1.0
        prediction = 'phishing'
    elif fraud_alert.get('is_fraud_or_illegal') or student_safety.get('is_blocked'):
        phish_prob = max(phish_prob, 95.0)
        legit_prob = round(100.0 - phish_prob, 2)
        prediction = 'phishing'
    else:
        prediction = 'phishing' if phish_prob >= 50.0 else 'legitimate'

    # Perform DOM content inspection (password fields, brand spoofing, form targets)
    dom_findings = inspect_page_dom(final_url)
    if dom_findings.get('risk_adjustment', 0) > 0:
        phish_prob = min(99.0, phish_prob + dom_findings['risk_adjustment'])
        legit_prob = round(100.0 - phish_prob, 2)
        if phish_prob >= 50.0:
            prediction = 'phishing'

    confidence = max(phish_prob, legit_prob)
    
    risk_info = calculate_risk(phish_prob, fraud_alert=fraud_alert)
    if student_safety.get('is_blocked'):
        risk_info['risk_score'] = max(risk_info['risk_score'], 96)
        risk_info['risk_level'] = 'CRITICAL'
        risk_info['badge_color'] = 'darkred'
        risk_info['recommendation'] = f"STUDENT ACCESS BLOCKED: {student_safety.get('reason')} {student_safety.get('action_advice')}"

    explanations = explain_prediction(vector, features)
    review = generate_security_review(features, prediction, risk_info, fraud_alert=fraud_alert, student_safety=student_safety)
    
    if len(redirect_chain) > 1:
        review['detected_issues'].insert(0, f"REDIRECT TRACED: Shortened URL resolves to final target destination: {final_url}")

    # Execute Deep Learning analysis (Char-1D-CNN + Deep MLP)
    dl_analysis = predict_deep_learning(final_url, vector)

    return {
        'url': url,
        'final_url': final_url,
        'redirect_chain': redirect_chain,
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
        'student_safety': student_safety,
        'dom_findings': dom_findings,
        'deep_learning': dl_analysis
    }
