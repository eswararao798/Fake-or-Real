import os
import joblib
import numpy as np
from backend.services.feature_extractor import FEATURE_NAMES

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../models'))
MODEL_PATH = os.path.join(MODELS_DIR, 'phishing_model.pkl')
EXPLAINER_PATH = os.path.join(MODELS_DIR, 'shap_explainer.pkl')

_model = None
_explainer = None
_explanation_cache = {}

FEATURE_HUMAN_NAMES = {
    'url_length': 'URL Length',
    'hostname_length': 'Hostname Length',
    'path_length': 'Path Length',
    'query_length': 'Query Length',
    'num_dots': 'Dot Count',
    'num_slashes': 'Slash Count',
    'num_hyphens': 'Hyphen Count',
    'num_underscores': 'Underscore Count',
    'num_digits': 'Digit Count',
    'num_special_chars': 'Special Characters',
    'has_ip': 'IP Address in Hostname',
    'has_https': 'HTTPS Protocol',
    'num_subdomains': 'Number of Subdomains',
    'has_at_symbol': '@ Symbol in URL',
    'is_shortened': 'URL Shortener Service',
    'has_suspicious_keyword': 'Suspicious Keywords Found',
    'suspicious_keyword_count': 'Suspicious Keyword Density',
    'domain_entropy': 'Domain Name Entropy',
    'suspicious_tld': 'High-Risk Suspicious TLD',
    'has_port': 'Non-Standard Network Port',
    'double_slash_in_path': 'Double Slash in URL Path',
    'percent_encoded_count': 'Hex/Percent Encoded Characters',
    'digit_to_letter_ratio': 'Digit-to-Letter Ratio',
    'hostname_has_dash': 'Dash in Domain Hostname'
}

def load_xai_artifacts():
    global _model, _explainer
    if _model is None and os.path.exists(MODEL_PATH):
        _model = joblib.load(MODEL_PATH)
    if _explainer is None and os.path.exists(EXPLAINER_PATH):
        _explainer = joblib.load(EXPLAINER_PATH)
    return _model, _explainer

def explain_prediction(feature_vector: list, feature_dict: dict) -> list:
    cache_key = tuple(feature_vector)
    if cache_key in _explanation_cache:
        return _explanation_cache[cache_key]

    model, explainer = load_xai_artifacts()
    if explainer is None or model is None:
        return []

    X = np.array([feature_vector])
    shap_values = explainer.shap_values(X)
    
    if isinstance(shap_values, list):
        phish_shap = shap_values[1][0]
    elif len(shap_values.shape) == 3:
        phish_shap = shap_values[0, :, 1]
    else:
        phish_shap = shap_values[0]

    explanations = []
    total_magnitude = sum(abs(v) for v in phish_shap) + 1e-6
    
    for idx, name in enumerate(FEATURE_NAMES):
        val = float(phish_shap[idx])
        raw_feat_val = feature_dict.get(name, 0)
        percentage_impact = round((val / total_magnitude) * 100, 1)
        
        human_name = FEATURE_HUMAN_NAMES.get(name, name)
        if val > 0.001:
            impact_type = 'increased_risk'
            description = f'{human_name} ({raw_feat_val}) increased the likelihood of phishing.'
        elif val < -0.001:
            impact_type = 'decreased_risk'
            description = f'{human_name} ({raw_feat_val}) supported legitimacy.'
        else:
            impact_type = 'neutral'
            description = f'{human_name} ({raw_feat_val}) had neutral impact on this prediction.'

        explanations.append({
            'feature': name,
            'feature_name': human_name,
            'raw_value': raw_feat_val,
            'shap_value': round(val, 4),
            'impact_percentage': percentage_impact,
            'impact_type': impact_type,
            'description': description
        })

    explanations.sort(key=lambda x: abs(x['shap_value']), reverse=True)
    if len(_explanation_cache) > 500:
        _explanation_cache.clear()
    _explanation_cache[cache_key] = explanations
    return explanations
