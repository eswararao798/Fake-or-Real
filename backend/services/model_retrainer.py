import os
import json
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import shap
from backend.services.feature_extractor import extract_features, features_to_vector, FEATURE_NAMES

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../models'))
MODEL_PATH = os.path.join(MODELS_DIR, 'phishing_model.pkl')
EXPLAINER_PATH = os.path.join(MODELS_DIR, 'shap_explainer.pkl')
METRICS_PATH = os.path.join(MODELS_DIR, 'model_metrics.json')
DATASET_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../dataset/phishing_urls_dataset.csv'))
REPORTS_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), '../database/user_reports.json'))

def retrain_model_with_user_reports() -> dict:
    """
    Retrains the Random Forest classifier and updates the SHAP explainer
    by incorporating newly reported phishing URLs from user_reports.json.
    """
    if not os.path.exists(DATASET_PATH):
        return {'status': 'error', 'message': f'Base dataset not found at {DATASET_PATH}'}

    df = pd.read_csv(DATASET_PATH)

    # Append user reports if present
    added_count = 0
    if os.path.exists(REPORTS_FILE):
        try:
            with open(REPORTS_FILE, 'r', encoding='utf-8') as f:
                reports = json.load(f)

            new_rows = []
            for r in reports:
                url = r.get('url')
                if url:
                    feats = extract_features(url)
                    feats['url'] = url
                    feats['label'] = 1 # Flagged as phishing
                    new_rows.append(feats)
                    added_count += 1

            if new_rows:
                df_new = pd.DataFrame(new_rows)
                df = pd.concat([df, df_new], ignore_index=True)
        except Exception:
            pass

    X = df[FEATURE_NAMES]
    y = df['label']

    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X, y)

    # Fit SHAP explainer on background sample
    sample_bg = X.sample(n=min(50, len(X)), random_state=42)
    explainer = shap.TreeExplainer(clf, sample_bg)

    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(explainer, EXPLAINER_PATH)

    metrics = {
        'total_training_samples': len(df),
        'user_reported_samples_added': added_count,
        'features_count': len(FEATURE_NAMES),
        'status': 'retrained_successfully'
    }

    with open(METRICS_PATH, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, indent=2)

    return metrics
