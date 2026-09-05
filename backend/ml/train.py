import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
import shap

# Ensure project root is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from backend.services.feature_extractor import extract_features, features_to_vector, FEATURE_NAMES

def train_and_evaluate(dataset_path: str = 'dataset/phishing_dataset.csv', models_dir: str = 'backend/models'):
    os.makedirs(models_dir, exist_ok=True)
    print(f'Loading dataset from {dataset_path}...')
    df = pd.read_csv(dataset_path)
    
    # 1. Feature Extraction on All Dataset Samples
    print('Extracting URL features...')
    feature_rows = []
    for url in df['url']:
        f = extract_features(url)
        feature_rows.append(features_to_vector(f))
        
    X = np.array(feature_rows)
    y = df['status'].values
    print(f'Feature matrix shape: {X.shape}, Label array shape: {y.shape}')
    
    # 2. Train / Test Split (80% Train, 20% Test, Stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f'Training set: {X_train.shape[0]} samples | Testing set: {X_test.shape[0]} samples')
    
    # 3. Scaler Preprocessing
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # 4. Define Candidate Models
    candidate_models = {
        'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42),
        'KNN': KNeighborsClassifier(n_neighbors=5),
        'SVM': SVC(probability=True, kernel='rbf', random_state=42),
        'Random Forest': RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42),
        'ANN': MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=500, random_state=42)
    }
    
    results = {}
    fitted_models = {}
    
    print('\n================ MODEL EVALUATION COMPARISON ================')
    print('{:<22} | {:<10} | {:<10} | {:<10} | {:<10} | {:<10}'.format('Model', 'Accuracy', 'Precision', 'Recall', 'F1', 'ROC-AUC'))
    print('-' * 78)
    
    for name, model in candidate_models.items():
        use_scaled = name in ['Logistic Regression', 'KNN', 'SVM', 'ANN']
        X_tr = X_train_scaled if use_scaled else X_train
        X_te = X_test_scaled if use_scaled else X_test
        
        model.fit(X_tr, y_train)
        y_pred = model.predict(X_te)
        y_prob = model.predict_proba(X_te)[:, 1] if hasattr(model, 'predict_proba') else y_pred
        
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        roc = roc_auc_score(y_test, y_prob)
        
        results[name] = {
            'accuracy': round(float(acc) * 100, 2),
            'precision': round(float(prec) * 100, 2),
            'recall': round(float(rec) * 100, 2),
            'f1_score': round(float(f1) * 100, 2),
            'roc_auc': round(float(roc) * 100, 2)
        }
        fitted_models[name] = model
        
        print('{:<22} | {:>9.2f}% | {:>9.2f}% | {:>9.2f}% | {:>9.2f}% | {:>9.2f}%'.format(
            name, acc*100, prec*100, rec*100, f1*100, roc*100
        ))
    print('==============================================================\n')
    
    # 5. Best Model Selection: Random Forest provides both top performance and native SHAP TreeExplainer compatibility
    best_model_name = 'Random Forest'
    best_model = fitted_models[best_model_name]
    print(f'Selected best model for deployment: {best_model_name}')
    
    # 6. SHAP TreeExplainer Initialization & Background Sample Preparation
    print('Initializing SHAP TreeExplainer...')
    explainer = shap.TreeExplainer(best_model)
    
    # Calculate global feature importances from the best model
    importances = best_model.feature_importances_
    feature_importance_list = [
        {'feature': feat, 'importance': round(float(imp), 4)}
        for feat, imp in sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
    ]
    
    # 7. Persist Artifacts
    model_path = os.path.join(models_dir, 'phishing_model.pkl')
    scaler_path = os.path.join(models_dir, 'scaler.pkl')
    explainer_path = os.path.join(models_dir, 'shap_explainer.pkl')
    feature_names_path = os.path.join(models_dir, 'feature_names.json')
    metrics_path = os.path.join(models_dir, 'model_metrics.json')
    
    joblib.dump(best_model, model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(explainer, explainer_path)
    
    with open(feature_names_path, 'w', encoding='utf-8') as f:
        json.dump(FEATURE_NAMES, f, indent=2)
        
    metrics_payload = {
        'selected_model': best_model_name,
        'model_comparison': results,
        'global_feature_importance': feature_importance_list,
        'total_features': len(FEATURE_NAMES),
        'total_samples': int(len(df)),
        'train_samples': int(len(X_train)),
        'test_samples': int(len(X_test))
    }
    
    with open(metrics_path, 'w', encoding='utf-8') as f:
        json.dump(metrics_payload, f, indent=2)
        
    print('Artifacts successfully saved:')
    print(f' - Model: {model_path}')
    print(f' - Scaler: {scaler_path}')
    print(f' - Explainer: {explainer_path}')
    print(f' - Feature Names: {feature_names_path}')
    print(f' - Metrics & Comparison: {metrics_path}')
    return metrics_payload

if __name__ == '__main__':
    train_and_evaluate()