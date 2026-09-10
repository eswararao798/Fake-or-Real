import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# Ensure root on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from backend.services.feature_extractor import extract_features, features_to_vector, FEATURE_NAMES
from backend.ml.deep_learning_models import encode_url_sequence, build_char_cnn_model, build_deep_mlp_model

def train_deep_learning_suite(
    dataset_path: str = 'dataset/phishing_dataset.csv',
    models_dir: str = 'backend/models'
):
    os.makedirs(models_dir, exist_ok=True)
    print(f"[DL Trainer] Loading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)
    
    urls = df['url'].tolist()
    labels = df['status'].values.astype(np.float32)
    
    # 1. Prepare Character Sequences for 1D-CNN
    print("[DL Trainer] Encoding raw URL character sequences...")
    X_seq = np.array([encode_url_sequence(u) for u in urls], dtype=np.int32)
    
    # 2. Prepare 24-Dimensional Lexical Feature Matrix for Deep MLP
    print("[DL Trainer] Extracting 24 tabular lexical features...")
    feature_rows = []
    for u in urls:
        f = extract_features(u)
        feature_rows.append(features_to_vector(f))
    X_feat = np.array(feature_rows, dtype=np.float32)
    
    # 3. Stratified Train / Test Split
    idx_train, idx_test = train_test_split(
        np.arange(len(labels)), test_size=0.20, random_state=42, stratify=labels
    )
    
    X_seq_train, X_seq_test = X_seq[idx_train], X_seq[idx_test]
    X_feat_train, X_feat_test = X_feat[idx_train], X_feat[idx_test]
    y_train, y_test = labels[idx_train], labels[idx_test]
    
    # Scale tabular features
    scaler = StandardScaler()
    X_feat_train_scaled = scaler.fit_transform(X_feat_train)
    X_feat_test_scaled = scaler.transform(X_feat_test)
    
    # ----------------------------------------------------
    # Model 1: Character-Level 1D-CNN Sequence Classifier
    # ----------------------------------------------------
    print("\n[DL Trainer] Compiling & Training Character-Level 1D-CNN...")
    char_cnn = build_char_cnn_model()
    char_cnn.fit(
        X_seq_train, y_train,
        validation_split=0.15,
        epochs=8,
        batch_size=32,
        verbose=1
    )
    
    y_pred_cnn_prob = char_cnn.predict(X_seq_test).flatten()
    y_pred_cnn = (y_pred_cnn_prob >= 0.5).astype(int)
    
    cnn_metrics = {
        'accuracy': round(float(accuracy_score(y_test, y_pred_cnn)) * 100, 2),
        'precision': round(float(precision_score(y_test, y_pred_cnn, zero_division=0)) * 100, 2),
        'recall': round(float(recall_score(y_test, y_pred_cnn, zero_division=0)) * 100, 2),
        'f1_score': round(float(f1_score(y_test, y_pred_cnn, zero_division=0)) * 100, 2),
        'roc_auc': round(float(roc_auc_score(y_test, y_pred_cnn_prob)) * 100, 2)
    }
    print(f"[DL Trainer] Char-1D-CNN Test Accuracy: {cnn_metrics['accuracy']}% | F1: {cnn_metrics['f1_score']}%")
    
    # ----------------------------------------------------
    # Model 2: Deep MLP (ANN) Neural Network
    # ----------------------------------------------------
    print("\n[DL Trainer] Compiling & Training Deep MLP (ANN)...")
    deep_mlp = build_deep_mlp_model(input_dim=len(FEATURE_NAMES))
    deep_mlp.fit(
        X_feat_train_scaled, y_train,
        validation_split=0.15,
        epochs=12,
        batch_size=32,
        verbose=1
    )
    
    y_pred_mlp_prob = deep_mlp.predict(X_feat_test_scaled).flatten()
    y_pred_mlp = (y_pred_mlp_prob >= 0.5).astype(int)
    
    mlp_metrics = {
        'accuracy': round(float(accuracy_score(y_test, y_pred_mlp)) * 100, 2),
        'precision': round(float(precision_score(y_test, y_pred_mlp, zero_division=0)) * 100, 2),
        'recall': round(float(recall_score(y_test, y_pred_mlp, zero_division=0)) * 100, 2),
        'f1_score': round(float(f1_score(y_test, y_pred_mlp, zero_division=0)) * 100, 2),
        'roc_auc': round(float(roc_auc_score(y_test, y_pred_mlp_prob)) * 100, 2)
    }
    print(f"[DL Trainer] Deep MLP Test Accuracy: {mlp_metrics['accuracy']}% | F1: {mlp_metrics['f1_score']}%")
    
    # ----------------------------------------------------
    # Model 3: Hybrid Ensemble (Random Forest + CNN + MLP)
    # ----------------------------------------------------
    rf_path = os.path.join(models_dir, 'phishing_model.pkl')
    if os.path.exists(rf_path):
        rf_model = joblib.load(rf_path)
        y_pred_rf_prob = rf_model.predict_proba(X_feat_test)[:, 1]
    else:
        y_pred_rf_prob = y_pred_mlp_prob
        
    # Weighted soft-voting ensemble: 50% Random Forest + 30% Char-CNN + 20% Deep MLP
    y_pred_hybrid_prob = 0.50 * y_pred_rf_prob + 0.30 * y_pred_cnn_prob + 0.20 * y_pred_mlp_prob
    y_pred_hybrid = (y_pred_hybrid_prob >= 0.5).astype(int)
    
    hybrid_metrics = {
        'accuracy': round(float(accuracy_score(y_test, y_pred_hybrid)) * 100, 2),
        'precision': round(float(precision_score(y_test, y_pred_hybrid, zero_division=0)) * 100, 2),
        'recall': round(float(recall_score(y_test, y_pred_hybrid, zero_division=0)) * 100, 2),
        'f1_score': round(float(f1_score(y_test, y_pred_hybrid, zero_division=0)) * 100, 2),
        'roc_auc': round(float(roc_auc_score(y_test, y_pred_hybrid_prob)) * 100, 2)
    }
    print(f"[DL Trainer] Hybrid Ensemble (RF + CNN + MLP) Accuracy: {hybrid_metrics['accuracy']}% | F1: {hybrid_metrics['f1_score']}%")

    # 4. Save Weights and Artifacts
    cnn_save_path = os.path.join(models_dir, 'char_cnn_model.keras')
    mlp_save_path = os.path.join(models_dir, 'deep_mlp_model.keras')
    dl_scaler_path = os.path.join(models_dir, 'dl_scaler.pkl')
    
    char_cnn.save(cnn_save_path)
    deep_mlp.save(mlp_save_path)
    joblib.dump(scaler, dl_scaler_path)
    
    # 5. Update model_metrics.json
    metrics_path = os.path.join(models_dir, 'model_metrics.json')
    metrics_data = {}
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, 'r', encoding='utf-8') as f:
                metrics_data = json.load(f)
        except Exception:
            metrics_data = {}
            
    if 'model_comparison' not in metrics_data:
        metrics_data['model_comparison'] = {}
        
    metrics_data['model_comparison']['Char-Level 1D-CNN (Deep Learning)'] = cnn_metrics
    metrics_data['model_comparison']['Deep MLP / ANN (Neural Network)'] = mlp_metrics
    metrics_data['model_comparison']['Hybrid Ensemble (RF + CNN + MLP)'] = hybrid_metrics
    metrics_data['deep_learning_enabled'] = True
    
    with open(metrics_path, 'w', encoding='utf-8') as f:
        json.dump(metrics_data, f, indent=2)
        
    print("\n[DL Trainer] All Deep Learning models successfully trained and saved!")
    return {
        'cnn_metrics': cnn_metrics,
        'mlp_metrics': mlp_metrics,
        'hybrid_metrics': hybrid_metrics
    }

if __name__ == '__main__':
    train_deep_learning_suite()
