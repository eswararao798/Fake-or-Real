# PhishNet Sentinel Architecture Specification

## Overview
PhishNet Sentinel is an Explainable AI (XAI) powered security suite designed to protect end users against phishing threats, credential theft, and deceitful web domains. Unlike opaque black-box machine learning detectors, PhishNet Sentinel exposes the internal reasoning of its decision boundaries via SHAP (SHapley Additive exPlanations) TreeExplainer values.

```
+-------------------------------------------------------------+
|                     Client Layer                            |
|  +---------------------------+  +------------------------+  |
|  | Manifest V3 Extension     |  | React 19 + Tailwind UI |  |
|  | (Chrome / Edge Popup)     |  | Dashboard & Visualizer |  |
|  +-------------+-------------+  +-----------+------------+  |
+----------------|----------------------------|---------------+
                 | JSON / REST                | JSON / REST
                 v                            v
+-------------------------------------------------------------+
|                     FastAPI Backend                         |
|  - Rate Limiter & SSRF Input Sanitizer                      |
|  - Endpoints: /api/analyze, /api/explain, /api/history...    |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                    Analysis Pipeline                        |
|  1. Feature Extractor: 24 lexical, entropy, SSL metrics      |
|  2. Scikit-Learn Scaler & Random Forest Classifier          |
|  3. SHAP TreeExplainer Local Attribution Computation        |
|  4. Dynamic Risk Engine (5-Tier Threat Scoring)             |
|  5. Heuristic Security Review & Recommendation Generator    |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                      Persistence Layer                      |
|  - SQLite Database (`phishnet.db`) via SQLAlchemy           |
|  - Scan History, Timestamps, Probabilities, Predictions     |
+-------------------------------------------------------------+
```

## System Components

### 1. Feature Extraction Service (`backend/services/feature_extractor.py`)
Extracts 24 numerical and boolean indicators from raw URLs without executing external network requests that could pose security risks to the server:
- Lexical metrics (length, token counts, subdomains)
- Suspicious keyword matching (`login`, `verify`, `banking`, `paypal`, `wallet`)
- Character entropy (Shannon entropy over the domain name)
- Protocol checks (HTTPS presence)
- IP-address hostname detection

### 2. Explainable AI Engine (`backend/services/xai_engine.py`)
Utilizes a SHAP `TreeExplainer` fitted against the trained Random Forest ensemble. For any query URL:
- Extracts exact positive SHAP attributions (features increasing phishing probability)
- Extracts negative SHAP attributions (features increasing legitimacy probability)
- Generates human-readable descriptions of why each feature contributed to the risk level.

### 3. Risk Engine (`backend/services/risk_engine.py`)
Computes an overall risk score from 0 to 100 based on ensemble class probabilities, penalized or boosted by critical structural flags (e.g. IP hostnames or extreme character entropy), and maps to:
- `LOW RISK` (0 - 20)
- `MODERATE RISK` (21 - 45)
- `MEDIUM RISK` (46 - 65)
- `HIGH RISK` (66 - 85)
- `CRITICAL RISK` (86 - 100)

### 4. Manifest V3 Browser Extension (`extension/`)
- Interacts with Chrome / Edge using active tab query APIs.
- Queries `http://localhost:8000/api/analyze` in real-time.
- Visualizes the top 4 contributing SHAP factors directly within the extension popup.
