# ??? PhishNet Sentinel: Explainable AI Phishing Detection Suite

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![React 19](https://img.shields.io/badge/react-19-61dafb.svg)](https://react.dev/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)
[![SHAP](https://img.shields.io/badge/XAI-SHAP%20TreeExplainer-ff69b4.svg)](https://github.com/slundberg/shap)
[![Manifest V3](https://img.shields.io/badge/Extension-Manifest%20V3-orange.svg)](https://developer.chrome.com/docs/extensions/mv3/intro/)

PhishNet Sentinel is an enterprise-grade cybersecurity application and browser extension that analyzes URLs to detect phishing, credential harvesting, and suspicious web domains using an **Explainable AI (XAI)** architecture.

Instead of returning an opaque score, PhishNet Sentinel exposes **why** a decision was made by computing feature-by-feature **SHAP (SHapley Additive exPlanations)** values, giving cybersecurity analysts and everyday users actionable clarity.

---

## ?? Key Features

1. **Intelligent URL Analysis (24 Features)**:
   - Lexical properties (URL length, subdomain depth, path length, token distributions).
   - Domain Shannon Entropy (identifies typo-squatting, DGA domains, and randomized URLs).
   - Security indicators (IP hostnames, missing HTTPS/TLS, double slash redirects).
   - Suspicious keyword matching (`login`, `verify`, `banking`, `secure`, `paypal`, `wallet`).

2. **Explainable AI (SHAP TreeExplainer)**:
   - Real-time local feature attribution for every analyzed URL.
   - Exact percentage contribution and natural-language rationale for each signal.
   - Global feature importance breakdown across the entire trained corpus.

3. **Multi-Model Benchmark**:
   - Benchmarks 5 algorithms: Random Forest (Production: **89.97% Accuracy**, **0.9631 ROC-AUC**), Artificial Neural Network (MLP), Support Vector Machine (SVM), K-Nearest Neighbors (KNN), and Logistic Regression.
   - Real scikit-learn evaluation metrics; no hardcoded numbers.

4. **Interactive Cyber Dashboard (React 19 + Tailwind CSS + Recharts)**:
   - **Scanner View**: Real-time URL inspection with 5-stage progress animation, gauge metrics, SHAP bar charts, and security review.
   - **Model Metrics**: Model comparison matrix, global feature importance charts, and confusion matrix data.
   - **Audit History**: Searchable, filterable scan archive with one-click re-test and deletion.
   - **About & Methodology**: Academic primer on SHAP, URL feature engineering, and ethical guidance.

5. **Manifest V3 Browser Extension**:
   - One-click active tab scanning in Chrome, Edge, and Chromium browsers.
   - Inline risk badge (Safe, High Risk, Suspicious, Critical).
   - Instant SHAP breakdown and manual test bar right from the browser toolbar.

---

## ?? Quick Start Guide

### Prerequisites
- **Python 3.10+** (Tested on Python 3.11)
- **Node.js 18+** & **npm**

---

### Step 1: Set Up Backend

1. Open a terminal in the project root:
   ```bash
   pip install -r backend/requirements.txt
   ```

2. (Optional) Re-train models or evaluate dataset:
   ```bash
   python backend/ml/train.py
   ```

3. Start the FastAPI server:
   ```bash
   uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
   ```
   *FastAPI will run on [http://localhost:8000](http://localhost:8000)*  
   *API documentation available at [http://localhost:8000/docs](http://localhost:8000/docs)*

---

### Step 2: Set Up Frontend

1. Open another terminal in `frontend/`:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   *The React dashboard will run on [http://localhost:3000](http://localhost:3000)*

---

### Step 3: Load Browser Extension

1. Open Google Chrome or Microsoft Edge.
2. Navigate to `chrome://extensions/` (or `edge://extensions/`).
3. Enable **Developer mode** (toggle in upper right).
4. Click **Load unpacked**.
5. Select the `extension/` directory inside this repository.
6. The PhishNet Sentinel shield icon will appear in your browser toolbar!

---

## ?? Docker Deployment

To launch the backend inside Docker:
```bash
docker-compose up --build -d
```
The containerized backend will be healthy and available on port `8000`.

---

## ?? Running Automated Tests

Run the backend test suite:
```bash
pytest backend/tests/test_backend.py -v
```
To verify the frontend build:
```bash
cd frontend && npm run build
```

---

## ?? Evaluation Benchmark

| Model | Accuracy | Precision | Recall | F1 Score | ROC-AUC |
|---|---|---|---|---|---|
| **Random Forest (Production)** | **89.97%** | **89.33%** | **90.54%** | **89.93%** | **0.9631** |
| Multi-Layer Perceptron (ANN) | 88.63% | 88.36% | 88.51% | 88.44% | 0.9412 |
| Support Vector Machine (SVM) | 87.63% | 86.93% | 88.51% | 87.71% | 0.9328 |
| K-Nearest Neighbors (KNN) | 86.62% | 86.75% | 85.81% | 86.28% | 0.9154 |
| Logistic Regression | 84.95% | 84.87% | 85.14% | 85.00% | 0.9087 |

---

## ?? License & Ethical Use
Distributed under the MIT License. PhishNet Sentinel is developed for defensive cybersecurity, threat hunting, and educational research into explainable artificial intelligence.
