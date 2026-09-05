# PhishNet Sentinel API Documentation

Base URL: `http://localhost:8000`  
Interactive Swagger Docs: `http://localhost:8000/docs`  
ReDoc: `http://localhost:8000/redoc`

---

### 1. `POST /api/analyze`
Analyzes a website URL and returns the prediction, probabilities, 5-tier risk score, detailed website security review, and SHAP feature attributions.

**Request Body:**
```json
{
  "url": "http://secure-paypal-login-verify.xyz/account"
}
```

**Response (200 OK):**
```json
{
  "url": "http://secure-paypal-login-verify.xyz/account",
  "prediction": "phishing",
  "risk_score": 92.5,
  "risk_level": "CRITICAL RISK",
  "phishing_probability": 92.5,
  "legitimate_probability": 7.5,
  "recommendation": "DANGER: High probability of phishing or credential theft. Do NOT enter sensitive credentials.",
  "features": {
    "url_length": 45,
    "num_subdomains": 3,
    "has_https": false,
    "has_ip": false,
    "domain_entropy": 4.12,
    "has_suspicious_keyword": true
  },
  "explanation": [
    {
      "feature_name": "has_suspicious_keyword",
      "raw_value": 1,
      "shap_value": 0.28,
      "percentage_impact": 35.2,
      "description": "Contains sensitive target keywords such as login, verify, or secure."
    }
  ],
  "security_review": {
    "overall_summary": "High risk website exhibiting multiple characteristics commonly associated with credential theft.",
    "detected_issues": [
      "Insecure plain HTTP protocol (No TLS)",
      "High domain Shannon entropy",
      "Contains sensitive keyword patterns"
    ],
    "positive_indicators": [],
    "disclaimer": "Automated ML prediction. Always cross-verify before submitting sensitive data."
  },
  "scan_id": 1,
  "timestamp": "2026-09-05T05:22:18.123456"
}
```

---

### 2. `POST /api/explain`
Returns targeted SHAP TreeExplainer breakdown for a URL without storing it to scan history.

**Request Body:**
```json
{
  "url": "https://www.google.com"
}
```

---

### 3. `GET /api/history`
Retrieves past URL scans sorted by creation date descending. Supports pagination and search queries.

**Query Parameters:**
- `limit` (default: 50)
- `search` (optional)

---

### 4. `DELETE /api/history/{scan_id}`
Deletes an individual scan record from the database.

---

### 5. `GET /api/stats`
Returns aggregate statistics:
- Total scans performed
- Phishing vs legitimate counts
- Average risk score
- Top detected suspicious keywords

---

### 6. `GET /api/model-info`
Returns production model metadata and actual training evaluation metrics across all 5 benchmarked algorithms (Random Forest, Logistic Regression, KNN, SVM, ANN).
