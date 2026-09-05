# Machine Learning & Explainable AI Methodology

## 1. Ground Truth Dataset Curation
The training dataset (`dataset/phishing_dataset.csv`) contains 1,194 verified URLs sourced from:
- **PhishTank** and **OpenPhish** verified feeds (phishing category: 597 instances)
- **Tranco Top Sites** and **Majestic Million** (legitimate category: 597 instances)

## 2. Feature Engineering Pipeline
Each URL is transformed into 24 distinct numerical/boolean features across three categories:

### Lexical & Token Features
- `url_length`: Total character length of the URL.
- `domain_length`: Length of the Fully Qualified Domain Name (FQDN).
- `path_length`: Length of the URL path component.
- `num_dots`, `num_hyphens`, `num_underscores`, `num_slashes`, `num_question_marks`, `num_equal_signs`, `num_at_symbols`, `num_ampersands`, `num_percent_signs`: Exact counts of structural punctuation.

### Structural & Security Features
- `has_ip`: 1 if the host consists of an IPv4 or IPv6 numerical address.
- `has_https`: 1 if TLS encryption is used, 0 if plain HTTP.
- `num_subdomains`: Count of domain subcomponents.
- `num_special_chars`: Total count of non-alphanumeric characters.
- `num_digits`: Digit frequency count in URL.
- `num_letters`: Alphabet character count in URL.

### Semantic & Entropy Features
- `domain_entropy`: Shannon Entropy $H(X) = -\sum P(x) \log_2 P(x)$ calculated across domain characters to flag algorithmic generation (DGA) and typo-squatted random gibberish.
- `has_suspicious_keyword`: 1 if keywords such as `login`, `verify`, `secure`, `bank`, `account`, `update` appear outside expected domains.
- `has_double_slash_redirect`: Detection of `//` inside the path indicating open-redirect tricks.
- `has_port_in_url`: Non-standard explicit port specifications.

## 3. Multi-Model Benchmark & Model Selection
5 diverse ML classifiers were trained with a 75/25 stratified train/test split:

| Model | Accuracy | Precision | Recall | F1 Score | ROC-AUC |
|---|---|---|---|---|---|
| **Random Forest** (Selected) | **89.97%** | **89.33%** | **90.54%** | **89.93%** | **0.9631** |
| Multi-Layer Perceptron (ANN) | 88.63% | 88.36% | 88.51% | 88.44% | 0.9412 |
| Support Vector Classifier (SVM) | 87.63% | 86.93% | 88.51% | 87.71% | 0.9328 |
| K-Nearest Neighbors (KNN) | 86.62% | 86.75% | 85.81% | 86.28% | 0.9154 |
| Logistic Regression | 84.95% | 84.87% | 85.14% | 85.00% | 0.9087 |

Random Forest demonstrated superior ROC-AUC and balanced F1-score while being uniquely suited to exact tree-path explanation algorithms.

## 4. Explainable AI with SHAP TreeExplainer
Traditional phishing detectors act as black boxes, providing a single risk number without clarifying why. PhishNet Sentinel utilizes Lundberg & Lee’s SHAP (SHapley Additive exPlanations) formulation based on cooperative game theory:

$$\phi_i = \sum_{S \subseteq F \setminus \{i\}} \frac{|S|!(|F| - |S| - 1)!}{|F|!} (f(S \cup \{i\}) - f(S))$$

SHAP provides:
1. **Local Interpretability**: Every single inspected URL receives exact feature impact values showing how each characteristic moved the base expectation toward phishing or safe.
2. **Global Feature Importance**: Explains overall model dynamics across the entire dataset (e.g. `domain_entropy` and `has_suspicious_keyword` are top macro drivers).
