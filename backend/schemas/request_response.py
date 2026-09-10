from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class AnalyzeRequest(BaseModel):
    url: str = Field(..., description='The website URL to analyze')

class ExplainRequest(BaseModel):
    url: str = Field(..., description='The website URL to explain')

class FeatureContribution(BaseModel):
    feature: str
    feature_name: str
    raw_value: Any
    shap_value: float
    impact_percentage: float
    impact_type: str
    description: str

class SecurityReview(BaseModel):
    overall_summary: str
    detected_issues: List[str]
    positive_indicators: List[str]
    disclaimer: str

class AnalyzeResponse(BaseModel):
    url: str
    prediction: str
    phishing_probability: float
    legitimate_probability: float
    confidence: float
    risk_score: int
    risk_level: str
    badge_color: str
    recommendation: str
    features: Dict[str, Any]
    explanation: List[FeatureContribution]
    security_review: SecurityReview
    fraud_alert: Optional[Dict[str, Any]] = None
    student_safety: Optional[Dict[str, Any]] = None
    dom_findings: Optional[Dict[str, Any]] = None
    deep_learning: Optional[Dict[str, Any]] = None
    scan_id: Optional[int] = None
    timestamp: Optional[str] = None

class HistoryItem(BaseModel):
    id: int
    url: str
    prediction: str
    phishing_probability: float
    legitimate_probability: float
    risk_score: int
    risk_level: str
    recommendation: str
    timestamp: Optional[str] = None

class StatsResponse(BaseModel):
    total_scans: int
    phishing_detected: int
    legitimate_count: int
    average_risk_score: float
    risk_distribution: Dict[str, int]
    recent_scans: List[Dict[str, Any]]

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    model_loaded: bool
