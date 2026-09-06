import os
import json
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from backend.schemas.request_response import (
    AnalyzeRequest, AnalyzeResponse, StatsResponse, HealthResponse, ExplainRequest
)
from backend.utils.validators import is_valid_url, is_safe_destination
from backend.services.website_analyzer import analyze_url, get_model
from backend.services.feature_extractor import extract_features, features_to_vector
from backend.services.xai_engine import explain_prediction
from backend.database.database import get_db, ScanRecord

app = FastAPI(
    title='PhishNet Sentinel API',
    description='Explainable AI (XAI) Based Phishing Detection and Website Security Analysis',
    version='1.0.0'
)

# Enable CORS for Chrome/Edge extensions and Frontend development server
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

@app.get('/api/health', response_model=HealthResponse)
def health_check():
    model = get_model()
    return {
        'status': 'healthy',
        'service': 'PhishNet Sentinel Backend',
        'version': '1.0.0',
        'model_loaded': model is not None
    }

@app.post('/api/analyze', response_model=AnalyzeResponse)
def analyze_endpoint(request: AnalyzeRequest, db: Session = Depends(get_db)):
    url = (request.url or '').strip()
    
    valid, err_msg = is_valid_url(url)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f'Invalid URL: {err_msg}'
        )

    safe, safe_err = is_safe_destination(url)
    if not safe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f'Security Constraint: {safe_err}'
        )

    try:
        result = analyze_url(url)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f'Analysis engine error: {str(e)}'
        )

    # Persist scan to database
    record = ScanRecord(
        url=url,
        prediction=result['prediction'],
        phishing_probability=result['phishing_probability'],
        legitimate_probability=result['legitimate_probability'],
        risk_score=result['risk_score'],
        risk_level=result['risk_level'],
        recommendation=result['recommendation'],
        features_json=json.dumps(result['features']),
        explanation_json=json.dumps(result['explanation']),
        security_review_json=json.dumps(result['security_review'])
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    result['scan_id'] = record.id
    result['timestamp'] = record.created_at.isoformat() if record.created_at else None
    return result

@app.post('/api/explain')
def explain_endpoint(request: ExplainRequest):
    url = (request.url or '').strip()
    valid, err_msg = is_valid_url(url)
    if not valid:
        raise HTTPException(status_code=422, detail=err_msg)

    features = extract_features(url)
    vector = features_to_vector(features)
    explanations = explain_prediction(vector, features)
    return {
        'url': url,
        'explanation': explanations
    }

@app.get('/api/history')
def get_history(
    limit: int = Query(50, ge=1, le=200),
    prediction: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(ScanRecord)
    if prediction:
        query = query.filter(ScanRecord.prediction.ilike(f'%{prediction}%'))
    if search:
        query = query.filter(ScanRecord.url.ilike(f'%{search}%'))

    records = query.order_by(ScanRecord.created_at.desc()).limit(limit).all()
    return [r.to_dict() for r in records]

@app.delete('/api/history/{scan_id}')
def delete_history_item(scan_id: int, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail='Scan record not found')
    db.delete(record)
    db.commit()
    return {'message': f'Scan record {scan_id} deleted successfully'}

@app.delete('/api/history')
def clear_all_history(db: Session = Depends(get_db)):
    deleted_count = db.query(ScanRecord).delete()
    db.commit()
    return {'message': f'Successfully cleared {deleted_count} scan records'}

@app.get('/api/stats', response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    total = db.query(ScanRecord).count()
    phishing = db.query(ScanRecord).filter(ScanRecord.prediction == 'phishing').count()
    legitimate = db.query(ScanRecord).filter(ScanRecord.prediction == 'legitimate').count()

    all_scores = [r.risk_score for r in db.query(ScanRecord.risk_score).all()]
    avg_score = round(sum(all_scores) / len(all_scores), 1) if all_scores else 0.0

    dist = {'LOW': 0, 'MODERATE': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for r in db.query(ScanRecord.risk_level).all():
        lvl = r[0]
        if lvl in dist:
            dist[lvl] += 1

    recent = [r.to_dict() for r in db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(5).all()]

    return {
        'total_scans': total,
        'phishing_detected': phishing,
        'legitimate_count': legitimate,
        'average_risk_score': avg_score,
        'risk_distribution': dist,
        'recent_scans': recent
    }

@app.get('/api/model-info')
def model_info():
    metrics_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'models/model_metrics.json'))
    if os.path.exists(metrics_path):
        with open(metrics_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {'message': 'Model metrics not found'}

@app.post('/api/report')
def report_phishing(request: AnalyzeRequest):
    url = (request.url or '').strip()
    valid, err_msg = is_valid_url(url)
    if not valid:
        raise HTTPException(status_code=422, detail=f'Invalid URL: {err_msg}')

    reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'database'))
    os.makedirs(reports_dir, exist_ok=True)
    reports_file = os.path.join(reports_dir, 'user_reports.json')

    reports = []
    if os.path.exists(reports_file):
        try:
            with open(reports_file, 'r', encoding='utf-8') as f:
                reports = json.load(f)
        except Exception:
            reports = []

    reports.append({
        'url': url,
        'reported_at': os.getenv('CURRENT_TIME', 'now'),
        'status': 'pending_retraining_queue'
    })

    with open(reports_file, 'w', encoding='utf-8') as f:
        json.dump(reports, f, indent=2)

    return {
        'status': 'success',
        'message': f'Thank you! URL {url} has been queued for continuous model retraining and threat database update.',
        'total_queued_reports': len(reports)
    }

@app.post('/api/retrain')
def trigger_retraining():
    from backend.services.model_retrainer import retrain_model_with_user_reports
    try:
        metrics = retrain_model_with_user_reports()
        return metrics
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Retraining engine failed: {str(e)}')
