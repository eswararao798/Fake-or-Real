import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.feature_extractor import extract_features, features_to_vector, FEATURE_NAMES
from backend.utils.validators import is_valid_url, is_safe_destination

client = TestClient(app)

def test_health():
    res = client.get('/api/health')
    assert res.status_code == 200
    data = res.json()
    assert data['status'] == 'healthy'
    assert data['model_loaded'] is True

def test_feature_extractor():
    features = extract_features('https://www.google.com')
    assert len(features) == len(FEATURE_NAMES)
    vec = features_to_vector(features)
    assert len(vec) == len(FEATURE_NAMES)
    assert features['has_https'] == 1
    assert features['has_ip'] == 0

def test_url_validators():
    valid, _ = is_valid_url('https://example.com')
    assert valid is True

    valid, _ = is_valid_url('')
    assert valid is False

    valid, _ = is_valid_url('not-a-valid-url-format')
    assert valid is False

    safe, _ = is_safe_destination('http://127.0.0.1:8000')
    assert safe is False

def test_analyze_legitimate():
    res = client.post('/api/analyze', json={'url': 'https://www.wikipedia.org'})
    assert res.status_code == 200
    data = res.json()
    assert 'prediction' in data
    assert 'phishing_probability' in data
    assert 'risk_score' in data
    assert 'explanation' in data
    assert 'security_review' in data
    assert len(data['explanation']) > 0

def test_analyze_phishing():
    res = client.post('/api/analyze', json={'url': 'http://192.168.1.100/paypal/login.php?verify=1'})
    # Notice this is flagged by SSRF / private IP safety check
    assert res.status_code == 400

    res_phish = client.post('/api/analyze', json={'url': 'http://secure-paypal-login-account-update.xyz/webscr?cmd=login'})
    assert res_phish.status_code == 200
    data = res_phish.json()
    assert data['prediction'] == 'phishing'
    assert data['phishing_probability'] >= 50.0
    assert data['risk_score'] >= 50

def test_stats_and_history():
    res_stats = client.get('/api/stats')
    assert res_stats.status_code == 200
    assert 'total_scans' in res_stats.json()

    res_history = client.get('/api/history')
    assert res_history.status_code == 200
    assert isinstance(res_history.json(), list)

def test_model_info():
    res = client.get('/api/model-info')
    assert res.status_code == 200
    data = res.json()
    assert 'selected_model' in data
    assert 'model_comparison' in data

def test_student_safety_educational():
    res = client.post('/api/analyze', json={'url': 'https://en.wikipedia.org/wiki/Computer_science'})
    assert res.status_code == 200
    data = res.json()
    assert data['student_safety']['is_student_safe'] is True
    assert data['student_safety']['category'] == 'EDUCATIONAL_RESOURCE'

def test_student_safety_betting_blocked():
    res = client.post('/api/analyze', json={'url': 'https://indian.1xbet.com/en?v=2'})
    assert res.status_code == 200
    data = res.json()
    assert data['student_safety']['is_blocked'] is True
    assert data['student_safety']['category'] == 'BETTING_AND_GAMBLING'
    assert data['risk_score'] >= 90

def test_student_safety_adult_blocked():
    res = client.post('/api/analyze', json={'url': 'https://pornhub.com'})
    assert res.status_code == 200
    data = res.json()
    assert data['student_safety']['is_blocked'] is True
    assert data['student_safety']['category'] == 'ADULT_18_PLUS'
    assert data['risk_score'] >= 90
