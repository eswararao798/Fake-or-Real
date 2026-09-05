import re
from urllib.parse import urlparse
import tldextract

# List of prominent unregulated/illegal online betting, high-risk gambling, financial scam, and cloned casino networks
ILLEGAL_GAMBLING_PATTERNS = [
    '1xbet', 'bet365', 'betway', 'parimatch', 'melbet', '22bet',
    'dafabet', 'mostbet', 'linebet', 'mega-pari', 'lotus365',
    'fairplay', 'betwinner', 'stake.com', 'cricbet99', 'skyexchange',
    'laserbook247', 'diamondexch', 'reddybook', 'allpanelexch',
    'silverexch', 'tiger247', 'crickex', 'rajabets', 'pin-up.casino',
    'jeetwin', 'purewin', 'baazi247', 'khelraja', 'indibet'
]

# Keywords often indicating illicit betting, unauthorized financial schemes, pyramid investments, or cloned fraud
HIGH_RISK_FRAUD_KEYWORDS = [
    'casino', 'betting', 'roulette', 'slot-online', 'satta', 'matka',
    'bonus365', 'double-money', 'fast-loan', 'instant-win', 'card-hack',
    'crypto-doubler', 'daily-profit', 'ponzi', 'telegram-vip-tips'
]

def detect_fraudulent_or_illegal_site(url: str) -> dict:
    """
    Evaluates whether a website domain belongs to banned/illegal gambling portals,
    unauthorized financial scam operations, or fake fraud clones.
    """
    clean_url = (url or '').strip()
    if not re.match(r'^[a-zA-Z]+://', clean_url):
        clean_url = 'http://' + clean_url

    parsed = urlparse(clean_url)
    hostname = (parsed.hostname or '').lower()
    path = (parsed.path or '').lower()
    query = (parsed.query or '').lower()
    full_str = f"{hostname}{path}{query}"

    ext = tldextract.extract(clean_url)
    domain_name = (ext.domain or '').lower()
    registered_domain = (ext.registered_domain or hostname).lower()

    matched_brands = []
    for brand in ILLEGAL_GAMBLING_PATTERNS:
        # Check if brand appears in hostname or registered domain
        if brand in hostname or brand in domain_name:
            matched_brands.append(brand)

    matched_keywords = []
    for kw in HIGH_RISK_FRAUD_KEYWORDS:
        if kw in full_str:
            matched_keywords.append(kw)

    is_illegal = len(matched_brands) > 0 or len(matched_keywords) > 0

    category = None
    reason = None
    if matched_brands:
        category = "ILLEGAL / HIGH-RISK BETTING & FRAUD"
        reason = f"Identified matching blacklisted offshore betting/gambling platform brand: '{matched_brands[0]}'."
    elif matched_keywords:
        category = "HIGH-RISK FRAUD / UNREGULATED FINANCIAL SCHEME"
        reason = f"Detected high-risk deceptive scheme keyword: '{matched_keywords[0]}'."

    return {
        'is_fraud_or_illegal': is_illegal,
        'category': category,
        'reason': reason,
        'matched_brands': matched_brands,
        'matched_keywords': matched_keywords
    }
