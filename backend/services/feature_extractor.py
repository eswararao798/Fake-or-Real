import re
import math
from urllib.parse import urlparse
import tldextract
import httpx

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'password', 'bank', 'wallet', 'confirm', 'authentication',
    'billing', 'security', 'support', 'service', 'appleid',
    'paypal', 'recovery', 'webscr', 'unlock', 'ebayisapi'
]

SHORTENING_SERVICES = {
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly', 'rebrand.ly', 'shorturl.at'
}

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'work', 'loan', 'club', 'buzz', 'click', 'vip', 'fit', 'gq', 'ml', 'cf', 'ga', 'tk'
}

FEATURE_NAMES = [
    'url_length', 'hostname_length', 'path_length', 'query_length',
    'num_dots', 'num_slashes', 'num_hyphens', 'num_underscores',
    'num_digits', 'num_special_chars', 'has_ip', 'has_https',
    'num_subdomains', 'has_at_symbol', 'is_shortened',
    'has_suspicious_keyword', 'suspicious_keyword_count',
    'domain_entropy', 'suspicious_tld', 'has_port',
    'double_slash_in_path', 'percent_encoded_count',
    'digit_to_letter_ratio', 'hostname_has_dash'
]

IP_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    probabilities = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum(p * math.log2(p) for p in probabilities if p > 0)

def unshorten_url(url: str, timeout: float = 2.5) -> tuple[str, list[str]]:
    """
    Traces HTTP redirect chains (e.g. bit.ly, tinyurl) to uncover the final target destination URL.
    Returns (final_url, list_of_redirect_hops).
    """
    clean_url = (url or '').strip()
    if not re.match(r'^[a-zA-Z]+://', clean_url):
        clean_url = 'http://' + clean_url

    redirect_chain = [clean_url]
    current_url = clean_url

    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, headers={'User-Agent': 'PhishNet-Sentinel-Scanner/1.0'}) as client:
            resp = client.head(clean_url)
            if resp.history:
                redirect_chain = [str(r.url) for r in resp.history] + [str(resp.url)]
                current_url = str(resp.url)
            elif resp.status_code in (405, 403, 400):
                resp_get = client.get(clean_url)
                if resp_get.history:
                    redirect_chain = [str(r.url) for r in resp_get.history] + [str(resp_get.url)]
                    current_url = str(resp_get.url)
    except Exception:
        pass

    return current_url, redirect_chain

def extract_features(url: str) -> dict:
    clean_url = (url or '').strip()
    if not re.match(r'^[a-zA-Z]+://', clean_url):
        clean_url_for_parsing = 'http://' + clean_url
    else:
        clean_url_for_parsing = clean_url

    parsed = urlparse(clean_url_for_parsing)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''

    ext = tldextract.extract(clean_url_for_parsing)
    domain_full = ext.registered_domain or hostname
    subdomain = ext.subdomain or ''

    url_length = len(clean_url)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)

    num_dots = clean_url.count('.')
    num_slashes = clean_url.count('/')
    num_hyphens = clean_url.count('-')
    num_underscores = clean_url.count('_')
    num_digits = sum(c.isdigit() for c in clean_url)
    num_special_chars = len(re.findall(r'[-_@?&=%#~+]', clean_url))

    has_ip = 1 if IP_PATTERN.match(hostname) else 0
    has_https = 1 if clean_url.lower().startswith('https://') else 0
    num_subdomains = len(subdomain.split('.')) if subdomain else 0
    has_at_symbol = 1 if '@' in clean_url else 0
    # Match shortener against registered domain or exact hostname to avoid false positives like 't.co' inside '1xbet.com'
    is_shortened = 1 if (domain_full.lower() in SHORTENING_SERVICES or hostname.lower() in SHORTENING_SERVICES) else 0

    url_lower = clean_url.lower()
    keyword_matches = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    has_suspicious_keyword = 1 if keyword_matches > 0 else 0
    suspicious_keyword_count = keyword_matches

    domain_entropy = round(calculate_entropy(domain_full), 4)
    suffix = (ext.suffix or '').lower()
    suspicious_tld = 1 if suffix in SUSPICIOUS_TLDS else 0
    has_port = 1 if parsed.port and parsed.port not in (80, 443) else 0
    double_slash_in_path = 1 if '//' in path else 0
    percent_encoded_count = clean_url.count('%')
    letters = sum(c.isalpha() for c in clean_url)
    digit_to_letter_ratio = round(num_digits / (letters + 1e-6), 4)
    hostname_has_dash = 1 if '-' in hostname else 0

    return {
        'url_length': url_length,
        'hostname_length': hostname_length,
        'path_length': path_length,
        'query_length': query_length,
        'num_dots': num_dots,
        'num_slashes': num_slashes,
        'num_hyphens': num_hyphens,
        'num_underscores': num_underscores,
        'num_digits': num_digits,
        'num_special_chars': num_special_chars,
        'has_ip': has_ip,
        'has_https': has_https,
        'num_subdomains': num_subdomains,
        'has_at_symbol': has_at_symbol,
        'is_shortened': is_shortened,
        'has_suspicious_keyword': has_suspicious_keyword,
        'suspicious_keyword_count': suspicious_keyword_count,
        'domain_entropy': domain_entropy,
        'suspicious_tld': suspicious_tld,
        'has_port': has_port,
        'double_slash_in_path': double_slash_in_path,
        'percent_encoded_count': percent_encoded_count,
        'digit_to_letter_ratio': digit_to_letter_ratio,
        'hostname_has_dash': hostname_has_dash,
    }

def features_to_vector(features: dict) -> list:
    return [features[name] for name in FEATURE_NAMES]
