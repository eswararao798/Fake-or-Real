import re
from html.parser import HTMLParser
from urllib.parse import urlparse
import tldextract
import httpx

KNOWN_BRANDS = {
    'paypal': ['paypal.com'],
    'microsoft': ['microsoft.com', 'live.com', 'office.com', 'office365.com', 'azure.com'],
    'google': ['google.com', 'accounts.google.com'],
    'apple': ['apple.com', 'icloud.com'],
    'netflix': ['netflix.com'],
    'facebook': ['facebook.com', 'meta.com'],
    'amazon': ['amazon.com', 'aws.amazon.com'],
    'bank of america': ['bankofamerica.com'],
    'chase': ['chase.com'],
    'wellsfargo': ['wellsfargo.com']
}

class DOMParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title_text = ""
        self.in_title = False
        self.has_password_field = False
        self.form_actions = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        tag_lower = tag.lower()
        if tag_lower == 'title':
            self.in_title = True
        elif tag_lower == 'input':
            input_type = (attrs_dict.get('type') or '').lower()
            if input_type == 'password':
                self.has_password_field = True
        elif tag_lower == 'form':
            action = attrs_dict.get('action')
            if action:
                self.form_actions.append(action)

    def handle_endtag(self, tag):
        if tag.lower() == 'title':
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_text += data

def inspect_page_dom(url: str, timeout: float = 3.0) -> dict:
    """
    Fetches and inspects webpage HTML for password inputs, brand spoofing titles, 
    and cross-domain form submission targets.
    """
    clean_url = (url or '').strip()
    if not re.match(r'^[a-zA-Z]+://', clean_url):
        clean_url = 'http://' + clean_url

    parsed = urlparse(clean_url)
    hostname = (parsed.hostname or '').lower()
    ext = tldextract.extract(clean_url)
    domain_full = (ext.registered_domain or hostname).lower()

    dom_findings = {
        'inspected': False,
        'has_password_input': False,
        'brand_spoof_detected': False,
        'spoofed_brand': None,
        'cross_domain_form_submission': False,
        'risk_adjustment': 0,
        'issues': []
    }

    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, headers={'User-Agent': 'PhishNet-Sentinel-DOMInspector/1.0'}) as client:
            resp = client.get(clean_url)
            if resp.status_code == 200 and 'text/html' in resp.headers.get('content-type', ''):
                html_content = resp.text[:150000] # Inspect first 150KB
                parser = DOMParser()
                parser.feed(html_content)

                dom_findings['inspected'] = True
                dom_findings['has_password_input'] = parser.has_password_field
                title = parser.title_text.lower()

                # Check brand spoofing in title
                for brand, official_domains in KNOWN_BRANDS.items():
                    if brand in title:
                        if not any(domain_full.endswith(od) or hostname.endswith(od) for od in official_domains):
                            dom_findings['brand_spoof_detected'] = True
                            dom_findings['spoofed_brand'] = brand.title()
                            dom_findings['risk_adjustment'] += 35
                            dom_findings['issues'].append(
                                f"BRAND SPOOFING DETECTED: Page title claims to be {brand.title()}, but host domain ({domain_full}) is not an official {brand.title()} domain."
                            )

                # Check password input on suspicious domain
                if parser.has_password_field:
                    if dom_findings['brand_spoof_detected'] or not any(domain_full.endswith(od) for ods in KNOWN_BRANDS.values() for od in ods):
                        dom_findings['risk_adjustment'] += 20
                        dom_findings['issues'].append(
                            "CREDENTIAL HARVESTING RISK: Detected password input field (<input type='password'>) on an unverified domain."
                        )

                # Check cross-domain form submission targets
                for action in parser.form_actions:
                    if action.startswith('http://') or action.startswith('https://'):
                        target_host = urlparse(action).hostname or ''
                        target_ext = tldextract.extract(action)
                        target_domain = (target_ext.registered_domain or target_host).lower()
                        if target_domain and target_domain != domain_full:
                            dom_findings['cross_domain_form_submission'] = True
                            dom_findings['risk_adjustment'] += 25
                            dom_findings['issues'].append(
                                f"EXTERNAL FORM TARGET: Login/data form submits sensitive data to external domain ({target_domain})."
                            )
                            break
    except Exception:
        # Offline or unreachable target - dom inspection gracefully skipped
        pass

    return dom_findings
