import re
from urllib.parse import urlparse
import tldextract

# Trusted educational and academic domains
EDUCATIONAL_DOMAINS = [
    'wikipedia.org', 'khanacademy.org', 'coursera.org', 'edx.org',
    'mit.edu', 'harvard.edu', 'stanford.edu', 'ox.ac.uk', 'cam.ac.uk',
    'arxiv.org', 'researchgate.net', 'sciencedirect.com', 'ieee.org',
    'springer.com', 'nature.com', 'geeksforgeeks.org', 'w3schools.com',
    'stackoverflow.com', 'github.com', 'gitlab.com', 'codecademy.com',
    'freecodecamp.org', 'duolingo.com', 'britannica.com', 'jstor.org',
    'ncbi.nlm.nih.gov', 'pubmed.ncbi.nlm.nih.gov', 'academia.edu',
    'udemy.com', 'nptel.ac.in', 'swayam.gov.in', 'ugc.ac.in', 'ignou.ac.in'
]

# Educational suffixes & government academic portals
EDUCATIONAL_SUFFIXES = ['.edu', '.ac.in', '.ac.uk', '.edu.in', '.res.in', '.gov.in']

# 18+ Adult & explicit content patterns
ADULT_PATTERNS = [
    'pornhub', 'xvideos', 'xnxx', 'xhamster', 'redtube', 'youporn',
    'chaturbate', 'stripchat', 'livejasmin', 'onlyfans', 'camsoda',
    'brazzers', 'bangbros', 'naughtyamerica', 'eporner', 'tube8',
    'spankbang', 'beeg', 'tnaflix', 'porntrex', 'daftsex', 'hqporner'
]

ADULT_KEYWORDS = [
    'porn', 'xxx', 'adult-chat', 'sex-cam', 'erotic', 'nude',
    'escort', 'dating-adult', 'live-girls', 'webcam-girls',
    'playboy', 'penthouse', 'stripper', 'fetish'
]

# Betting, gambling, casinos, and high-risk satta operations
BETTING_PATTERNS = [
    '1xbet', 'bet365', 'betway', 'parimatch', 'melbet', '22bet',
    'dafabet', 'mostbet', 'linebet', 'mega-pari', 'lotus365',
    'fairplay', 'betwinner', 'stake.com', 'cricbet99', 'skyexchange',
    'laserbook247', 'diamondexch', 'reddybook', 'allpanelexch',
    'silverexch', 'tiger247', 'crickex', 'rajabets', 'pin-up.casino',
    'jeetwin', 'purewin', 'baazi247', 'khelraja', 'indibet',
    'betfair', 'williamhill', '888casino', 'bwin', 'unibet', 'pokerstars'
]

BETTING_KEYWORDS = [
    'casino', 'betting', 'roulette', 'slot-online', 'satta', 'matka',
    'bonus365', 'double-money', 'fast-loan', 'instant-win', 'card-hack',
    'crypto-doubler', 'daily-profit', 'ponzi', 'telegram-vip-tips',
    'blackjack', 'baccarat', 'online-gambling'
]

def evaluate_student_safety(url: str, is_phishing_predicted: bool = False) -> dict:
    """
    Evaluates whether a website is appropriate, safe, and useful for students.
    Identifies 18+ adult content, betting/gambling, and scam/phishing sites.
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
    suffix = (ext.suffix or '').lower()

    # 1. Check for Verified Educational Resources
    is_educational = (
        registered_domain in EDUCATIONAL_DOMAINS or
        any(hostname.endswith(sfx) for sfx in EDUCATIONAL_SUFFIXES)
    )

    # 2. Check for 18+ Adult Content
    matched_adult = []
    for brand in ADULT_PATTERNS:
        if brand in hostname or brand in domain_name:
            matched_adult.append(brand)
    for kw in ADULT_KEYWORDS:
        if kw in full_str:
            matched_adult.append(kw)

    # 3. Check for Betting & Gambling Apps
    matched_betting = []
    for brand in BETTING_PATTERNS:
        if brand in hostname or brand in domain_name:
            matched_betting.append(brand)
    for kw in BETTING_KEYWORDS:
        if kw in full_str:
            matched_betting.append(kw)

    # Decision logic
    if matched_adult:
        return {
            'is_student_safe': False,
            'category': 'ADULT_18_PLUS',
            'category_label': '18+ Adult & Explicit Content',
            'is_blocked': True,
            'reason': f"Contains 18+ adult content and explicit material ('{matched_adult[0]}'). Strictly prohibited for students.",
            'action_advice': 'This website is strictly blocked for student safety. Focus on approved academic and educational resources.'
        }
    elif matched_betting:
        return {
            'is_student_safe': False,
            'category': 'BETTING_AND_GAMBLING',
            'category_label': 'Illegal Betting & Gambling Platform',
            'is_blocked': True,
            'reason': f"Identified unauthorized online betting/gambling platform ('{matched_betting[0]}'). Leads to financial extortion, cyber fraud, and student distraction.",
            'action_advice': 'DO NOT USE THIS LINK. Betting and gambling sites are illegal for minors and frequently steal user funds.'
        }
    elif is_phishing_predicted:
        return {
            'is_student_safe': False,
            'category': 'FAKE_OR_PHISHING',
            'category_label': 'Fraudulent / Fake Website',
            'is_blocked': True,
            'reason': "Website exhibits deceptive phishing signatures, fake login forms, or scam patterns designed to harvest credentials.",
            'action_advice': 'Dangerous fake website. Do not enter school IDs, passwords, or personal details.'
        }
    elif is_educational:
        return {
            'is_student_safe': True,
            'category': 'EDUCATIONAL_RESOURCE',
            'category_label': 'Verified Student Educational Resource',
            'is_blocked': False,
            'reason': 'Recognized authentic academic, university, or educational learning resource.',
            'action_advice': 'Safe and useful for educational research, study, and learning.'
        }
    else:
        return {
            'is_student_safe': True,
            'category': 'GENERAL_WEB',
            'category_label': 'General Web Resource',
            'is_blocked': False,
            'reason': 'Standard web domain. No explicit student safety violations detected.',
            'action_advice': 'Proceed with normal awareness. Verify information authenticity before use.'
        }
