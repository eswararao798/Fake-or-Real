import re
from urllib.parse import urlparse
import tldextract

# Trusted educational and developer domains
EDUCATIONAL_DOMAINS = [
    'wikipedia.org', 'khanacademy.org', 'coursera.org', 'edx.org',
    'mit.edu', 'harvard.edu', 'stanford.edu', 'ox.ac.uk', 'cam.ac.uk',
    'arxiv.org', 'researchgate.net', 'sciencedirect.com', 'ieee.org',
    'springer.com', 'nature.com', 'geeksforgeeks.org', 'w3schools.com',
    'stackoverflow.com', 'codecademy.com', 'freecodecamp.org', 'duolingo.com',
    'britannica.com', 'jstor.org', 'ncbi.nlm.nih.gov', 'pubmed.ncbi.nlm.nih.gov',
    'academia.edu', 'udemy.com', 'nptel.ac.in', 'swayam.gov.in', 'ugc.ac.in', 'ignou.ac.in'
]

DEVELOPER_DOMAINS = [
    'github.com', 'gitlab.com', 'bitbucket.org', 'sourceforge.net',
    'npmjs.com', 'pypi.org', 'docker.com', 'huggingface.co',
    'stackexchange.com', 'codepen.io', 'replit.com'
]

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

# Online Betting, Gambling, Casino, and Satta networks
BETTING_PATTERNS = [
    '1xbet', 'bet365', 'betway', 'parimatch', 'melbet', '22bet',
    'dafabet', 'mostbet', 'linebet', 'mega-pari', 'lotus365',
    'fairplay', 'betwinner', 'stake.com', 'cricbet99', 'skyexchange',
    'laserbook247', 'diamondexch', 'reddybook', 'allpanelexch',
    'silverexch', 'tiger247', 'crickex', 'rajabets', 'pin-up.casino',
    'jeetwin', 'purewin', 'baazi247', 'khelraja', 'indibet',
    'betfair', 'williamhill', '888casino', 'bwin', 'unibet', 'pokerstars',
    'betting', 'gambling', 'casino', 'slot-online', 'satta'
]

BETTING_KEYWORDS = [
    'casino', 'betting', 'roulette', 'slot-online', 'satta', 'matka',
    'bonus365', 'double-money', 'fast-loan', 'instant-win', 'card-hack',
    'crypto-doubler', 'daily-profit', 'ponzi', 'telegram-vip-tips',
    'blackjack', 'baccarat', 'online-gambling', 'win-cash', 'aviator-game'
]

def evaluate_student_safety(url: str, is_phishing_predicted: bool = False) -> dict:
    """
    Evaluates website purpose and student safety policy.
    Explicitly categorizes Developer platforms, Academic resources, Betting apps, and Adult content.
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

    # 1. Check Betting & Gambling Apps (STRICT PROHIBITION FOR STUDENTS)
    matched_betting = []
    for brand in BETTING_PATTERNS:
        if brand in hostname or brand in domain_name:
            matched_betting.append(brand)
    for kw in BETTING_KEYWORDS:
        if kw in full_str:
            matched_betting.append(kw)

    if matched_betting:
        return {
            'is_student_safe': False,
            'category': 'BETTING_AND_GAMBLING',
            'category_label': 'Online Betting & Gambling App (Prohibited for Students)',
            'purpose': 'Commercial Online Gambling & Sports Betting Portal',
            'is_blocked': True,
            'reason': f"Identified online betting/gambling service ('{matched_betting[0]}'). Strictly prohibited in academic/student environments due to financial loss, addictive gambling, and cyber fraud risks.",
            'action_advice': 'RESTRICTED FOR STUDENTS. Do not use this link. Betting apps are unauthorized for student environments and frequently freeze user funds.'
        }

    # 2. Check 18+ Adult Content
    matched_adult = []
    for brand in ADULT_PATTERNS:
        if brand in hostname or brand in domain_name:
            matched_adult.append(brand)
    for kw in ADULT_KEYWORDS:
        if kw in full_str:
            matched_adult.append(kw)

    if matched_adult:
        return {
            'is_student_safe': False,
            'category': 'ADULT_18_PLUS',
            'category_label': '18+ Adult & Explicit Content',
            'purpose': 'Adult Entertainment & Explicit Media Portal',
            'is_blocked': True,
            'reason': f"Contains 18+ adult content ('{matched_adult[0]}'). Strictly blocked for student safety.",
            'action_advice': 'This website is strictly blocked for student safety.'
        }

    # 3. Check Phishing / Deceptive Clone
    if is_phishing_predicted:
        return {
            'is_student_safe': False,
            'category': 'FAKE_OR_PHISHING',
            'category_label': 'Fraudulent Phishing Clone',
            'purpose': 'Deceptive Credential Theft & Phishing Scam Portal',
            'is_blocked': True,
            'reason': "Exhibits suspicious structural anomalies and credential harvesting signatures designed to steal passwords.",
            'action_advice': 'Dangerous malicious site. Do not enter passwords or personal details.'
        }

    # 4. Check Developer Platforms (GitHub, GitLab, etc.)
    if registered_domain in DEVELOPER_DOMAINS:
        return {
            'is_student_safe': True,
            'category': 'DEVELOPER_PLATFORM',
            'category_label': 'Developer & Code Repository Platform (Student Approved)',
            'purpose': 'Software Development, Open Source Code Repository & Academic Projects',
            'is_blocked': False,
            'reason': 'Official verified developer platform and code repository. Essential for computer science and engineering coursework.',
            'action_advice': 'Approved developer resource. Safe for coding projects and technical learning.'
        }

    # 5. Check Academic & Educational Resources
    is_educational = (
        registered_domain in EDUCATIONAL_DOMAINS or
        any(hostname.endswith(sfx) for sfx in EDUCATIONAL_SUFFIXES)
    )

    if is_educational:
        return {
            'is_student_safe': True,
            'category': 'EDUCATIONAL_RESOURCE',
            'category_label': 'Verified Student Educational Resource',
            'purpose': 'Academic Research, E-Learning & Educational Reference Portal',
            'is_blocked': False,
            'reason': 'Recognized authentic academic institution, university portal, or educational reference site.',
            'action_advice': 'Verified student resource. Highly recommended for study and academic research.'
        }

    # 6. Default General Web Resource
    return {
        'is_student_safe': True,
        'category': 'GENERAL_WEB',
        'category_label': 'General Web Destination',
        'purpose': 'General Information & Utility Portal',
        'is_blocked': False,
        'reason': 'Standard internet destination. No academic safety policy violations detected.',
        'action_advice': 'Standard web domain. Always verify site authenticity before submitting sensitive data.'
    }
