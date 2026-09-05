import os
import random
import pandas as pd
from backend.services.feature_extractor import extract_features, FEATURE_NAMES

# Representative list of legitimate domains and URLs
LEGITIMATE_SAMPLES = [
    'https://www.google.com', 'https://www.youtube.com', 'https://www.facebook.com',
    'https://www.amazon.com', 'https://www.wikipedia.org', 'https://www.reddit.com',
    'https://www.yahoo.com', 'https://www.twitter.com', 'https://www.instagram.com',
    'https://www.linkedin.com', 'https://www.netflix.com', 'https://www.microsoft.com',
    'https://www.apple.com', 'https://www.github.com', 'https://www.stackoverflow.com',
    'https://www.medium.com', 'https://www.bing.com', 'https://www.twitch.tv',
    'https://www.adobe.com', 'https://www.dropbox.com', 'https://www.paypal.com/signin',
    'https://www.bankofamerica.com', 'https://www.chase.com', 'https://www.wellsfargo.com',
    'https://www.nytimes.com', 'https://www.cnn.com', 'https://www.bbc.com/news',
    'https://www.espn.com', 'https://www.imdb.com', 'https://www.pinterest.com',
    'https://www.quora.com', 'https://www.spotify.com', 'https://www.ebay.com',
    'https://www.walmart.com', 'https://www.target.com', 'https://www.craigslist.org',
    'https://developer.mozilla.org/en-US', 'https://pypi.org/project/fastapi',
    'https://docs.python.org/3/library', 'https://www.coursera.org/learn/machine-learning',
    'https://www.khanacademy.org', 'https://www.udemy.com/course/python-programming',
    'https://www.salesforce.com', 'https://workspace.google.com', 'https://aws.amazon.com/console',
    'https://portal.azure.com', 'https://cloud.google.com/products', 'https://www.oracle.com',
    'https://www.cisco.com', 'https://www.ibm.com/cloud', 'https://news.ycombinator.com',
    'https://www.nature.com', 'https://www.sciencedirect.com', 'https://arxiv.org/abs/2301.00001',
    'https://www.nih.gov', 'https://www.cdc.gov', 'https://www.who.int',
    'https://www.harvard.edu', 'https://www.mit.edu', 'https://www.stanford.edu',
    'https://www.cam.ac.uk', 'https://www.ox.ac.uk', 'https://www.berkeley.edu',
    'https://hub.docker.com', 'https://gitlab.com', 'https://bitbucket.org',
    'https://www.atlassian.com/software/jira', 'https://slack.com/workspace',
    'https://zoom.us/join', 'https://www.notion.so', 'https://www.figma.com',
    'https://www.canva.com', 'https://www.tableau.com', 'https://www.postgresql.org/docs',
    'https://react.dev', 'https://vuejs.org', 'https://angular.io',
    'https://tailwindcss.com/docs', 'https://getbootstrap.com', 'https://web.dev',
    'https://www.w3schools.com', 'https://developer.apple.com/documentation',
    'https://learn.microsoft.com', 'https://support.google.com', 'https://help.netflix.com',
    'https://www.yelp.com', 'https://www.tripadvisor.com', 'https://www.booking.com',
    'https://www.airbnb.com', 'https://www.uber.com', 'https://www.lyft.com',
    'https://www.zillow.com', 'https://www.realtor.com', 'https://www.indeed.com',
    'https://www.glassdoor.com', 'https://www.monster.com', 'https://www.weather.com',
    'https://www.nationalgeographic.com', 'https://www.forbes.com', 'https://www.bloomberg.com'
]

# Variations and synthetically diverse benign URL structures (paths, queries)
BENIGN_PATHS = [
    '/articles/2026/05/security-updates',
    '/products/category/item?id=98721&ref=home',
    '/documentation/v2/api-reference',
    '/search?q=machine+learning+tutorial',
    '/blog/post/announcement-release',
    '/about-us/team',
    '/contact-sales?region=us-east',
    '/support/knowledge-base/article-1029',
    '/explore/trending/topics',
    '/help/center/faq'
]

# Phishing URL patterns derived from PhishTank / OpenPhish patterns
PHISHING_PATTERNS = [
    'http://192.168.1.105/paypal/signin.html?cmd=_login-run&dispatch=5885d80a13c0db1f',
    'http://104.244.78.12/secure-account/login.php?verification=true',
    'http://185.220.101.5/appleid/verify/account-update.php',
    'http://paypal-verification-account-security-update.xyz/webscr?cmd=login_submit',
    'http://chase-bank-online-security-alert-login.top/account/verify.html',
    'http://secure-wellsfargo-bank-verification.loan/login.aspx?auth=token991',
    'http://bankofamerica-customer-security-support.work/update-billing.php',
    'http://login.microsoft.com.account-verification-service.click/auth',
    'http://appleid.apple.com.manage-id-recovery-security.buzz/verify',
    'http://google-drive-shared-document-verify-login.xyz/docs/signin',
    'http://netflix-billing-subscription-failed-update.top/user/payment',
    'http://amazon-prime-account-suspended-action-required.club/verify-info',
    'http://facebook-security-check-login-confirmation.fit/checkpoint',
    'http://instagram-copyright-infringement-appeal-form.vip/verify',
    'http://crypto-wallet-metamask-seedphrase-recovery.xyz/connect',
    'http://binance-security-kyc-verification-notice.top/account',
    'http://coinbase-authorization-required-login.buzz/verify-wallet',
    'http://ebay-suspended-account-confirm-identity.xyz/ebayisapi.php',
    'http://dhl-express-package-delivery-tracking-fee.click/pay-customs',
    'http://fedex-parcel-pending-delivery-verification.top/confirm-address',
    'http://irs-tax-refund-status-claim-online.loan/refund/form',
    'http://gov-stimulus-payment-registration-portal.club/apply',
    'http://secure-webmail-corporate-login-exchange.fit/owa/auth.php',
    'http://cpanel-webmail-update-storage-quota.work/login.html',
    'http://office365-password-expiration-warning-keep-password.top/login',
    'http://it-helpdesk-urgent-system-upgrade-credentials.click/verify',
    'http://bit.ly/3xUrL0g?redirect=http%3A%2F%2Ffake-chase-login.com',
    'http://tinyurl.com/secure-login-bank-verify?token=948210',
    'http://is.gd/update_account_password_now_urgent',
    'http://secure.account-update.bank.com.fake-domain-stealer.xyz/login',
    'http://support-service-apple-recovery-id.cf/login/verify.php',
    'http://auth.token.verification.paypal.com.phishnet-test.ml/signin',
    'http://billing-update-required-netflix.gq/login?session_id=89231',
    'http://secure-login-verification-portal-992182.ga/account/verify',
    'http://confirm-identity-security-alert-online.tk/confirm.php?user=victim',
    'http://172.16.254.1/chase/login.php?account_id=9871&token=abc',
    'http://203.0.113.195/wellsfargo/verification-center/secure.jsp',
    'http://www.google.com-support-account-recovery-centre.top/web/login',
    'http://www.microsoft.com.security-alert-threat-protection.club/signin.php',
    'http://appleid.apple.com.id-verify-portal-notice.work/sign-in',
    'http://www-paypal-com.webscr-cmd-login-run-verification.top/signin'
]

def generate_dataset(output_path: str = 'dataset/phishing_dataset.csv', n_samples: int = 1200):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    rows = []
    
    # 1. Base Legitimate Samples
    for base in LEGITIMATE_SAMPLES:
        rows.append({'url': base, 'status': 0})
        for path in BENIGN_PATHS[:5]:
            rows.append({'url': f'{base}{path}', 'status': 0})

    # Expand legitimate samples with realistic subdomain and path combinations
    tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co.uk', '.de']
    sub_prefixes = ['www', 'app', 'blog', 'support', 'docs', 'developer', 'status', 'portal']
    words = ['tech', 'cloud', 'digital', 'systems', 'solutions', 'media', 'network', 'analytics', 'global', 'nexus']

    while len([r for r in rows if r['status'] == 0]) < (n_samples // 2):
        domain_name = f'{random.choice(words)}{random.choice(words)}{random.randint(10, 99)}'
        tld = random.choice(tlds)
        sub = random.choice(sub_prefixes)
        scheme = 'https://' if random.random() > 0.1 else 'http://'
        path = random.choice(BENIGN_PATHS) if random.random() > 0.4 else ''
        url = f'{scheme}{sub}.{domain_name}{tld}{path}'
        rows.append({'url': url, 'status': 0})

    # 2. Phishing Samples
    for p in PHISHING_PATTERNS:
        rows.append({'url': p, 'status': 1})

    phish_keywords = ['login', 'verify', 'account', 'secure', 'bank', 'update', 'password', 'confirm', 'wallet', 'security']
    targets = ['paypal', 'chase', 'appleid', 'microsoft', 'netflix', 'amazon', 'wells-fargo', 'bankofamerica', 'coinbase', 'google']
    phish_tlds = ['.xyz', '.top', '.work', '.loan', '.club', '.buzz', '.click', '.vip', '.fit', '.tk', '.ml']

    while len([r for r in rows if r['status'] == 1]) < (n_samples // 2):
        target = random.choice(targets)
        kw1 = random.choice(phish_keywords)
        kw2 = random.choice(phish_keywords)
        tld = random.choice(phish_tlds)
        
        mode = random.randint(1, 4)
        if mode == 1:
            # IP address based
            ip = f'{random.randint(11, 210)}.{random.randint(1, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}'
            url = f'http://{ip}/{target}/{kw1}.php?id={random.randint(10000, 99999)}&{kw2}=true'
        elif mode == 2:
            # Deep subdomain spoofing
            url = f'http://{target}.com.{kw1}-{kw2}-portal-check{random.randint(1, 999)}{tld}/auth/login.php'
        elif mode == 3:
            # Excessive hyphens & keywords
            url = f'http://secure-{target}-online-{kw1}-verification-center-notice{tld}/webscr?cmd={kw2}&token={random.randint(100000, 999999)}'
        else:
            # Port or encoded
            url = f'http://{target}-{kw1}-support{tld}:8080/account/update-password.html'
            
        rows.append({'url': url, 'status': 1})

    df = pd.DataFrame(rows)
    # Shuffle and drop duplicate URLs
    df = df.sample(frac=1.0, random_state=42).drop_duplicates(subset=['url']).reset_index(drop=True)
    
    print(f'Total URLs compiled: {len(df)}')
    print('Class distribution:')
    print(df['status'].value_counts())
    
    df.to_csv(output_path, index=False)
    print(f'Dataset successfully written to {output_path}')
    return df

if __name__ == '__main__':
    generate_dataset()
