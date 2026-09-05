import re
import ipaddress
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

URL_REGEX = re.compile(
    r'^(?:https?://)?'
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}|'
    r'localhost|'
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    r'(?::\d+)?'
    r'(?:/?|[/?]\S+)$', re.IGNORECASE
)

def is_valid_url(url: str):
    if not url or not isinstance(url, str):
        return False, 'URL cannot be empty.'
    
    clean_url = url.strip()
    if len(clean_url) > 2048:
        return False, 'URL exceeds maximum allowable length of 2048 characters.'
        
    if not re.match(r'^[a-zA-Z]+://', clean_url):
        clean_url = 'http://' + clean_url
        
    if not URL_REGEX.match(clean_url):
        return False, 'Invalid URL format or malformed syntax.'
        
    parsed = urlparse(clean_url)
    if parsed.scheme not in ('http', 'https'):
        return False, 'Unsupported URL protocol: ' + str(parsed.scheme) + '. Only HTTP and HTTPS are permitted.'
        
    hostname = parsed.hostname or ''
    if not hostname:
        return False, 'URL domain or hostname is missing.'

    return True, ''

def is_safe_destination(url: str):
    is_valid, err = is_valid_url(url)
    if not is_valid:
        return False, err
        
    clean_url = url.strip()
    if not re.match(r'^[a-zA-Z]+://', clean_url):
        clean_url = 'http://' + clean_url
        
    parsed = urlparse(clean_url)
    hostname = parsed.hostname or ''
    
    if hostname.lower() in ('localhost', '127.0.0.1', '::1', '0.0.0.0'):
        return False, 'Access to local loopback addresses is restricted for security.'

    try:
        ip = ipaddress.ip_address(hostname)
        for net in BLOCKED_NETWORKS:
            if ip in net:
                return False, 'Target IP address falls within a restricted internal/private subnet.'
    except ValueError:
        pass
        
    return True, ''
