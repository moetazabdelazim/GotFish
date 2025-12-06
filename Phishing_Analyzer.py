import re
from urllib.parse import urlparse
from difflib import SequenceMatcher
import unicodedata
import json
import os

# Trusted brands: typosquatting
BRAND_KEYWORDS = [
    "google", "gmail", "microsoft", "outlook", "hotmail",
    "yahoo", "apple", "icloud", "paypal", "amazon",
    "facebook", "instagram", "twitter", "linkedin",
    "netflix", "wordpress"
]

# DNSTwist permutation database
DNSTWIST_LOOKUP = {}
DNSTWIST_LOADED = False

# Whitelist: add new entries here
LEGITIMATE_DOMAINS = [
    "google.com", "gmail.com", "microsoft.com", "outlook.com",
    "yahoo.com", "apple.com", "icloud.com", "paypal.com",
    "amazon.com", "facebook.com", "instagram.com", "twitter.com",
    "linkedin.com", "netflix.com", "wordpress.com"
]

# Suspicious TLDs
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.click']

# Homograph attack - confusable characters
CONFUSABLES = {
    'a': ['а', 'ɑ', 'α', 'ạ'], 
    'e': ['е', 'ė', 'ë', 'ę'],
    'o': ['о', 'ο', '0', 'ọ'],
    'i': ['і', 'l', '1', 'ı', 'ï'],
    'c': ['с', 'ϲ', 'ⅽ'],
    'p': ['р', 'ρ'],
    'h': ['һ', 'ｈ'],
    'x': ['х', 'ⅹ'],
    'y': ['у', 'ｙ'],
}

def similarity(a: str, b: str) -> float:
    """Calculate string similarity ratio"""
    return SequenceMatcher(None, a, b).ratio()

def load_dnstwist_database():
    """Load pre-generated DNSTwist permutations"""
    global DNSTWIST_LOOKUP, DNSTWIST_LOADED
    
    db_path = 'dnstwist_permutations.json'
    
    if not os.path.exists(db_path):
        print(f"DNSTwist database not found at {db_path}")
        print(f"Permutations will be generated on app startup")
        return False
    
    try:
        with open(db_path, 'r') as f:
            data = json.load(f)
        
        DNSTWIST_LOOKUP = {
            brand: set(info['permutations'])
            for brand, info in data.items()
            if brand != '_metadata'
        }
        
        total = sum(len(perms) for perms in DNSTWIST_LOOKUP.values())
        brands = len(DNSTWIST_LOOKUP)
        
        print(f"DNSTwist: Loaded {total:,} permutations for {brands} brands")
        
        # check database age
        try:
            from datetime import datetime
            generated_at = datetime.fromisoformat(data['_metadata']['generated_at'])
            age_days = (datetime.now() - generated_at).days
            print(f"   Database age: {age_days} days")
        except:
            pass
        
        DNSTWIST_LOADED = True
        return True
        
    except Exception as e:
        print(f"Error loading DNSTwist database: {e}")
        return False

def check_dnstwist_typosquat(domain: str) -> dict:
    """Check if domain matches any DNSTwist permutation"""
    if not DNSTWIST_LOADED or not DNSTWIST_LOOKUP:
        return {'checked': False, 'reason': 'DNSTwist database not loaded'}
    
  
    for brand, permutations in DNSTWIST_LOOKUP.items():
        if domain in permutations:
            return {
                'is_typosquat': True,
                'target_brand': brand,
                'detection_method': 'DNSTwist',
                'confidence': 98,
                'checked': True
            }
    
    parts = domain.split('.')
    if len(parts) > 2:
        root = '.'.join(parts[-2:])
        for brand, permutations in DNSTWIST_LOOKUP.items():
            if root in permutations:
                return {
                    'is_typosquat': True,
                    'target_brand': brand,
                    'detection_method': 'DNSTwist (root domain)',
                    'confidence': 95,
                    'checked': True
                }
    
    return {'is_typosquat': False, 'checked': True}

def detect_homograph(text: str) -> list:
    """characters that could be used in homograph attacks"""
    suspicious = []
    for char in text:
        for latin, confusables in CONFUSABLES.items():
            if char in confusables:
                suspicious.append(f"'{char}' (U+{ord(char):04X}) looks like '{latin}'")
    return suspicious

def check_ip_address(domain: str) -> bool:
    """domain is an IP address?"""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ip_pattern, domain))

def extract_domain_parts(url: str) -> tuple:
    """extract full domain, root domain, and subdomain from URL"""
    try:
        # Add scheme if missing for proper parsing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        full_domain = parsed.netloc.lower()
        
        # port strip
        if ':' in full_domain:
            full_domain = full_domain.split(':')[0]
        
        parts = full_domain.split('.')
        
        if len(parts) >= 2:
            root_domain = '.'.join(parts[-2:])
            subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ""
        else:
            root_domain = full_domain
            subdomain = ""
        
        return full_domain, root_domain, subdomain
    except Exception as e:
        raise ValueError(f"Could not parse domain: {e}")

def calculate_risk_score(domain: str, subdomain: str, root_domain: str) -> tuple:
    """risk score and return detailed reasons"""
    score = 0
    reasons = []
    
    # if whitelisted (automatic pass)
    if root_domain in LEGITIMATE_DOMAINS and not subdomain:
        return 0, ["Verified legitimate domain"]
    
    # DNSTwist typosquatting check (PRIORITY CHECK)
    dnstwist_result = check_dnstwist_typosquat(domain)
    if dnstwist_result.get('is_typosquat'):
        score += 45
        reasons.append(
            f"CONFIRMED TYPOSQUAT of '{dnstwist_result['target_brand']}' "
            f"(DNSTwist database match - {dnstwist_result['confidence']}% confidence)"
        )
    
    # IP address check
    if check_ip_address(domain):
        score += 40
        reasons.append("Domain is an IP address (not typical for legitimate sites)")
    
    # Homograph detection
    homographs = detect_homograph(domain)
    if homographs:
        score += 35
        reasons.append(f"Homograph attack detected: {', '.join(homographs)}")
    
    # Suspicious TLD check
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 25
            reasons.append(f"Suspicious TLD '{tld}' (commonly used in phishing)")
            break
    
    # @ symbol check (authentication bypass attempt)
    if '@' in domain:
        score += 40
        reasons.append("Contains '@' symbol (possible redirect/bypass attempt)")
    
    # Repeated dashes
    if re.search(r'-{2,}', domain):
        score += 15
        reasons.append("Contains repeated dashes (suspicious pattern)")
    
    # Excessive length
    if len(domain) > 50:
        score += 10
        reasons.append("Unusually long domain name")
    
    # Excessive subdomains
    if subdomain and subdomain.count('.') >= 2:
        score += 15
        reasons.append(f"Multiple subdomains detected: {subdomain}")
    
    # Brand typosquatting check - improved logic
    for brand in BRAND_KEYWORDS:
        # Check if brand appears as a complete word in domain
        domain_parts = re.split(r'[.\-_]', domain)
        
        # Exact match in parts (legitimate use)
        if brand in domain_parts:
            if root_domain not in LEGITIMATE_DOMAINS:
                reasons.append(f"Contains brand keyword '{brand}' in non-official domain")
            continue
        
        # Similarity check for typosquatting
        sim_score = similarity(root_domain.replace('.com', '').replace('.net', ''), brand)
        # hard coded, change it
        if sim_score > 0.80:  # High similarity threshold
            score += 30
            reasons.append(f"Domain '{root_domain}' is very similar to '{brand}' (similarity: {sim_score:.2f})")
        elif sim_score > 0.65:  # Moderate similarity
            score += 15
            reasons.append(f"Domain '{root_domain}' resembles '{brand}' (similarity: {sim_score:.2f})")
    
    # Check for brand keywords in suspicious positions
    if subdomain:
        for brand in BRAND_KEYWORDS:
            if brand in subdomain:
                score += 20
                reasons.append(f"Brand '{brand}' found in subdomain of different domain")
    
    # Non-ASCII characters (potential punycode/IDN attack)
    non_ascii = [ch for ch in domain if ord(ch) > 127]
    if non_ascii:
        score += 20
        reasons.append(f"Contains non-ASCII characters: {', '.join(set(non_ascii))}")
    
    return score, reasons

def get_risk_level(score: int) -> tuple:
    """Convert numeric score to risk level"""
    if score >= 70:
        return "CRITICAL RISK", "#ff0000"
    elif score >= 40:
        return "HIGH RISK", "#ff6600"
    elif score >= 20:
        return "MODERATE RISK", "#ffcc00"
    elif score >= 10:
        return "LOW RISK", "#66ff66"
    else:
        return "SAFE", "#00ff00"

def analyze_url(url: str) -> dict:
    """Analyze URL for phishing indicators"""
    if not url.strip():
        return {
            'verdict': 'SAFE',
            'score': 0,
            'color': '#00ff00',
            'reasons': ['No URL provided'],
            'domain_info': {}
        }
    
    try:
        full_domain, root_domain, subdomain = extract_domain_parts(url)
        
        score, reasons = calculate_risk_score(full_domain, subdomain, root_domain)
        verdict, color = get_risk_level(score)
        
        # Add character breakdown
        char_breakdown = ' '.join([f"{ch}(U+{ord(ch):04X})" if ord(ch) > 127 else ch for ch in url[:100]])
        
        return {
            'verdict': verdict,
            'score': score,
            'color': color,
            'reasons': reasons if reasons else ['No suspicious patterns detected'],
            'domain_info': {
                'full_domain': full_domain,
                'root_domain': root_domain,
                'subdomain': subdomain if subdomain else 'None',
                'char_breakdown': char_breakdown
            }
        }
    
    except Exception as e:
        return {
            'verdict': 'ERROR',
            'score': 0,
            'color': '#ff0000',
            'reasons': [f'URL parsing failed: {str(e)}'],
            'domain_info': {}
        }

def analyze_email(sender: str) -> dict:
    """Analyze email sender for phishing indicators"""
    if not sender.strip():
        return {
            'verdict': 'SAFE',
            'score': 0,
            'color': '#00ff00',
            'reasons': ['No email provided'],
            'domain_info': {}
        }
    
    try:
        # Extract email domain
        match = re.search(r'@([A-Za-z0-9\.-]+)$', sender)
        if not match:
            return {
                'verdict': 'CRITICAL RISK',
                'score': 100,
                'color': '#ff0000',
                'reasons': ['Invalid email format - missing or malformed domain'],
                'domain_info': {}
            }
        
        domain = match.group(1).lower()
        parts = domain.split('.')
        
        if len(parts) < 2:
            return {
                'verdict': 'CRITICAL RISK',
                'score': 100,
                'color': '#ff0000',
                'reasons': ['Email domain missing TLD (e.g., .com, .org)'],
                'domain_info': {}
            }
        
        root_domain = '.'.join(parts[-2:])
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ""
        
        score, reasons = calculate_risk_score(domain, subdomain, root_domain)
        verdict, color = get_risk_level(score)
        
        # Additional email-specific checks
        if sender.count('@') > 1:
            score += 40
            reasons.append('Multiple @ symbols detected')
            verdict, color = get_risk_level(score)
        
        # Display name spoofing check
        if '<' in sender and '>' in sender:
            display_match = re.search(r'(.+?)\s*<', sender)
            if display_match:
                display_name = display_match.group(1).strip('"\'')
                reasons.append(f"Display name: '{display_name}' (verify this matches the domain)")
        
        char_breakdown = ' '.join([f"{ch}(U+{ord(ch):04X})" if ord(ch) > 127 else ch for ch in sender[:100]])
        
        return {
            'verdict': verdict,
            'score': score,
            'color': color,
            'reasons': reasons if reasons else ['No suspicious patterns detected'],
            'domain_info': {
                'full_domain': domain,
                'root_domain': root_domain,
                'subdomain': subdomain if subdomain else 'None',
                'char_breakdown': char_breakdown
            }
        }
    
    except Exception as e:
        return {
            'verdict': 'ERROR',
            'score': 0,
            'color': '#ff0000',
            'reasons': [f'Email parsing failed: {str(e)}'],
            'domain_info': {}
        }

