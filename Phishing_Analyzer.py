import re
import idna
import unicodedata
from difflib import SequenceMatcher

# Trusted brands we want to protect against typosquatting
BRAND_KEYWORDS = [
    "google", "gmail", "microsoft", "outlook", "hotmail",
    "yahoo", "apple", "icloud", "paypal", "amazon",
    "facebook", "instagram", "twitter", "linkedin",
    "netflix", "bank", "secure", "login"
]

def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()

def spell_out_text(text: str):
    spelled = []
    for ch in text:
        codepoint = ord(ch)
        if codepoint > 127:
            # Flag non-ASCII / foreign characters
            spelled.append(f"{ch}(U+{codepoint:04X} ⚠️)")
        else:
            spelled.append(ch)
    return ' '.join(spelled)

def analyze_url(url: str):
    if not url.strip():
        return "Pass ✅", ["No URL provided"]

    reasons = []
    verdict = "Pass ✅"

    try:
        domain = re.sub(r"https?://", "", url)
        domain = domain.split("/")[0].split("?")[0]
        parts = domain.split(".")
        print(domain)
        if len(parts) > 2:  
            subdomain = ".".join(parts[:-2])   # everything before the root + TLD
            domain = ".".join(parts[-2:])      # keep only root + TLD
        else:
            subdomain = ""  

        # IDNA decoding
        try:
            domain = idna.decode(domain.encode("utf-8"))
        except Exception:
            pass

        domain_norm = domain.lower()
        brand_suspect = any(similarity(domain_norm, b.lower()) > 0.25 for b in BRAND_KEYWORDS)
        


        if re.search(r"@", domain):
            verdict = "Suspicious ❌"
            reasons.append("URL contains '@' → possible phishing redirect")
        if re.search(r"[-]{2,}", domain):
            verdict = "Suspicious ❌"
            reasons.append("Domain contains repeated dashes")


        for brand in BRAND_KEYWORDS:
            score = similarity(domain_norm, brand.lower())
            if brand.lower() in domain_norm:
                reasons.append(f"Domain contains brand keyword '{brand}'")
            elif score > 0.25:
                verdict = "Suspicious ❌"
                reasons.append(f"Domain '{domain}' is visually similar to '{brand}' (score={score:.2f})")


        reasons.append("Input characters spelled out: " + " ".join(list(url)))

    except Exception as e:
        verdict = "Error ❌"
        reasons.append(f"URL parsing failed: {e}")

    if verdict == "Suspicious ❌" and domain_norm in BRAND_KEYWORDS:
            verdict = "False Positive ⚠️"
            reasons.append("Domain matches a trusted brand exactly → likely safe")

    if not reasons:
        reasons.append("No suspicious patterns detected")

    return verdict, reasons

def analyze_email(sender: str):
    if not sender.strip():
        return "Pass ✅", ["No sender provided"]

    reasons = []
    verdict = "Pass ✅"

    try:
        match = re.search(r"@([A-Za-z0-9\.-]+)", sender)
        if not match:
            return "Suspicious ❌", ["Sender email missing domain part"]

        domain = match.group(1)
        domain_norm = domain.lower()
        brand_suspect = any(similarity(domain_norm, b.lower()) > 0.25 for b in BRAND_KEYWORDS)
        

        for brand in BRAND_KEYWORDS:
            score = similarity(domain_norm, brand.lower())
            if brand.lower() in domain_norm:
                reasons.append(f"Sender domain contains brand keyword '{brand}'")
            elif score > 0.25:
                verdict = "Suspicious ❌"
                reasons.append(f"Sender domain '{domain}' is visually similar to '{brand}' (score={score:.2f})")

        reasons.append("Input characters spelled out: " + " ".join(list(sender)))

    except Exception as e:
        verdict = "Error ❌"
        reasons.append(f"Email parsing failed: {e}")


    if not reasons:
        reasons.append("No suspicious patterns detected")


    return verdict, reasons
