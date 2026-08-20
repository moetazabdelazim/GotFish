import re
import time
import unicodedata
import urllib.parse
from difflib import SequenceMatcher

import requests

# Brands commonly targeted by phishing / typosquatting.
# These are only reference points for the analyst; the tool no longer renders
# a verdict. Short, ambiguous tokens (e.g. "ing", "td") are deliberately
# excluded — they substring-match ordinary words and drown the analyst in
# noise.
BRAND_KEYWORDS = [
    # Big tech / email / productivity
    "google", "gmail", "microsoft", "outlook", "hotmail", "office365",
    "apple", "icloud", "yahoo", "aol", "protonmail", "zoho",
    "github", "gitlab", "dropbox", "docusign", "adobe", "slack", "zoom",
    "salesforce", "okta", "godaddy", "cloudflare", "wordpress", "shopify",
    # Social / messaging / streaming
    "facebook", "instagram", "twitter", "linkedin", "whatsapp", "telegram",
    "discord", "snapchat", "tiktok", "reddit", "pinterest", "twitch",
    "netflix", "spotify", "hulu", "disney", "youtube",
    # Payments / fintech / crypto
    "paypal", "venmo", "cashapp", "zelle", "stripe", "square",
    "visa", "mastercard", "amex", "discover", "wise", "revolut",
    "coinbase", "binance", "kraken", "metamask", "ledger", "blockchain",
    # Banks
    "chase", "wellsfargo", "bankofamerica", "citibank", "capitalone",
    "usbank", "pnc", "usaa", "navyfederal", "schwab", "fidelity",
    "hsbc", "barclays", "lloyds", "santander", "commbank", "westpac",
    "rbc", "scotiabank", "bmo", "cibc",
    # Retail / shipping / services
    "amazon", "ebay", "walmart", "target", "costco", "homedepot",
    "aliexpress", "etsy", "fedex", "dhl", "usps", "uber", "airbnb",
    "booking", "expedia", "doordash",
    # Gaming
    "steam", "roblox", "epicgames", "playstation", "xbox", "nintendo",
    # Telecom / government-adjacent
    "verizon", "tmobile", "comcast", "xfinity", "vodafone", "irs",
    "moeblogs",
]

# Homograph / confusable characters: Latin-alphabet lookalikes.
CONFUSABLES = {
    'a': ['а', 'ɑ', 'α', 'ạ'],
    'e': ['е', 'ė', 'ë', 'ę'],
    'i': ['і', 'l', '1', 'ı', 'ï', 'ɪ'],
    'o': ['о', 'ο', '0', 'ọ'],
    'c': ['с', 'ϲ', 'ⅽ'],
    'p': ['р', 'ρ'],
    'h': ['һ', 'ｈ'],
    'x': ['х', 'ⅹ'],
    'y': ['у', 'ｙ'],
    's': ['ѕ', 'Ｓ'],
    't': ['т', 'Ｔ'],
    'n': ['ո', 'ռ'],
    'r': ['г'],
}

# Reverse lookup: confusable char -> Latin-alphabet letter it resembles.
CONFUSABLE_TO_LATIN = {
    conf: latin
    for latin, conf_list in CONFUSABLES.items()
    for conf in conf_list
}

# Publicly hosted dnstwist instance (no local dnstwist package required).
DNSTWIST_BASE = "https://dnstwist.it"
DNSTWIST_POLL_INTERVAL = 0.5
DNSTWIST_MAX_POLL_TIME = 30

EMAIL_TYPE = "email"
URL_TYPE = "url"


def _is_printable_ascii(text):
    """Return True if *text* is plain ASCII and printable."""
    try:
        return text.encode("ascii") and all(ord(ch) >= 32 or ch in "\t\n\r" for ch in text)
    except UnicodeEncodeError:
        return False


def similarity(a: str, b: str) -> float:
    """Case-insensitive string similarity ratio."""
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _normalize_confusables(text: str) -> str:
    """Replace non-ASCII lookalike characters with their Latin equivalents."""
    return "".join(CONFUSABLE_TO_LATIN.get(ch, ch) if ord(ch) > 127 else ch for ch in text)


def levenshtein_distance(a: str, b: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(a) < len(b):
        return levenshtein_distance(b, a)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, c1 in enumerate(a):
        current_row = [i + 1]
        for j, c2 in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def detect_input_type(value: str) -> str:
    """Detect whether the input is an email address or a URL/domain."""
    value = value.strip()

    # Explicit URL scheme → URL.  This covers full URLs with @ in the query.
    if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', value):
        return URL_TYPE

    # Strip an optional "Display Name" <addr> wrapper if present.
    addr_part = value
    if "<" in value and ">" in value:
        m = re.search(r'<(.+?)>\s*$', value)
        if m:
            addr_part = m.group(1).strip()

    # Normalize confusables so admin@micrоsoft.com (Cyrillic o) is still
    # recognized as an email address.
    normalized = _normalize_confusables(addr_part)

    # Multiple '@' symbols without an explicit URL scheme is a common email
    # parsing trick; route it through email analysis so the analyst sees it.
    if normalized.count("@") > 1:
        return EMAIL_TYPE

    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', normalized):
        return EMAIL_TYPE

    # Everything else (bare domains, schemeless URLs) is treated as a URL.
    return URL_TYPE


def extract_domain_parts(url: str) -> dict:
    """Parse a URL and return its components for the analyst."""
    raw = url.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw

    parsed = urllib.parse.urlparse(raw)
    full_domain = parsed.netloc.lower()

    # Strip userinfo (e.g. http://user@example.com or http://u@host@evil.com);
    # the real host is everything after the final '@' in the netloc.
    if "@" in full_domain:
        full_domain = full_domain.rsplit("@", 1)[-1]

    if ":" in full_domain:
        full_domain = full_domain.rsplit(":", 1)[0]

    parts = full_domain.split(".")
    if len(parts) >= 2:
        root_domain = ".".join(parts[-2:])
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    else:
        root_domain = full_domain
        subdomain = ""

    return {
        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "full_domain": full_domain,
        "root_domain": root_domain,
        "subdomain": subdomain,
    }


def extract_email_parts(email: str) -> dict:
    """Parse an email address and return its components for the analyst."""
    raw = email.strip()
    display_name = ""
    addr_part = raw

    # Handle "Display Name" <user@domain.com> format
    if "<" in raw and ">" in raw:
        m = re.search(r'^(.*?)\s*<(.+?)>\s*$', raw)
        if m:
            display_name = m.group(1).strip('"\'')
            addr_part = m.group(2).strip()

    at_count = addr_part.count("@")
    if "@" not in addr_part:
        return {
            "raw": raw,
            "valid_format": False,
            "display_name": display_name,
            "local_part": "",
            "domain": "",
            "root_domain": "",
            "subdomain": "",
            "at_count": at_count,
        }

    local_part, domain = addr_part.rsplit("@", 1)
    domain = domain.lower()
    parts = domain.split(".")
    if len(parts) >= 2:
        root_domain = ".".join(parts[-2:])
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    else:
        root_domain = domain
        subdomain = ""

    return {
        "raw": raw,
        "valid_format": True,
        "display_name": display_name,
        "local_part": local_part,
        "domain": domain,
        "root_domain": root_domain,
        "subdomain": subdomain,
        "at_count": at_count,
    }


def _character_breakdown(text: str) -> list:
    """Return an indexed character breakdown with Unicode code points and names."""
    breakdown = []
    for idx, ch in enumerate(text[:200]):
        breakdown.append({
            "index": idx,
            "character": ch,
            "codepoint": f"U+{ord(ch):04X}",
            "name": unicodedata.name(ch, "UNKNOWN CHARACTER"),
        })
    return breakdown


def spell_out_input(input_value: str, input_type: str) -> dict:
    """Spell out the website/email for the analyst: what characters are really there."""
    raw = input_value.strip()[:200]

    if input_type == URL_TYPE:
        parts = extract_domain_parts(input_value)

        # Punycode decoding if present
        punycode_decoded = None
        if "xn--" in parts["full_domain"]:
            try:
                punycode_decoded = parts["full_domain"].encode("ascii").decode("idna")
            except (UnicodeError, UnicodeDecodeError):
                pass

        return {
            "input_type": "URL / Website Link",
            "raw_input": raw,
            "spelled_out": raw,
            "scheme": parts["scheme"],
            "netloc": parts["netloc"],
            "path": parts["path"],
            "query": parts["query"],
            "fragment": parts["fragment"],
            "full_domain": parts["full_domain"],
            "root_domain": parts["root_domain"],
            "subdomain": parts["subdomain"],
            "punycode_decoded": punycode_decoded,
            "character_breakdown": _character_breakdown(raw),
            "is_printable_ascii": _is_printable_ascii(raw),
        }

    else:  # email
        parts = extract_email_parts(input_value)

        return {
            "input_type": "Email Sender Address",
            "raw_input": raw,
            "spelled_out": raw,
            "valid_format": parts.get("valid_format", False),
            "display_name": parts.get("display_name", ""),
            "local_part": parts.get("local_part", ""),
            "domain": parts.get("domain", ""),
            "root_domain": parts.get("root_domain", ""),
            "subdomain": parts.get("subdomain", ""),
            "at_count": parts.get("at_count", 0),
            "character_breakdown": _character_breakdown(raw),
            "is_printable_ascii": _is_printable_ascii(raw),
        }


def detect_homograph_and_brand_similarity(
    full_domain: str,
    root_domain: str,
    subdomain: str,
    decoded_full_domain: str = None,
    decoded_root_domain: str = None,
) -> dict:
    """Surface homograph-like characters and brand similarity for analyst review."""
    text_to_inspect = full_domain
    findings = []
    lookalikes = []

    for ch in text_to_inspect:
        # Homograph attacks are about non-ASCII characters that visually
        # resemble Latin letters. Plain ASCII digits/Latin letters are normal
        # and should not be flagged here (substitutions are handled separately).
        if ord(ch) <= 127:
            continue
        latin = CONFUSABLE_TO_LATIN.get(ch)
        if latin:
            lookalikes.append({
                "character": ch,
                "codepoint": f"U+{ord(ch):04X}",
                "name": unicodedata.name(ch, "UNKNOWN CHARACTER"),
                "resembles": latin,
            })

    if lookalikes:
        unique = list({(item["character"], item["resembles"]): item for item in lookalikes}.values())
        findings.append(
            f"Found {len(unique)} lookalike character(s) that resemble Latin letters: "
            f"{', '.join(f'{item['character']} (U+{ord(item['character']):04X}) looks like {item['resembles']}' for item in unique)}"
        )

    brand_matches = []

    # For brand checks, prefer the decoded IDN form (e.g. аpple.com) when the
    # input is punycode, otherwise use the normalized form.
    root_for_self_check = decoded_root_domain or root_domain
    normalized_root = _normalize_confusables(root_for_self_check)
    normalized_full = _normalize_confusables(decoded_full_domain or full_domain)
    base_root = re.sub(r"\.(com|net|org|co\.\w+|\w+)$", "", normalized_root)
    all_parts = re.split(r"[.\-_]", normalized_full)

    for brand in BRAND_KEYWORDS:
        # Skip noisy self-matches on legitimate brand domains (e.g. google.com).
        # Use the original (decoded) root so that homograph variants like
        # micrоsoft.com still get flagged as brand lookalikes.
        self_check_base = re.sub(r"\.(com|net|org|co\.\w+|\w+)$", "", root_for_self_check)
        is_self_match = self_check_base.lower() == brand.lower()

        # Exact occurrence of the brand name somewhere in the normalized domain.
        if not is_self_match and brand in all_parts:
            brand_matches.append({
                "brand": brand,
                "match_type": "exact",
                "context": "brand keyword appears as a whole token in the domain",
            })
            findings.append(f"Brand keyword '{brand}' appears as a whole token in the domain")

        # Fuzzy similarity to the root domain.
        sim = similarity(base_root, brand)
        if not is_self_match and sim >= 0.75:
            brand_matches.append({
                "brand": brand,
                "match_type": "fuzzy",
                "similarity": round(sim, 3),
                "context": "root domain is visually/phonetically close to this brand",
            })
            findings.append(
                f"Root domain '{root_domain}' is similar to brand '{brand}' "
                f"(similarity: {sim:.2f})"
            )

        # Edit-distance fallback for near-typosquats that fall just below the
        # fuzzy threshold (e.g., gogle.com vs google).
        if not is_self_match and brand not in [m["brand"] for m in brand_matches]:
            if len(base_root) >= 4 and len(brand) >= 4:
                dist = levenshtein_distance(base_root.lower(), brand.lower())
                max_len = max(len(base_root), len(brand))
                ratio = 1 - (dist / max_len)
                if dist <= 2 and ratio >= 0.65:
                    brand_matches.append({
                        "brand": brand,
                        "match_type": "typosquat",
                        "similarity": round(ratio, 3),
                        "context": "root domain is an edit-distance near-match to this brand",
                    })
                    findings.append(
                        f"Root domain '{root_domain}' is close to brand '{brand}' "
                        f"(edit distance: {dist}; possible typosquat)"
                    )

    # Numeric substitution common in typosquatting (e.g., paypa1, micr0soft)
    substitutions = re.findall(r"[a-z]+\d+[a-z]*|\d+[a-z]+", full_domain)
    if substitutions:
        findings.append(
            f"Detected alphanumeric patterns that may be letter substitutions: {', '.join(substitutions)}"
        )

    return {
        "lookalike_characters": unique if lookalikes else [],
        "brand_matches": brand_matches,
        "findings": findings,
    }


def detect_subdomain_spoofing(full_domain: str, root_domain: str, subdomain: str) -> dict:
    """Flag cases where a trusted brand name is hosted under an unrelated root domain."""
    findings = []
    subdomain_parts = subdomain.split(".") if subdomain else []

    if subdomain:
        for brand in BRAND_KEYWORDS:
            if brand in subdomain.lower():
                findings.append(
                    f"Brand keyword '{brand}' appears in the subdomain '{subdomain}', "
                    f"but the root domain is '{root_domain}'. Analysts should verify that "
                    f"'{root_domain}' is actually operated by {brand}."
                )

    # Look for suspicious root-domain masquerades like brand-name-something.tld
    brand_in_root = [brand for brand in BRAND_KEYWORDS if brand in root_domain.lower()]
    if brand_in_root and root_domain not in [f"{brand}.com" for brand in BRAND_KEYWORDS]:
        # This is a weaker signal; only note if the brand is used as a prefix.
        for brand in brand_in_root:
            if root_domain.startswith(brand) and not root_domain == f"{brand}.com":
                findings.append(
                    f"Root domain '{root_domain}' starts with brand keyword '{brand}' but is not the "
                    f"official '{brand}.com' domain."
                )

    if len(subdomain_parts) >= 3:
        findings.append(
            f"Unusually deep subdomain chain ({len(subdomain_parts)} levels): '{subdomain}'. "
            f"Deep subdomains are sometimes used to push the real registrant domain deeper into the URL."
        )

    # Common path-segment spoofing is not applicable to bare domains, but hyphen-heavy
    # tokens in the subdomain are worth noting.
    if subdomain and subdomain.count("-") >= 2:
        findings.append(
            f"Subdomain '{subdomain}' contains multiple hyphens; this is a common typosquatting pattern."
        )

    return {
        "subdomain_parts": subdomain_parts,
        "brand_keywords_in_subdomain": [b for b in BRAND_KEYWORDS if b in subdomain.lower()],
        "findings": findings,
    }


def detect_idn_and_non_ascii(domain: str) -> dict:
    """Surface IDN / punycode and non-ASCII characters for analyst review."""
    findings = []
    non_ascii = []

    punycode = None
    decoded_idn = None
    starts_with_xn = domain.lower().startswith("xn--") or ".xn--" in domain.lower()

    # If the domain is punycode, decode it first; the real non-ASCII characters
    # are hidden inside the decoded form.
    domains_to_inspect = [domain]
    if starts_with_xn:
        punycode = domain
        try:
            decoded_idn = domain.encode("ascii").decode("idna")
            domains_to_inspect.append(decoded_idn)
            findings.append(
                f"Punycode domain detected: '{domain}' decodes to '{decoded_idn}'. "
                f"IDN homograph attacks use punycode to hide non-ASCII lookalikes."
            )
        except (UnicodeError, UnicodeDecodeError):
            findings.append(
                f"Punycode prefix 'xn--' detected in '{domain}', but it could not be decoded."
            )

    seen = set()
    for text in domains_to_inspect:
        for ch in text:
            if ord(ch) <= 127 or ch in seen:
                continue
            seen.add(ch)
            non_ascii.append({
                "character": ch,
                "codepoint": f"U+{ord(ch):04X}",
                "name": unicodedata.name(ch, "UNKNOWN CHARACTER"),
            })

    if non_ascii:
        chars = ", ".join(
            f"{item['character']} (U+{item['codepoint'].replace('U+', '')})" for item in non_ascii
        )
        findings.append(f"Non-ASCII characters found: {chars}")

    return {
        "punycode": punycode,
        "decoded_idn": decoded_idn,
        "non_ascii_characters": non_ascii,
        "findings": findings,
    }


def _domain_from_input(input_value: str, input_type: str) -> str:
    """Extract the root domain to pass to dnstwist.it."""
    if input_type == URL_TYPE:
        parts = extract_domain_parts(input_value)
        return parts["root_domain"]
    else:
        parts = extract_email_parts(input_value)
        return parts.get("root_domain", "")


def query_dnstwist_it(domain: str, timeout: int = DNSTWIST_MAX_POLL_TIME) -> dict:
    """Query the public dnstwist.it instance and return registered permutations."""
    result = {
        "queried_domain": domain,
        "scan_id": None,
        "scan_url": None,
        "total_permutations": 0,
        "registered_count": 0,
        "unregistered_count": 0,
        "registered_domains": [],
        "all_permutations": [],
        "error": None,
        "timed_out": False,
    }

    if not domain or "." not in domain:
        result["error"] = "No valid root domain to scan."
        return result

    try:
        resp = requests.post(
            f"{DNSTWIST_BASE}/api/scans",
            json={"url": domain},
            timeout=10,
        )
        resp.raise_for_status()
        scan = resp.json()
        scan_id = scan.get("id")
        if not scan_id:
            result["error"] = "dnstwist.it did not return a scan id."
            return result

        result["scan_id"] = scan_id
        result["scan_url"] = f"{DNSTWIST_BASE}/api/scans/{scan_id}"
        result["total_permutations"] = scan.get("total", 0)

        # Poll until the scan finishes or we hit the timeout.
        start = time.time()
        while True:
            status = requests.get(
                f"{DNSTWIST_BASE}/api/scans/{scan_id}",
                timeout=10,
            ).json()
            if status.get("remaining", 0) <= 0:
                break
            if time.time() - start > timeout:
                result["timed_out"] = True
                break
            time.sleep(DNSTWIST_POLL_INTERVAL)

        result["registered_count"] = status.get("registered", 0)

        # Registered domains with DNS details.
        reg_resp = requests.get(
            f"{DNSTWIST_BASE}/api/scans/{scan_id}/domains",
            timeout=15,
        )
        reg_resp.raise_for_status()
        registered = reg_resp.json()

        # Strip the fuzzer field; we show only registered domain + DNS info.
        result["registered_domains"] = [
            {k: v for k, v in item.items() if k != "fuzzer"}
            for item in registered
        ]

        # Full permutation list to derive unregistered count.
        list_resp = requests.get(
            f"{DNSTWIST_BASE}/api/scans/{scan_id}/list",
            timeout=15,
        )
        list_resp.raise_for_status()
        all_perms = [line.strip() for line in list_resp.text.splitlines() if line.strip()]
        result["all_permutations"] = all_perms

        registered_names = {item.get("domain", "").lower() for item in registered}
        unregistered = [
            perm for perm in all_perms
            if perm.lower() not in registered_names
        ]
        result["unregistered_count"] = len(unregistered)

    except requests.exceptions.RequestException as exc:
        result["error"] = f"dnstwist.it request failed: {exc}"
    except Exception as exc:
        result["error"] = f"dnstwist.it integration error: {exc}"

    return result


def _build_analysis(input_value: str, input_type: str, domain: str, root_domain: str, subdomain: str) -> dict:
    """Assemble the full analyst-facing analysis structure."""
    spelled_out = spell_out_input(input_value, input_type)
    idn_analysis = detect_idn_and_non_ascii(domain)

    # If the domain is punycode, decode it before brand checks so the real IDN
    # (e.g. аpple.com) is matched against brand keywords.
    decoded_full = idn_analysis.get("decoded_idn") or domain
    decoded_root = root_domain
    if decoded_full != domain:
        parts = decoded_full.split(".")
        if len(parts) >= 2:
            decoded_root = ".".join(parts[-2:])
        else:
            decoded_root = decoded_full

    homograph = detect_homograph_and_brand_similarity(
        domain, root_domain, subdomain, decoded_full, decoded_root
    )
    subdomain_analysis = detect_subdomain_spoofing(domain, root_domain, subdomain)
    dnstwist = query_dnstwist_it(root_domain)

    observations = []

    # 1. Homograph / brand similarity
    if homograph["lookalike_characters"]:
        observations.append(
            f"Homograph-style characters detected: "
            f"{len(homograph['lookalike_characters'])} lookalike(s)."
        )
    if homograph["brand_matches"]:
        observations.append(
            f"Brand similarity check found {len(homograph['brand_matches'])} reference(s) to known brands."
        )

    # 2. Subdomain spoofing
    if subdomain:
        observations.append(
            f"Subdomain detected: '{subdomain}'. Verify whether any brand keywords here belong to the registrant."
        )

    # 3. IDN / Non-ASCII
    if idn_analysis["non_ascii_characters"] or idn_analysis["punycode"]:
        observations.append(
            "Non-ASCII / IDN characters detected; review the decoded punycode and Unicode breakdown."
        )

    # 4. DNSTwist summary
    if dnstwist["error"]:
        observations.append(f"dnstwist.it lookup could not be completed: {dnstwist['error']}")
    else:
        observations.append(
            f"dnstwist.it generated {dnstwist['total_permutations']} permutations; "
            f"{dnstwist['registered_count']} registered and "
            f"{dnstwist['unregistered_count']} unregistered."
        )

    return {
        "input_type": input_type,
        "spelled_out": spelled_out,
        "observations": observations,
        "homograph_and_brand_similarity": homograph,
        "subdomain_spoofing": subdomain_analysis,
        "idn_and_non_ascii": idn_analysis,
        "dnstwist_it": dnstwist,
    }


def analyze_url(url: str) -> dict:
    """Analyze a URL and return analyst-facing observations (no verdict)."""
    if not url.strip():
        return {
            "input_type": URL_TYPE,
            "spelled_out": {"raw_input": ""},
            "observations": ["No URL provided."],
            "homograph_and_brand_similarity": {},
            "subdomain_spoofing": {},
            "idn_and_non_ascii": {},
            "dnstwist_it": {},
        }

    try:
        parts = extract_domain_parts(url)
        return _build_analysis(url, URL_TYPE, parts["full_domain"], parts["root_domain"], parts["subdomain"])
    except Exception as exc:
        return {
            "input_type": URL_TYPE,
            "spelled_out": {"raw_input": url.strip()[:200]},
            "observations": [f"Parsing failed: {exc}"],
            "homograph_and_brand_similarity": {},
            "subdomain_spoofing": {},
            "idn_and_non_ascii": {},
            "dnstwist_it": {},
        }


def analyze_email(sender: str) -> dict:
    """Analyze an email sender address and return analyst-facing observations (no verdict)."""
    if not sender.strip():
        return {
            "input_type": EMAIL_TYPE,
            "spelled_out": {"raw_input": ""},
            "observations": ["No email provided."],
            "homograph_and_brand_similarity": {},
            "subdomain_spoofing": {},
            "idn_and_non_ascii": {},
            "dnstwist_it": {},
        }

    try:
        parts = extract_email_parts(sender)
        if not parts.get("valid_format"):
            return {
                "input_type": EMAIL_TYPE,
                "spelled_out": spell_out_input(sender, EMAIL_TYPE),
                "observations": ["Email format is invalid or missing a domain."],
                "homograph_and_brand_similarity": {},
                "subdomain_spoofing": {},
                "idn_and_non_ascii": {},
                "dnstwist_it": {},
            }

        analysis = _build_analysis(
            sender, EMAIL_TYPE, parts["domain"], parts["root_domain"], parts["subdomain"]
        )

        if parts.get("display_name"):
            analysis["observations"].append(
                f"Display name '{parts['display_name']}' is present; verify it matches the sending domain."
            )

        if parts.get("at_count", 0) > 1:
            analysis["observations"].append(
                f"Multiple '@' symbols detected ({parts['at_count']}); this is a common parsing trick."
            )

        return analysis

    except Exception as exc:
        return {
            "input_type": EMAIL_TYPE,
            "spelled_out": {"raw_input": sender.strip()[:200]},
            "observations": [f"Parsing failed: {exc}"],
            "homograph_and_brand_similarity": {},
            "subdomain_spoofing": {},
            "idn_and_non_ascii": {},
            "dnstwist_it": {},
        }
