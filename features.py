"""
features.py - Turns a URL into numbers that a machine-learning model can learn from.

Phishing URLs usually share tell-tale patterns:
  * very long URLs or hostnames
  * an IP address instead of a domain name
  * many subdomains (paypal.com.secure-login.xyz)
  * scary words like "verify", "suspended", "login"
  * a famous brand name that is NOT the real domain
  * cheap / unusual top-level domains (.xyz, .tk, .top ...)

Each function below measures one of these patterns.
"""

import math
import re
from collections import Counter
from urllib.parse import urlparse

# ----------------------------------------------------------------------------
# Word lists used by the features
# ----------------------------------------------------------------------------

SUSPICIOUS_WORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "password", "banking", "suspend", "suspended",
    "unlock", "wallet", "billing", "invoice", "webscr", "authenticate", "recover",
    "reset", "validation", "limited", "alert", "urgent", "free", "bonus", "gift",
    "prize", "claim", "kyc",
]

# Well-known brands that attackers love to imitate, mapped to their real domains
BRANDS = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "icloud": ["icloud.com", "apple.com"],
    "google": ["google.com", "google.co.in", "youtube.com", "gmail.com"],
    "gmail": ["gmail.com", "google.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "outlook": ["outlook.com", "live.com", "microsoft.com"],
    "office365": ["office.com", "microsoft.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "linkedin": ["linkedin.com"],
    "sbi": ["onlinesbi.sbi", "sbi.co.in"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "flipkart": ["flipkart.com"],
    "dropbox": ["dropbox.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "link", "live",
    "support", "info", "online", "site", "buzz", "rest", "fit", "icu", "cyou",
    "monster", "loan", "country", "kim", "zip", "mov", "cam", "shop",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "s.id",
}

# Country-code second-level domains like .co.in, .co.uk, .gov.in
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "nic", "res"}

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# ----------------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------------

def normalize(url: str) -> str:
    """Add http:// if the user typed a bare domain like 'example.com/login'."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def registered_domain(hostname: str) -> str:
    """
    Return the 'real' domain someone registered.
      login.paypal.com          -> paypal.com
      paypal.com.verify-me.xyz  -> verify-me.xyz   (the attacker's domain!)
      www.bbc.co.uk             -> bbc.co.uk
    """
    parts = hostname.lower().strip(".").split(".")
    if len(parts) <= 2 or _IP_RE.match(hostname):
        return hostname.lower()
    if parts[-2] in _SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def shannon_entropy(text: str) -> float:
    """How 'random' a string looks. Random gibberish domains score high."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


_LOOKALIKE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})


def undo_lookalikes(text: str) -> str:
    """Reverse common look-alike tricks:  amaz0n -> amazon,  paypa1 -> paypal,  rnicrosoft -> microsoft."""
    return text.translate(_LOOKALIKE).replace("rn", "m").replace("vv", "w")


def _brand_misuse(url_lower: str, reg_domain: str) -> int:
    """1 if a famous brand appears in the URL (even misspelled like 'amaz0n')
    but the real domain does not belong to that brand."""
    candidates = (url_lower, undo_lookalikes(url_lower))
    for brand, real_domains in BRANDS.items():
        if any(brand in c for c in candidates) and reg_domain not in real_domains:
            return 1
    return 0


# ----------------------------------------------------------------------------
# Main feature extractor
# ----------------------------------------------------------------------------

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "num_dots",
    "num_hyphens_host",
    "num_at",
    "num_digits",
    "digit_ratio",
    "num_special_chars",
    "num_query_params",
    "num_subdomains",
    "has_ip",
    "uses_https",
    "has_port",
    "suspicious_tld",
    "is_shortener",
    "has_punycode",
    "double_slash_redirect",
    "suspicious_word_count",
    "brand_misuse",
    "host_entropy",
    "longest_host_token",
]


def extract_features(url: str) -> list:
    """Convert one URL into a list of numbers (same order as FEATURE_NAMES)."""
    url = normalize(url)
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    url_lower = url.lower()

    reg_domain = registered_domain(hostname)
    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    has_ip = 1 if _IP_RE.match(hostname) else 0
    subdomain_part = hostname[: -len(reg_domain)].strip(".") if not has_ip else ""
    subdomains = [s for s in subdomain_part.split(".") if s and s != "www"]

    try:
        has_port = 1 if parsed.port else 0
    except ValueError:  # malformed port
        has_port = 1

    digits = sum(ch.isdigit() for ch in url)
    host_tokens = re.split(r"[.\-]", hostname) if hostname else [""]

    return [
        len(url),
        len(hostname),
        len(path),
        url.count("."),
        hostname.count("-"),
        url.count("@"),
        digits,
        round(digits / max(len(url), 1), 4),
        sum(url.count(c) for c in "%=?&~_+!*"),
        len([p for p in query.split("&") if p]),
        len(subdomains),
        has_ip,
        1 if parsed.scheme == "https" else 0,
        has_port,
        1 if tld in SUSPICIOUS_TLDS else 0,
        1 if reg_domain in URL_SHORTENERS else 0,
        1 if "xn--" in hostname else 0,
        1 if url.find("//", 8) != -1 else 0,
        sum(1 for w in SUSPICIOUS_WORDS if w in url_lower),
        _brand_misuse(url_lower, reg_domain),
        round(shannon_entropy(hostname), 4),
        max(len(t) for t in host_tokens),
    ]


def explain(url: str) -> list:
    """
    Human-readable reasons why a URL looks risky.
    These are shown in the web app next to the AI's verdict.
    """
    f = dict(zip(FEATURE_NAMES, extract_features(url)))
    url_n = normalize(url)
    host = (urlparse(url_n).hostname or "").lower()
    reasons = []

    reg = registered_domain(host)
    if f["has_ip"]:
        reasons.append(("high", "Uses an IP address instead of a domain name"))
    if f["brand_misuse"]:
        lookalike = undo_lookalikes(host) != host and not any(b in host for b in BRANDS)
        if lookalike:
            reasons.append(("high", f"Imitates a brand name with look-alike characters (real domain: '{reg}')"))
        else:
            reasons.append(("high", f"Mentions a well-known brand, but the real domain is '{reg}'"))
    if f["num_at"]:
        reasons.append(("high", "Contains '@' - browsers ignore everything before it"))
    if f["has_punycode"]:
        reasons.append(("high", "Uses punycode (xn--) - may imitate letters from another alphabet"))
    if f["double_slash_redirect"]:
        reasons.append(("medium", "Contains '//' inside the path - possible hidden redirect"))
    if f["suspicious_tld"]:
        reasons.append(("medium", f"Uses a top-level domain often abused by scammers (.{host.rsplit('.', 1)[-1]})"))
    if f["is_shortener"]:
        reasons.append(("medium", "Shortened link - the real destination is hidden"))
    if f["suspicious_word_count"] >= 2:
        reasons.append(("medium", f"Contains {f['suspicious_word_count']} pressure words (login, verify, urgent ...)"))
    elif f["suspicious_word_count"] == 1:
        reasons.append(("low", "Contains a sensitive word (login, verify, account ...)"))
    if f["num_subdomains"] >= 3:
        reasons.append(("medium", f"Has {f['num_subdomains']} subdomains - used to hide the real domain"))
    if f["num_hyphens_host"] >= 2:
        reasons.append(("low", "Many hyphens in the domain name"))
    if f["has_port"]:
        reasons.append(("low", "Uses a non-standard port number"))
    if not f["uses_https"]:
        reasons.append(("low", "Not using HTTPS (no encryption)"))
    if f["url_length"] > 90:
        reasons.append(("low", f"Very long URL ({f['url_length']} characters)"))
    name = reg.split(".")[0]
    if not f["has_ip"] and len(name) >= 10 and "-" not in name and shannon_entropy(name) > 3.2 \
            and sum(ch in "aeiou" for ch in name) / len(name) < 0.3:
        reasons.append(("low", f"Domain name '{name}' looks randomly generated"))
    return reasons
