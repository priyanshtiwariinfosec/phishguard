"""
generate_dataset.py - Builds a labelled training dataset (data/urls.csv).

  label 0 = legitimate URL
  label 1 = phishing URL

Legitimate URLs use real, popular websites with realistic paths.
Phishing URLs are SYNTHETIC: they copy the tricks real attackers use
(brand names in subdomains, IP addresses, scary words, cheap TLDs ...)
but every phishing domain is randomly made up.

For a stronger model you can also train on a real dataset such as
PhishTank or the Kaggle "Malicious URLs" dataset - see README.md.

Usage:
    python generate_dataset.py            # 3000 legit + 3000 phishing
    python generate_dataset.py --n 5000
"""

import argparse
import csv
import os
import random
import string

random.seed(42)

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "amazon.in", "amazon.com",
    "flipkart.com", "github.com", "stackoverflow.com", "linkedin.com",
    "microsoft.com", "apple.com", "netflix.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "reddit.com", "bbc.co.uk", "nytimes.com",
    "theguardian.com", "hindustantimes.com", "timesofindia.indiatimes.com",
    "ndtv.com", "irctc.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
    "paytm.com", "phonepe.com", "zomato.com", "swiggy.com", "myntra.com",
    "python.org", "w3schools.com", "geeksforgeeks.org", "coursera.org",
    "udemy.com", "khanacademy.org", "medium.com", "dev.to", "mozilla.org",
    "cloudflare.com", "aws.amazon.com", "azure.microsoft.com", "dropbox.com",
    "zoom.us", "slack.com", "notion.so", "canva.com", "spotify.com",
    "paypal.com", "ebay.com", "walmart.com", "imdb.com", "quora.com",
    "nptel.ac.in", "iitb.ac.in", "ugc.gov.in", "india.gov.in", "uidai.gov.in",
    "incometax.gov.in", "nasa.gov", "who.int", "un.org", "harvard.edu",
    "mit.edu", "stanford.edu", "kaggle.com", "huggingface.co", "openai.com",
    "anthropic.com", "docker.com", "npmjs.com", "pypi.org", "gitlab.com",
    "bitbucket.org", "atlassian.com", "adobe.com", "booking.com", "airbnb.com",
    "makemytrip.com", "uber.com", "olacabs.com", "hotstar.com", "jio.com",
    "airtel.in", "steampowered.com", "binance.com", "coinbase.com",
    # small legitimate sites (some with hyphens, like real small businesses)
    "green-valley-bakery.com", "city-dental-care.in", "raj-tutorials.com",
    "learnwithpriya.in", "the-coding-blog.dev", "mumbai-marathon.org",
]

LEGIT_SUBDOMAINS = ["", "", "", "www.", "www.", "m.", "docs.", "blog.", "help.",
                    "support.", "accounts.", "mail.", "news.", "shop.", "en."]

LEGIT_PATHS = [
    "", "/", "/about", "/contact", "/help", "/login", "/signin", "/account",
    "/products/{w}", "/blog/{w}-{w}-{w}", "/news/{w}/{n}", "/watch?v={r}",
    "/search?q={w}+{w}", "/wiki/{W}_{W}", "/questions/{n}/{w}-{w}-{w}",
    "/user/{w}{n}", "/courses/{w}-{w}", "/docs/{w}/{w}", "/dp/{R}",
    "/p/{w}-{w}?pid={R}&lid={R}", "/en/{w}/{w}.html", "/{w}/{w}",
    "/settings/security", "/orders?ref={w}", "/item/{n}", "/r/{w}/comments/{r}/{w}_{w}",
    "/s?k={w}+{w}&ref=nb_sb_noss", "/in/{w}-{w}-{n}", "/download", "/pricing",
]

WORDS = ["python", "security", "network", "phone", "laptop", "shoes", "travel",
         "cricket", "music", "movie", "recipe", "college", "exam", "results",
         "india", "world", "data", "cloud", "learning", "guide", "review",
         "best", "cheap", "new", "how", "to", "install", "linux", "career",
         "jobs", "health", "fitness", "budget", "kids", "school", "project"]

PHISH_BRANDS = ["paypal", "apple", "icloud", "microsoft", "outlook", "office365",
                "amazon", "netflix", "facebook", "instagram", "whatsapp",
                "google", "gmail", "sbi", "hdfc", "icici", "paytm", "phonepe",
                "flipkart", "dropbox", "chase", "wellsfargo", "binance",
                "coinbase", "steam", "linkedin"]

PHISH_WORDS = ["login", "signin", "verify", "verification", "secure", "account",
               "update", "confirm", "suspended", "unlock", "wallet", "billing",
               "kyc", "reset", "recover", "alert", "support", "service",
               "auth", "id", "customer", "help", "bonus", "gift", "claim"]

PHISH_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click",
              "link", "live", "support", "info", "online", "site", "buzz",
              "icu", "cyou", "monster", "shop", "com", "net", "org", "in", "co"]

SHORTENERS = ["bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd", "t.co"]


def rand_str(k, chars=string.ascii_lowercase + string.digits):
    return "".join(random.choice(chars) for _ in range(k))


def fill(template):
    """Replace {w} {W} {n} {r} {R} placeholders with random values."""
    out = template
    while "{w}" in out:
        out = out.replace("{w}", random.choice(WORDS), 1)
    while "{W}" in out:
        out = out.replace("{W}", random.choice(WORDS).capitalize(), 1)
    while "{n}" in out:
        out = out.replace("{n}", str(random.randint(1, 99999)), 1)
    while "{r}" in out:
        out = out.replace("{r}", rand_str(random.randint(6, 11), string.ascii_letters + string.digits), 1)
    while "{R}" in out:
        out = out.replace("{R}", rand_str(10).upper(), 1)
    return out


def legit_url():
    scheme = "https://" if random.random() < 0.93 else "http://"
    return scheme + random.choice(LEGIT_SUBDOMAINS) + random.choice(LEGIT_DOMAINS) + fill(random.choice(LEGIT_PATHS))


def fake_domain():
    """A made-up attacker domain such as 'secure-paypal-verify.xyz'."""
    style = random.random()
    tld = random.choice(PHISH_TLDS)
    if style < 0.45:
        parts = random.sample([random.choice(PHISH_BRANDS)] + random.sample(PHISH_WORDS, 2), random.randint(2, 3))
        return "-".join(parts) + "." + tld
    if style < 0.70:
        return random.choice(PHISH_WORDS) + rand_str(random.randint(2, 5)) + "." + tld
    if style < 0.85:
        return rand_str(random.randint(8, 18)) + "." + tld
    # typo-squatting: paypa1, amaz0n, rnicrosoft
    brand = random.choice(PHISH_BRANDS)
    swaps = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "m": "rn", "s": "5"}
    chars = [c for c in brand if c in swaps]
    if chars:
        c = random.choice(chars)
        brand = brand.replace(c, swaps[c], 1)
    return brand + random.choice(["", "-" + random.choice(PHISH_WORDS)]) + "." + tld


def phish_url():
    scheme = "https://" if random.random() < 0.55 else "http://"
    brand = random.choice(PHISH_BRANDS)
    word = random.choice(PHISH_WORDS)
    trick = random.random()

    if trick < 0.25:   # brand hidden in subdomains
        host = f"{brand}.com.{word}.{fake_domain()}"
    elif trick < 0.40:   # raw IP address
        host = ".".join(str(random.randint(1, 254)) for _ in range(4))
        if random.random() < 0.3:
            host += f":{random.choice([8080, 8000, 8443, 2083])}"
    elif trick < 0.50:   # URL shortener
        return "https://" + random.choice(SHORTENERS) + "/" + rand_str(random.randint(5, 8), string.ascii_letters + string.digits)
    elif trick < 0.58:   # '@' trick: browser goes to the part after '@'
        host = f"{brand}.com@{fake_domain()}"
    elif trick < 0.63:   # punycode look-alike
        host = "xn--" + rand_str(random.randint(5, 10)) + "." + random.choice(["com", "net", "xyz"])
    else:
        host = random.choice(["", "www.", f"{word}.", f"{brand}-{word}."]) + fake_domain()

    path_choices = [
        f"/{brand}/{word}/index.php",
        f"/{word}/{brand}-{random.choice(PHISH_WORDS)}.html",
        f"/wp-content/{rand_str(6)}/{word}.php",
        f"/{word}?session={rand_str(24)}&user={rand_str(8)}",
        f"/{brand}/signin?redirect=//{fake_domain()}",
        f"/{rand_str(10)}/{word}/{random.choice(PHISH_WORDS)}",
        f"/secure/{word}.php?id={random.randint(1000, 999999)}",
        "", "/",
        f"/{word}",
    ]
    return scheme + host + random.choice(path_choices)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=3000, help="URLs per class")
    ap.add_argument("--out", default="data/urls.csv")
    args = ap.parse_args()

    rows = [(legit_url(), 0) for _ in range(args.n)] + [(phish_url(), 1) for _ in range(args.n)]
    random.shuffle(rows)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "label"])
        w.writerows(rows)
    print(f"Saved {len(rows)} URLs to {args.out}  ({args.n} legitimate + {args.n} phishing)")


if __name__ == "__main__":
    main()
