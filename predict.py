"""
predict.py - Check URLs from the command line (also used by the web app).

The URL is only analysed as TEXT - it is never opened or visited,
so checking a dangerous link is completely safe.

Usage:
    python predict.py "http://paypal.com.verify-account.xyz/login"
    python predict.py https://github.com https://amaz0n-kyc-update.top
"""

import os
import sys

import joblib

from urllib.parse import urlparse

from features import BRANDS, FEATURE_NAMES, explain, extract_features, normalize, registered_domain

# Layer 1 of the hybrid detector: official domains of well-known brands.
# (Layer 2 is the machine-learning model.)
OFFICIAL_DOMAINS = {d: brand for brand, domains in BRANDS.items() for d in domains}

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model", "phishing_model.joblib")
_bundle = None


def load_model():
    global _bundle
    if _bundle is None:
        if not os.path.exists(MODEL_PATH):
            raise SystemExit("Model not found. Run:  python generate_dataset.py  then  python train.py")
        _bundle = joblib.load(MODEL_PATH)
    return _bundle


def analyze(url: str) -> dict:
    """Return verdict, risk score (0-100), reasons and raw features for one URL."""
    bundle = load_model()
    feats = extract_features(url)
    proba = float(bundle["model"].predict_proba([feats])[0][1])
    risk = round(proba * 100, 1)

    reasons = [{"level": lvl, "text": txt} for lvl, txt in explain(url)]

    # Allowlist check: the exact registered domain must match (paypal.com.evil.xyz does NOT match)
    host = (urlparse(normalize(url)).hostname or "").lower()
    official_brand = OFFICIAL_DOMAINS.get(registered_domain(host))
    if official_brand:
        risk = min(risk, 5.0)
        name = official_brand.upper() if len(official_brand) <= 5 else official_brand.capitalize()
        reasons = [{"level": "info", "text": f"Verified official domain of {name} (allowlist)"}] \
            + [r for r in reasons if r["level"] == "low"]

    if risk >= 70:
        verdict = "PHISHING"
    elif risk >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "url": normalize(url),
        "verdict": verdict,
        "risk": risk,
        "reasons": reasons,
        "features": dict(zip(FEATURE_NAMES, feats)),
        "model": bundle["model_name"],
    }


COLORS = {"PHISHING": "\033[91m", "SUSPICIOUS": "\033[93m", "SAFE": "\033[92m"}
RESET = "\033[0m"


def main():
    urls = sys.argv[1:]
    if not urls:
        print('Usage: python predict.py "<url>" ["<url>" ...]')
        sys.exit(1)
    os.system("")  # enables colours in the Windows terminal
    for url in urls:
        r = analyze(url)
        print(f"\n{r['url']}")
        print(f"  Verdict : {COLORS[r['verdict']]}{r['verdict']}{RESET}   (risk {r['risk']}%)")
        for reason in r["reasons"]:
            print(f"  - [{reason['level']:<6}] {reason['text']}")


if __name__ == "__main__":
    main()
