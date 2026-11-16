"""
prepare_real_dataset.py - Converts the real PhiUSIIL dataset into our url,label format
and removes its hidden biases.

Dataset: PhiUSIIL Phishing URL Dataset (UCI Machine Learning Repository, 2024)
         134,850 legitimate + 100,945 phishing URLs, CC BY 4.0 license.
         Prasad, A. & Chandra, S. (2024). Computers & Security.
         https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

!! The dataset's labels are REVERSED compared to ours:
     PhiUSIIL: 1 = legitimate, 0 = phishing
     Ours    : 0 = legitimate, 1 = phishing

!! THE BIAS PROBLEM (shortcut learning)
   In PhiUSIIL, EVERY legitimate URL looks exactly like "https://www.<domain>"
   - 100% start with https://www.   and   0% have a path (/login, /about ...)
   Phishing URLs are written in many different ways.

   A model trained on this raw data learns a shortcut:
       "has a path" or "no www."  ->  phishing
   so it wrongly flags real links like https://github.com/login.

   Fix (--mode debiased, the default):
     1. Remove the leading "www." from every URL (both classes), so the
        model cannot use it as a shortcut.
     2. Give 60% of the legitimate URLs a realistic path (/about, /login,
        /3/tutorial/index.html, /search?q=...). A real website with a path
        is still a real website, so the label stays correct.
     3. Make 10% of the legitimate URLs use http://, as some real sites still do.
     4. Give 30% of the legitimate URLs a common subdomain (docs., mail.,
        accounts. ...), because the raw legit URLs almost never have one,
        while real sites (docs.python.org, mail.google.com) often do.

Usage:
    python prepare_real_dataset.py                 # -> data/real_urls.csv (debiased)
    python prepare_real_dataset.py --mode raw      # -> data/real_urls_raw.csv (for comparison)
"""

import argparse
import csv
import os
import random
import re

from generate_dataset import LEGIT_PATHS, fill

RAW_CSV = "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv"


def strip_www(url: str) -> str:
    return re.sub(r"^(https?://)www\.", r"\1", url, flags=re.I)


COMMON_SUBDOMAINS = ["docs", "mail", "accounts", "blog", "shop", "store", "support",
                     "help", "m", "en", "app", "news", "portal", "my", "login", "auth",
                     "learn", "dev", "api", "community", "careers", "static", "cdn"]


def realistic_path() -> str:
    """A varied path like real websites have: /3/tutorial/index.html, /mail/u/0/, /2024/05/my-post?ref=home"""
    segments = []
    for _ in range(random.randint(1, 5)):
        kind = random.random()
        if kind < 0.55:
            segments.append(fill("{w}"))
        elif kind < 0.75:
            segments.append(fill("{w}-{w}" + random.choice(["", "-{w}", "-{w}-{w}"])))
        elif kind < 0.90:
            segments.append(str(random.choice([random.randint(0, 9), random.randint(10, 9999),
                                               random.randint(100000, 99999999)])))
        else:
            segments.append(random.choice(["v1", "v2", "3", "stable", "latest", "en", "en-us",
                                           "u", "0", "2023", "2024", "2025", "static", "api"]))
    path = "/" + "/".join(segments)
    r = random.random()
    if r < 0.25:
        path += random.choice([".html", ".htm", ".php", ".aspx", ".jsp", "/index.html", "/"])
    elif r < 0.40:
        path += "/"
    if random.random() < 0.25:
        params = [fill(random.choice(["q={w}+{w}", "id={n}", "ref={w}", "page={n}", "lang=en",
                                      "utm_source={w}", "v={r}", "sort={w}", "tab={w}"]))
                  for _ in range(random.randint(1, 3))]
        path += "?" + "&".join(params)
    if random.random() < 0.05:
        path += "#" + fill("{w}")
    return path


def debias_legit(url: str) -> str:
    url = strip_www(url).rstrip("/")
    if random.random() < 0.10:
        url = re.sub(r"^https://", "http://", url)
    if random.random() < 0.30:   # real sites use subdomains like docs.python.org
        sub = random.choice(COMMON_SUBDOMAINS)
        if random.random() < 0.15:
            sub = random.choice(COMMON_SUBDOMAINS) + "." + sub
        url = re.sub(r"^(https?://)", r"\g<1>" + sub + ".", url)
    if random.random() < 0.60:
        if random.random() < 0.4:
            url += fill(random.choice([p for p in LEGIT_PATHS if p not in ("", "/")]))
        else:
            url += realistic_path()
    return url


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["debiased", "raw"], default="debiased")
    ap.add_argument("--raw-csv", default=RAW_CSV)
    args = ap.parse_args()
    random.seed(42)

    if not os.path.exists(args.raw_csv):
        raise SystemExit(
            f"{args.raw_csv} not found.\n"
            "Download the zip from https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset\n"
            "and extract PhiUSIIL_Phishing_URL_Dataset.csv into data/raw/")

    out_path = "data/real_urls.csv" if args.mode == "debiased" else "data/real_urls_raw.csv"
    seen, rows = set(), []
    with open(args.raw_csv, newline="", encoding="utf-8", errors="ignore") as fh:
        for r in csv.DictReader(fh):
            url = r["URL"].strip()
            if not url or url in seen:
                continue
            seen.add(url)
            label = 0 if r["label"].strip() == "1" else 1   # flip to our convention
            if args.mode == "debiased":
                url = debias_legit(url) if label == 0 else strip_www(url)
            rows.append((url, label))

    random.shuffle(rows)
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "label"])
        w.writerows(rows)
    legit = sum(1 for _, l in rows if l == 0)
    print(f"Saved {len(rows)} URLs to {out_path}  ({legit} legitimate, {len(rows) - legit} phishing)  mode={args.mode}")


if __name__ == "__main__":
    main()
