"""
train.py - Trains and compares machine-learning models for phishing detection.

Steps:
  1. Load URLs from a CSV file (columns: url, label)
  2. Convert every URL into numeric features (features.py)
  3. Split into 80% training / 20% testing data
  4. Train 3 models and compare them:
        - Logistic Regression  (simple baseline)
        - Decision Tree        (easy to explain)
        - Random Forest        (many trees voting - usually best)
  5. Save the best model to model/phishing_model.joblib

Usage:
    python train.py                         # uses data/urls.csv
    python train.py --data my_dataset.csv   # use your own / a real dataset
"""

import argparse
import csv
import json
import os
import time

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from features import FEATURE_NAMES, extract_features

# Real-world check: everyday URLs the model must get right.
# Legitimate ones are real links people actually visit (many with paths like /login).
# Phishing ones follow common attack patterns (domains are made up).
REAL_WORLD_CHECK = [
    ("https://github.com/login", 0),
    ("https://accounts.google.com/signin/v2/identifier", 0),
    ("https://www.amazon.in/dp/B0CHX1W1XY", 0),
    ("https://www.flipkart.com/search?q=laptop", 0),
    ("https://en.wikipedia.org/wiki/Phishing", 0),
    ("https://stackoverflow.com/questions/231767/what-does-the-yield-keyword-do", 0),
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", 0),
    ("https://docs.python.org/3/tutorial/index.html", 0),
    ("https://www.paypal.com/signin", 0),
    ("https://www.linkedin.com/in/some-student-123", 0),
    ("https://mail.google.com/mail/u/0/#inbox", 0),
    ("https://www.onlinesbi.sbi/", 0),
    ("https://www.irctc.co.in/nget/train-search", 0),
    ("https://www.netflix.com/browse", 0),
    ("https://scikit-learn.org/stable/modules/ensemble.html", 0),
    ("http://paypal.com.verify-account.xyz/signin", 1),
    ("http://192.168.45.10:8080/sbi/kyc-update.php", 1),
    ("https://amaz0n-billing.top/confirm", 1),
    ("https://rnicrosoft-support.com/reset", 1),
    ("https://netflix-account-suspended.com/update", 1),
    ("https://hdfcbank-netbanking-verify.in/login", 1),
    ("http://secure-login-apple-id.cf/verify?session=8f7a6d5c4b3a", 1),
    ("https://fb-restriction-appeal-552901.firebaseapp.com/", 1),
    ("http://wallet-connect-claim-bonus.xyz/", 1),
    ("https://office365-mail-auth.web.app/login.html", 1),
    ("http://instagram-copyright-help.ml/form", 1),
    ("https://kyc-paytm-update.online/", 1),
    ("http://usps-redelivery-fee.top/track", 1),
    ("https://binance-airdrop-claim.site/connect", 1),
    ("http://whatsapp-gold-download.tk/", 1),
]

LABEL_WORDS = {"0": 0, "1": 1, "good": 0, "benign": 0, "legitimate": 0, "safe": 0,
               "bad": 1, "phishing": 1, "malicious": 1, "defacement": 1}


def load_dataset(path):
    """Read url,label rows. Labels can be 0/1 or words like 'phishing'/'benign'."""
    urls, labels = [], []
    with open(path, newline="", encoding="utf-8", errors="ignore") as fh:
        reader = csv.DictReader(fh)
        cols = {c.lower(): c for c in reader.fieldnames}
        url_col = cols.get("url")
        label_col = cols.get("label") or cols.get("type") or cols.get("status")
        if not url_col or not label_col:
            raise SystemExit(f"CSV needs a 'url' column and a 'label' column. Found: {reader.fieldnames}")
        for row in reader:
            label = LABEL_WORDS.get(str(row[label_col]).strip().lower())
            if label is None or not row[url_col]:
                continue
            urls.append(row[url_col])
            labels.append(label)
    return urls, labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/real_urls.csv" if os.path.exists("data/real_urls.csv") else "data/urls.csv")
    ap.add_argument("--model-dir", default="model")
    args = ap.parse_args()

    if not os.path.exists(args.data):
        raise SystemExit(f"{args.data} not found. Run:  python generate_dataset.py")

    print(f"[1/4] Loading dataset: {args.data}")
    urls, y = load_dataset(args.data)
    print(f"      {len(urls)} URLs  ({y.count(0)} legitimate, {y.count(1)} phishing)")

    print(f"[2/4] Extracting {len(FEATURE_NAMES)} features from each URL ...")
    X = [extract_features(u) for u in urls]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    models = {
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
        "Decision Tree": DecisionTreeClassifier(max_depth=10, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=150, min_samples_leaf=3,
                                                random_state=42, n_jobs=-1),
    }

    print("[3/4] Training and comparing models ...\n")
    print(f"      {'Model':<22}{'Accuracy':>10}{'Precision':>11}{'Recall':>9}{'F1':>8}{'Time':>9}")
    print("      " + "-" * 69)
    results = {}
    for name, model in models.items():
        start = time.time()
        model.fit(X_train, y_train)
        pred = model.predict(X_test)
        results[name] = {
            "accuracy": accuracy_score(y_test, pred),
            "precision": precision_score(y_test, pred),
            "recall": recall_score(y_test, pred),
            "f1": f1_score(y_test, pred),
            "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
        }
        r = results[name]
        print(f"      {name:<22}{r['accuracy']:>10.2%}{r['precision']:>11.2%}{r['recall']:>9.2%}"
              f"{r['f1']:>8.2%}{time.time() - start:>8.2f}s")

    best_name = max(results, key=lambda n: results[n]["f1"])
    best = models[best_name]
    cm = results[best_name]["confusion_matrix"]
    print(f"\n      Best model: {best_name}")
    print("      Confusion matrix (test set):")
    print("                         Predicted SAFE   Predicted PHISHING")
    print(f"      Actually SAFE      {cm[0][0]:>12}   {cm[0][1]:>16}")
    print(f"      Actually PHISHING  {cm[1][0]:>12}   {cm[1][1]:>16}")

    if hasattr(best, "feature_importances_"):
        print("\n      Most important features:")
        ranked = sorted(zip(FEATURE_NAMES, best.feature_importances_), key=lambda t: -t[1])
        for fname, imp in ranked[:8]:
            print(f"        {fname:<24} {'#' * int(imp * 100):<30} {imp:.3f}")

    # Real-world check: catches "shortcut learning" that a normal test split cannot see
    rw_pred = best.predict([extract_features(u) for u, _ in REAL_WORLD_CHECK])
    rw_correct = sum(int(p == l) for p, (_, l) in zip(rw_pred, REAL_WORLD_CHECK))
    rw_fp = [u for p, (u, l) in zip(rw_pred, REAL_WORLD_CHECK) if l == 0 and p == 1]
    rw_fn = [u for p, (u, l) in zip(rw_pred, REAL_WORLD_CHECK) if l == 1 and p == 0]
    print(f"\n      Real-world check: {rw_correct}/{len(REAL_WORLD_CHECK)} correct")
    for u in rw_fp:
        print(f"        FALSE ALARM  (safe site flagged as phishing): {u}")
    for u in rw_fn:
        print(f"        MISSED       (phishing marked as safe):       {u}")

    print("\n[4/4] Saving model ...")
    os.makedirs(args.model_dir, exist_ok=True)
    model_path = os.path.join(args.model_dir, "phishing_model.joblib")
    joblib.dump({"model": best, "model_name": best_name, "features": FEATURE_NAMES},
                model_path, compress=3)
    with open(os.path.join(args.model_dir, "metrics.json"), "w") as fh:
        json.dump({"best_model": best_name, "dataset": args.data,
                   "train_size": len(X_train), "test_size": len(X_test),
                   "results": results,
                   "real_world_check": {"correct": rw_correct, "total": len(REAL_WORLD_CHECK),
                                        "false_alarms": rw_fp, "missed": rw_fn}}, fh, indent=2)
    print(f"      Saved {model_path} ({os.path.getsize(model_path) / 1e6:.1f} MB) and metrics.json")
    print("\nDone! Next:  python app.py   (then open http://127.0.0.1:5000)")


if __name__ == "__main__":
    main()
