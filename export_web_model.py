"""
export_web_model.py - Builds the compact model used by the live browser demo (docs/).

The full model (model/phishing_model.joblib, 150 deep trees, ~33 MB) is too big to
download in a web page. This script trains a smaller Random Forest on the SAME
debiased dataset and train/test split, measures it honestly, and exports it to
docs/model.json so docs/phishguard.js can run it entirely in the browser.

Usage:
    python export_web_model.py                 # train, compare, export
    python export_web_model.py --trees 40 --depth 12
"""

import argparse
import json
import os
import time

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

import features as F
from predict import OFFICIAL_DOMAINS
from train import REAL_WORLD_CHECK, load_dataset


def export_tree(est):
    """Flatten one sklearn decision tree into compact arrays."""
    t = est.tree_
    feat, thr, left, right, prob = [], [], [], [], []
    for i in range(t.node_count):
        is_leaf = t.children_left[i] == -1
        feat.append(-1 if is_leaf else int(t.feature[i]))
        thr.append(0 if is_leaf else float(t.threshold[i]))
        left.append(int(t.children_left[i]))
        right.append(int(t.children_right[i]))
        v = t.value[i][0]
        prob.append(round(float(v[1] / v.sum()), 5) if is_leaf else 0)
    return {"f": feat, "t": thr, "l": left, "r": right, "p": prob}


def with_allowlist(urls, probs):
    """Apply the same official-domain allowlist as predict.py (risk capped at 5%)."""
    out = []
    for u, p in zip(urls, probs):
        host = (F.urlparse(F.normalize(u)).hostname or "").lower()
        out.append(min(p, 0.05) if F.registered_domain(host) in OFFICIAL_DOMAINS else p)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/real_urls.csv")
    ap.add_argument("--trees", type=int, default=40)
    ap.add_argument("--depth", type=int, default=12)
    ap.add_argument("--out", default="docs/model.json")
    ap.add_argument("--fixture", default=None, help="also write a JS/Python parity test file here")
    args = ap.parse_args()

    urls, y = load_dataset(args.data)
    X = [F.extract_features(u) for u in urls]
    idx = list(range(len(urls)))
    i_train, i_test = train_test_split(idx, test_size=0.2, random_state=42, stratify=y)
    X_train = [X[i] for i in i_train]; y_train = [y[i] for i in i_train]
    X_test = [X[i] for i in i_test]; y_test = [y[i] for i in i_test]

    start = time.time()
    model = RandomForestClassifier(n_estimators=args.trees, max_depth=args.depth,
                                   min_samples_leaf=3, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    metrics = {
        "accuracy": round(accuracy_score(y_test, pred) * 100, 2),
        "precision": round(precision_score(y_test, pred) * 100, 2),
        "recall": round(recall_score(y_test, pred) * 100, 2),
        "f1": round(f1_score(y_test, pred) * 100, 2),
        "test_size": len(y_test),
        "dataset_size": len(urls),
    }

    rw_urls = [u for u, _ in REAL_WORLD_CHECK]
    rw_prob = with_allowlist(rw_urls, model.predict_proba([F.extract_features(u) for u in rw_urls])[:, 1])
    rw_correct = sum(int((p >= 0.4) == bool(l)) for p, (_, l) in zip(rw_prob, REAL_WORLD_CHECK))
    metrics["real_world_check"] = f"{rw_correct}/{len(REAL_WORLD_CHECK)}"

    bundle = {
        "model": f"Random Forest ({args.trees} trees, depth {args.depth})",
        "metrics": metrics,
        "feature_names": F.FEATURE_NAMES,
        "lists": {
            "suspicious_words": F.SUSPICIOUS_WORDS,
            "brands": F.BRANDS,
            "suspicious_tlds": sorted(F.SUSPICIOUS_TLDS),
            "url_shorteners": sorted(F.URL_SHORTENERS),
            "second_level": sorted(F._SECOND_LEVEL),
        },
        "trees": [export_tree(e) for e in model.estimators_],
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as fh:
        json.dump(bundle, fh, separators=(",", ":"))

    nodes = sum(e.tree_.node_count for e in model.estimators_)
    print(f"Trees={args.trees} depth={args.depth}  nodes={nodes}  "
          f"size={os.path.getsize(args.out) / 1e6:.2f} MB  time={time.time() - start:.1f}s")
    print(f"Accuracy {metrics['accuracy']}%  Precision {metrics['precision']}%  "
          f"Recall {metrics['recall']}%  F1 {metrics['f1']}%  Real-world {metrics['real_world_check']}")

    if args.fixture:
        # Parity test: the browser must produce the same features and probabilities
        sample = [urls[i] for i in i_test[:3000]] + rw_urls + [
            "paypal.com.verify-account.xyz/login", "http://user:pass@1.2.3.4:99999/x;p?a=1&b=2#f",
            "https://xn--pple-43d.com/", "https://WWW.Example.CO.UK/Path", "https://bit.ly/abc",
            "http://a.b.c.d.e.example.com//redirect?x=%20", "https://münchen.de/straße", "ftp://files.example.org",
            "https://amaz0n-billing.top/confirm", "https://rnicrosoft-support.com/reset", "",
        ]
        feats = [F.extract_features(u) for u in sample]
        model.set_params(n_jobs=1)
        probs = model.predict_proba(feats)[:, 1]
        fx = [{"url": u, "f": f, "p": float(p)} for u, f, p in zip(sample, feats, probs)]
        with open(args.fixture, "w", encoding="utf-8") as fh:
            json.dump(fx, fh, ensure_ascii=False)
        print(f"Wrote parity fixture with {len(fx)} URLs to {args.fixture}")


if __name__ == "__main__":
    main()
