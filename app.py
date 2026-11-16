"""
app.py - Web interface for the Phishing URL Detector.

Run:
    python app.py
Then open http://127.0.0.1:5000 in your browser.

Endpoints:
    GET  /            - web page
    POST /api/check   - JSON API:  {"url": "..."}  ->  verdict, risk, reasons
    GET  /api/stats   - model accuracy and recent checks
"""

import json
import os
from collections import deque
from datetime import datetime

from flask import Flask, jsonify, render_template, request

from predict import analyze, load_model

app = Flask(__name__)
HISTORY = deque(maxlen=10)   # last 10 checks (kept in memory only)
METRICS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model", "metrics.json")


def model_metrics():
    try:
        with open(METRICS_PATH) as fh:
            m = json.load(fh)
        best = m["results"][m["best_model"]]
        return {"model": m["best_model"], "accuracy": round(best["accuracy"] * 100, 2),
                "precision": round(best["precision"] * 100, 2),
                "recall": round(best["recall"] * 100, 2),
                "trained_on": m["train_size"] + m["test_size"]}
    except (OSError, KeyError, ValueError):
        return None


@app.route("/")
def index():
    return render_template("index.html", metrics=model_metrics())


@app.post("/api/check")
def check():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()
    if not url:
        return jsonify({"error": "Please enter a URL"}), 400
    if len(url) > 2000:
        return jsonify({"error": "URL is too long (max 2000 characters)"}), 400
    result = analyze(url)
    HISTORY.appendleft({"url": result["url"], "verdict": result["verdict"],
                        "risk": result["risk"], "time": datetime.now().strftime("%H:%M:%S")})
    result["history"] = list(HISTORY)
    return jsonify(result)


@app.get("/api/stats")
def stats():
    return jsonify({"metrics": model_metrics(), "history": list(HISTORY)})


if __name__ == "__main__":
    load_model()  # fail early with a helpful message if the model is missing
    print("Phishing URL Detector running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
