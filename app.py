from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse
import pandas as pd
import ipaddress
import joblib
import sqlite3
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Load the trained Machine Learning model
model = joblib.load("phishing_model.pkl")

# Database file name
DATABASE = "linkshield.db"

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "dot_count",
    "hyphen_count",
    "at_count",
    "slash_count",
    "uses_https",
    "has_ip",
    "suspicious_word_count"
]

SUSPICIOUS_WORDS = [
    "login", "verify", "password",
    "banking", "account", "secure"
]


# ---------------------------------
# DATABASE CONNECTION
# ---------------------------------

def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


# ---------------------------------
# CREATE DATABASE TABLE
# ---------------------------------

def create_table():
    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            status TEXT NOT NULL,
            risk TEXT NOT NULL,
            score INTEGER NOT NULL,
            reasons TEXT,
            recommendation TEXT,
            scanned_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


# ---------------------------------
# SAVE SCAN RESULT TO DATABASE
# ---------------------------------

def save_scan(url, result):
    connection = get_db_connection()

    connection.execute("""
        INSERT INTO scan_history (
            url,
            status,
            risk,
            score,
            reasons,
            recommendation,
            scanned_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        result["status"],
        result["risk"],
        result["score"],
        json.dumps(result["reasons"]),
        result["recommendation"],
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()


# ---------------------------------
# EXTRACT URL FEATURES
# ---------------------------------

def extract_features(url):
    url = url.strip()

    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    return [
        len(url),
        len(hostname),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("//"),
        1 if parsed.scheme == "https" else 0,
        has_ip,
        sum(
            word in url.lower()
            for word in SUSPICIOUS_WORDS
        )
    ]


# ---------------------------------
# MACHINE LEARNING URL ANALYSIS
# ---------------------------------

def check_url(url):
    url = url.strip()

    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)

    if (
        parsed.scheme not in ["http", "https"]
        or not parsed.hostname
    ):
        return {
            "status": "Invalid URL",
            "risk": "Unknown",
            "score": 0,
            "reasons": [
                "Enter a valid HTTP or HTTPS URL."
            ],
            "recommendation": (
                "Check the URL and try again."
            )
        }

    features = extract_features(url)

    feature_data = pd.DataFrame(
        [features],
        columns=FEATURE_NAMES
    )

    # Predict using the trained ML model
    prediction = int(model.predict(feature_data)[0])

    probabilities = model.predict_proba(feature_data)[0]

    phishing_index = list(model.classes_).index(1)

    score = round(
        float(probabilities[phishing_index]) * 100
    )

    reasons = []

    if parsed.scheme != "https":
        reasons.append(
            "The URL does not use HTTPS."
        )

    hostname = parsed.hostname.lower()

    try:
        ipaddress.ip_address(hostname)

        reasons.append(
            "The URL uses an IP address instead of a domain name."
        )

    except ValueError:
        pass

    found_words = [
        word for word in SUSPICIOUS_WORDS
        if word in url.lower()
    ]

    if found_words:
        reasons.append(
            "Potentially suspicious keywords: "
            + ", ".join(found_words)
        )

    if prediction == 1:
        risk = "High"
        status = "Potential Phishing URL"

        recommendation = (
            "Avoid entering personal information. "
            "Verify the address using the organisation's "
            "official website."
        )

    else:
        risk = "Low"
        status = "No Phishing Pattern Predicted"

        recommendation = (
            "This demo model did not predict phishing. "
            "This does not guarantee that the website is safe."
        )

    if not reasons:
        reasons.append(
            "No listed warning signs were found by the basic checks."
        )

    return {
        "status": status,
        "risk": risk,
        "score": score,
        "reasons": reasons,
        "recommendation": recommendation
    }


# ---------------------------------
# HOME PAGE
# ---------------------------------

@app.route("/")
def home():
    return "LinkShield AI ML Backend is Running!"


# ---------------------------------
# SCAN URL AND SAVE TO DATABASE
# ---------------------------------

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}

    url = data.get("url", "")

    if not isinstance(url, str) or not url.strip():
        return jsonify({
            "error": "Please enter a valid URL."
        }), 400

    url = url.strip()

    try:
        result = check_url(url)

        # Save the scan result to SQLite
        if result["risk"] != "Unknown":
            save_scan(url, result)

        return jsonify(result)

    except Exception:
        app.logger.exception("URL scan failed")

        return jsonify({
            "error": "Unable to analyse this URL."
        }), 500


# ---------------------------------
# VIEW SCAN HISTORY FROM DATABASE
# ---------------------------------

@app.route("/history", methods=["GET"])
def history():
    connection = get_db_connection()

    rows = connection.execute("""
        SELECT *
        FROM scan_history
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    history_data = []

    for row in rows:
        history_data.append({
            "id": row["id"],
            "url": row["url"],
            "status": row["status"],
            "risk": row["risk"],
            "score": row["score"],
            "reasons": json.loads(row["reasons"]),
            "recommendation": row["recommendation"],
            "scanned_at": row["scanned_at"]
        })

    return jsonify(history_data)


# ---------------------------------
# START APPLICATION
# ---------------------------------

@app.route("/clear-history", methods=["DELETE"])
def clear_history():
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM scan_history")
        conn.commit()
        conn.close()

        return {"message": "Scan history cleared successfully"}, 200

    except Exception as e:
        return {"error": str(e)}, 500

if __name__ == "__main__":
    create_table()

    print("LinkShield AI database connected successfully!")

    app.run(debug=True)