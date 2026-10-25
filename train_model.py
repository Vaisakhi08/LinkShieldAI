import pandas as pd
import re
import ipaddress

from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

# Load dataset
data = pd.read_csv("phishing_data.csv")


# Extract numerical features from each URL
def extract_features(url):
    url = str(url).strip()

    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    suspicious_words = [
        "login", "verify", "password",
        "banking", "account", "secure"
    ]

    return [
        len(url),
        len(hostname),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("//"),
        1 if parsed.scheme == "https" else 0,
        has_ip,
        sum(word in url.lower() for word in suspicious_words)
    ]


# Convert URLs into numerical features
X = pd.DataFrame(
    data["url"].apply(extract_features).tolist(),
    columns=[
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
)

y = data["label"]

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)

# Train the model
model = make_pipeline(
    StandardScaler(),
    LogisticRegression(max_iter=1000, random_state=42)
)

model.fit(X_train, y_train)

# Evaluate the model
predictions = model.predict(X_test)

print("Model training completed!")
print("Test accuracy:", round(accuracy_score(y_test, predictions) * 100, 2), "%")
print("\nClassification Report:")
print(classification_report(
    y_test,
    predictions,
    labels=[0, 1],
    zero_division=0
))

# Save the trained model and feature extraction function's feature list
import joblib

joblib.dump(model, "phishing_model.pkl")

print("Model saved as phishing_model.pkl")