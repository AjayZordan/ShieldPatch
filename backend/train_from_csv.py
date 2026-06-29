# train_from_csv.py
# Trains a TF-IDF -> classifier pipeline from your CSV.
# If a real label with >=2 classes is available it trains LogisticRegression(random_state=42).
# Otherwise it trains a DummyClassifier that always predicts the most frequent class
# (this is only to produce loadable .joblib files and keep the backend working).

import os
import sys
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.dummy import DummyClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report

CSV_PATH = "combined_vulnerabilities_fixed.csv"
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

candidates = [
    "description", "summary", "vulnerability", "vuln_description",
    "cve_description", "details", "text", "long_description"
]

print("Loading CSV:", CSV_PATH)
if not os.path.exists(CSV_PATH):
    print("CSV not found at", CSV_PATH)
    sys.exit(1)

df = pd.read_csv(CSV_PATH, low_memory=False)
print("CSV loaded, shape:", df.shape)

# choose text column
text_col = None
for c in candidates:
    if c in df.columns:
        non_null = df[c].astype(str).str.strip()
        if non_null.dropna().map(bool).any():
            text_col = c
            break

if text_col is None:
    for c in df.select_dtypes(include=["object"]).columns:
        if df[c].astype(str).str.strip().dropna().map(bool).any():
            text_col = c
            break

if text_col is None:
    print("Could not find a suitable text column. Columns:", list(df.columns))
    sys.exit(1)

print("Using text column:", text_col)

# detect label column
label_candidates = ["label", "target", "severity", "risk", "class"]
label_col = None
for c in label_candidates:
    if c in df.columns:
        label_col = c
        break

# if severity numeric, bucket it
if label_col is None and "severity" in df.columns:
    try:
        df["__label__"] = pd.cut(df["severity"].astype(float), bins=3, labels=["low","medium","high"])
        label_col = "__label__"
    except Exception:
        label_col = None

# fallback: try again to find any non-empty object column that looks like a label (small cardinality)
if label_col is None:
    for c in df.select_dtypes(exclude=["number"]).columns:
        unique_vals = df[c].dropna().astype(str).str.strip()
        if len(unique_vals.unique()) > 1 and len(unique_vals.unique()) < max(50, len(df)//2):
            label_col = c
            break

# as last resort create dummy presence-of-cve label
if label_col is None:
    print("No clear label column found. Creating dummy binary label based on 'cve' presence.")
    df["__label__"] = df.get("cve_id", df.get("CVE", df.get("cve", None)))
    if df["__label__"].isnull().all():
        # if still null, mark everything 1 (we'll handle single class below)
        df["__label__"] = 1
    else:
        df["__label__"] = df["__label__"].notna().astype(int)
    label_col = "__label__"

print("Using label column:", label_col)

X = df[text_col].fillna("").astype(str)
y = df[label_col]
if y.dtype == object or y.dtype.name == "category":
    y = y.astype(str)

# ensure at least 1 sample in train/test if small dataset
stratify = y if len(set(y)) > 1 and len(y) > 1 else None
test_size = 0.12 if len(y) > 10 else 0.2

try:
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=stratify)
except Exception:
    # fallback: simple split
    split_at = int(len(X) * (1 - test_size))
    X_train, X_test = X[:split_at], X[split_at:]
    y_train, y_test = y[:split_at], y[split_at:]

print("Train/test sizes:", X_train.shape, X_test.shape)

# build pipeline common part
tfidf = TfidfVectorizer(max_features=20000, ngram_range=(1,2))

# decide estimator depending on number of classes
unique_labels = set(y_train.astype(str).unique())
print("Unique labels in training set:", unique_labels)

if len(unique_labels) >= 2:
    print("Training LogisticRegression (random_state=42)")
    estimator = LogisticRegression(max_iter=300, solver="lbfgs", random_state=42)
else:
    print("Only one class detected — training DummyClassifier(most_frequent).")
    estimator = DummyClassifier(strategy="most_frequent")

pipeline = Pipeline([
    ("tfidf", tfidf),
    ("clf", estimator)
])

print("Training pipeline...")
pipeline.fit(X_train, y_train)
print("Training done.")

# quick eval if possible
try:
    if len(set(y_test)) > 1:
        preds = pipeline.predict(X_test)
        print("Quick eval:")
        print(classification_report(y_test, preds))
except Exception:
    pass

# save
full_path = os.path.join(MODEL_DIR, "best_model.joblib")
plain_path = os.path.join(MODEL_DIR, "best_model_plain.joblib")
joblib.dump(pipeline, full_path, protocol=4)
try:
    # if classifier has named step 'clf' we try to save the plain estimator
    joblib.dump(pipeline.named_steps["clf"], plain_path, protocol=4)
except Exception:
    pass

print("Saved:", full_path, plain_path)