#!/usr/bin/env python3
"""
FINAL & STABLE TRAINING SCRIPT
Text + Numeric → CVSS Score Prediction
"""

from pathlib import Path
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, mean_absolute_error
from sklearn.linear_model import Ridge

# --------------------------------------------------
# Paths
# --------------------------------------------------
ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data/final/cve_dataset_ml_ready.csv"
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)

MODEL_PATH = MODEL_DIR / "best_model.joblib"
RANDOM_STATE = 42

# --------------------------------------------------
# Load dataset
# --------------------------------------------------
print("[data] loading dataset")
df = pd.read_csv(
    DATA_PATH,
    engine="python",
    on_bad_lines="skip"
)

# --------------------------------------------------
# Required columns
# --------------------------------------------------
TEXT_COL = "description_text"
NUM_COLS = [
    "references_count",
    "weaknesses_count",
    "os_count",
    "years_since_published"
]
TARGET = "cvss_score"

# --------------------------------------------------
# Safety cleaning (FINAL)
# --------------------------------------------------
df[TEXT_COL] = (
    df[TEXT_COL]
    .fillna("no_description_available")
    .astype(str)
    .str.strip()
)

# 🔥 EXTRA SAFETY: guarantee non-empty text
df.loc[df[TEXT_COL] == "", TEXT_COL] = "no_description_available"

for c in NUM_COLS + [TARGET]:
    df[c] = pd.to_numeric(df[c], errors="coerce")

df = df[df[TARGET].notna()]

print("[data] rows after cleaning:", len(df))

# --------------------------------------------------
# Features / Target
# --------------------------------------------------
X = df[[TEXT_COL] + NUM_COLS]
y = df[TARGET]

# --------------------------------------------------
# Train / Test split
# --------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.15,
    random_state=RANDOM_STATE
)

print(f"[split] train={len(X_train)} test={len(X_test)}")

# --------------------------------------------------
# Preprocessing
# --------------------------------------------------
preprocessor = ColumnTransformer(
    transformers=[
        (
            "text",
            TfidfVectorizer(
                max_features=30000,
                ngram_range=(1, 2),
                min_df=2,
                stop_words="english",
                lowercase=True,
                token_pattern=r"(?u)\b\w+\b"  # 🔥 CRITICAL FIX
            ),
            TEXT_COL
        ),
        ("num", StandardScaler(), NUM_COLS)
    ]
)

# --------------------------------------------------
# Model
# --------------------------------------------------
model = Ridge(
    alpha=1.0,
    random_state=RANDOM_STATE
)

pipeline = Pipeline([
    ("preprocessor", preprocessor),
    ("model", model)
])

# --------------------------------------------------
# Train
# --------------------------------------------------
print("[train] training FINAL model (TEXT + NUMERIC)")
pipeline.fit(X_train, y_train)

# --------------------------------------------------
# Evaluate
# --------------------------------------------------
preds = pipeline.predict(X_test)

rmse = np.sqrt(mean_squared_error(y_test, preds))
mae = mean_absolute_error(y_test, preds)

print(f"[eval] RMSE = {rmse:.3f}")
print(f"[eval] MAE  = {mae:.3f}")

# --------------------------------------------------
# Save
# --------------------------------------------------
joblib.dump(pipeline, MODEL_PATH, compress=3)

print(f"[save] model saved → {MODEL_PATH}")
print("[done] FINAL TRAINING COMPLETED")