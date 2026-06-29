#!/usr/bin/env python3
"""
quick_check_small.py (robust)
Sample 1% (min 10 rows) and show ACTUAL vs PREDICTED.
If best_model.joblib is corrupt/partial, it will fall back to best_model_plain + tfidf.
Saves CSV for screenshots: sample_small_output.csv
"""
import os, sys, math, json, traceback
import pandas as pd
import numpy as np
import joblib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "ml_dataset_cleaned_fast.csv"
MODELS = ROOT / "models"
BEST = MODELS / "best_model.joblib"
PLAIN = MODELS / "best_model_plain.joblib"
TFIDF = MODELS / "tfidf.joblib"
OUTCSV = ROOT / "sample_small_output.csv"

def show_model_dir_info():
    print("\n[models dir listing]")
    try:
        for p in sorted(MODELS.glob("*")):
            try:
                size = p.stat().st_size
            except Exception:
                size = 0
            print(f" - {p.name:30}  exists={p.exists():5}  size={size:,} bytes")
    except Exception as e:
        print("Could not list models dir:", e)

# ------------------------- LOAD MODEL -------------------------
def load_pipeline_model():
    """Try to load full pipeline first. Raise exceptions to allow fallback."""
    # joblib may raise EOFError/pickle errors if file corrupt
    print(f"[model] Attempting to load pipeline: {BEST}")
    obj = joblib.load(str(BEST))
    print("[model] Pipeline loaded successfully.")
    return obj

def load_plain_plus_tfidf():
    """Load plain estimator + tfidf separately and return a dict-style model."""
    print(f"[model] Attempting to load plain estimator: {PLAIN} + {TFIDF}")
    clf = joblib.load(str(PLAIN))
    tf = joblib.load(str(TFIDF))
    print("[model] plain estimator + tfidf loaded successfully.")
    return {"clf": clf, "tfidf": tf}

def load_model_with_fallback():
    # prefer full pipeline
    show_model_dir_info()
    if BEST.exists():
        try:
            return load_pipeline_model()
        except Exception as e:
            print("[warn] Failed loading pipeline (will attempt plain+tfidf):", type(e).__name__, str(e))
            traceback.print_exc(limit=1)
    # fallback
    if PLAIN.exists() and TFIDF.exists():
        try:
            return load_plain_plus_tfidf()
        except Exception as e:
            print("[error] Failed loading plain+tfidf:", type(e).__name__, str(e))
            traceback.print_exc(limit=1)
    raise RuntimeError("No usable model found. Either best_model.joblib is corrupt or plain+tfidf missing.")

# ------------------------- PREDICT -------------------------
def run_prediction(model, texts, numeric_df=None):
    """Handles both pipeline models and (tfidf + clf) models."""
    # plain dict path
    if isinstance(model, dict):
        tf = model.get("tfidf")
        clf = model.get("clf")
        if tf is None or clf is None:
            raise RuntimeError("Plain model dict is missing tfidf or clf")
        X = tf.transform(texts)
        try:
            return clf.predict(X)
        except Exception:
            # some classifiers may not accept sparse -> convert to dense
            return clf.predict(X.toarray())

    # pipeline path
    try:
        # try passing DataFrame with text column (works if pipeline uses ColumnTransformer)
        df_in = pd.DataFrame({"description_text": texts})
        if numeric_df is not None:
            for c in numeric_df.columns:
                # align lengths
                df_in[c] = numeric_df[c].values[:len(df_in)]
        return model.predict(df_in)
    except Exception:
        # last resort: pass raw text list (works if pipeline is simple tfidf->estimator)
        try:
            return model.predict(texts)
        except Exception as e:
            raise RuntimeError("Model prediction failed with both DataFrame and raw-text inputs: " + str(e))

# ------------------------- MAIN -------------------------
def main():
    if not DATA.exists():
        print("❌ CSV missing:", DATA)
        sys.exit(1)

    df = pd.read_csv(DATA, low_memory=False)
    df = df.dropna(subset=["description_text"])
    n = len(df)
    sample_n = max(10, math.ceil(n * 0.01))  # 1% OR min 10 rows
    sample = df.sample(sample_n, random_state=42).reset_index(drop=True)

    texts = sample["description_text"].astype(str).tolist()

    # pick numeric columns if present
    numeric_cols = [
        c for c in ["cvss_score", "references_count", "weaknesses_count",
                    "os_count", "years_since_published", "severity_num"]
        if c in sample.columns
    ]
    numeric_df = sample[numeric_cols] if numeric_cols else None

    # actual values (prefer predicted_score)
    if "predicted_score" in sample.columns:
        actual = pd.to_numeric(sample["predicted_score"], errors="coerce").fillna(0.0).values
    else:
        actual = pd.to_numeric(sample["cvss_score"], errors="coerce").fillna(0.0).values

    try:
        model = load_model_with_fallback()
    except Exception as e:
        print("\n🚨 Could not load any model:", e)
        print("Recommendation:\n - If best_model.joblib is corrupted, re-run training to regenerate files.")
        print("Quick dev retrain (use small sample to be fast):")
        print("  TRAIN_SAMPLE_FRAC=0.05 python train_risk_model.py")
        print("Or run full training:")
        print("  python train_risk_model.py")
        sys.exit(2)

    try:
        preds = run_prediction(model, texts, numeric_df=numeric_df)
    except Exception as e:
        print("❌ Prediction failed:", type(e).__name__, e)
        traceback.print_exc(limit=1)
        sys.exit(3)

    # prepare output table
    rows = []
    for i, (t, a, p) in enumerate(zip(texts, actual, preds)):
        short = t[:200] + ("..." if len(t) > 200 else "")
        try:
            pval = float(p)
        except Exception:
            pval = float(np.nan)
        rows.append({
            "index": i,
            "actual": float(a),
            "predicted": float(pval),
            "diff": float(pval) - float(a),
            "text": short
        })

    outdf = pd.DataFrame(rows)
    outdf.to_csv(OUTCSV, index=False)

    print("\n================ SAMPLE (1%) RESULTS ================")
    print(outdf.to_string(index=False, max_colwidth=160))
    print("\nSaved CSV →", OUTCSV)
    print("=====================================================\n")

    print("Example JSON for frontend (first row):")
    print(json.dumps(rows[0], indent=2))

if __name__ == "__main__":
    main()