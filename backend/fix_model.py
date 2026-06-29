# fix_model.py
import joblib
import os
import traceback

# --- Shim: recreate clean_text function so joblib can unpickle ---
def clean_text(x):
    try:
        return x.lower()
    except Exception:
        return x

# Path to your model
FULL_MODEL = "/Users/ajaykumar/Desktop/ShieldPatch/backend/models/best_model.joblib"
PLAIN_MODEL = "/Users/ajaykumar/Desktop/ShieldPatch/backend/models/best_model_plain.joblib"

print("Loading:", FULL_MODEL)

try:
    obj = joblib.load(FULL_MODEL)

    # find estimator inside dict
    def find_estimator(o):
        if hasattr(o, "predict"):
            return o
        if isinstance(o, dict):
            for k in ("model", "estimator", "pipeline", "clf", "classifier", "pipe"):
                if k in o and hasattr(o[k], "predict"):
                    return o[k]
            # fallback
            for v in o.values():
                if hasattr(v, "predict"):
                    return v
        return None

    est = find_estimator(obj)

    if est is None:
        print("❌ Could not find estimator inside the saved model.")
        print("Keys:", list(obj.keys()) if isinstance(obj, dict) else "(not a dict)")
    else:
        joblib.dump(est, PLAIN_MODEL, compress=3)
        print("\n✅ Saved plain estimator to:", PLAIN_MODEL)
        print("Estimator type:", type(est).__name__)
        print("Has predict:", hasattr(est, "predict"))

except Exception as e:
    print("❌ Failed to load/save model")
    traceback.print_exc()