# extract_components.py
import os, joblib, json, traceback, sys

# ---- Ensure any helper names used at pickle time are available in __main__ ----
# If you have a shim train.py in the backend folder that defines clean_text (and any other helpers),
# import it and inject its names into __main__ so pickle can find them.
try:
    import train  # your shim: backend/train.py
    # inject names referenced by the pickle into __main__
    main_mod = sys.modules.get("__main__")
    if main_mod is not None:
        if hasattr(train, "clean_text"):
            setattr(main_mod, "clean_text", train.clean_text)
        # add additional injected names here if pickle complains later:
        # if hasattr(train, "other_helper"): setattr(main_mod, "other_helper", train.other_helper)
except Exception:
    # If train.py missing, we continue — joblib.load may still fail but we'll show clear error.
    pass
# ------------------------------------------------------------------------------

BASE = os.path.expanduser("~/Desktop/ShieldPatch/backend/models")
FULL = os.path.join(BASE, "best_model.joblib")
OUT_TFIDF = os.path.join(BASE, "tfidf.joblib")
OUT_PRE = os.path.join(BASE, "preprocessor.joblib")
OUT_MODEL_PLAIN = os.path.join(BASE, "best_model_plain.joblib")
OUT_META = os.path.join(BASE, "model_meta.json")

print("FULL PATH:", FULL)
if not os.path.exists(FULL):
    raise SystemExit("Full payload not found at: " + FULL)

try:
    obj = joblib.load(FULL)
except Exception:
    print("Failed to load full payload. Traceback:")
    traceback.print_exc()
    raise

meta = {}
if isinstance(obj, dict):
    meta["keys"] = list(obj.keys())
    est = None
    for k in ("model","estimator","pipeline","clf","classifier","pipe"):
        if k in obj and hasattr(obj[k], "predict"):
            est = obj[k]
            meta["estimator_key"] = k
            break
    if est is None:
        for k,v in obj.items():
            if hasattr(v, "predict"):
                est = v
                meta["estimator_key"] = k
                break

    if "tfidf" in obj and obj["tfidf"] is not None:
        joblib.dump(obj["tfidf"], OUT_TFIDF, compress=3)
        print("Saved tfidf ->", OUT_TFIDF)
        meta["tfidf_saved"] = True
    else:
        meta["tfidf_saved"] = False

    if "preprocessor" in obj and obj["preprocessor"] is not None:
        joblib.dump(obj["preprocessor"], OUT_PRE, compress=3)
        print("Saved preprocessor ->", OUT_PRE)
        meta["preprocessor_saved"] = True
    else:
        meta["preprocessor_saved"] = False

    for k in ("numeric_cols","cat_cols","text_col","model_name"):
        if k in obj:
            meta[k] = obj[k]

    if est is not None:
        joblib.dump(est, OUT_MODEL_PLAIN, compress=3)
        print("Saved plain estimator ->", OUT_MODEL_PLAIN)
        meta["plain_saved"] = True
        meta["estimator_type"] = type(est).__name__
    else:
        meta["plain_saved"] = False
else:
    if hasattr(obj, "predict"):
        joblib.dump(obj, OUT_MODEL_PLAIN, compress=3)
        print("Saved plain estimator ->", OUT_MODEL_PLAIN)
        meta["plain_saved"] = True
        meta["estimator_type"] = type(obj).__name__
    else:
        raise SystemExit("Loaded object is not a dict nor an estimator; keys unknown")

with open(OUT_META, "w") as fh:
    json.dump(meta, fh, indent=2)
print("Wrote meta ->", OUT_META)
print("Done. Meta:", meta)