# backend/ml_predictor.py
import os
import joblib
import numpy as np
from scipy import sparse

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "best_model.joblib")

_model_package = None

def load_model_package(force_reload=False):
    global _model_package
    if _model_package is None or force_reload:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")
        _model_package = joblib.load(MODEL_PATH)
    return _model_package

def _ensure_loaded():
    pkg = load_model_package()
    # expected keys in package: model_name, model, preprocessor, tfidf, numeric_cols, cat_cols, text_col
    required = ("model_name", "model", "preprocessor", "tfidf", "numeric_cols", "cat_cols", "text_col")
    for k in required:
        if k not in pkg:
            raise RuntimeError("Loaded model package missing key: " + k)
    return pkg

def _prepare_feature_matrix(pkg, items):
    """
    items: list of dict-like objects (or a single dict) with keys matching numeric_cols/cat_cols/text_col.
    Returns: scipy sparse matrix (n x features)
    """
    from pandas import DataFrame
    if not isinstance(items, (list, tuple)):
        items = [items]
    df = DataFrame(items)
    # fill missing columns
    for c in pkg["numeric_cols"] + pkg["cat_cols"] + [pkg["text_col"]]:
        if c not in df.columns:
            df[c] = None

    # preprocessor -> transform numeric+cat (dense ndarray)
    preproc = pkg["preprocessor"]
    X_numcat = preproc.transform(df[pkg["numeric_cols"] + pkg["cat_cols"]])
    # tfidf -> transform text (sparse)
    X_text = pkg["tfidf"].transform(df[pkg["text_col"]].fillna("").astype(str))
    # combine
    left = sparse.csr_matrix(X_numcat) if not sparse.issparse(X_numcat) else X_numcat
    right = X_text if sparse.issparse(X_text) else sparse.csr_matrix(X_text)
    X_comb = sparse.hstack([left, right], format="csr")
    return X_comb

def predict_from_dict(item):
    """
    item: dict with keys: numeric_cols, cat_cols, text_col (model package defines names)
    returns: {"predicted": float, "model_name": str}
    """
    pkg = _ensure_loaded()
    model = pkg["model"]
    X_comb = _prepare_feature_matrix(pkg, item)

    # HGB may require dense input; handle generically
    try:
        if hasattr(model, "predict"):
            if sparse.issparse(X_comb):
                # some models (HGB) need dense
                if model.__class__.__name__.lower().find("histgradientboosting") >= 0 or getattr(model, "requires_dense", False):
                    X_for_pred = X_comb.toarray()
                else:
                    X_for_pred = X_comb
            else:
                X_for_pred = X_comb
            pred = model.predict(X_for_pred)
        else:
            raise RuntimeError("Loaded model has no predict() method")
    except MemoryError:
        # fallback: try to convert to dense in smaller chunks (not implemented here)
        raise

    return {"predicted": float(pred[0]), "model_name": pkg["model_name"]}

# convenience function: predict from item dict but accept different field names (like DB row)
def predict_from_row_like(row_like):
    """
    row_like can be dict or object with attributes. Build dict with expected keys.
    """
    pkg = _ensure_loaded()
    numeric_cols = pkg["numeric_cols"]
    cat_cols = pkg["cat_cols"]
    text_col = pkg["text_col"]

    item = {}
    for c in numeric_cols + cat_cols:
        # prefer dict get, then attribute
        if isinstance(row_like, dict):
            item[c] = row_like.get(c)
        else:
            item[c] = getattr(row_like, c, None)
    # text field
    if isinstance(row_like, dict):
        item[text_col] = row_like.get(text_col) or row_like.get("description_text") or row_like.get("description") or ""
    else:
        item[text_col] = getattr(row_like, text_col, None) or getattr(row_like, "description_text", None) or getattr(row_like, "description", None) or ""

    # make sure numeric columns are floats/ints
    for c in numeric_cols:
        try:
            if item[c] is None:
                continue
            item[c] = float(item[c])
        except Exception:
            # leave None or let preprocessor handle missing
            item[c] = None

    return predict_from_dict(item)