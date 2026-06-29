# routes/threatintel_routes.py
from flask import Blueprint, request, jsonify, current_app as app
from models import db, Threat  # ensure Threat model exists in models.py
from datetime import datetime

# --- new imports ---
import os
import io
import logging
import joblib
import pandas as pd

# end new imports
threat_bp = Blueprint("threats", __name__, url_prefix="/api")

@threat_bp.route("/threats/", methods=["GET"])
def get_threats():
    try:
        limit = int(request.args.get("limit", 100))
    except Exception:
        limit = 100
    rows = Threat.query.order_by(Threat.id.desc()).limit(limit).all()
    indicators = []
    for r in rows:
        indicators.append({
            "id": r.id,
            "source": r.source,
            "ioc": r.ioc,
            "type": r.type,
            "description": r.description,
            "first_seen": r.first_seen
        })
    return jsonify({"success": True, "count": len(indicators), "indicators": indicators}), 200

@threat_bp.route("/threats/", methods=["POST"])
def post_threats():
    """
    Accepts JSON:
    { "indicators": [ {source, ioc, type, description, first_seen?}, ... ] }
    """
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({"success": False, "error": "invalid json"}), 400

    items = payload.get("indicators") or payload.get("data") or []
    if not isinstance(items, list):
        return jsonify({"success": False, "error": "indicators must be a list"}), 400

    saved = 0
    for it in items:
        try:
            src = it.get("source", "")[:255]
            ioc = it.get("ioc", "")
            t = it.get("type", "")[:100]
            desc = it.get("description", "")
            fs = it.get("first_seen") or datetime.utcnow().isoformat()
            th = Threat(source=src, ioc=ioc, type=t, description=desc, first_seen=fs)
            db.session.add(th)
            saved += 1
        except Exception as e:
            app.logger.debug("threat insert failed for item: %s error: %s", it, e)
            continue
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.exception("Failed to commit threats: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500

    return jsonify({"success": True, "received": saved}), 200


# ---------------------------
# Batch prediction: /api/vulnlookup/predict/batch
# ---------------------------

# Configure a simple file logger for predictions (adds file handler once)
pred_log_name = "prediction_logger"
_pred_logger = logging.getLogger(pred_log_name)
if not any(isinstance(h, logging.FileHandler) for h in _pred_logger.handlers):
    _pred_logger.setLevel(logging.INFO)
    try:
        fh = logging.FileHandler('prediction_logs.log')
        fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        _pred_logger.addHandler(fh)
    except Exception:
        # fallback to app.logger if file handler fails
        app.logger.info("Could not create prediction_logs.log file handler; using app.logger for logging.")

# Helper: model loader (cached)
_model_cache = {"model": None}
def load_model():
    if _model_cache["model"] is None:
        # try a few sensible places relative to app root
        candidate_paths = [
            os.path.join(app.root_path, 'data', 'models', 'best_model.joblib'),
            os.path.join(app.root_path, 'models', 'best_model.joblib'),
            os.path.join(app.root_path, 'best_model.joblib'),
        ]
        found = None
        for p in candidate_paths:
            if os.path.exists(p):
                found = p
                break
        if not found:
            # not fatal here: raise so caller can handle
            raise FileNotFoundError(f"Model file not found in expected locations: {candidate_paths}")
        _model_cache["model"] = joblib.load(found)
        app.logger.info("Loaded model from %s", found)
    return _model_cache["model"]

# expected columns/features for normalization
EXPECTED_COLUMNS = [
    "description",
    "cvss_score",
    "references_count",
    "weaknesses_count",
    "os_count",
    "severity",
    "years_since_published"
]

# simple severity mapping (adapt to your training pipeline if different)
SEVERITY_MAP = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

def normalize_row(row):
    out = {}
    out["description"] = str(row.get("description", "")).strip()
    try:
        out["cvss_score"] = float(row.get("cvss_score", 0.0))
    except Exception:
        out["cvss_score"] = None
    for f in ("references_count", "weaknesses_count", "os_count"):
        try:
            out[f] = int(row.get(f, 0))
        except Exception:
            out[f] = None
    severity_raw = row.get("severity", "")
    if severity_raw is None:
        severity_raw = ""
    severity_norm = str(severity_raw).upper().strip()
    out["severity"] = SEVERITY_MAP.get(severity_norm, None)
    try:
        out["years_since_published"] = float(row.get("years_since_published", 0.0))
    except Exception:
        out["years_since_published"] = None
    return out

def validate_row(norm_row):
    errors = []
    if norm_row["cvss_score"] is None or not (0.0 <= norm_row["cvss_score"] <= 10.0):
        errors.append("cvss_score must be a number between 0 and 10")
    for f in ("references_count", "weaknesses_count", "os_count"):
        if norm_row[f] is None or norm_row[f] < 0:
            errors.append(f"{f} must be an integer >= 0")
    if norm_row["severity"] is None:
        errors.append("severity must be one of LOW, MEDIUM, HIGH, CRITICAL")
    if norm_row["years_since_published"] is None or norm_row["years_since_published"] < 0:
        errors.append("years_since_published must be >= 0")
    return errors

@threat_bp.route("/vulnlookup/predict/batch", methods=["POST", "OPTIONS"])
def predict_batch():
    """
    POST body options:
      - JSON array: [ {...}, {...} ]
      - JSON object: {"items": [ {...}, {...} ]}
      - multipart/form-data with CSV file field named 'file' (CSV header columns matching expected names)

    Response (200):
      { "success": True, "predictions": [ {input_index, input, predicted, model}, ... ] }

    On validation errors -> 400 with row_errors list.
    """
    # OPTIONS -> simple empty response to satisfy preflight
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data_list = None

    # 1) JSON body (array or {"items":[..]})
    if request.is_json:
        try:
            payload = request.get_json()
            if isinstance(payload, dict) and payload.get("items"):
                data_list = payload.get("items")
            elif isinstance(payload, list):
                data_list = payload
            else:
                # not matching accepted container shapes
                return jsonify({"success": False, "error": "Invalid JSON shape. Send an array or {'items': [...]}"}), 400
        except Exception as e:
            return jsonify({"success": False, "error": f"Invalid JSON: {str(e)}"}), 400

    # 2) CSV upload (multipart/form-data)
    elif 'file' in request.files:
        try:
            csvfile = request.files['file']
            # pandas can read file-like objects
            df = pd.read_csv(csvfile)
            data_list = df.to_dict(orient='records')
        except Exception as e:
            return jsonify({"success": False, "error": f"Failed to read CSV file: {str(e)}"}), 400
    else:
        return jsonify({"success": False, "error": "Unsupported content type. Send JSON array or multipart form with 'file' CSV."}), 400

    if not data_list or len(data_list) == 0:
        return jsonify({"success": False, "error": "No items provided"}), 400

    normalized = []
    row_errors = []
    for idx, item in enumerate(data_list):
        norm = normalize_row(item)
        v = validate_row(norm)
        if v:
            row_errors.append({"index": idx, "errors": v, "input": item})
        normalized.append(norm)

    if row_errors:
        return jsonify({"success": False, "error": "Validation failed", "row_errors": row_errors}), 400

    # convert to DataFrame for model pipeline
    df_features = pd.DataFrame(normalized)

    # load model and predict
    try:
        model = load_model()
    except FileNotFoundError as e:
        app.logger.exception("Model file not found: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500
    except Exception as e:
        app.logger.exception("Failed to load model: %s", e)
        return jsonify({"success": False, "error": f"Failed to load model: {str(e)}"}), 500

    # Do prediction
    try:
        preds = model.predict(df_features)
    except Exception as e:
        # fallback: try predict_proba second column if exists
        try:
            preds = model.predict_proba(df_features)[:, 1]
        except Exception:
            app.logger.exception("Model prediction failed: %s", e)
            return jsonify({"success": False, "error": f"Model prediction failed: {str(e)}"}), 500

    # prepare response
    response_list = []
    for i, inp in enumerate(data_list):
        try:
            pred_val = float(preds[i])
        except Exception:
            pred_val = None
        response_list.append({
            "input_index": i,
            "input": inp,
            "predicted": pred_val,
            "model": type(model).__name__
        })

    # log summary
    client_ip = request.remote_addr or "unknown"
    try:
        _pred_logger.info(f"Batch prediction: count={len(response_list)} ip={client_ip}")
    except Exception:
        app.logger.info("Batch prediction: count=%s ip=%s", len(response_list), client_ip)

    return jsonify({"success": True, "predictions": response_list}), 200