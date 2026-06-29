# routes/vulnlookup_routes.py
import os
import traceback
import logging
import json
from flask import Blueprint, request, jsonify, current_app
import joblib
import pandas as pd
import numpy as np
import sys
import re
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS
from utils.logging import save_risk_log
from datetime import datetime

logger = logging.getLogger(__name__)
vuln_bp = Blueprint("vulnlookup", __name__, url_prefix="/api/vulnlookup")

# -------------------- PATHS --------------------
BASE = os.path.expanduser("~/Desktop/ShieldPatch/backend/models")
FULL_PATH = os.path.join(BASE, "best_model.joblib")

DATA_CSV = os.path.expanduser(
    "~/Desktop/ShieldPatch/backend/data/ml_dataset_cleaned_fast.csv"
)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024

_DATA_DF = None

MODEL_PAYLOAD = {
    "model": None,
    "model_name": None,
    "text_col": "description_text",
    "numeric_cols": [
        "references_count",
        "weaknesses_count",
        "os_count",
        "years_since_published",
    ],
}

# -------------------- HELPERS --------------------
def clean_text(text: str) -> str:
    if text is None:
        return ""
    s = str(text).lower()
    s = re.sub(r"http\S+|www\.\S+", " ", s)
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    try:
        return " ".join(t for t in s.split() if t not in ENGLISH_STOP_WORDS)
    except Exception:
        return s


try:
    sys.modules.setdefault("__main__", sys.modules.get("__main__"))
    setattr(sys.modules["__main__"], "clean_text", clean_text)
except Exception:
    pass


# -------------------- LOAD MODEL --------------------
def try_load_models():
    if not os.path.exists(FULL_PATH):
        logger.error("❌ Model file not found: %s", FULL_PATH)
        return

    try:
        model = joblib.load(FULL_PATH)

        MODEL_PAYLOAD.update(
            {
                "model": model,
                "model_name": "SklearnPipeline",
            }
        )

        logger.info("✅ Loaded sklearn Pipeline model successfully")

    except Exception as e:
        logger.exception("❌ Failed to load model: %s", e)


try_load_models()


# -------------------- CSV LOOKUP --------------------
def _load_data_df():
    global _DATA_DF
    if _DATA_DF is not None:
        return _DATA_DF

    if not os.path.exists(DATA_CSV):
        return None

    df = pd.read_csv(DATA_CSV, low_memory=False)
    if "cve_id" in df.columns:
        df["cve_id_norm"] = df["cve_id"].astype(str).str.upper().str.strip()
    _DATA_DF = df
    return df


def local_lookup_cve(cve_id):
    df = _load_data_df()
    if df is None or not cve_id:
        return None

    key = str(cve_id).upper().strip()
    rows = df[df["cve_id_norm"] == key]
    if rows.empty:
        return None

    row = rows.iloc[0]
    return row.to_dict()


# -------------------- ENRICH INPUT --------------------
def estimate_severity_from_text(text):
    t = (text or "").lower()
    if any(k in t for k in ["remote code execution", "rce", "buffer overflow"]):
        return "CRITICAL"
    if any(k in t for k in ["sql injection", "command injection"]):
        return "HIGH"
    if any(k in t for k in ["information disclosure", "exposure"]):
        return "MEDIUM"
    return "LOW"


def enrich_input(payload):
    out = {}
    desc = payload.get("description_text") or payload.get("description") or ""
    cve = payload.get("cve_id")

    if cve:
        meta = local_lookup_cve(cve)
        if meta:
            out.update(meta)

    out.setdefault("severity", estimate_severity_from_text(desc))
    out.setdefault("references_count", 0)
    out.setdefault("weaknesses_count", 0)
    out.setdefault("os_count", 1)
    out.setdefault("years_since_published", 0)
    out.setdefault("description_text", desc)

    return out


# -------------------- VALIDATION --------------------
def normalize_input_df(df):
    df["severity"] = df["severity"].astype(str).str.upper()
    for c in MODEL_PAYLOAD["numeric_cols"]:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
    df["description_text"] = df["description_text"].astype(str)
    return df


def validate_input_df(df):
    required = ["description_text"] + MODEL_PAYLOAD["numeric_cols"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        return False, f"Missing columns: {missing}"
    return True, None


# -------------------- MODEL INFO --------------------
@vuln_bp.route("/model_info", methods=["GET"])
def model_info():
    return jsonify(
        {
            "success": True,
            "model": {
                "model_name": MODEL_PAYLOAD["model_name"],
                "has_preprocessor": True,
                "has_tfidf": True,
                "numeric_cols": MODEL_PAYLOAD["numeric_cols"],
                "text_col": MODEL_PAYLOAD["text_col"],
            },
        }
    )


# -------------------- BATCH PREDICT --------------------
@vuln_bp.route("/predict/batch", methods=["POST"])
def predict_batch():
    if MODEL_PAYLOAD["model"] is None:
        return jsonify({"success": False, "error": "model_not_loaded"}), 500

    payload = request.get_json(force=True)
    if isinstance(payload, dict):
        payload = [payload]

    df = pd.DataFrame(payload)

    for i in range(len(df)):
        extra = enrich_input(df.iloc[i].to_dict())
        for k, v in extra.items():
            df.loc[i, k] = v

    ok, err = validate_input_df(df)
    if not ok:
        return jsonify({"success": False, "error": err}), 400

    df = normalize_input_df(df)

    preds = MODEL_PAYLOAD["model"].predict(df)

    out = []
    for i, p in enumerate(preds):
        sev = cvss_to_severity(float(p))
        out.append(
            {
                "index": i,
                "predicted": round(float(p), 2),
                "severity": sev,
                "risk": sev,
                "input": df.iloc[i].to_dict(),
            }
        )

        try:
            sev = cvss_to_severity(float(p))

            save_risk_log(
                cve_id=df.iloc[i].get("cve_id"),
                input_payload=df.iloc[i].to_dict(),
                predicted_score=float(p),
                severity=sev,   # 🔥 THIS IS THE FIX
                model_name=MODEL_PAYLOAD["model_name"],
                extra_info={"method": "batch"},
            )
        except Exception:
            pass

    return jsonify({"success": True, "count": len(out), "predictions": out})


# -------------------- SINGLE PREDICT --------------------
@vuln_bp.route("/predict", methods=["POST"])
def predict_single():
    payload = request.get_json(force=True)
    df = pd.DataFrame([payload])

    extra = enrich_input(payload)
    for k, v in extra.items():
        df.loc[0, k] = v

    ok, err = validate_input_df(df)
    if not ok:
        return jsonify({"success": False, "error": err}), 400

    df = normalize_input_df(df)

    pred = float(MODEL_PAYLOAD["model"].predict(df)[0])
    sev = cvss_to_severity(pred)

    try:

        sev = cvss_to_severity(pred)


        save_risk_log(
            cve_id=payload.get("cve_id"),
            input_payload=payload,
            predicted_score=pred,
            severity=sev,   # 🔥 THIS IS THE FIX
            model_name=MODEL_PAYLOAD["model_name"],
            extra_info={"method": "single"},
    )
    except Exception:
        pass

    return jsonify(
        {
            "success": True,
            "predicted": round(pred, 2),
            "severity": sev,
            "risk": sev,
        }
    )


# -------------------- SEVERITY MAP --------------------
def cvss_to_severity(cvss):
    if cvss >= 9:
        return "CRITICAL"
    if cvss >= 7:
        return "HIGH"
    if cvss >= 4:
        return "MEDIUM"
    return "LOW"

@vuln_bp.route("/stats/severity", methods=["GET"])
def severity_stats():
    """
    Severity distribution based on ML prediction logs.
    This is the canonical, future-proof source of truth.
    """
    try:
        from models import RiskLog
        from sqlalchemy import func

        rows = (
            RiskLog.query
            .with_entities(
                func.upper(RiskLog.severity).label("severity"),
                func.count(RiskLog.id).label("count")
            )
            .group_by(func.upper(RiskLog.severity))
            .all()
        )

        counts = {r.severity: int(r.count) for r in rows if r.severity}
        total = sum(counts.values())

        return jsonify({
            "success": True,
            "counts": counts,
            "total": total
        }), 200

    except Exception as e:
        current_app.logger.exception("Severity stats failed")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
    
@vuln_bp.route("", methods=["GET"])
def list_cves():
    """
    CVE Library list endpoint (used by frontend CVE Library page)
    """
    try:
        from models import CVE
        from sqlalchemy import or_, func

        limit = int(request.args.get("limit", 50))
        offset = int(request.args.get("offset", 0))
        q = request.args.get("q", "").strip()
        severity = request.args.get("severity", "").strip().upper()

        query = CVE.query

        # Search by CVE ID or summary
        if q:
            like = f"%{q}%"
            query = query.filter(
                or_(
                    CVE.cve_id.ilike(like),
                    CVE.summary.ilike(like)
                )
            )

        # Severity filter
        if severity and severity != "ALL":
            query = query.filter(func.upper(CVE.severity) == severity)

        total = query.count()

        rows = (
            query
            .order_by(
                CVE.published.is_(None),  # NULLs last (MySQL-safe)
                CVE.published.desc()
            )
            .limit(limit)
            .offset(offset)
            .all()
        )

        results = []
        for r in rows:
            d = r.to_dict()

            # 🔥 NORMALIZATION FIX (summary → description)
            if not d.get("description"):
                d["description"] = d.get("summary")

            results.append(d)

        return jsonify({
            "success": True,
            "count": total,
            "results": results
        })

    except Exception as e:
        current_app.logger.exception("Failed to list CVEs")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500