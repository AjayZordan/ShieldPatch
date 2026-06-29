# utils/logging.py
from models import db, RiskLog
from sqlalchemy.exc import SQLAlchemyError

def save_risk_log(cve_id: str, input_payload: dict, predicted_score: float, model_name: str = None, extra_info: dict | None = None) -> RiskLog | None:
    """Persist a risk prediction to DB and return the RiskLog row (or None on failure)."""
    try:
        log = RiskLog(
            cve_id = cve_id,
            input_payload = input_payload,
            predicted_score = float(predicted_score),
            severity=severity,          # ✅ MUST BE HERE
            model_name = model_name,
            extra_info = extra_info
        )
        db.session.add(log)
        db.session.commit()
        return log
    except SQLAlchemyError as e:
        db.session.rollback()
        # optionally log the exception to your logger
        print("DB write failed:", e)
        return None