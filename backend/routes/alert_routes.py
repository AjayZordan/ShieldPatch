from flask import Blueprint, jsonify
from sqlalchemy import text
from models import db

alert_bp = Blueprint("alert_bp", __name__)

@alert_bp.route("/alerts", methods=["GET"])
def get_alerts():
    result = db.session.execute(
        text("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 20")
    ).mappings().all()

    return jsonify({
        "success": True,
        "alerts": [dict(r) for r in result]
    })