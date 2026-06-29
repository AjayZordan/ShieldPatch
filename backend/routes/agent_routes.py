# routes/agent_routes.py
import os
import datetime
import logging
from flask import Blueprint, jsonify, request

log = logging.getLogger("agent_routes")
if not log.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(h)
log.setLevel(logging.INFO)

agent_bp = Blueprint("agent_bp", __name__, url_prefix="/api")

# in-memory status store (simple, persists only while Flask runs)
LAST_HEARTBEAT = {
    "last_seen": None,
    "agent_ip": None,
    "agent_user_agent": None,
    "status": "unknown",
}

def _now_iso():
    return datetime.datetime.utcnow().isoformat() + "Z"


@agent_bp.route("/health", methods=["GET", "POST"])
def health():
    """
    Agent heartbeat endpoint.
    - Accepts GET (used by current agent) and POST (future agents can POST JSON).
    - Updates LAST_HEARTBEAT with a timestamp, IP and user-agent when called.
    """
    try:
        client_ip = request.remote_addr
    except Exception:
        client_ip = None

    ua = request.headers.get("User-Agent", None)

    # If POST with JSON, prefer explicit agent info
    if request.method == "POST":
        try:
            j = request.get_json(silent=True) or {}
            agent_id = j.get("agent_id")
            ts = j.get("timestamp")
            if ts:
                # trust posted timestamp if given
                LAST_HEARTBEAT["last_seen"] = ts
            else:
                LAST_HEARTBEAT["last_seen"] = _now_iso()
            LAST_HEARTBEAT["agent_ip"] = agent_id or client_ip
        except Exception:
            LAST_HEARTBEAT["last_seen"] = _now_iso()
            LAST_HEARTBEAT["agent_ip"] = client_ip
    else:
        # GET: update with now
        LAST_HEARTBEAT["last_seen"] = _now_iso()
        LAST_HEARTBEAT["agent_ip"] = client_ip

    LAST_HEARTBEAT["agent_user_agent"] = ua
    LAST_HEARTBEAT["status"] = "online"

    # reply with minimal info (HTTP 200)
    return jsonify({"status": "ok", "last_seen": LAST_HEARTBEAT["last_seen"]}), 200


@agent_bp.route("/agent/status", methods=["GET"])
def agent_status():
    """
    Return the last heartbeat and simple derived fields for frontend.
    """
    last = LAST_HEARTBEAT.get("last_seen")
    status = LAST_HEARTBEAT.get("status", "offline")
    agent_ip = LAST_HEARTBEAT.get("agent_ip")
    ua = LAST_HEARTBEAT.get("agent_user_agent")

    # compute online/offline: consider agent offline if last_seen older than 2x poll interval (default 600s)
    offline_threshold_seconds = int(os.getenv("AGENT_OFFLINE_THRESHOLD", "600"))
    online = False
    if last:
        try:
            last_dt = datetime.datetime.fromisoformat(last.replace("Z", "+00:00"))
            delta = (datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc) - last_dt.astimezone(datetime.timezone.utc)).total_seconds()
            online = delta < offline_threshold_seconds
        except Exception:
            online = True

    resp = {
        "agent": {
            "status": "online" if online else "offline",
            "last_seen": last,
            "agent_ip": agent_ip,
            "user_agent": ua,
        },
    }
    return jsonify(resp), 200