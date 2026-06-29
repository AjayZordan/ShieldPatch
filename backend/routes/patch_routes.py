# backend/routes/patch_routes.py
from flask import Blueprint, request, jsonify
from utils import patch_engine

patch_bp = Blueprint("patch_routes", __name__)

@patch_bp.route("/api/patches/recommend", methods=["GET"])
def recommend():
    """
    GET /api/patches/recommend?query=<CVE or product>
    """
    query = request.args.get("query") or request.args.get("cve") or ""

    if not query:
        return jsonify({"error": "Missing 'query' parameter"}), 400

    suggestions = patch_engine.recommend_patch(query)

    # Add simple compatibility field (None for now)
    for s in suggestions:
        s["compatible"] = None

    return jsonify(suggestions), 200


import requests

@patch_bp.route("/api/patches/apply", methods=["POST"])
def apply_patch_now():
    """
    Trigger sandbox patch execution.
    Called ONLY when user clicks 'Patch Now'
    """
    body = request.get_json(force=True)

    job_name = body.get("job_name", "manual_patch")
    workdir = body.get("workdir", "/sandbox/data/testapp")
    script = body.get("script", "./apply_patch.sh")
    host_data_dir = body.get("host_data_dir", "./sandbox/data")

    payload = {
        "host_data_dir": host_data_dir,
        "job_name": job_name,
        "workdir": workdir,
        "script": script,
        "snapshot_after": True,
        "keep_container": False
    }

    try:
        resp = requests.post(
            "http://127.0.0.1:5000/api/sandbox/run_job",
            json=payload,
            timeout=90
        )
        return jsonify(resp.json()), resp.status_code

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "sandbox_execution_failed",
            "detail": str(e)
        }), 500