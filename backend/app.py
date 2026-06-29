# ---- REQUIRED FOR ML MODEL PICKLE ----
def identity_array(x):
    return x

# app.py (Flask backend with SQLAlchemy + threat collector endpoint)
from flask import Flask, jsonify, request
from routes.threatintel_routes import threat_bp
from routes.patch_routes import patch_bp
from routes.alert_routes import alert_bp
from routes.scan_routes import scan_bp
import os
from dotenv import load_dotenv
import time
import random
import subprocess
import json
import shutil
import plistlib
from pathlib import Path
import platform
from datetime import datetime
import jwt  # <<< added for decoding JWT tokens
from sqlalchemy import text
from vuln_api import bp as vuln_bp

# --- NEW: imports & helper needed for model unpickle compatibility ----
# These are intentionally minimal. The model you trained referenced a
# function named `clean_text` at pickle time. Joblib/pickle needs this
# symbol available on import when the model is loaded in the backend.
import re
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

# Additional imports for new features
import io
import tempfile

def clean_text(text: str) -> str:
    """
    Lightweight text cleaner used during model training. Keep this
    function here so pickled TF-IDF or custom transformers that refer
    to `clean_text` can be unpicked correctly.

    Behavior:
      - Lowercases text
      - Removes URLs
      - Removes non-alphanumeric characters (keeps spaces)
      - Collapses whitespace
      - Removes common English stopwords (matches training expectations)
    """
    if text is None:
        return ""
    s = str(text)
    s = s.lower()
    # remove URLs
    s = re.sub(r"http\S+|www\.\S+", " ", s)
    # replace non-alphanumeric characters with space
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    # collapse whitespace
    s = re.sub(r"\s+", " ", s).strip()
    # remove very common english stop words (if training used similar)
    try:
        tokens = [tok for tok in s.split() if tok not in ENGLISH_STOP_WORDS]
        return " ".join(tokens)
    except Exception:
        return s
# ---------------------------------------------------------------------

# NOTE: vuln_api import/registration moved below after app creation to avoid NameError

# --- load .env ---
load_dotenv()

# JWT secret (use same secret used to sign tokens in your auth routes)
JWT_SECRET = os.getenv("JWT_SECRET", os.getenv("SECRET_KEY", "change-me"))
JWT_ALGO = os.getenv("JWT_ALGO", "HS256")

# --- create Flask app ---
app = Flask(__name__)

from flask_cors import CORS

CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    allow_headers=["Content-Type", "Authorization", "X-User-ID"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)

#from flask_cors import CORS

#CORS(
    #app,
   # resources={r"/api/*": {"origins": "http://localhost:3000"}},
  #  supports_credentials=True,
 #   allow_headers=["Content-Type", "Authorization", "X-User-ID"]
#)

#CORS(app, resources={r"/api/*": {"origins": "*"}})

# initial DB config (may be overridden later by env)
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://shieldpatch_user:ajaykumar%40040702@localhost:3306/ShieldPatch"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.register_blueprint(alert_bp, url_prefix="/api")

# -------------------- NEW CONFIG / METADATA PATHS --------------------
# Request size limit (bytes) — prefer env var if provided. Default = 10MB.
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH", str(10 * 1024 * 1024)))
# Default maximum rows allowed for batch CSV upload (safe-guard)
MAX_BATCH_ROWS = int(os.getenv("MAX_BATCH_ROWS", "5000"))

# Model meta file path used by vuln lookup routes too (mirrors routes' META_PATH)
MODEL_META_PATH = os.path.expanduser(os.getenv("MODEL_META_PATH", "~/Desktop/ShieldPatch/backend/models/model_meta.json"))
# ---------------------------------------------------------------------

from routes.vulnlookup_routes import vuln_bp
app.register_blueprint(vuln_bp)

app.register_blueprint(patch_bp)

# register blueprint (if you have other threatintel routes)
try:
    app.register_blueprint(threat_bp)
except Exception:
    # If the blueprint import fails or isn't present, continue — routes below still work
    app.logger.debug("threatintel_routes blueprint not registered (missing or error).")

# register auth blueprint (user register/login)


from routes.auth_routes import auth_bp
app.register_blueprint(auth_bp, url_prefix="/api/auth")
print(">>> auth blueprint registered at /api/auth")    



app.register_blueprint(scan_bp)

# Now import & register the vulnlookup blueprint AFTER app exists
try:
    from vuln_api import bp as vulnlookup_bp
    try:
        app.register_blueprint(vulnlookup_bp)
    except Exception:
        app.logger.debug("vuln_api blueprint import succeeded but registration failed.")
except Exception:
    # keep app running even if vuln_api.py is missing or raises on import
    app.logger.debug("vuln_api blueprint not imported (missing or error).")

# --- CORS for frontend dev ---
#CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)
# --- Extra CORS for ML Risk Prediction endpoint ---
#CORS(app, resources={
 #   r"/predict-risk": {"origins": "*"},
  #  r"/predict-risk/": {"origins": "*"},
#}, supports_credentials=True)

# ------------------ ADDED: robust after_request CORS header injection --------------
# This ensures every responses (including POST responses and error responses)
# contains the CORS headers browsers require. It complements flask-cors usage
# and prevents sporadic "Failed to fetch" client errors caused by missing
# headers on non-OPTIONS responses.
# put this into app.py replacing your existing @app.after_request function
@app.after_request
def _ensure_cors_headers(response):
    origin = request.headers.get("Origin")
    allowed = False
    if origin:
        if origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1") or origin.endswith(":3000"):
            allowed = True

    if allowed:
        # Echo origin and allow credentials (safe)
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    else:
        # No credentials; allow any origin (non-credentialed)
        response.headers["Access-Control-Allow-Origin"] = "*"
        # do NOT set Access-Control-Allow-Credentials to true when origin is '*'
        # (omit the header or set to "false")
        if "Access-Control-Allow-Credentials" in response.headers:
            del response.headers["Access-Control-Allow-Credentials"]

    response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS,PATCH,HEAD"
    response.headers["Access-Control-Allow-Headers"] = "Authorization,Content-Type,X-Requested-With,Accept,X-User-ID"
    response.headers["Access-Control-Max-Age"] = "3600"
    return response
# -------------------------------------------------------------------------------

# --- Database config ---
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_USER = os.getenv("DB_USER", "shieldpatch_user")
DB_PASS = os.getenv("DB_PASS", "ajaykumar@040702")
DB_NAME = os.getenv("DB_NAME", "ShieldPatch")

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "SQLALCHEMY_DATABASE_URI",
    f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = os.getenv("SQLALCHEMY_ECHO", "False").lower() in ("1", "true", "yes")

# --- initialize DB (models.py should define db, Agent, ScanResult, Package, CVE) ---
from models import db, Agent, ScanResult, Package, CVE  # ensure models.py exists and exports these
db.init_app(app)

with app.app_context():
    try:
        db.create_all()
        app.logger.info("Database tables ensured (create_all).")
    except Exception as e:
        app.logger.warning("Failed to create tables: %s", e)

app.app_context().push()

# -------------------------
# Register sandbox blueprint safely now that `app` exists
# (this avoids NameError at import time if app wasn't defined yet)
# -------------------------
print(">>> BEFORE importing sandbox_routes")

try:
    from routes.sandbox_routes import sandbox_bp
    print(">>> sandbox_routes imported OK")

    app.register_blueprint(sandbox_bp, url_prefix="/api/sandbox")
    print(">>> sandbox blueprint registered at /api/sandbox")

except Exception as e:
    print(">>> SANDBOX IMPORT FAILED:", e)
# ---------------------------------------------------------

# ---------------------------------------------------------
# UTILITIES (osqueryi and macOS fallbacks)
# ---------------------------------------------------------
def find_osqueryi():
    path = shutil.which("osqueryi")
    if not path:
        possible = ["/usr/local/bin/osqueryi", "/opt/homebrew/bin/osqueryi", "/usr/bin/osqueryi"]
        for p in possible:
            if Path(p).exists() and os.access(p, os.X_OK):
                return p
        return None
    return path

def run_osquery(query, timeout=10, try_sudo=False):
    osqueryi = find_osqueryi()
    if not osqueryi:
        raise RuntimeError("osqueryi not found in PATH")

    base_cmd = [osqueryi, "--json", query]
    cmds_to_try = []
    if try_sudo:
        sudo_path = shutil.which("sudo") or "/usr/bin/sudo"
        if sudo_path and Path(sudo_path).exists():
            cmds_to_try.append([sudo_path, "-n"] + base_cmd)
    cmds_to_try.append(base_cmd)

    last_err = None
    for cmd in cmds_to_try:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
            out = proc.stdout.strip()
            if not out:
                return []
            try:
                data = json.loads(out)
                return data if isinstance(data, list) else [data]
            except json.JSONDecodeError:
                lines = [l for l in out.splitlines() if l.strip()]
                rows = []
                for ln in lines:
                    try:
                        part = json.loads(ln)
                        rows.extend(part if isinstance(part, list) else [part])
                    except Exception:
                        continue
                return rows
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"osqueryi command failed: {last_err}")

def manual_mac_apps():
    app_dirs = [
        Path("/Applications"),
        Path("/Applications/Utilities"),
        Path("/System/Applications"),
        Path.home() / "Applications"
    ]
    seen = set()
    packages = []
    for d in app_dirs:
        if not d.exists():
            continue
        for app_bundle in d.glob("*.app"):
            info_plist = app_bundle / "Contents" / "Info.plist"
            if not info_plist.exists():
                continue
            try:
                with open(info_plist, "rb") as f:
                    pl = plistlib.load(f)
                name = pl.get("CFBundleName") or pl.get("CFBundleDisplayName") or app_bundle.stem
                bundle_id = pl.get("CFBundleIdentifier") or ""
                version = pl.get("CFBundleShortVersionString") or pl.get("CFBundleVersion") or ""
                path = str(app_bundle.resolve())
                key = (name, bundle_id, version, path)
                if key not in seen:
                    seen.add(key)
                    packages.append({"name": name, "bundle_identifier": bundle_id, "version": version, "path": path})
            except Exception as e:
                app.logger.debug("manual_mac_apps: %s", e)
    return packages

def brew_packages():
    brew = shutil.which("brew")
    if not brew:
        return []
    try:
        proc = subprocess.run([brew, "list", "--versions"], capture_output=True, text=True, check=True, timeout=8)
        pkgs = []
        for ln in proc.stdout.strip().splitlines():
            parts = ln.split()
            if parts:
                pkgs.append({"name": parts[0], "version": parts[1] if len(parts) > 1 else "", "path": ""})
        return pkgs
    except Exception as e:
        app.logger.debug("brew_packages: %s", e)
        return []

# ---------------------------------------------------------
# SAMPLE DATA
# ---------------------------------------------------------
SAMPLE_SCAN_RESULTS = [
    {"id": 101, "software": "OpenSSL", "cve": "CVE-2024-12345", "description": "Buffer overflow in TLS handshake", "severity": "High", "riskScore": 90, "color": "#ff4d4d", "patchAvailable": True},
    {"id": 102, "software": "ExampleApp v1.2.3", "cve": "CVE-2023-54321", "description": "Improper input validation", "severity": "Critical", "riskScore": 98, "color": "#cc0000", "patchAvailable": True},
    {"id": 103, "software": "LocalDaemon", "cve": None, "description": "Weak permissions on config file", "severity": "Medium", "riskScore": 45, "color": "#ffd700", "patchAvailable": False}
]

# ---------------------------------------------------------
# ROUTES
# ---------------------------------------------------------
@app.route("/", methods=["GET"])
def root_health():
    return jsonify({"service": "ShieldPatch Backend", "status": "ok", "time": int(time.time())}), 200

@app.route("/api/health", methods=["GET", "POST"])
def api_health():
    if request.method == "POST":
        try:
            payload = request.get_json(force=True)
            agent_ip = payload.get("agent_ip", request.remote_addr)
            status = payload.get("status", "online")
            ua = payload.get("user_agent", request.headers.get("User-Agent", "unknown"))
            ts = payload.get("timestamp")
        except Exception:
            return jsonify({"success": False, "error": "invalid json"}), 400

        try:
            agent = Agent.query.filter_by(agent_ip=agent_ip).first()
            last_seen = datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else datetime.utcnow()
            if agent:
                agent.status = status
                agent.user_agent = ua
                agent.last_seen = last_seen
            else:
                agent = Agent(agent_ip=agent_ip, status=status, user_agent=ua, last_seen=last_seen)
                db.session.add(agent)
            db.session.commit()
            return jsonify({"last_seen": last_seen.isoformat(), "status": "ok"}), 200
        except Exception as e:
            app.logger.exception("Heartbeat save failed: %s", e)
            return jsonify({"success": False, "error": str(e)}), 500

    return jsonify({"service": "shieldpatch", "ok": True}), 200

@app.route("/api/agent/status", methods=["GET"])
def api_agent_status():
    agent = Agent.query.order_by(Agent.last_seen.desc()).first()
    if not agent:
        return jsonify({"agent": {"status": "offline"}}), 200
    now = datetime.utcnow()
    from datetime import timedelta
    threshold_seconds = int(os.getenv("AGENT_ONLINE_THRESHOLD", "120"))
    online = (now - agent.last_seen) <= timedelta(seconds=threshold_seconds)
    return jsonify({
        "agent": {
            "agent_ip": agent.agent_ip,
            "last_seen": agent.last_seen.isoformat(),
            "status": "online" if online else "offline",
            "user_agent": agent.user_agent
        }
    }), 200

# ------------------- NEW: before_request guard for vulnlookup batch -------------------
@app.before_request
def enforce_request_guards():
    """
    General request guards:
      - Respect MAX_CONTENT_LENGTH already set in config (Flask will reject larger),
        but additionally check Content-Length header for early rejection.
      - If endpoint is vulnlookup/predict/batch and method POST:
          * enforce Content-Length <= MAX_CONTENT_LENGTH
          * if a file is uploaded, count rows and reject if > MAX_BATCH_ROWS
          * if JSON array is provided, check number of items and reject if > MAX_BATCH_ROWS
    """
    try:
        # Only check relevant endpoints
        path = request.path or ""
        if request.method != "POST":
            return None

        # If this request targets the vulnlookup batch endpoint (or similar), enforce guards
        if path.endswith("/api/vulnlookup/predict/batch") or path.endswith("/api/vulnlookup/predict/batch/"):
            # 1) content-length header quick check
            cl = request.content_length or 0
            if cl and cl > app.config.get("MAX_CONTENT_LENGTH", 0):
                return jsonify({"success": False, "error": "request_too_large", "detail": f"Content-Length {cl} > allowed {app.config.get('MAX_CONTENT_LENGTH')}" }), 413

            # 2) If file upload, count lines in uploaded CSV (without consuming stream permanently)
            #    We attempt to read up to MAX_BATCH_ROWS+1 lines to decide.
            if "file" in request.files:
                f = request.files["file"]
                # Some file storages support seek; else we copy into temp file
                data = b""
                try:
                    stream = f.stream
                    try:
                        # Try reading via seek
                        cur_pos = stream.tell()
                        stream.seek(0)
                        data = stream.read()
                        # try to rewind back to original pos
                        try:
                            stream.seek(cur_pos)
                        except Exception:
                            # best effort; if cannot, we'll handle later
                            pass
                    except Exception:
                        # fallback: read small portion through f.read()
                        try:
                            data = f.read()
                        except Exception:
                            data = b""
                        # reset file pointer to start for route handler (if possible)
                        try:
                            f.stream.seek(0)
                        except Exception:
                            # if cannot seek, write to temp file and replace request.files entry
                            try:
                                tmp = tempfile.NamedTemporaryFile(delete=False)
                                tmp.write(data)
                                tmp.flush()
                                tmp.close()
                                new_f = open(tmp.name, "rb")
                                request.files = request.files.copy()
                                request.files["file"] = new_f
                            except Exception:
                                # give up the replacement silently; route will handle
                                pass
                except Exception:
                    # top-level fallback attempt: try reading via f.read()
                    try:
                        data = f.read()
                    except Exception:
                        data = b""

                # Count newline occurrences (CSV rows). Decode safely.
                try:
                    txt = data.decode("utf-8", errors="ignore")
                except Exception:
                    txt = str(data)

                lines = txt.splitlines()
                row_count = len(lines)

                # Conservative count: if there is a header and >1 line, you may want to subtract 1,
                # but to be safe we count all lines. User can set MAX_BATCH_ROWS accordingly.
                if row_count > MAX_BATCH_ROWS:
                    return jsonify({"success": False, "error": "too_many_rows", "detail": f"CSV has {row_count} rows, limit {MAX_BATCH_ROWS}"}), 413

                # Rewind file object so route can read it. Try best-effort.
                try:
                    f.stream.seek(0)
                except Exception:
                    pass

            else:
                # 3) If JSON payload, validate number of items if it's an array
                content_type = request.content_type or ""
                if "application/json" in content_type:
                    try:
                        # small optimization: read cached body
                        raw = request.get_data(cache=True)
                        if raw:
                            parsed = json.loads(raw)
                            if isinstance(parsed, list) and len(parsed) > MAX_BATCH_ROWS:
                                return jsonify({"success": False, "error": "too_many_items", "detail": f"JSON array length {len(parsed)} > {MAX_BATCH_ROWS}"}), 413
                    except Exception:
                        # if parsing fails, let the route handle bad JSON
                        pass

    except Exception as e:
        # Do not break the app for guard errors — log and continue
        app.logger.debug("enforce_request_guards encountered exception: %s", e)
    return None
# -------------------------------------------------------------------------

# ---------------------------------------------------------
# 🟢 Threat Intelligence ingestion endpoint (GET + POST)
# ---------------------------------------------------------
from sqlalchemy import text

@app.route("/api/threats/", methods=["GET", "POST"])
def api_threats():
    """
    GET -> list indicators
    POST -> bulk insert indicators from collector
    """
    # GET: list stored indicators (raw SQL used for simplicity)
    if request.method == "GET":
        try:
            rows = db.session.execute(text("SELECT id, source, ioc, type, description, first_seen FROM threats ORDER BY id DESC LIMIT 50;")).mappings().all()
            indicators = [dict(r) for r in rows]
            return jsonify({"success": True, "count": len(indicators), "indicators": indicators}), 200
        except Exception as e:
            app.logger.warning("GET /api/threats failed: %s", e)
            return jsonify({"success": False, "error": str(e)}), 500

    # POST: store incoming indicators
    try:
        body = request.get_json(force=True)
        indicators = body.get("indicators") or []
        if not indicators:
            return jsonify({"success": False, "error": "no indicators provided"}), 400
        inserted = 0
        for ind in indicators:
            src = ind.get("source", "collector")
            ioc = ind.get("ioc") or ind.get("value") or ""
            itype = ind.get("type", "unknown")
            desc = (ind.get("description") or "")[:1000]
            first_seen = ind.get("first_seen") or datetime.utcnow().isoformat()
            q = text("INSERT INTO threats (source, ioc, type, description, first_seen) VALUES (:s, :i, :t, :d, :f)")
            db.session.execute(q, {"s": src, "i": ioc, "t": itype, "d": desc, "f": first_seen})
            inserted += 1
        db.session.commit()
        return jsonify({"success": True, "received": inserted}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.exception("POST /api/threats failed: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500

# ---------------------------------------------------------
# Other sample routes (scan, discover, patch, upload)
# ---------------------------------------------------------
@app.route("/api/scan-old", methods=["GET"])
def api_scan():
    time.sleep(1)

    # 1) Prepare scan results
    results = []
    for r in SAMPLE_SCAN_RESULTS:
        rr = dict(r)
        rr["riskScore"] = min(100, max(0, rr.get("riskScore", 50) + random.randint(-5, 5)))
        results.append(rr)

    # =========================
    # 🚨 CREATE ALERTS FROM SYSTEM SCAN
    # =========================
    try:
        from models import db
        from sqlalchemy import text

        for r in results:
            severity = str(r.get("severity", "")).upper()

            if severity in ["HIGH", "CRITICAL"]:
                db.session.execute(
                    text("INSERT INTO alerts (message, severity, created_at) VALUES (:msg, :sev, :ts)"),
                    {
                        "msg": f"{r['software']} - {r.get('cve')} needs patching",
                        "sev": severity,
                        "ts": datetime.utcnow()
                    }
                )

        db.session.commit()
        print("🚨 SYSTEM SCAN ALERTS INSERTED")

    except Exception as e:
        db.session.rollback()
        print("❌ SYSTEM ALERT FAILED:", str(e))

    # 2) Discovery (keep as it was)
    discover_info = {"packages": [], "osquery_available": False}
    system = platform.system().lower()

    try:
        osq_path = find_osqueryi()
        if osq_path:
            discover_info["osquery_available"] = True
            rows = run_osquery("SELECT name, bundle_identifier as id, path, version FROM apps;", timeout=6)
            if rows:
                for row in rows:
                    discover_info["packages"].append({
                        "name": row.get("name"),
                        "version": row.get("version"),
                        "path": row.get("path")
                    })
    except:
        pass

    return jsonify({
        "success": True,
        "results": results,
        "discovery": discover_info
    }), 200
# --------------------- ADDED: robust file upload endpoint ---------------------
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config.setdefault("MAX_CONTENT_LENGTH", 100 * 1024 * 1024)  # 100 MB

# EICAR signature
EICAR_BYTES = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

def _save_uploaded_file_and_respond(f):
    """Save file and perform enhanced deterministic checks."""
    import re

    safe_name = os.path.basename(f.filename)
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    save_name = f"{ts}-{safe_name}"

    # Save to uploads root temporarily first (we'll move into per-user folder after we get user id)
    temp_save_path = os.path.join(UPLOAD_FOLDER, save_name)

    try:
        f.save(temp_save_path)
    except Exception as e:
        return {"ok": False, "error": f"save_failed: {e}"}, 500

    try:
        with open(temp_save_path, "rb") as fh:
            data = fh.read(2 * 1024 * 1024)
    except Exception as e:
        return {"ok": False, "error": f"read_failed: {e}"}, 500

    # default summary uses the temporary path; will update after move
    summary = {"status": "OK", "match": None, "path": temp_save_path}

    # 1) EICAR detection
    if EICAR_BYTES in data:
        summary["status"] = "FOUND"
        summary["match"] = "EICAR"
    else:
        # 2) Robust token detection in contents + filename
        try:
            txt = data.decode("utf-8", errors="ignore").lower()
        except:
            txt = ""

        fname = safe_name.lower()

        # Normalize punctuation → space
        normalized_txt = re.sub(r"[^\w\s]", " ", txt)
        normalized_fname = re.sub(r"[^\w\s]", " ", fname)

        # Expanded set of suspicious tokens
        SUSPICIOUS_TOKENS_EXPANDED = [
            "drop table", "delete from", "exec(", "malicious", "suspicious",
            "ransomware", "encrypt(", "lockfiles", "<virus>", "backdoor",
            "wget http", "curl http", "chmod 777"
        ]

        found = None
        for tk in SUSPICIOUS_TOKENS_EXPANDED:
            token = tk.lower()
            if token in normalized_txt or token in normalized_fname:
                found = token
                break
            if re.search(r"\b" + re.escape(token) + r"\b", normalized_txt):
                found = token
                break

        if found:
            summary["status"] = "FOUND"
            summary["match"] = found

    # Save DB record (optional)
    try:
        # Attempt to get user_id from JWT in Authorization header (if present)
        current_user_id = None
        try:
            auth_header = request.headers.get("Authorization", "") or ""
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ", 1)[1]
                try:
                    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
                    # token fields might be 'user_id' or 'id' depending on your auth implementation
                    current_user_id = payload.get("user_id") or payload.get("id") or payload.get("uid")
                except Exception:
                    current_user_id = None
        except Exception:
            current_user_id = None

        # Now move the temp file into the per-user folder
        try:
            uid = str(current_user_id) if current_user_id is not None else "anon"
            user_folder = os.path.join(UPLOAD_FOLDER, f"user_{uid}")
            os.makedirs(user_folder, exist_ok=True)
            final_save_path = os.path.join(user_folder, save_name)

            # Move/rename the file (atomic on same filesystem)
            try:
                os.replace(temp_save_path, final_save_path)
            except Exception:
                # fallback to copy then remove
                shutil.copy2(temp_save_path, final_save_path)
                try:
                    os.remove(temp_save_path)
                except Exception:
                    pass

            # update summary path to final location
            summary["path"] = final_save_path
        except Exception as e:
            app.logger.debug("Failed to move file into user folder: %s", e)
            # leave summary path as temp_save_path if moving failed

        # DEBUG prints to help diagnose why DB rows are NULL
        print("DEBUG >>> _save_uploaded_file_and_respond running")
        print("DEBUG >>> safe_name:", repr(safe_name))
        print("DEBUG >>> summary:", repr(summary))
        print("DEBUG >>> current_user_id:", repr(current_user_id))

        sr = ScanResult(
            user_id=current_user_id,
            filename=safe_name,
            software=safe_name,
            cve=summary["match"] if summary["match"] else None,
            description=f"Uploaded file scanned: status={summary['status']}",
            severity=("Malicious" if summary['status'] == "FOUND" else "Clean"),
            risk_score=(90 if summary['status'] == "FOUND" else 0),
            color=("#ff4d4d" if summary['status'] == "FOUND" else "#4caf50"),
            source="web-ui"
        )
        db.session.add(sr)
        db.session.commit()
    except Exception as e:
        # log the exception so you can see the real error in flask logs / terminal
        app.logger.exception("Failed to save scan result to DB: %s", e)
        db.session.rollback()

    return {"ok": True, "summary": summary, "raw": {"saved_path": summary["path"]}}, 200


@app.route("/predict-risk", methods=["POST"])
def predict_risk_simple():
    """
    Minimal prediction logging endpoint used by tests:
    - accepts JSON: {"cve_id": "...", "features": {...}, ...}
    - tries to call loaded model (if available)
    - otherwise stores predicted_score = 0.0 and logs the payload to risk_logs
    Returns JSON including "predicted_score" and "logged": True/False and "log_id". 
    """
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({"success": False, "error": "invalid_json"}), 400

    cve_id = payload.get("cve_id")
    features = payload.get("features") or payload.get("input") or payload

    predicted_score = 0.0
    model_name = None

    # Try to run model if available via routes.vulnlookup_routes MODEL_PAYLOAD
    try:
        from ml_predictor import predict_from_dict

        try:
            result = predict_from_dict(features)
            predicted_score = result.get("predicted", 0.0)
            # ✅ Generate CVSS (scale to 0–10)
            cvss_score = round((predicted_score / 100) * 10, 1)
            model_name = result.get("model_name")
        except Exception as e:
            print("ML ERROR:", e)
            predicted_score = 0.0
        model_name = _MODEL_PAYLOAD.get("model_name")
        numeric_cols = _MODEL_PAYLOAD.get("numeric_cols") or []

        # Attempt a simple numeric prediction if model and numeric_cols are present
        if model is not None and isinstance(features, dict) and numeric_cols:
            import numpy as np
            row = []
            for c in numeric_cols:
                v = features.get(c)
                try:
                    row.append(float(v) if v is not None else 0.0)
                except Exception:
                    row.append(0.0)
            X = np.array(row).reshape(1, -1)
            try:
                preds = model.predict(X)
                # support array-like or scalar
                if isinstance(preds, (list, tuple, np.ndarray)):
                    predicted_score = float(preds[0])
                else:
                    predicted_score = float(preds)
            except Exception:
                # prediction failed — leave predicted_score as default
                predicted_score = 0.0
    except Exception:
        # any import or model error => leave default predicted_score
        predicted_score = predicted_score

    # Persist a RiskLog row
    try:
        from models import RiskLog
        rl = RiskLog(
            cve_id=cve_id,
            input_payload=payload,
            predicted_score=float(predicted_score),
            model_name=(model_name if model_name is not None else None),
            extra_info={"saved_by": "predict-risk-endpoint"}
        )
        db.session.add(rl)
        db.session.commit()

        # return both id and log_id to satisfy tests and callers
        return jsonify({
            "success": True,
            "predicted_score": float(predicted_score),
            "cvss_score": float(cvss_score), 
            "logged": True,
            "log_id": int(rl.id),
            "id": int(rl.id)
        }), 200

    except Exception as e:
        # attempt rollback, but ignore errors during rollback
        try:
            db.session.rollback()
        except Exception:
            pass
        app.logger.exception("Failed to save RiskLog: %s", e)
        # return 500 but include logged: False so tests or caller can see it wasn't stored
        return jsonify({
            "success": False,
            "error": "db_save_failed",
            "detail": str(e),
            "predicted_score": float(predicted_score),
            "logged": False,
            "log_id": None,
            "id": None
        }), 500
    
@app.route("/api/predict", methods=["POST"])
def predict_api_alias():
    return predict_risk_simple()    
    

@app.route("/api/scan/file", methods=["POST"])
def api_scan_file():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "no file part"}), 400
    f = request.files["file"]
    if f.filename == "":
        return jsonify({"ok": False, "error": "no file selected"}), 400
    resp, code = _save_uploaded_file_and_respond(f)
    return jsonify(resp), code

# ------------------- NEW: Model metadata endpoints -------------------
@app.route("/api/vulnlookup/model/info", methods=["GET"])
def model_info():
    """
    Return model metadata saved in models/model_meta.json (if present).
    This is useful for frontend to show expected fields and dimensions.
    """
    try:
        if not os.path.exists(MODEL_META_PATH):
            return jsonify({"success": False, "error": "meta_not_found", "detail": MODEL_META_PATH}), 404
        with open(MODEL_META_PATH, "r") as fh:
            meta = json.load(fh)
        return jsonify({"success": True, "meta": meta}), 200
    except Exception as e:
        app.logger.exception("model_info failed: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/vulnlookup/model/save_meta", methods=["POST"])
def model_save_meta():
    """
    Allows saving model metadata (expected dims, numeric/cat cols, text_col, etc)
    Body: JSON object with keys: expected_n_features, numeric_cols, cat_cols, text_col, model_name
    """
    try:
        data = request.get_json(force=True)
        # Basic hygiene
        allowed_keys = {"expected_n_features", "numeric_cols", "cat_cols", "text_col", "model_name"}
        out = {k: data.get(k) for k in allowed_keys if k in data}
        os.makedirs(os.path.dirname(MODEL_META_PATH), exist_ok=True)
        with open(MODEL_META_PATH, "w") as fh:
            json.dump(out, fh, indent=2)
        return jsonify({"success": True, "saved": out}), 200
    except Exception as e:
        app.logger.exception("model_save_meta failed: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500
    

# --- add this to app.py (place near other routes) ---

@app.route("/api/vulnlookup/model/check_dimensions", methods=["GET"])
def model_check_dimensions():
    """
    Quick check comparing the loaded estimator's n_features_in_ (if available)
    against the saved expected_n_features in the meta file. Returns a report.
    """
    try:
        # Attempt to find the estimator via routes.vulnlookup_routes' MODEL_PAYLOAD if possible
        try:
            from routes.vulnlookup_routes import MODEL_PAYLOAD as _MODEL_PAYLOAD
            model = _MODEL_PAYLOAD.get("model")
        except Exception:
            model = None

        reported = {"meta_exists": False, "meta": None, "model_n_features_in_": None, "match": None}
        if os.path.exists(MODEL_META_PATH):
            reported["meta_exists"] = True
            with open(MODEL_META_PATH, "r") as fh:
                meta = json.load(fh)
            reported["meta"] = meta
        if model is not None:
            expected = getattr(model, "n_features_in_", None)
            reported["model_n_features_in_"] = int(expected) if expected is not None else None

        # Compare
        if reported["meta"] and reported["model_n_features_in_"] is not None:
            mval = reported["meta"].get("expected_n_features")
            reported["match"] = (int(mval) == int(reported["model_n_features_in_"])) if mval is not None else False

        return jsonify({"success": True, "report": reported}), 200
    except Exception as e:
        app.logger.exception("model_check_dimensions failed: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500
    

    
# ---------------------------------------------------------------------

# ---------------------------------------------------------
# Run dev server
# ---------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    host = os.getenv("HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=True)

print("SQLALCHEMY_DATABASE_URI =", app.config["SQLALCHEMY_DATABASE_URI"])
with app.app_context():
    try:
        r = db.session.execute(text("SELECT DATABASE()")).fetchone()
        print("APP connected to DATABASE():", r[0] if r else None)
    except Exception as e:
        print("Error getting DATABASE() from app connection:", e)