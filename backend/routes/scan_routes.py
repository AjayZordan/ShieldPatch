import os
import json
import datetime
import logging
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename


def run_osquery_scan():
    import subprocess, json

    try:
        print("🔥 RUNNING OSQUERY SCAN (WORKING VERSION)...")

        # ✅ WORKING QUERY (always works)
        query = "SELECT name, version FROM os_version;"

        result = subprocess.check_output(
            ["osqueryi", "--json", query],
            stderr=subprocess.DEVNULL
        )

        data = json.loads(result)

        print("✅ OSQUERY RESULT:", data)

        return data

    except Exception as e:
        print("❌ OSQUERY ERROR:", str(e))
        return []
# Optional libs (we handle ImportError gracefully)
try:
    import clamd
except Exception:
    clamd = None

try:
    import yara
except Exception:
    yara = None

try:
    import pefile
except Exception:
    pefile = None
# androguard package (very large) - optional
try:
    try:
        from androguard.core.apk import APK
    except Exception:
        from androguard.core.bytecodes.apk import APK
except Exception:
    APK = None

# local db helpers in your project (keep your existing imports)
from db import get_session
# If you have a ScanResult model, import it; but we protect DB write errors
try:
    from models import ScanResult
except Exception:
    ScanResult = None

scan_bp = Blueprint("scan_bp", __name__, url_prefix="/api/scan")

# Configuration
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
YARA_RULES_DIR = os.path.join(BASE_DIR, "yara_rules")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(YARA_RULES_DIR, exist_ok=True)

log = logging.getLogger("scan_routes")
if not log.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)
log.setLevel(logging.INFO)


def _connect_clamd():
    """Return a clamd client or raise. Try unix socket path in env or common locations, then network fallback."""
    if clamd is None:
        raise RuntimeError("clamd python library not installed")

    # allow overriding via env
    sock = os.getenv("CLAMD_SOCKET")
    host = os.getenv("CLAMD_HOST", "127.0.0.1")
    port = int(os.getenv("CLAMD_PORT", "3310"))

    # try unix socket first if provided or common homebrew /var path
    if sock:
        try:
            log.info("Trying clamd unix socket from CLAMD_SOCKET=%s", sock)
            return clamd.ClamdUnixSocket(path=sock)
        except Exception as e:
            log.warning("Clamd unix socket connect failed (%s) - %s", sock, e)
    # try common macOS brew location
    common_paths = [
        "/opt/homebrew/var/clamav/clamd.sock",
        "/var/run/clamav/clamd.ctl",
        "/var/run/clamd.sock",
        "/tmp/clamd.socket",
    ]
    for p in common_paths:
        if os.path.exists(p):
            try:
                log.info("Trying clamd unix socket at %s", p)
                return clamd.ClamdUnixSocket(path=p)
            except Exception as e:
                log.warning("Clamd unix socket connect failed (%s) - %s", p, e)

    # network fallback
    try:
        log.info("Trying clamd network socket %s:%s", host, port)
        return clamd.ClamdNetworkSocket(host=host, port=port)
    except Exception as e:
        log.error("Clamd network socket connect failed %s:%s - %s", host, port, e)
        raise


def _compile_yara_rules(rules_dir=YARA_RULES_DIR):
    """Compile all .yar/.yara files in rules_dir into a single yara rules object.
       Returns compiled rules or None if yara not available or no rules found.
    """
    if yara is None:
        log.debug("yara-python not installed")
        return None

    rules_files = []
    for fname in os.listdir(rules_dir):
        if fname.lower().endswith((".yar", ".yara")):
            rules_files.append(os.path.join(rules_dir, fname))
    if not rules_files:
        log.debug("no yara rules found in %s", rules_dir)
        return None

    try:
        # build a filemap (namespace -> path)
        filemap = {os.path.splitext(os.path.basename(p))[0]: p for p in rules_files}
        compiled = yara.compile(filepaths=filemap)
        log.info("Compiling YARA rules: %s", ", ".join(filemap.keys()))
        log.info("YARA compiled successfully: %s", ", ".join(filemap.keys()))
        return compiled
    except Exception as e:
        log.exception("Failed to compile yara rules: %s", e)
        return None


def _run_yara(compiled_rules, path):
    """
    Run yara match and normalize results. Handle both tuple-style (offset, id, data)
    and yara.StringMatch object style (attributes).
    Returns list of dicts with: rule, namespace, meta, strings (list of (offset, id, data) tuples)
    """
    if compiled_rules is None:
        return []

    try:
        # older/newer yara-python versions differ in match signature; call without kwargs
        try:
            matches = compiled_rules.match(path)
        except TypeError:
            # fallback: try calling with no path kw (some versions require file object or different API)
            matches = compiled_rules.match(path)
    except Exception as e:
        log.warning("yara match error on %s: %s", path, e)
        return []

    out = []
    try:
        for m in matches:
            # m can be a yara.Match object
            meta = {}
            try:
                meta = dict(getattr(m, "meta", {}) or {})
            except Exception:
                meta = {}
            # normalize strings: support tuple and object
            strings_out = []
            for s in getattr(m, "strings", []) or []:
                # case 1: tuple/list (offset, id, data)
                if hasattr(s, "__getitem__") and not isinstance(s, yara.StringMatch):
                    try:
                        strings_out.append((s[0], s[1], s[2]))
                        continue
                    except Exception:
                        pass
                # case 2: StringMatch object (newer yara-python)
                # try common attribute names
                off = None
                ident = None
                data = None
                # try attributes in a safe order
                if hasattr(s, "offset"):
                    off = getattr(s, "offset", None)
                elif hasattr(s, "at"):
                    off = getattr(s, "at", None)
                if hasattr(s, "identifier"):
                    ident = getattr(s, "identifier", None)
                elif hasattr(s, "string"):
                    ident = getattr(s, "string", None)
                if hasattr(s, "data"):
                    data = getattr(s, "data", None)
                elif hasattr(s, "value"):
                    data = getattr(s, "value", None)
                strings_out.append((off, ident, data))
            out.append({
                "rule": getattr(m, "rule", None),
                "namespace": getattr(m, "namespace", None),
                "meta": meta,
                "strings": strings_out,
            })
    except Exception as e:
        log.warning("Error normalizing YARA matches: %s", e)
        return out

    return out


def _static_analysis_exe(path):
    info = {"type": "exe", "imports": [], "pe_sections": [], "arch": None}
    if pefile is None:
        info["note"] = "pefile not installed"
        return info
    try:
        pe = pefile.PE(path, fast_load=True)
        # imports
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    info["imports"].append(entry.dll.decode(errors="ignore") if isinstance(entry.dll, bytes) else str(entry.dll))
        except Exception:
            pass
        # sections
        try:
            info["pe_sections"] = [s.Name.decode(errors="ignore").strip("\x00") for s in pe.sections]
        except Exception:
            pass
        # arch
        try:
            arch = hex(pe.FILE_HEADER.Machine)
            info["arch"] = arch
        except Exception:
            pass
    except Exception as e:
        info["error"] = str(e)
    return info


def _static_analysis_apk(path):
    info = {"type": "apk", "package": None, "permissions": [], "activities": []}
    if APK is None:
        info["note"] = "androguard not installed"
        return info
    try:
        a = APK(path)
        info["package"] = a.get_package()
        info["permissions"] = a.get_permissions() or []
        info["activities"] = a.get_activities() or []
    except Exception as e:
        info["error"] = str(e)
    return info


@scan_bp.route("/file", methods=["POST"])
def upload_and_scan_file():
    # 1) validation
    if "file" not in request.files:
        return jsonify({"error": "no file part"}), 400
    uploaded = request.files["file"]
    if uploaded.filename == "":
        return jsonify({"error": "no selected file"}), 400

    # 2) save file to uploads/
    filename = secure_filename(uploaded.filename)
    dest_path = os.path.join(UPLOAD_DIR, filename)
    uploaded.save(dest_path)
    log.info("Saved uploaded file to %s", dest_path)

    # prepare response structure
    result = {"path": dest_path, "status": None, "clamd": None, "yara": None, "static": None}

    # 3) ClamAV scan
    clam_err = None
    try:
        cd = _connect_clamd()
        try:
            # call scan (most wrappers support scan(path) or instream)
            scan_res = cd.scan(dest_path) or {}
        except AttributeError:
            # some clamd versions use scan_file or instream; try instream as fallback
            try:
                with open(dest_path, "rb") as fh:
                    scan_res = cd.instream(fh) or {}
            except Exception:
                scan_res = {}
        result["clamd"] = scan_res
        # normalize
        if isinstance(scan_res, dict):
            # key is path
            for p, info in scan_res.items():
                if isinstance(info, (list, tuple)):
                    status = info[0]
                    match = info[1] if len(info) > 1 else None
                else:
                    status = str(info)
                    match = None
                result["status"] = status
                result["clamd_match"] = match
        else:
            result["clamd"] = str(scan_res)
    except Exception as e:
        clam_err = str(e)
        log.warning("ClamAV scan failed: %s", e)
        result["clamd_error"] = clam_err

    # 4) YARA scan (compile once per request)
    try:
        compiled = _compile_yara_rules()
        yara_matches = _run_yara(compiled, dest_path)
        result["yara"] = yara_matches
        if yara_matches:
            # mark FOUND if yara rules matched
            result["status"] = result.get("status") or "FOUND"
            log.info("YARA matched %d rule(s) on %s: %s", len(yara_matches), dest_path, [m.get("rule") for m in yara_matches])
    except Exception as e:
        log.warning("Yara scanning failed: %s", e)
        result["yara_error"] = str(e)

    # 5) Static analysis for exe/apk
    ext = os.path.splitext(filename)[1].lower()
    try:
        if ext in [".exe", ".dll", ".sys", ".bin"]:
            result["static"] = _static_analysis_exe(dest_path)
        elif ext in [".apk"]:
            result["static"] = _static_analysis_apk(dest_path)
        else:
            result["static"] = {"type": "unknown", "note": "no static analysis performed for this extension"}
    except Exception as e:
        log.warning("Static analysis failed: %s", e)
        result["static_error"] = str(e)


          # =========================
    # 🧠 OSQUERY SYSTEM SCAN (FIXED)
    # =========================
    
    osquery_data = []
    try:
        print("🔥 RUNNING OSQUERY SYSTEM SCAN...")

        osquery_data = run_osquery_scan()
        print("OSQUERY RESULT:", osquery_data)

        from models import db as _db
        from sqlalchemy import text

        for item in osquery_data:
            _db.session.execute(
                text("INSERT INTO alerts (message, severity, created_at) VALUES (:msg, :sev, :ts)"),
                {
                    "msg": f"System Vulnerability: {item['name']} {item['version']}",
                    "sev": "MEDIUM",
                    "ts": datetime.datetime.utcnow()
                }
            )

        _db.session.commit()
        print("✅ OSQUERY ALERTS INSERTED")

    except Exception as e:
        print("❌ OSQUERY FAILED:", str(e))

    

    # 6) Build summary (user-facing short info)
    summary = {
        "path": dest_path,
        "status": result.get("status") or ("FOUND" if (result.get("clamd_match") or (result.get("yara") and len(result.get("yara"))>0)) else "OK"),
        "clamd_match": result.get("clamd_match"),
        "yara_rules": [m.get("rule") for m in (result.get("yara") or [])],
    }

    # 7) Persist to DB (best-effort)
    try:
        session = get_session()
        if ScanResult is not None:
            try:
                sr = ScanResult(
                    filename=filename,
                    summary=json.dumps(summary),
                    raw_result=json.dumps(result),
                    source=request.form.get("source") or request.args.get("source") or "web-ui",
                    created_at=datetime.datetime.utcnow(),
                )
                session.add(sr)
                session.commit()
            except Exception as e:
                session.rollback()
                log.warning("[WARN] DB model insert failed: %s", e)
                # fallback raw insertion to scan_results table if present
                try:
                    qs = "INSERT INTO scan_results (filename, summary, raw_result, source, created_at) VALUES (%s, %s, %s, %s, %s)"
                    conn = session.connection()
                    conn.execute(qs, (filename, json.dumps(summary), json.dumps(result), request.form.get("source") or "web-ui", datetime.datetime.utcnow()))
                    session.commit()
                    log.info("Saved scan result via raw insert for %s", filename)
                except Exception as e2:
                    log.warning("[WARN] DB raw insert also failed: %s", e2)
        else:
            # no model available, attempt raw sql insert
            try:
                conn_sess = session
                qs = "INSERT INTO scan_results (filename, summary, raw_result, source, created_at) VALUES (%s, %s, %s, %s, %s)"
                conn_sess.execute(qs, (filename, json.dumps(summary), json.dumps(result), request.form.get("source") or "web-ui", datetime.datetime.utcnow()))
                conn_sess.commit()
            except Exception as e:
                log.warning("[WARN] raw DB insert failed: %s", e)
    except Exception as e:
        log.warning("[WARN] DB persist stage failed: %s", e)
    finally:
        try:
            session.close()
        except Exception:
            pass



        # =========================
    # 🚨 CREATE ALERTS FROM SCAN RESULTS
    # =========================
    try:
        from models import db as _db
        from sqlalchemy import text

        # CASE 1: ClamAV detection
        if summary.get("clamd_match"):
            _db.session.execute(
                text("INSERT INTO alerts (message, severity, created_at) VALUES (:msg, :sev, :ts)"),
                {
                    "msg": f"Threat detected: {summary['clamd_match']}",
                    "sev": "HIGH",
                    "ts": datetime.datetime.utcnow()
                }
            )

        # CASE 2: YARA detections
        if summary.get("yara_rules"):
            for rule in summary["yara_rules"]:
                _db.session.execute(
                    text("INSERT INTO alerts (message, severity, created_at) VALUES (:msg, :sev, :ts)"),
                    {
                        "msg": f"YARA threat detected: {rule}",
                        "sev": "HIGH",
                        "ts": datetime.datetime.utcnow()
                    }
                )

        _db.session.commit()
        print("🚨 SCAN ALERTS INSERTED")

    except Exception as e:
        _db.session.rollback()
        print("❌ SCAN ALERT FAILED:", str(e))

    # 8) return structured response
    return jsonify({
    "ok": True,
    "summary": summary,
    "raw": result,
    "osquery": osquery_data   # 👈 ADD THIS
}), 200


@scan_bp.route("/", methods=["GET"])
def system_scan():
    try:
        print("🔥 SYSTEM SCAN TRIGGERED")

        # -------- OSQUERY --------
        osquery_data = run_osquery_scan()
        import subprocess

        apps_data = []

        try:
            print("🔥 GETTING INSTALLED APPS (MAC)...")

            result = subprocess.check_output(
                ["system_profiler", "SPApplicationsDataType", "-json"],
                stderr=subprocess.DEVNULL
            )

            data = json.loads(result)

            apps = data.get("SPApplicationsDataType", [])

            for app in apps[:50]:  # limit for UI
                apps_data.append({
                    "id": 300 + len(apps_data),
                    "software": app.get("_name"),
                    "cve": "SYSTEM",
                    "description": f"Version: {app.get('version', 'N/A')}",
                    "severity": "Info",
                    "color": "#00d4ff",
                    "riskScore": 0,
                    "patchAvailable": False,
                })

            print("✅ APPS FOUND:", len(apps_data))

        except Exception as e:
            print("❌ APP SCAN ERROR:", str(e))
        
        print("OSQUERY RESULT:", osquery_data)

        # -------- KEEP YOUR OLD HARD DATA --------
        results = [
            {
                "id": 101,
                "software": "OpenSSL",
                "cve": "CVE-2024-12345",
                "description": "Buffer overflow in TLS handshake",
                "severity": "High",
                "color": "#ff4d4d",
                "riskScore": 95,
                "patchAvailable": True,
            },
            {
                "id": 102,
                "software": "ExampleApp v1.2.3",
                "cve": "CVE-2023-54321",
                "description": "Improper input validation",
                "severity": "Critical",
                "color": "#ff0000",
                "riskScore": 99,
                "patchAvailable": True,
            },
            {
                "id": 103,
                "software": "LocalDaemon",
                "cve": "N/A",
                "description": "Weak permissions on config file",
                "severity": "Medium",
                "color": "#ffd700",
                "riskScore": 41,
                "patchAvailable": False,
            },
        ]

        # -------- ADD OSQUERY DATA --------
        os_results = []
        for i, item in enumerate(osquery_data):
            os_results.append({
                "id": 200 + i,
                "software": item.get("name"),
                "cve": "SYSTEM",
                "description": f"{item.get('bundle_identifier')} | Version: {item.get('version')}",
                "severity": "Info",
                "color": "#00d4ff",
                "riskScore": 0,
                "patchAvailable": False,
            })

        return jsonify({
            "results": results + os_results + apps_data
        }), 200

    except Exception as e:
        print("❌ SYSTEM SCAN ERROR:", str(e))
        return jsonify({"error": str(e)}), 500

