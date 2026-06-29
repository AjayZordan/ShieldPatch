# routes/sandbox_routes.py
import os
import subprocess
import shlex
import uuid
import time
import shutil
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app as app
import json
from models import JobImage, db as models_db
from models import db as _db
from sqlalchemy import text
from datetime import datetime as _dt
from flask import Response 
from flask import g


sandbox_bp = Blueprint("sandbox_bp", __name__)

# default host folder to mount into sandbox container (adjust if needed)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SANDBOX_DATA = os.path.abspath(os.path.join(BASE_DIR, "..", "sandbox", "data"))
# image name you built earlier
SANDBOX_IMAGE = os.getenv("SANDBOX_IMAGE", "shieldpatch/sandbox-job")
DOCKER_TIMEOUT = int(os.getenv("SANDBOX_DOCKER_TIMEOUT", "20"))  # seconds

def _docker_available():
    """Return True if docker CLI is available to the backend process."""
    return shutil.which("docker") is not None

def _run_cmd(cmd, timeout=DOCKER_TIMEOUT):
    """Run a shell command list and return (ok, stdout, stderr, returncode)."""
    try:
        app.logger.debug("Running shell: %s", cmd)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return (proc.returncode == 0, proc.stdout.strip(), proc.stderr.strip(), proc.returncode)
    except subprocess.TimeoutExpired as e:
        return (False, "", f"timeout after {timeout}s", 124)
    except Exception as e:
        return (False, "", str(e), 1)
    

def _get_request_user_id():
    """
    Read user identity from request:
    - prefer header 'X-User-ID' (int)
    - fallback to query param 'user_id'
    Returns int or None.
    """
    try:
        h = request.headers.get("X-User-ID")
        if h:
            return int(h)
    except Exception:
        pass
    try:
        q = request.args.get("user_id")
        if q is not None and q != "":
            return int(q)
    except Exception:
        pass
    return None    


def create_backup(app_path):
    """
    Create a timestamped backup of the application folder
    """
    if not os.path.exists(app_path):
        raise FileNotFoundError(f"App path not found: {app_path}")

    base_dir = os.path.dirname(app_path)
    app_name = os.path.basename(app_path)

    backup_root = os.path.join(base_dir, ".rollback_backups")
    os.makedirs(backup_root, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
    backup_path = os.path.join(backup_root, f"{app_name}_{timestamp}")

    shutil.copytree(app_path, backup_path)

    return backup_path

@sandbox_bp.route("/status", methods=["GET"])
def sandbox_status():
    """
    Check Docker availability and optionally return container state.
    Query params:
      - container_name (optional) : name of container to inspect
    """
    if not _docker_available():
        return jsonify({"success": False, "error": "docker_not_available", "detail": "docker CLI not found in PATH"}), 503

    container = request.args.get("container_name") or request.args.get("name")
    if not container:
        # just report docker is available
        ok, out, err, rc = _run_cmd(["docker", "version"], timeout=6)
        return jsonify({"success": ok, "docker_version_output_ok": ok, "stdout": out, "stderr": err}), 200 if ok else 500

    # if container provided, try to inspect it
    ok, out, err, rc = _run_cmd(["docker", "ps", "-a", "--filter", f"name={container}", "--format", "{{.ID}}||{{.Status}}||{{.Names}}"])
    if not ok:
        return jsonify({"success": False, "error": "docker_ps_failed", "stdout": out, "stderr": err, "rc": rc}), 500

    if not out:
        return jsonify({"success": True, "found": False, "container": container}), 200

    # parse the first matching line
    line = out.splitlines()[0]
    parts = line.split("||")
    cid = parts[0] if len(parts) > 0 else None
    status = parts[1] if len(parts) > 1 else None
    name = parts[2] if len(parts) > 2 else container
    return jsonify({"success": True, "found": True, "id": cid, "name": name, "status": status}), 200

@sandbox_bp.route("rollback_host", methods=["POST"])
def rollback_host():
    """
    Restore application from a rollback backup.
    Body:
    {
      "backup_path": "/absolute/path/to/.rollback_backups/testapp_xxx",
      "restore_path": "/absolute/path/to/sandbox/data/testapp"
    }
    """
    body = request.get_json(silent=True) or {}
    backup_path = body.get("backup_path")
    restore_path = body.get("restore_path")

    if not backup_path or not restore_path:
        return jsonify({"success": False, "error": "backup_path and restore_path required"}), 400

    if not os.path.exists(backup_path):
        return jsonify({"success": False, "error": "backup_not_found"}), 404

    try:
        if os.path.exists(restore_path):
            shutil.rmtree(restore_path)

        shutil.copytree(backup_path, restore_path)

        return jsonify({
            "success": True,
            "restored_from": backup_path,
            "restored_to": restore_path
        }), 200

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@sandbox_bp.route("start", methods=["POST"])
def sandbox_start():
    """
    Start a sandbox container.
    Body JSON (optional):
      {
        "host_data_dir": "/absolute/path/to/host/sandbox/data",
        "name": "optional-container-name"
      }
    Returns: { success, container_name, stdout, stderr }
    """
    if not _docker_available():
        return jsonify({"success": False, "error": "docker_not_available", "detail": "docker CLI not found in PATH"}), 503

    body = request.get_json(silent=True) or {}
    host_dir = body.get("host_data_dir") or DEFAULT_SANDBOX_DATA
    if not os.path.isabs(host_dir):
        host_dir = os.path.abspath(host_dir)

    if not os.path.exists(host_dir):
        return jsonify({"success": False, "error": "host_data_dir_missing", "detail": host_dir}), 400

    # create a deterministic container name if not provided
    container_name = body.get("name") or f"shieldpatch_sandbox_{uuid.uuid4().hex[:8]}"

    # Use --entrypoint tail -f /dev/null to keep container alive regardless of image entrypoint
    cmd = [
        "docker", "run", "-d",
"-v", f"{host_dir}:/sandbox/data",
"--name", container_name,
SANDBOX_IMAGE,
"sleep", "infinity"
    ]
    ok, out, err, rc = _run_cmd(cmd, timeout=40)
    if not ok:
        return jsonify({"success": False, "error": "docker_run_failed", "stdout": out, "stderr": err, "rc": rc}), 500

    return jsonify({"success": True, "container_name": container_name, "container_id": out.strip(), "stdout": out, "stderr": err}), 200


@sandbox_bp.route("stop", methods=["POST"])
def sandbox_stop():
    if not _docker_available():
        return jsonify({"success": False, "error": "docker_not_available", "detail": "docker CLI not found in PATH"}), 503

    body = request.get_json(silent=True) or {}
    container = body.get("container_name")
    if not container:
        return jsonify({"success": False, "error": "container_name_required"}), 400

    # stop (gracefully) then remove
    ok1, out1, err1, rc1 = _run_cmd(["docker", "stop", container], timeout=15)
    ok2, out2, err2, rc2 = _run_cmd(["docker", "rm", "-f", container], timeout=15)
    return jsonify({
        "success": True,
        "stopped": ok1,
        "stopped_stdout": out1,
        "stopped_stderr": err1,
        "removed": ok2,
        "removed_stdout": out2,
        "removed_stderr": err2
    }), 200


@sandbox_bp.route("/api/sandbox/snapshot_before", methods=["POST"])
def snapshot_before():
    """
    Commit the running container to a 'before' tag. Body: { "container_name": "...", "tag": "optional" }
    """
    if not _docker_available():
        return jsonify({"success": False, "error": "docker_not_available", "detail": "docker CLI not found in PATH"}), 503

    body = request.get_json(silent=True) or {}
    container = body.get("container_name")
    if not container:
        return jsonify({"success": False, "error": "container_name_required"}), 400

    tag = body.get("tag") or f"shieldpatch/sandbox:before-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    ok, out, err, rc = _run_cmd(["docker", "commit", container, tag], timeout=30)
    if not ok:
        return jsonify({"success": False, "error": "docker_commit_failed", "stdout": out, "stderr": err, "rc": rc}), 500

    return jsonify({"success": True, "tag": tag, "stdout": out}), 200


@sandbox_bp.route("snapshot_after", methods=["POST"])
def snapshot_after():
    """
    Commit the running container to an 'after' tag. Body: { "container_name": "...", "tag": "optional" }
    """
    if not _docker_available():
        return jsonify({"success": False, "error": "docker_not_available", "detail": "docker CLI not found in PATH"}), 503

    body = request.get_json(silent=True) or {}
    container = body.get("container_name")
    if not container:
        return jsonify({"success": False, "error": "container_name_required"}), 400

    tag = body.get("tag") or f"shieldpatch/sandbox:after-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    ok, out, err, rc = _run_cmd(["docker", "commit", container, tag], timeout=30)
    if not ok:
        return jsonify({"success": False, "error": "docker_commit_failed", "stdout": out, "stderr": err, "rc": rc}), 500

    return jsonify({"success": True, "tag": tag, "stdout": out}), 200


@sandbox_bp.route("apply_patch", methods=["POST"])
def apply_patch():
    """
    Execute the patch script in the sandbox container.
    Body JSON:
      {
        "container_name": "...",
        "workdir": "/sandbox/data/testapp",   # optional
        "script": "./apply_patch.sh"         # optional
      }
    """
    if not _docker_available():
        return jsonify({"success": False, "error": "docker_not_available", "detail": "docker CLI not found in PATH"}), 503

    body = request.get_json(silent=True) or {}
    container = body.get("container_name")
    if not container:
        return jsonify({"success": False, "error": "container_name_required"}), 400

    workdir = body.get("workdir") or "/sandbox/data/testapp"
    script = body.get("script") or "./apply_patch.sh"

    # run the script via docker exec
    cmd = ["docker", "exec", container, "bash", "-lc", f"cd {shlex.quote(workdir)} && chmod +x {shlex.quote(script)} && {shlex.quote(script)}"]
    ok, out, err, rc = _run_cmd(cmd, timeout=60)
    status_code = 200 if ok else 500
    return jsonify({"success": ok, "stdout": out, "stderr": err, "rc": rc}), status_code


@sandbox_bp.route("rollback", methods=["POST"])
def sandbox_rollback():
    """
    Run the rollback script inside the container.
    Body: { "container_name": "...", "workdir": "/sandbox/data/testapp", "script": "./rollback_local.sh" }
    """
    if not _docker_available():
        return jsonify({"success": False, "error": "docker_not_available", "detail": "docker CLI not found in PATH"}), 503

    body = request.get_json(silent=True) or {}
    container = body.get("container_name")
    if not container:
        return jsonify({"success": False, "error": "container_name_required"}), 400

    workdir = body.get("workdir") or "/sandbox/data/testapp"
    script = body.get("script") or "./rollback_local.sh"

    cmd = ["docker", "exec", container, "bash", "-lc", f"cd {shlex.quote(workdir)} && chmod +x {shlex.quote(script)} && {shlex.quote(script)}"]
    ok, out, err, rc = _run_cmd(cmd, timeout=40)
    status_code = 200 if ok else 500
    return jsonify({"success": ok, "stdout": out, "stderr": err, "rc": rc}), status_code


@sandbox_bp.route("restore_from_image", methods=["POST"])
def sandbox_restore_from_image():
    """
    Create a new container from an existing image tag and mount host data dir.
    Body JSON:
      {
        "image_tag": "shieldpatch/sandbox:before",
        "container_name": "shieldpatch-sandbox-restored",
        "host_data_dir": "/absolute/path/to/host/sandbox/data"
      }
    """
    if not _docker_available():
        return jsonify({"success": False, "error": "docker_not_available"}), 503

    body = request.get_json(silent=True) or {}
    image_tag = body.get("image_tag")
    if not image_tag:
        return jsonify({"success": False, "error": "image_tag_required"}), 400

    host_dir = body.get("host_data_dir") or DEFAULT_SANDBOX_DATA
    if not os.path.isabs(host_dir):
        host_dir = os.path.abspath(host_dir)
    if not os.path.exists(host_dir):
        return jsonify({"success": False, "error": "host_data_dir_missing", "detail": host_dir}), 400

    container_name = body.get("container_name") or f"shieldpatch_restore_{uuid.uuid4().hex[:8]}"

    # Run container from image and keep it alive
    cmd = [
        "docker", "run", "-dit",
        "--entrypoint", "/bin/sh",
        "-v", f"{host_dir}:/sandbox/data:rw",
        "--name", container_name,
        image_tag,
        "-c", "while true; do :; done"
    ]
    ok, out, err, rc = _run_cmd(cmd, timeout=40)
    if not ok:
        return jsonify({"success": False, "error": "docker_run_failed", "stdout": out, "stderr": err, "rc": rc}), 500

    return jsonify({"success": True, "container_name": container_name, "container_id": out.strip(), "stdout": out, "stderr": err}), 200

@sandbox_bp.route("/run_job", methods=["POST"])
def sandbox_run_job():
    """
    Orchestrate ephemeral-per-job:
      - create a container (detached, tail -f /dev/null)
      - exec the provided script (workdir + script)
      - optionally snapshot the container to an image tag
      - optionally keep the container or remove it

    Body JSON:
    {
      "host_data_dir": "/absolute/path/to/host/sandbox/data",   # optional
      "container_name": "optional-name",                       # optional
      "job_name": "friendly-job-name",                         # optional
      "workdir": "/sandbox/data/testapp",                      # optional
      "script": "./apply_patch.sh",                            # optional
      "snapshot_after": true|false,                            # optional (default false)
      "keep_container": true|false,                            # optional (default false)
      "timeout_secs": 60,                                      # optional per-op timeout
      "user_id": 123                                           # optional
    }

    Returns JSON with success, stdout/stderr, container_id, image_tag (if snapshot), rc, and job_id.
    """
    if not _docker_available():
        return jsonify({"success": False, "error": "docker_not_available", "detail": "docker CLI not found"}), 503

    body = request.get_json(silent=True) or {}
    dry_run = bool(body.get("dry_run", False))
    host_dir = body.get("host_data_dir") or DEFAULT_SANDBOX_DATA
    if not os.path.isabs(host_dir):
        host_dir = os.path.abspath(host_dir)

    if not os.path.exists(host_dir):
        return jsonify({"success": False, "error": "host_data_dir_missing", "detail": host_dir}), 400

    container_name = body.get("container_name") or f"sandbox_job_{uuid.uuid4().hex[:8]}"
    job_name = body.get("job_name") or container_name
    # FIX: run directly inside testapp folder
    workdir = "/sandbox/data/testapp"
    script = body.get("script") or "./apply_patch.sh"
    snapshot_after = bool(body.get("snapshot_after", False))
    keep = bool(body.get("keep_container", False))
    op_timeout = int(body.get("timeout_secs", DOCKER_TIMEOUT))
    user_id = body.get("user_id", None)

    # 1) create container (detached), keep it alive with tail -f /dev/null
    run_cmd = [
        "docker", "run", "-d",
        "-v", f"{host_dir}:/sandbox/data",
        "-w", "/sandbox/data",
        "--name", container_name,
        SANDBOX_IMAGE,
        "sleep", "infinity"
    ]
    ok, out, err, rc = _run_cmd(run_cmd, timeout=op_timeout + 20)
    print("DOCKER CMD:", run_cmd)
    print("DOCKER STDOUT:", out)
    print("DOCKER STDERR:", err)
    print("DOCKER RC:", rc)
    if not ok:
        print("❌ DOCKER RUN FAILED")
        print("STDOUT:", out)
        print("STDERR:", err)
        print("RETURN CODE:", rc)

        # persist a failed job run record
        try:
            ji = JobImage(
                image_tag=None, image_id="",
                container_name=container_name, job_name=job_name,
                succeeded=False,
                stdout=out, stderr=err,
                snapshot_tag=None, user_id=user_id, host_path=host_dir
            )
            models_db.session.add(ji)
            models_db.session.commit()
        except Exception:
            try:
                models_db.session.rollback()
            except Exception:
                pass
        return jsonify({"success": False, "error": "docker_run_failed", "stdout": out, "stderr": err, "rc": rc}), 500

    container_id = out.strip()
    print("DEBUG CONTAINER CREATED:", container_name)
    _run_cmd(["docker", "exec", container_name, "ls", "-l", "/sandbox/data"])
    _run_cmd(["docker", "exec", container_name, "ls", "-l", workdir])

    # =========================
    # 🔐 ROLLBACK BACKUP (HOST LEVEL)
    # =========================
    try:
        # FIX: explicitly point to testapp folder inside host
        host_app_path = os.path.join(host_dir, "testapp")

        rollback_backup_path = create_backup(host_app_path)
    except Exception as e:
        # If backup fails, STOP PATCH — rollback safety first
        _run_cmd(["docker", "stop", container_name])
        _run_cmd(["docker", "rm", "-f", container_name])
        
        return jsonify({
            "success": False,
            "error": "rollback_backup_failed",
            "detail": str(e)
        }), 500

    # 2) run the script inside container
    if dry_run:
        print("DEBUG HOST DIR:", host_dir)
        print("DEBUG WORKDIR:", workdir)
        exec_cmd = [
            "docker", "exec", container_name,
            "bash", "-lc",
            f"cd {shlex.quote(workdir)} && ls -l && if [ -f {shlex.quote(script)} ]; then chmod +x {shlex.quote(script)} && echo '[DRY-RUN OK USING CUSTOM SCRIPT]'; elif [ -f ./apply_patch.sh ]; then chmod +x ./apply_patch.sh && echo '[DRY-RUN OK USING DEFAULT SCRIPT]'; else echo 'NO PATCH SCRIPT FOUND'; exit 1; fi"
        ]
    else:
        print("DEBUG HOST DIR:", host_dir)
        print("DEBUG WORKDIR:", workdir)
        exec_cmd = [
            "docker", "exec", container_name,
            "bash", "-lc",
            f"cd {shlex.quote(workdir)} && ls -l && if [ -f {shlex.quote(script)} ]; then chmod +x {shlex.quote(script)} && {shlex.quote(script)}; elif [ -f ./apply_patch.sh ]; then chmod +x ./apply_patch.sh && ./apply_patch.sh; else echo 'NO PATCH SCRIPT FOUND'; exit 1; fi"
        ]
    _run_cmd(["docker", "exec", container_name, "ls", "-l", "/sandbox/data"])
    _run_cmd(["docker", "exec", container_name, "ls", "-l", workdir])

    ok_exec, out_exec, err_exec, rc_exec = _run_cmd(exec_cmd, timeout=op_timeout)

    result = {
        "container_name": container_name,
        "container_id": container_id,
        "apply_ok": ok_exec,
        "apply_stdout": out_exec,
        "apply_stderr": err_exec,
        "apply_rc": rc_exec,
        "rollback_backup_path": rollback_backup_path,
        "dry_run": dry_run,
    }

    # 3) snapshot if requested
    image_tag = None
    snapshot_stdout = None
    snapshot_stderr = None
    snapshot_rc = None
    image_id = None
    if snapshot_after and not dry_run:
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        image_tag = f"shieldpatch/sandbox:job-{container_name}-after-{timestamp}"
        ok_c, out_c, err_c, rc_c = _run_cmd(["docker", "commit", container_name, image_tag], timeout=op_timeout + 10)
        snapshot_stdout = out_c
        snapshot_stderr = err_c
        snapshot_rc = rc_c
        result.update({
            "snapshot_tag": image_tag,
            "snapshot_ok": ok_c,
            "snapshot_stdout": out_c,
            "snapshot_stderr": err_c,
            "snapshot_rc": rc_c
        })
        # try to derive image id (sha256:...) -> take last part if present
        if out_c:
            # out_c often is "sha256:..."; extract hex id
            image_id = out_c.split(":", 1)[-1] if ":" in out_c else out_c

    # 4) cleanup (stop+remove) unless user wants to keep
    if not keep:
        ok_s, out_s, err_s, rc_s = _run_cmd(["docker", "stop", container_name], timeout=15)
        ok_r, out_r, err_r, rc_r = _run_cmd(["docker", "rm", "-f", container_name], timeout=15)
        result.update({
            "stopped": ok_s,
            "stopped_stdout": out_s,
            "stopped_stderr": err_s,
            "removed": ok_r,
            "removed_stdout": out_r,
            "removed_stderr": err_r
        })
    else:
        result["kept"] = True

    # overall status
    overall_ok = ok_exec and (not snapshot_after or result.get("snapshot_ok", True))
    result["success"] = bool(overall_ok)

    from sqlalchemy import text

    # =========================
    # 🚨 ALERT LOGIC (FIXED)
    # =========================
    try:
        if overall_ok:
            _db.session.execute(
                text("DELETE FROM alerts WHERE message LIKE :msg"),
                {"msg": f"%{job_name}%"}
            )

            _db.session.execute(
                text("INSERT INTO alerts (message, severity, created_at) VALUES (:msg, :sev, :ts)"),
                {
                    "msg": f"Patch applied successfully: {job_name}",
                    "sev": "LOW",
                    "ts": datetime.utcnow()
                }
            )
        else:
            _db.session.execute(
                text("INSERT INTO alerts (message, severity, created_at) VALUES (:msg, :sev, :ts)"),
                {
                    "msg": f"Patch failed: {job_name}",
                    "sev": "HIGH",
                    "ts": datetime.utcnow()
                }
            )

        _db.session.commit()
        print("✅ ALERT UPDATED AFTER PATCH")

    except Exception as e:
        _db.session.rollback()
        print("❌ ALERT UPDATE FAILED:", str(e))


    
    # =========================
    # 🔔 PATCH STATUS FOR UI
    # =========================
    if dry_run:
        result["patch_status"] = "BLOCKED_DRY_RUN"
    elif overall_ok:
        result["patch_status"] = "PATCH_APPLIED"
    else:
        result["patch_status"] = "PATCH_FAILED_ROLLED_BACK"

    # 5) persist JobImage record
    try:
        ji = JobImage(
            image_tag=image_tag or "",
            image_id=image_id or container_id or "",
            container_name=container_name,
            job_name=job_name,
            succeeded=bool(overall_ok),
            stdout=f"[STATUS={result['patch_status']}]\n" + (out_exec if out_exec else out or ""),
            stderr=("\n\n---apply_stderr---\n" + (err_exec or "")) if err_exec else (err or ""),
            snapshot_tag=image_tag,
            user_id=user_id,
            host_path=rollback_backup_path
        )
        models_db.session.add(ji)
        models_db.session.commit()
        result["job_id"] = ji.id

        return jsonify(result), 200
    except Exception as e:
        try:
            models_db.session.rollback()
        except Exception:
            pass
        # attach DB error but don't fail the whole response
        result["db_error"] = str(e)
        return jsonify(result), (200 if overall_ok else 500)


# --- replace or update your job_history handler with this improved version ---
@sandbox_bp.route("job_history", methods=["GET"])
def sandbox_job_history():
    """
    GET /api/sandbox/job_history
    Query params:
      - page (int, default 1)
      - per_page (int, default 50)
      - since (ISO datetime string)
      - succeeded (0|1)
      - job_name (string)
      - user_id (int) OR pass X-User-ID header
      - preview_chars (int) -> return stdout_preview/stderr_preview truncated to this length
    """
    try:
        page = max(1, int(request.args.get("page", 1)))
    except Exception:
        page = 1
    try:
        per_page = max(1, min(200, int(request.args.get("per_page", 50))))
    except Exception:
        per_page = 50

    params = {}
    where_clauses = []

    since = request.args.get("since")
    if since:
        where_clauses.append("created_at >= :since")
        params["since"] = since

    succ = request.args.get("succeeded")
    if succ is not None:
        if str(succ).lower() in ("1", "true", "yes"):
            params["succeeded"] = 1
        else:
            params["succeeded"] = 0
        where_clauses.append("succeeded = :succeeded")

    job_name = request.args.get("job_name")
    if job_name:
        where_clauses.append("job_name = :job_name")
        params["job_name"] = job_name

    # Enforce user filter if provided (header or query)
    req_user = _get_request_user_id()
    if req_user is not None:
        where_clauses.append("user_id = :user_id")
        params["user_id"] = req_user
    else:
        # allow explicit query-based user_id for backwards compatibility
        q_user = request.args.get("user_id")
        if q_user:
            try:
                params["user_id"] = int(q_user)
                where_clauses.append("user_id = :user_id")
            except Exception:
                pass

    params["limit"] = per_page
    offset = (page - 1) * per_page
    params["offset"] = offset

    preview_chars = None
    try:
        pc = request.args.get("preview_chars")
        if pc:
            preview_chars = int(pc)
    except Exception:
        preview_chars = None

    sql = """
      SELECT id, image_tag, image_id, container_name, job_name, succeeded,
             snapshot_tag, stdout, stderr, user_id, host_path, created_at
      FROM job_images
    """
    if where_clauses:
        sql += " WHERE " + " AND ".join(where_clauses)
    sql += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"

    try:
        stmt = text(sql)
        result = _db.session.execute(stmt, params).mappings().all()
        jobs = []
        for row in result:
            r = dict(row)
            ca = r.get("created_at")
            if isinstance(ca, _dt):
                r["created_at"] = ca.isoformat()
            # create previews and remove full stdout/stderr unless preview_chars is None
            full_stdout = r.get("stdout") or ""
            full_stderr = r.get("stderr") or ""
            if preview_chars is not None:
                r["stdout_preview"] = (full_stdout[:preview_chars] + "...") if len(full_stdout) > preview_chars else full_stdout
                r["stderr_preview"] = (full_stderr[:preview_chars] + "...") if len(full_stderr) > preview_chars else full_stderr
                # avoid sending full logs in list view
                r.pop("stdout", None)
                r.pop("stderr", None)
            else:
                # if not requesting preview, keep existing keys but keep them (you may truncate server-side)
                r["stdout_preview"] = full_stdout[:1000] if len(full_stdout) > 1000 else full_stdout
                r["stderr_preview"] = full_stderr[:1000] if len(full_stderr) > 1000 else full_stderr
                r.pop("stdout", None)
                r.pop("stderr", None)
            jobs.append(r)

        # total count for client-side UI (optional: you can expose a faster count query)
        count = len(jobs)
        return jsonify({"success": True, "count": count, "page": page, "per_page": per_page, "jobs": jobs}), 200
    except Exception as e:
        app.logger.exception("job_history failed: %s", e)
        return jsonify({"success": False, "error": "job_history_failed", "detail": str(e)}), 500
    
# GET full logs for a job
@sandbox_bp.route("job_log/<int:job_id>", methods=["GET"])
def sandbox_job_log(job_id):
    """
    Returns full stdout/stderr for a given job_images.id
    GET /api/sandbox/job_log/<job_id>
    Returns: { success, id, stdout, stderr, image_tag, job_name, created_at }
    """
    try:
        from app import db as _db
        stmt = text("""
            SELECT id, image_tag, job_name, stdout, stderr, created_at
            FROM job_images
            WHERE id = :id
            LIMIT 1
        """)
        row = _db.session.execute(stmt, {"id": job_id}).mappings().first()
        if not row:
            return jsonify({"success": False, "error": "not_found", "detail": "job id not found"}), 404

        r = dict(row)
        ca = r.get("created_at")
        try:
            created_at_iso = ca.isoformat() if hasattr(ca, "isoformat") else str(ca)
        except Exception:
            created_at_iso = str(ca)

        return jsonify({
            "success": True,
            "id": int(r.get("id")),
            "image_tag": r.get("image_tag"),
            "job_name": r.get("job_name"),
            "stdout": r.get("stdout") or "",
            "stderr": r.get("stderr") or "",
            "created_at": created_at_iso
        }), 200

    except Exception as e:
        app.logger.exception("job_log failed: %s", e)
        return jsonify({"success": False, "error": "job_log_failed", "detail": str(e)}), 500    

# --- protect the download endpoint so only owner (or admin) can download ---
@sandbox_bp.route("job_log/<int:job_id>/download", methods=["GET"])
def sandbox_job_log_download(job_id):
    try:
        # fetch record
        stmt = text("SELECT id, stdout, stderr, job_name, user_id, created_at, image_tag FROM job_images WHERE id=:id")
        rec = _db.session.execute(stmt, {"id": job_id}).mappings().first()
        if not rec:
            return jsonify({"success": False, "error": "not_found"}), 404

        # auth: allow download only if requester matches user_id OR if no user_id provided (legacy mode)
        req_user = _get_request_user_id()
        if req_user is not None and rec["user_id"] is not None and int(rec["user_id"]) != int(req_user):
            return jsonify({"success": False, "error": "forbidden"}), 403

        # prepare plain-text log
        created_at = rec.get("created_at")
        if isinstance(created_at, _dt):
            created_at = created_at.isoformat()
        body = []
        body.append(f"--- JOB ID: {rec['id']} ---")
        body.append(f"image_tag: {rec.get('image_tag')}")
        body.append(f"job_name: {rec.get('job_name')}")
        body.append(f"created_at: {created_at}")
        body.append("\n--- STDOUT ---\n")
        body.append(rec.get("stdout") or "")
        body.append("\n--- STDERR ---\n")
        body.append(rec.get("stderr") or "")
        out = "\n".join(body)

        # send as attachment
        resp = Response(out, mimetype="text/plain; charset=utf-8")
        filename = f"job-{rec['id']}-{rec.get('job_name') or 'job'}.log"
        resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return resp
    except Exception as e:
        app.logger.exception("job_log download failed: %s", e)
        return jsonify({"success": False, "error": "download_failed", "detail": str(e)}), 500