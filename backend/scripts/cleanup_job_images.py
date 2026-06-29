#!/usr/bin/env python3
"""
cleanup_job_images.py

Deletes old "job" docker images (e.g. repository/tag starting with
'a.b.c/job-' or default 'shieldpatch/sandbox:job-') and logs each deletion
to the MySQL table `job_image_deletions`. Has dry-run mode and CSV fallback.

Usage examples:
  # dry-run, default 30 days
  python cleanup_job_images.py --dry-run

  # actually delete images older than 7 days and log to DB via env vars
  export DB_HOST=localhost DB_USER=shieldpatch_user DB_PASS='yourpass' DB_NAME=ShieldPatch
  python cleanup_job_images.py --days 7

  # custom pattern and user
  python cleanup_job_images.py --pattern 'shieldpatch/sandbox:job-' --user admin
"""

from __future__ import annotations
import argparse
import subprocess
import shlex
import json
import os
import csv
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Tuple
import os
import pymysql
from datetime import datetime

# Try to import pymysql (optional). If not installed, script falls back to CSV logging.
try:
    import pymysql
except Exception:
    pymysql = None

DEFAULT_PATTERN = "shieldpatch/sandbox:job-"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FALLBACK = os.path.join(SCRIPT_DIR, "deletions_log.csv")


# configure via env (set these in your env or .env)
DB_HOST = os.getenv("JOB_DB_HOST", "localhost")
DB_PORT = int(os.getenv("JOB_DB_PORT", "3306"))
DB_USER = os.getenv("JOB_DB_USER", "shieldpatch_user")
DB_PASS = os.getenv("JOB_DB_PASS", "ajaykumar%40040702")
DB_NAME = os.getenv("JOB_DB_NAME", "ShieldPatch")

def db_log_deletion(image_id, image_tag, container_name=None, job_name=None, user_id=None,
                    removed_stdout=None, removed_stderr=None, removed_succeeded=0, host_path=None, note=None):
    try:
        conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS, db=DB_NAME, charset='utf8mb4')
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO job_image_deletions
                (job_image_id, image_id, image_tag, container_name, job_name, user_id,
                 removed_at, removed_by, removed_stdout, removed_stderr, removed_succeeded, host_path, note)
                VALUES (NULL, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                image_id, image_tag, container_name, job_name, user_id,
                datetime.utcnow(), "system", removed_stdout, removed_stderr, removed_succeeded, host_path, note
            ))
            conn.commit()
        conn.close()
        return True
    except Exception as e:
        # fallback to CSV logging (script already does CSV fallback) — just return False
        print("[DB LOGGING FAILED]", e)
        return False


def run_cmd(cmd: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    """Run command and return (rc, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired as e:
        return 124, "", f"timeout after {timeout}s"
    except Exception as e:
        return 1, "", str(e)


def list_docker_images() -> List[Dict]:
    """
    Return list of images as dicts: { 'repo_tag': 'repo:tag', 'id': '<image_id>' }.
    Uses docker images --format to avoid parsing table headers.
    """
    rc, out, err = run_cmd(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}||{{.ID}}"])
    if rc != 0:
        raise RuntimeError(f"docker images failed: {err}")
    images = []
    for line in out.splitlines():
        if "||" not in line:
            continue
        repo_tag, imgid = line.split("||", 1)
        images.append({"repo_tag": repo_tag.strip(), "id": imgid.strip()})
    return images


def image_created_iso(image_id: str) -> Optional[str]:
    """Return image .Created as ISO string via docker image inspect, or None."""
    rc, out, err = run_cmd(["docker", "image", "inspect", "--format", "{{.Created}}", image_id])
    if rc != 0 or not out:
        return None
    return out.strip()


def parse_iso_to_dt(iso: str) -> Optional[datetime]:
    """
    Parse docker's .Created ISO timestamp to aware UTC datetime.
    Example value: '2025-12-09T09:07:34.123456789Z'
    """
    if not iso:
        return None
    try:
        # Trim excessive fractional seconds if present and ensure Z -> +00:00
        iso_norm = iso.rstrip("Z")
        # some outputs include nanoseconds; python can parse up to microseconds.
        if "." in iso_norm:
            base, frac = iso_norm.split(".", 1)
            # keep only microseconds (6 digits)
            frac = frac[:6]
            iso_norm = f"{base}.{frac}"
        dt = datetime.fromisoformat(iso_norm).replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        # fallback try parsing naive
        try:
            return datetime.fromisoformat(iso).astimezone(timezone.utc)
        except Exception:
            return None


def should_delete(created_dt: Optional[datetime], days_threshold: int) -> bool:
    if created_dt is None:
        # be conservative: do not delete images with unknown created time
        return False
    age = datetime.now(timezone.utc) - created_dt
    return age >= timedelta(days=days_threshold)


def insert_db_record(db_conf: Dict, record: Dict) -> bool:
    """
    Try to insert a record into job_image_deletions table.
    db_conf: {host, user, password, database, port}
    record: dict matching columns: job_image_id (nullable), image_id, image_tag, container_name,
            job_name, user_id, removed_stdout, removed_stderr, removed_succeeded (0/1), host_path, note
    Returns True if insertion succeeded.
    """
    if pymysql is None:
        return False
    try:
        conn = pymysql.connect(host=db_conf.get("host", "localhost"),
                               user=db_conf["user"],
                               password=db_conf.get("password", ""),
                               database=db_conf.get("database"),
                               port=int(db_conf.get("port", 3306)),
                               charset="utf8mb4",
                               cursorclass=pymysql.cursors.DictCursor,
                               autocommit=True)
        with conn.cursor() as cur:
            sql = """
            INSERT INTO job_image_deletions
            (job_image_id, image_id, image_tag, container_name, job_name, user_id,
             removed_stdout, removed_stderr, removed_succeeded, host_path, note)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cur.execute(sql, (
                record.get("job_image_id"),
                record.get("image_id"),
                record.get("image_tag"),
                record.get("container_name"),
                record.get("job_name"),
                record.get("user_id"),
                record.get("removed_stdout"),
                record.get("removed_stderr"),
                int(bool(record.get("removed_succeeded"))),
                record.get("host_path"),
                record.get("note")
            ))
        conn.close()
        return True
    except Exception as e:
        print(f"[DB] insert failed: {e}")
        return False


def append_csv_fallback(path: str, record: Dict):
    """Append a CSV row to fallback log file if DB insert fails or DB not configured."""
    fieldnames = [
        "ts_utc",
        "job_image_id", "image_id", "image_tag", "container_name", "job_name", "user_id",
        "removed_succeeded", "removed_stdout", "removed_stderr", "host_path", "note"
    ]
    exists = os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        row = {
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "job_image_id": record.get("job_image_id"),
            "image_id": record.get("image_id"),
            "image_tag": record.get("image_tag"),
            "container_name": record.get("container_name"),
            "job_name": record.get("job_name"),
            "user_id": record.get("user_id"),
            "removed_succeeded": int(bool(record.get("removed_succeeded"))),
            "removed_stdout": record.get("removed_stdout"),
            "removed_stderr": record.get("removed_stderr"),
            "host_path": record.get("host_path"),
            "note": record.get("note")
        }
        writer.writerow(row)


def main():
    p = argparse.ArgumentParser(description="Cleanup old job docker images and log deletions")
    p.add_argument("--days", type=int, default=30, help="Age (days) threshold for deletion (default 30)")
    p.add_argument("--dry-run", action="store_true", help="Do not delete; just print what would be done")
    p.add_argument("--pattern", type=str, default=DEFAULT_PATTERN, help=f"Match image repo_tag prefix (default '{DEFAULT_PATTERN}')")
    p.add_argument("--user", type=str, default=os.environ.get("CLEANUP_USER", "system"), help="actor performing deletion")
    p.add_argument("--db-host", type=str, default=os.environ.get("DB_HOST"))
    p.add_argument("--db-user", type=str, default=os.environ.get("DB_USER"))
    p.add_argument("--db-pass", type=str, default=os.environ.get("DB_PASS"))
    p.add_argument("--db-name", type=str, default=os.environ.get("DB_NAME") or os.environ.get("DB_DATABASE") or "ShieldPatch")
    p.add_argument("--db-port", type=int, default=int(os.environ.get("DB_PORT") or 3306))
    p.add_argument("--host-path", type=str, default=os.environ.get("SANDBOX_HOST_PATH") or "")
    args = p.parse_args()

    db_conf = None
    if args.db_host and args.db_user and args.db_name:
        db_conf = {
            "host": args.db_host,
            "user": args.db_user,
            "password": args.db_pass or "",
            "database": args.db_name,
            "port": args.db_port
        }
        print(f"[INFO] DB logging enabled (host={db_conf['host']} user={db_conf['user']})")
    else:
        print("[INFO] DB logging disabled / not configured. Will write CSV fallback.")

    try:
        images = list_docker_images()
    except Exception as e:
        print(f"[ERROR] Failed to list docker images: {e}")
        return 2

    to_delete = []
    for img in images:
        repo_tag = img["repo_tag"]
        if not repo_tag.startswith(args.pattern):
            continue
        created_iso = image_created_iso(img["id"])
        created_dt = parse_iso_to_dt(created_iso) if created_iso else None
        if should_delete(created_dt, args.days):
            to_delete.append({"repo_tag": repo_tag, "id": img["id"], "created_iso": created_iso, "created_dt": created_dt})

    if not to_delete:
        print(f"[OK] No images matching pattern '{args.pattern}' older than {args.days} days found.")
        return 0

    print(f"[FOUND] {len(to_delete)} images older than {args.days} days (pattern='{args.pattern}'):")
    for i in to_delete:
        cd = i["created_dt"].isoformat() if i.get("created_dt") else "unknown"
        print(f"  - {i['repo_tag']}  id={i['id']}  created={cd}")

    if args.dry_run:
        print("[DRY-RUN] No images will be deleted.")
        return 0

    # proceed to delete each image
    summary = []
    for img in to_delete:
        image_ref = img["id"]  # safer than repo:tag for deletion by id
        print(f"[DEL] Removing image {img['repo_tag']} ({image_ref}) ...")
        rc, out, err = run_cmd(["docker", "rmi", image_ref], timeout=60)
        succeeded = (rc == 0)
        print(f"    rc={rc} succeeded={succeeded}")
        if out:
            print("    stdout:", out)
        if err:
            print("    stderr:", err)

        rec = {
            "job_image_id": None,
            "image_id": image_ref,
            "image_tag": img["repo_tag"],
            "container_name": None,
            "job_name": None,
            "user_id": None,
            "removed_stdout": out,
            "removed_stderr": err,
            "removed_succeeded": int(succeeded),
            "host_path": args.host_path or None,
            "note": f"deleted_by={args.user}"
        }

        # Try DB insert, else fallback CSV
        db_ok = False
        if db_conf:
            try:
                db_ok = insert_db_record(db_conf, rec)
                if db_ok:
                    print("    [DB] logged deletion to job_image_deletions")
            except Exception as e:
                print(f"    [DB] insert exception: {e}")
                db_ok = False

        if not db_ok:
            append_csv_fallback(CSV_FALLBACK, rec)
            print(f"    [CSV] appended fallback log to {CSV_FALLBACK}")

        summary.append({"image": img["repo_tag"], "id": image_ref, "deleted": succeeded})

    print("[DONE] Summary:")
    for s in summary:
        print(f"  - {s['image']} id={s['id']} deleted={s['deleted']}")

    return 0


if __name__ == "__main__":
    exit(main())