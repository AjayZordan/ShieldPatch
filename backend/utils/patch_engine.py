# backend/utils/patch_engine.py
"""
Patch engine loader & simple search.
Prefers MySQL (ShieldPatch.patches) and falls back to backend/data/patches.json.
"""

import os
import json
from typing import List, Dict, Any

# DB defaults — adapt with env if you prefer
DB_HOST = os.getenv("PATCH_DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("PATCH_DB_PORT", "3306"))
DB_USER = os.getenv("PATCH_DB_USER", "shieldpatch_user")
DB_PASS = os.getenv("PATCH_DB_PASS", "ajaykumar@040702")
DB_NAME = os.getenv("PATCH_DB_NAME", "ShieldPatch")

THIS_DIR = os.path.dirname(os.path.dirname(__file__))  # backend/utils -> backend
PATCH_JSON = os.path.join(THIS_DIR, "data", "patches.json")

# ---------------------------
# JSON fallback loader
# ---------------------------
def load_patches_from_json() -> List[Dict[str, Any]]:
    try:
        with open(PATCH_JSON, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            # sometimes file may be dict { "patches": [...] }
            if isinstance(data, dict) and "patches" in data and isinstance(data["patches"], list):
                return data["patches"]
    except Exception:
        pass
    return []

# ---------------------------
# MySQL loader
# ---------------------------
def _get_mysql_conn():
    try:
        import pymysql
    except Exception:
        return None
    try:
        conn = pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASS,
            db=DB_NAME,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
        )
        return conn
    except Exception:
        return None

def load_patches_from_db() -> List[Dict[str, Any]]:
    conn = _get_mysql_conn()
    if not conn:
        return []
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM patches ORDER BY verified DESC, confidence DESC, updated_at DESC LIMIT 5000")
            rows = cur.fetchall()
            # normalize JSON fields if needed
            for r in rows:
                if isinstance(r.get("cpe_matches"), str):
                    try:
                        r["cpe_matches"] = json.loads(r["cpe_matches"])
                    except Exception:
                        # store as single-element list if not valid JSON
                        r["cpe_matches"] = [r["cpe_matches"]] if r["cpe_matches"] else []
            return rows
    except Exception:
        return []
    finally:
        conn.close()

# unified loader
def load_patches() -> List[Dict[str, Any]]:
    # Try DB first
    rows = load_patches_from_db()
    if rows:
        return rows
    # Fallback to JSON file in repo
    return load_patches_from_json()

# ---------------------------
# Simple matching utilities
# ---------------------------
def recommend_by_cve(cve_id: str) -> List[Dict[str, Any]]:
    if not cve_id:
        return []
    c = cve_id.strip().upper()
    patches = load_patches()
    return [p for p in patches if (p.get("cve_id") and str(p.get("cve_id")).strip().upper() == c)]

def recommend_by_product(q: str) -> List[Dict[str, Any]]:
    if not q:
        return []
    ql = q.strip().lower()
    patches = load_patches()
    out = []
    for p in patches:
        title = (p.get("title") or "").lower()
        vendor = (p.get("vendor") or "").lower()
        cpe_matches = p.get("cpe_matches") or []
        # cpe_matches may be JSON string or list — normalize
        if isinstance(cpe_matches, str):
            try:
                cpe_matches = json.loads(cpe_matches)
            except Exception:
                cpe_matches = [cpe_matches]
        cpe_text = " ".join(cpe_matches).lower() if isinstance(cpe_matches, (list, tuple)) else str(cpe_matches).lower()
        if ql in title or ql in vendor or ql in cpe_text:
            out.append(p)
    return out

def recommend_patch(query: str) -> List[Dict[str, Any]]:
    if not query:
        return []
    q = query.strip()
    # if CVE-like
    if q.upper().startswith("CVE-"):
        res = recommend_by_cve(q)
        if res:
            return res
    # fallback to product search
    return recommend_by_product(q)