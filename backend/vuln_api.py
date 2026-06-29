# vuln_api.py
import os
import io
import json
import gzip
import requests
from flask import Blueprint, request, jsonify, current_app as app
from sqlalchemy import or_, text
from db import get_session
from urllib.parse import urlparse
from datetime import datetime
from dateutil import parser as dateparser  # used for parsing published dates when available
from sqlalchemy import func

# Import models used for upserts
from models import Vulnerability, CVE

# ------------------ ML imports added ------------------
import joblib
import numpy as np
import pandas as pd
from scipy import sparse
# ------------------------------------------------------

bp = Blueprint("vuln_api", __name__, url_prefix="/api/vulnlookup")
bp.strict_slashes = False


# -------------------- helpers for parsing raw_data --------------------
def _safe_get_list(obj, path_list, default=None):
    """
    Walk nested dict/list structure safely by following path_list (keys or indices).
    Returns default if any step fails.
    """
    cur = obj
    try:
        for p in path_list:
            if cur is None:
                return default
            if isinstance(p, int):
                # index into list
                if not isinstance(cur, (list, tuple)) or p >= len(cur):
                    return default
                cur = cur[p]
            else:
                if not isinstance(cur, dict):
                    return default
                cur = cur.get(p)
        return cur if cur is not None else default
    except Exception:
        return default


def _parse_date_to_iso(value):
    """Try to parse a date-like string/object to ISO string, otherwise return the original value."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    try:
        parsed = dateparser.parse(value)
        return parsed.isoformat() if parsed else None
    except Exception:
        return None


def parse_raw_data_into_fields(row_like):
    """
    Given a row-like mapping or object that may contain 'raw_data' (JSON string or dict),
    return a dict with extra parsed fields:
      description, published, cvss_score, cvss_severity, references, weaknesses, parsed

    This is defensive and will not raise on malformed JSON.
    """
    extra = {
        "description": None,
        "published": None,
        "cvss_score": None,
        "cvss_severity": None,
        "references": [],
        "weaknesses": [],
        "parsed": None,
    }

    # Accept either dict-like (from as_dict) or object with attribute raw_data
    raw = None
    if isinstance(row_like, dict):
        raw = row_like.get("raw_data") or row_like.get("rawData") or row_like.get("raw")
    else:
        raw = getattr(row_like, "raw_data", None) if hasattr(row_like, "raw_data") else None

    if not raw:
        return extra

    parsed = None
    # raw might already be JSON object/dict if as_dict returned it parsed
    if isinstance(raw, (dict, list)):
        parsed = raw
    else:
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = None

    if not parsed:
        return extra

    # keep parsed for caller (useful for debugging / raw view)
    extra["parsed"] = parsed

    # Many feeds wrap the structured CVE under 'cve' key.
    # fallback to parsed top-level if not present.
    cve = parsed.get("cve") if isinstance(parsed, dict) else None
    if not isinstance(cve, dict):
        # In some feeds top-level is the cve structure
        cve = parsed if isinstance(parsed, dict) else None

    # description lookups: common NVD shapes
    desc = None
    if cve:
        # NVD-like description path
        desc = _safe_get_list(cve, ["descriptions", 0, "value"])
        if not desc:
            desc = _safe_get_list(cve, ["description", "description_data", 0, "value"])
    # try parsed top-level alternatives
    if not desc:
        desc = _safe_get_list(parsed, ["description", "description_data", 0, "value"])
    if not desc:
        # Some sources use 'summary'
        if isinstance(parsed, dict):
            desc = parsed.get("summary") or parsed.get("summary_text") or parsed.get("title")
    extra["description"] = desc

    # published date: several possible keys
    pub = _safe_get_list(cve, ["published"]) if cve else None
    if not pub:
        pub = parsed.get("publishedDate") or parsed.get("published") or parsed.get("published_at") or parsed.get("datePublished")
    extra["published"] = _parse_date_to_iso(pub)

    # Try CVSS v3 shapes: many different shapes exist
    cvss_score = _safe_get_list(cve, ["metrics", "cvssMetricV31", 0, "cvssData", "baseScore"]) if cve else None
    cvss_severity = _safe_get_list(cve, ["metrics", "cvssMetricV31", 0, "cvssData", "baseSeverity"]) if cve else None

    # fallback locations
    if cvss_score is None:
        cvss_score = _safe_get_list(cve, ["metrics", "cvssMetricV3", 0, "cvssData", "baseScore"]) if cve else None
    if cvss_score is None:
        cvss_score = _safe_get_list(parsed, ["impact", "baseMetricV3", "cvssV3", "baseScore"])
    if cvss_severity is None:
        cvss_severity = _safe_get_list(parsed, ["impact", "baseMetricV3", "cvssV3", "baseSeverity"])

    # If still None, try CVSSv2
    if cvss_score is None:
        cvss_score = _safe_get_list(cve, ["metrics", "cvssMetricV2", 0, "cvssData", "baseScore"]) if cve else None
    if cvss_severity is None:
        cvss_severity = _safe_get_list(cve, ["metrics", "cvssMetricV2", 0, "cvssData", "baseSeverity"]) if cve else None

    # Normalize numeric cvss_score when possible
    try:
        if cvss_score is not None:
            cvss_score = float(cvss_score)
    except Exception:
        # leave as-is if conversion fails
        pass

    extra["cvss_score"] = cvss_score
    extra["cvss_severity"] = cvss_severity

    # References extraction (common shapes)
    refs = []
    try:
        if cve and isinstance(cve, dict):
            # NVD-like: cve.references.reference_data => list of {url, name, ...}
            rd = _safe_get_list(cve, ["references", "reference_data"]) or _safe_get_list(cve, ["references"])
            if isinstance(rd, list):
                for r in rd:
                    if isinstance(r, dict):
                        url = r.get("url") or r.get("href") or r.get("link")
                        if url:
                            refs.append(url)
                        else:
                            refs.append(json.dumps(r))
                    else:
                        refs.append(str(r))
        # top-level references
        if not refs and isinstance(parsed, dict):
            toprefs = parsed.get("references") or parsed.get("refs") or parsed.get("links")
            if isinstance(toprefs, list):
                for r in toprefs:
                    if isinstance(r, dict):
                        refs.append(r.get("url") or json.dumps(r))
                    else:
                        refs.append(str(r))
            elif toprefs:
                refs.append(str(toprefs))
    except Exception:
        refs = refs
    extra["references"] = refs

    # Weaknesses / CWEs extraction
    wk = []
    try:
        if cve and isinstance(cve, dict):
            # some feeds: cve.weaknesses => list
            wdata = cve.get("weaknesses") or parsed.get("weaknesses")
            if isinstance(wdata, list):
                for w in wdata:
                    if isinstance(w, dict):
                        # NVD style: description array or id
                        descr = _safe_get_list(w, ["description", 0, "value"]) or w.get("id") or w.get("cwe") or json.dumps(w)
                        wk.append(descr)
                    else:
                        wk.append(str(w))
        else:
            wdata = parsed.get("weaknesses") if isinstance(parsed, dict) else None
            if isinstance(wdata, list):
                for w in wdata:
                    wk.append(w if isinstance(w, str) else json.dumps(w))
    except Exception:
        wk = wk
    extra["weaknesses"] = wk

    return extra


# -------------------- existing code (unchanged, except merging parsed fields on output) --------------------
def _read_url_or_file(feed_url: str, headers: dict = None, timeout: int = 60):
    """
    Read raw bytes from either:
      - an HTTP(S) URL (requests)
      - a local file path or file:// URL (open file)
    Returns: (bytes, source_description)
    Raises: Exception on failure with a clear message
    """
    headers = headers or {}
    parsed = urlparse(feed_url)

    # Handle file:// or plain filesystem paths
    if parsed.scheme == "file" or (parsed.scheme == "" and os.path.exists(feed_url)):
        # allow both: "file:///abs/path" and "/abs/path"
        if parsed.scheme == "file":
            path = os.path.abspath(os.path.join(parsed.netloc, parsed.path))
        else:
            path = os.path.abspath(feed_url)
        if not os.path.exists(path):
            raise FileNotFoundError(f"Local file not found: {path}")
        with open(path, "rb") as fh:
            data = fh.read()
        return data, f"file:{path}"

    # Otherwise treat as HTTP(S)
    if parsed.scheme not in ("http", "https"):
        # try to be helpful
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme} for {feed_url}")

    # Use requests to download
    r = requests.get(feed_url, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.content, f"http:{feed_url}"


def process_feed_bytes(raw_bytes: bytes, source_desc: str):
    """
    Process raw bytes (gzipped or plain JSON), parse JSON, normalize NVD items,
    and upsert into Vulnerability table.
    Returns: dict with import stats or raises Exception which caller should catch.
    """
    # Quick sanity checks: small HTML responses (common when remote host redirects to a human page)
    head_snippet = (raw_bytes[:512] or b"").lstrip()
    if head_snippet.startswith(b"<") or head_snippet.lower().startswith(b"<!doctype"):
        snippet = head_snippet.decode("utf-8", errors="replace")[:800]
        raise ValueError("downloaded_html_instead_of_feed", snippet)

    # Detect gzipped by magic bytes
    is_gz = False
    if len(raw_bytes) >= 2 and raw_bytes[0:2] == b"\x1f\x8b":
        is_gz = True

    if is_gz:
        with gzip.GzipFile(fileobj=io.BytesIO(raw_bytes)) as gz:
            text = gz.read().decode("utf-8", errors="replace")
    else:
        text = raw_bytes.decode("utf-8", errors="replace")

    # parse JSON
    try:
        data = json.loads(text)
    except Exception as e:
        snippet = (text or "")[:1000]
        raise ValueError("invalid_json", str(e), snippet)

    # find items (NVD shape or other)
    items = []
    if isinstance(data, dict) and "CVE_Items" in data:
        items = data.get("CVE_Items", [])
    elif isinstance(data, dict) and "vulnerabilities" in data:
        items = data.get("vulnerabilities", [])
    elif isinstance(data, list):
        items = data
    else:
        raise ValueError("no_cve_items", "Feed did not contain CVE_Items or list")

    session = get_session()
    imported = 0
    try:
        for it in items:
            cve_id = None
            summary = None
            published = None
            last_modified = None
            severity = None
            raw_blob = None
            cvss_val = None

            if isinstance(it, dict):
                meta = it.get("cve", {}).get("CVE_data_meta", {}) or {}
                cve_id = meta.get("ID") or it.get("cve", {}).get("id")
                desc_list = it.get("cve", {}).get("description", {}).get("description_data", [])
                if desc_list:
                    summary = desc_list[0].get("value")
                published = it.get("publishedDate") or it.get("published")
                last_modified = it.get("lastModifiedDate") or it.get("lastModified")
                # best-effort severity and cvss score
                try:
                    cvss_v3 = it.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})
                    if isinstance(cvss_v3, dict):
                        cvss_val = cvss_v3.get("baseScore") or cvss_v3.get("baseSeverity")
                        # if baseScore present, ensure numeric
                        if cvss_val is not None:
                            try:
                                cvss_val = float(cvss_val)
                            except Exception:
                                # sometimes baseSeverity is text (e.g., "HIGH"); keep None
                                cvss_val = None
                    # severity text
                    sev = it.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity")
                except Exception:
                    sev = None
                if not sev:
                    sev = it.get("impact", {}).get("baseMetricV2", {}).get("severity")
                severity = sev or None
                raw_blob = json.dumps(it)
            else:
                continue

            if not cve_id:
                continue

            # --- ensure cves table has this cve_id (upsert minimal row) ---
            try:
                cve_row = session.query(CVE).filter(CVE.cve_id == cve_id).first()
                if not cve_row:
                    # create minimal CVE record so FK constraint won't fail
                    cve_kwargs = {"cve_id": cve_id}
                    if summary:
                        cve_kwargs["summary"] = summary
                    if severity:
                        cve_kwargs["severity"] = severity
                    # parse published date safely
                    if published:
                        try:
                            cve_kwargs["published"] = dateparser.parse(published)
                        except Exception:
                            pass
                    if last_modified:
                        try:
                            cve_kwargs["last_modified"] = dateparser.parse(last_modified)
                        except Exception:
                            pass

                    # store any CVSS v3 numeric score into cve_row if available
                    if cvss_val is not None:
                        # CVE model has cvss_v3 field
                        cve_kwargs["cvss_v3"] = cvss_val

                    cve_row = CVE(**cve_kwargs)
                    session.add(cve_row)
                    # flush to ensure DB sees the new CVE before inserting vulnerabilities that reference it
                    try:
                        session.flush()
                    except Exception as flush_exc:
                        # if flush fails, rollback this item and continue
                        session.rollback()
                        app.logger.debug("Failed to flush new CVE %s, skipping: %s", cve_id, flush_exc)
                        continue
                else:
                    # optionally update cve summary / severity if missing or shorter
                    updated = False
                    if summary and (not cve_row.summary or len(summary) > (len(cve_row.summary) if cve_row.summary else 0)):
                        cve_row.summary = summary
                        updated = True
                    if severity and not cve_row.severity:
                        cve_row.severity = severity
                        updated = True
                    if published and not getattr(cve_row, "published", None):
                        try:
                            cve_row.published = dateparser.parse(published)
                            updated = True
                        except Exception:
                            pass
                    if cvss_val is not None and not getattr(cve_row, "cvss_v3", None):
                        try:
                            cve_row.cvss_v3 = float(cvss_val)
                            updated = True
                        except Exception:
                            pass
                    if updated:
                        session.add(cve_row)
                        try:
                            session.flush()
                        except Exception as flush_exc:
                            session.rollback()
                            app.logger.debug("Failed to flush updated CVE %s: %s", cve_id, flush_exc)
            except Exception as e:
                app.logger.exception("CVE upsert failed for %s: %s", cve_id, e)
                # skip this item safely
                continue

            # Upsert Vulnerability (existing check)
            try:
                existing = session.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
            except Exception:
                existing = None

            if existing:
                updated = False
                if summary and (not existing.description or len(summary) > (len(existing.description) if existing.description else 0)):
                    existing.description = summary
                    updated = True
                if severity and not getattr(existing, "severity", None):
                    existing.severity = severity
                    updated = True
                if raw_blob and not getattr(existing, "raw_data", None):
                    try:
                        if hasattr(existing, "raw_data"):
                            existing.raw_data = raw_blob
                            updated = True
                    except Exception:
                        pass
                # if cvss exists on model, set if missing
                try:
                    if cvss_val is not None and hasattr(existing, "cvss_score") and not getattr(existing, "cvss_score", None):
                        existing.cvss_score = cvss_val
                        updated = True
                except Exception:
                    pass
                if updated:
                    session.add(existing)
            else:
                # create new Vulnerability row; ensure cve_id is set (FK satisfied because cves row exists)
                try:
                    v = Vulnerability(
                        cve_id=cve_id,
                        description=summary,
                        severity=(severity or None),
                        raw_data=(raw_blob or None),
                        published=(dateparser.parse(published) if published else None),
                        last_modified=(dateparser.parse(last_modified) if last_modified else None),
                        created_at=None
                    )
                    # if Vulnerability model has cvss_score, set it
                    try:
                        if cvss_val is not None and hasattr(Vulnerability, "cvss_score"):
                            setattr(v, "cvss_score", cvss_val)
                    except Exception:
                        pass

                    session.add(v)
                    imported += 1
                except Exception as ex:
                    app.logger.debug("Failed to create Vulnerability object for %s: %s", cve_id, ex)
                    # skip, don't fail entire import
                    continue

        # commit once per feed
        session.commit()
    except Exception as e:
        session.rollback()
        app.logger.exception("Failed to import vulnerabilities: %s", e)
        raise
    finally:
        session.close()

    return {"imported": imported, "count_in_feed": len(items), "source": source_desc}


@bp.route("/", methods=["GET"],strict_slashes=False)
def lookup():
    """
    Enhanced lookup with filtering:
      ?cve=CVE-2025-1234
      ?q=openssl                 (search in cve_id or description)
      ?os=windows                (case-insensitive substring match on affected_os)
      ?min_cvss=5.0
      ?max_cvss=9.8
      ?severity=HIGH
      ?source=wordfence
      ?limit=20&offset=0

    Returns JSON: { success: True, count: N, results: [...] }
    """
    session = get_session()
    try:
        # params
        cve = request.args.get("cve")
        q = request.args.get("q")
        os_filter = request.args.get("os")               # e.g. windows, linux, android
        min_cvss = request.args.get("min_cvss")
        max_cvss = request.args.get("max_cvss")
        severity = request.args.get("severity")
        source = request.args.get("source")
        limit = int(request.args.get("limit", 20))
        offset = int(request.args.get("offset", 0))

        if cve:
            # try to fetch vulnerability row + join CVE table for extra fields (if CVE model/table exists)
            try:
                row = session.query(Vulnerability, CVE).outerjoin(
                    CVE, Vulnerability.cve_id == CVE.cve_id
                ).filter(Vulnerability.cve_id == cve).first()
            except Exception:
                row = None

            if not row:
                vuln = session.query(Vulnerability).filter(Vulnerability.cve_id == cve).first()
                if not vuln:
                    return jsonify({"success": True, "result": None}), 200

                try:
                    item = vuln.as_dict()
                except Exception:
                    item = {
                        "id": getattr(vuln, "id", None),
                        "cve_id": getattr(vuln, "cve_id", None),
                        "description": getattr(vuln, "description", None),
                        "published": getattr(vuln, "published", None),
                        "raw_data": getattr(vuln, "raw_data", None),
                        "severity": getattr(vuln, "severity", None),
                        "cvss_score": getattr(vuln, "cvss_score", None) if hasattr(vuln, "cvss_score") else None
                    }

                extra = parse_raw_data_into_fields(item)
                if not item.get("description"):
                    item["description"] = extra.get("description")
                if not item.get("published"):
                    item["published"] = extra.get("published")
                if not item.get("severity"):
                    item["severity"] = extra.get("cvss_severity")
                if not item.get("cvss_score"):
                    item["cvss_score"] = extra.get("cvss_score")

                if isinstance(item.get("published"), datetime):
                    item["published"] = item["published"].isoformat()

                return jsonify({"success": True, "result": item}), 200

            vuln_row, cve_row = row

            try:
                item = vuln_row.as_dict()
            except Exception:
                item = {
                    "id": getattr(vuln_row, "id", None),
                    "cve_id": getattr(vuln_row, "cve_id", None),
                    "description": getattr(vuln_row, "description", None),
                    "published": getattr(vuln_row, "published", None),
                    "raw_data": getattr(vuln_row, "raw_data", None),
                    "severity": getattr(vuln_row, "severity", None),
                    "cvss_score": getattr(vuln_row, "cvss_score", None) if hasattr(vuln_row, "cvss_score") else None
                }

            if "raw_data" not in item or not item.get("raw_data"):
                item["raw_data"] = getattr(vuln_row, "raw_data", None)
            if "description" not in item or not item.get("description"):
                item["description"] = getattr(vuln_row, "description", None)
            if "published" not in item or not item.get("published"):
                item["published"] = getattr(vuln_row, "published", None)
            if "severity" not in item or not item.get("severity"):
                item["severity"] = getattr(vuln_row, "severity", None)
            if "cvss_score" not in item or not item.get("cvss_score"):
                item["cvss_score"] = getattr(vuln_row, "cvss_score", None) if hasattr(vuln_row, "cvss_score") else None

            try:
                if cve_row:
                    cv_summary = getattr(cve_row, "summary", None) if hasattr(cve_row, "__table__") else cve_row.get("summary")
                    cv_published = getattr(cve_row, "published", None) if hasattr(cve_row, "__table__") else cve_row.get("published")
                    cv_cvss = getattr(cve_row, "cvss_v3", None) if hasattr(cve_row, "__table__") else cve_row.get("cvss_v3")
                    if not item.get("description") and cv_summary:
                        item["description"] = cv_summary
                    if not item.get("published") and cv_published:
                        item["published"] = cv_published
                    if not item.get("cvss_score") and cv_cvss:
                        item["cvss_score"] = float(cv_cvss)
            except Exception:
                pass

            extra = parse_raw_data_into_fields(item)
            if not item.get("description"):
                item["description"] = extra.get("description")
            if not item.get("published"):
                item["published"] = extra.get("published")
            if not item.get("severity"):
                item["severity"] = extra.get("cvss_severity")
            if not item.get("cvss_score"):
                item["cvss_score"] = extra.get("cvss_score")

            if isinstance(item.get("published"), datetime):
                item["published"] = item["published"].isoformat()

            return jsonify({"success": True, "result": item}), 200

        qry = session.query(Vulnerability)

        if q:
            pattern = f"%{q}%"
            qry = qry.filter(
                or_(
                    Vulnerability.cve_id.ilike(pattern),
                    Vulnerability.description.ilike(pattern),
                )
            )

        if os_filter:
            os_pat = f"%{os_filter}%"
            if hasattr(Vulnerability, "affected_os"):
                qry = qry.filter(Vulnerability.affected_os.ilike(os_pat))
            else:
                qry = qry.filter(Vulnerability.raw_data.ilike(os_pat))

        if severity:
            qry = qry.filter(Vulnerability.severity.ilike(severity))

        if source:
            src_pat = f"%{source}%"
            if hasattr(Vulnerability, "source"):
                qry = qry.filter(Vulnerability.source.ilike(src_pat))
            else:
                qry = qry.filter(Vulnerability.raw_data.ilike(src_pat))

        try:
            if min_cvss is not None:
                min_val = float(min_cvss)
                if hasattr(Vulnerability, "cvss_score"):
                    qry = qry.filter(Vulnerability.cvss_score >= min_val)
                else:
                    qry = qry.filter(Vulnerability.raw_data.ilike(f'%"baseScore": {min_val}%'))
            if max_cvss is not None:
                max_val = float(max_cvss)
                if hasattr(Vulnerability, "cvss_score"):
                    qry = qry.filter(Vulnerability.cvss_score <= max_val)
                else:
                    qry = qry.filter(Vulnerability.raw_data.ilike(f'%"baseScore": {max_val}%'))
        except ValueError:
            pass

        total = qry.count()
        rows = qry.order_by(Vulnerability.created_at.desc()).limit(limit).offset(offset).all()

        results = []
        for r in rows:
            try:
                item = r.as_dict()
            except Exception:
                item = {
                    "id": getattr(r, "id", None),
                    "cve_id": getattr(r, "cve_id", None),
                    "description": getattr(r, "description", None),
                    "published": getattr(r, "published", None),
                    "raw_data": getattr(r, "raw_data", None),
                    "severity": getattr(r, "severity", None),
                    "cvss_score": getattr(r, "cvss_score", None) if hasattr(r, "cvss_score") else None
                }

            if "raw_data" not in item or not item.get("raw_data"):
                item["raw_data"] = getattr(r, "raw_data", None)
            if "published" not in item or not item.get("published"):
                item["published"] = getattr(r, "published", None)
            if "description" not in item or not item.get("description"):
                item["description"] = getattr(r, "description", None)
            if "severity" not in item or not item.get("severity"):
                item["severity"] = getattr(r, "severity", None)
            if "cvss_score" not in item or not item.get("cvss_score"):
                item["cvss_score"] = getattr(r, "cvss_score", None) if hasattr(r, "cvss_score") else None

            extra = parse_raw_data_into_fields(item)
            if not item.get("description"):
                item["description"] = extra.get("description")
            if not item.get("published"):
                item["published"] = extra.get("published")
            if not item.get("severity"):
                item["severity"] = extra.get("cvss_severity")
            if not item.get("cvss_score"):
                item["cvss_score"] = extra.get("cvss_score")

            if extra.get("references"):
                item["references"] = extra.get("references")
            if extra.get("weaknesses"):
                item["weaknesses"] = extra.get("weaknesses")
            if extra.get("parsed") is not None:
                item["parsed_raw"] = extra.get("parsed")

            if isinstance(item.get("published"), datetime):
                item["published"] = item["published"].isoformat()

            results.append(item)

        return jsonify({"success": True, "count": total, "results": results}), 200

    finally:
        session.close()


# -------------------- ML helper functions (added) --------------------
_MODEL_PACKAGE = None
MODEL_CANDIDATES = [
    # relative to this file
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "best_model.joblib"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models", "best_model.joblib"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "ml_risk_model.joblib"),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models", "ml_risk_model.joblib"),
]

def load_model_package():
    """
    Load and cache the joblib model package.
    Expects a dict with keys: model_name, model, preprocessor, tfidf, numeric_cols, cat_cols, text_col
    """
    global _MODEL_PACKAGE
    if _MODEL_PACKAGE is not None:
        return _MODEL_PACKAGE

    found = None
    for p in MODEL_CANDIDATES:
        if p and os.path.exists(p):
            found = p
            break

    if not found:
        # helpful log + raise so calling code can report meaningful error
        app.logger.error("ML model file not found. Looked for: %s", MODEL_CANDIDATES)
        raise FileNotFoundError(f"ML model not found. Put best_model.joblib in backend/models or update MODEL_CANDIDATES.")

    pkg = joblib.load(found)
    # basic validation
    required = ["model", "preprocessor", "tfidf", "numeric_cols", "cat_cols", "text_col"]
    for k in required:
        if k not in pkg:
            app.logger.warning("Loaded model package missing key: %s", k)
    _MODEL_PACKAGE = pkg
    app.logger.info("Loaded ML model package from %s (model_name=%s)", found, pkg.get("model_name"))
    return _MODEL_PACKAGE

def _make_feature_row_from_mapping(mapping):
    """
    mapping can be:
      - dict from POST body (keys: description, cvss_score, references_count, weaknesses_count, os_count, severity, years_since_published)
      - ORM object (Vulnerability) — we handle that in predict_from_row_like by extracting attributes + parsing raw_data
    Returns a DataFrame with a single row containing training features + text column name matching model package.
    """
    # safe extraction with defaults
    def _get(m, k, default=None):
        if isinstance(m, dict):
            return m.get(k, default)
        return getattr(m, k, default)

    # For counts, try to find common names
    years = _get(mapping, "years_since_published", None)
    if years is None:
        years = _get(mapping, "years", None)
    try:
        years = float(years) if years is not None and years != "" else 0.0
    except Exception:
        years = 0.0

    cvss = _get(mapping, "cvss_score", None)
    try:
        cvss = float(cvss) if cvss is not None and cvss != "" else np.nan
    except Exception:
        cvss = np.nan

    refs = _get(mapping, "references_count", None)
    if refs is None:
        refs = _get(mapping, "references", None)
    try:
        refs = int(refs) if refs is not None and refs != "" else 0
    except Exception:
        refs = 0

    wk = _get(mapping, "weaknesses_count", None)
    if wk is None:
        # sometimes weaknesses is list
        wk = _get(mapping, "weaknesses", None)
        if isinstance(wk, (list, tuple)):
            wk = len(wk)
    try:
        wk = int(wk) if wk is not None and wk != "" else 0
    except Exception:
        wk = 0

    oscount = _get(mapping, "os_count", None)
    if oscount is None:
        # try common flags
        hw = _get(mapping, "has_windows", 0)
        hl = _get(mapping, "has_linux", 0)
        ha = _get(mapping, "has_android", 0)
        try:
            oscount = int(hw) + int(hl) + int(ha)
        except Exception:
            oscount = 0
    try:
        oscount = int(oscount)
    except Exception:
        oscount = 0

    severity = _get(mapping, "severity", None)
    # attempt to extract description from mapping or parsed raw_data
    desc = _get(mapping, "description", None)
    if not desc and hasattr(mapping, "raw_data"):
        try:
            extra = parse_raw_data_into_fields(mapping)
            desc = extra.get("description") or desc
            # if cvss missing fill
            if _get(mapping, "cvss_score", None) is None and extra.get("cvss_score") is not None:
                cvss = extra.get("cvss_score")
        except Exception:
            pass
    if not desc and isinstance(mapping, dict):
        # try parsed fields in dict
        desc = mapping.get("description_text") or mapping.get("description") or mapping.get("summary") or ""

    # Build final row - ensure column names match training
    row = {
        "years_since_published": float(years),
        "cvss_score": float(cvss) if not np.isnan(cvss) else np.nan,
        "references_count": int(refs),
        "weaknesses_count": int(wk),
        "os_count": int(oscount),
        "severity": severity if severity is not None else None,
        # training expects text column named 'description_text' per your pipeline
        "description_text": desc if desc is not None else ""
    }
    return pd.DataFrame([row])

def predict_from_df(df_X, model_pkg):
    """
    df_X: dataframe with columns matching numeric + categorical + text_col
    model_pkg: loaded model package
    returns numpy array of predictions
    """
    model = model_pkg["model"]
    preprocessor = model_pkg["preprocessor"]
    tfidf = model_pkg["tfidf"]
    text_col = model_pkg["text_col"]

    # numeric/categorical -> dense matrix via preprocessor
    X_numcat = preprocessor.transform(df_X)  # dense ndarray

    # text -> tfidf sparse
    X_text = tfidf.transform(df_X[text_col].fillna(""))

    # combine
    left = sparse.csr_matrix(X_numcat)
    right = X_text if sparse.issparse(X_text) else sparse.csr_matrix(X_text)
    X_comb = sparse.hstack([left, right], format="csr")

    model_cls_name = getattr(model, "__class__", type(model)).__name__
    # convert to dense if required
    if model_cls_name in ("HistGradientBoostingRegressor", "HistGradientBoostingClassifier"):
        X_use = X_comb.toarray()
    else:
        X_use = X_comb

    preds = model.predict(X_use)
    return np.asarray(preds).ravel()

# -------------------- NEW: extended predict route (supports POST JSON & GET by cve) --------------------
@bp.route("/predict", methods=["GET", "POST", "OPTIONS"])
def predict_cve():
    """
    GET /api/vulnlookup/predict?cve=...  (DB-driven flow)
    POST /api/vulnlookup/predict        (new) Accepts JSON body for single prediction:
       - {"description":"...", "cvss_score": 7.8, ...}
    OPTIONS preflight allowed.
    """
    # quick helper used for numeric coercion
    def _safe_get_scalar(dct, key):
        try:
            if not isinstance(dct, dict):
                return None
            v = dct.get(key)
            if v is None:
                return None
            return float(v)
        except Exception:
            return None

    # OPTIONS preflight
    if request.method == "OPTIONS":
        return jsonify({}), 200

        # GET flow: DB lookup + prediction
    if request.method == "GET":
        # optional compatibility: try to import only predict_from_row_like from project's ml_predictor
        # DO NOT import load_model_package here because we have a local implementation in this file
        try:
            from ml_predictor import predict_from_row_like  # optional
        except Exception:
            predict_from_row_like = None

        session = get_session()
        try:
            cve = request.args.get("cve")
            if not cve:
                return jsonify({"success": False, "error": "no_cve_param"}), 400

            vuln = session.query(Vulnerability).filter(Vulnerability.cve_id == cve).first()
            if not vuln:
                return jsonify({"success": True, "cve": cve, "predicted": None, "error": "not_found"}), 200

            # ensure model loaded (will raise informative error if not present)
            try:
                load_model_package()
            except Exception as e:
                return jsonify({"success": False, "error": "model_load_failed", "detail": str(e)}), 500

            try:
                # try project's ml_predictor compatibility first (if imported above)
                try:
                    if predict_from_row_like:
                        res = predict_from_row_like(vuln)
                        if isinstance(res, dict) and "predicted" in res:
                            return jsonify({"success": True, "cve": cve, "predicted": res.get("predicted"), "model": res.get("model_name")}), 200
                except Exception:
                    # compatibility function failed — fall back to local flow
                    pass

                # fallback: use local loader + predictor
                pkg = load_model_package()
                df = _make_feature_row_from_mapping(vuln)
                preds = predict_from_df(df, pkg)
                return jsonify({"success": True, "cve": cve, "predicted": float(preds[0]), "model": pkg.get("model_name")}), 200
            except Exception as e:
                return jsonify({"success": False, "error": "prediction_failed", "detail": str(e)}), 500
        finally:
            session.close()

    # POST flow: ad-hoc prediction from JSON body
    if request.method == "POST":
        try:
            payload = request.get_json(force=True)
        except Exception as e:
            return jsonify({"success": False, "error": "invalid_json", "detail": str(e)}), 400

        if isinstance(payload, dict) and payload.get("cve"):
            return jsonify({"success": True, "info": f"Use GET /api/vulnlookup?cve={payload.get('cve')} to fetch DB record and GET /api/vulnlookup/predict?cve={payload.get('cve')} for prediction."}), 200

        try:
            pkg = load_model_package()
        except Exception as e:
            return jsonify({"success": False, "error": "model_load_failed", "detail": str(e)}), 500

        try:
            if isinstance(payload, dict):
                if "cvss_score" in payload:
                    payload["cvss_score"] = _safe_get_scalar(payload, "cvss_score")
                if "years_since_published" in payload:
                    payload["years_since_published"] = _safe_get_scalar(payload, "years_since_published")

                # ✅ AUTO FIX INPUT BEFORE MODEL

                # 1. Ensure description exists
                if not payload.get("description"):
                    payload["description"] = payload.get("query", "")

                # 2. Fix CVSS (IMPORTANT 🔥)
                cvss = payload.get("cvss_score")

                if cvss is None or cvss == "" or cvss == "NaN":
                # fallback logic
                    desc = (payload.get("description") or "").lower()

                if "critical" in desc:
                    cvss = 9.0
                elif "overflow" in desc or "rce" in desc:
                    cvss = 8.5
                elif "sql" in desc or "injection" in desc:
                    cvss = 7.5
                elif "xss" in desc:
                    cvss = 6.5
                else:
                    cvss = 5.0   # default safe value

            payload["cvss_score"] = float(cvss)

            # 3. Ensure severity exists
            if not payload.get("severity"):
                if cvss >= 9:
                    payload["severity"] = "CRITICAL"
                elif cvss >= 7:
                    payload["severity"] = "HIGH"
                elif cvss >= 4:
                    payload["severity"] = "MEDIUM"
                else:
                    payload["severity"] = "LOW"

            # ✅ Now run model
            df = _make_feature_row_from_mapping(payload)
            preds = predict_from_df(df, pkg)
            prediction_value = float(preds[0])

            # ✅ SAVE LOG (simple file logging)
            try:
                log_path = os.path.join(os.path.dirname(__file__), "prediction_logs.log")

                with open(log_path, "a") as f:
                    f.write(json.dumps({
                        "timestamp": str(datetime.now()),
                        "input": payload,
                        "prediction": prediction_value
                    }) + "\n")

                model_status = "saved"
            except Exception as e:
                model_status = "not saved"

            return jsonify({
    "success": True,
    "model": pkg.get("model_name"),
    "predicted": prediction_value,

    # ✅ ADD THIS (VERY IMPORTANT)
    "cvss_score": payload.get("cvss_score"),

    "model_logging": model_status
}), 200
        except Exception as e:
            app.logger.exception("POST /predict failed: %s", e)
            return jsonify({"success": False, "error": "predict_failed", "detail": str(e)}), 500


# ---- batch predict endpoint (added) ----
@bp.route("/predict-batch", methods=["POST"])
def predict_batch():
    """
    POST JSON body: {"items": [ {description:..., cvss_score:..., ...}, {...} ]}
    Returns: {"success": True, "model": "<name>", "predictions": [<float>, ...]}
    """
    try:
        payload = request.get_json(force=True)
    except Exception as e:
        return jsonify({"success": False, "error": "invalid_json", "detail": str(e)}), 400

    items = payload.get("items") if isinstance(payload, dict) else None
    if not items or not isinstance(items, list):
        return jsonify({"success": False, "error": "no_items_provided"}), 400

    try:
        pkg = load_model_package()
    except Exception as e:
        return jsonify({"success": False, "error": "model_load_failed", "detail": str(e)}), 500

    try:
        dfs = [_make_feature_row_from_mapping(it) for it in items]
        df_all = pd.concat(dfs, ignore_index=True)
        preds = predict_from_df(df_all, pkg)
        predictions = [float(x) for x in preds]

        # ✅ Convert prediction → CVSS (0–10 scale)
        cvss_scores = [round((p / 100) * 10, 1) for p in predictions]

        # ✅ Add simple logging
        try:
            log_path = os.path.join(os.path.dirname(__file__), "prediction_logs.log")
            with open(log_path, "a") as f:
                f.write(json.dumps({
                    "timestamp": str(datetime.now()),
                    "inputs": items,
                    "predictions": predictions,
                    "cvss_scores": cvss_scores
                }) + "\n")
            model_status = "saved"
        except:
            model_status = "not saved"

        return jsonify({
            "success": True,
            "model": pkg.get("model_name"),
            "predictions": predictions,
            "cvss_scores": cvss_scores,   # ✅ THIS FIXES CVSS
            "model_logging": model_status # ✅ THIS FIXES LOGGING
        }), 200
    except Exception as e:
        app.logger.exception("Batch prediction failed: %s", e)
        return jsonify({"success": False, "error": "predict_failed", "detail": str(e)}), 500


# -------------------- summary endpoint for dashboard aggregation --------------------
@bp.route("/summary", methods=["GET"])
def summary():
    """
    Returns aggregated threat statistics for dashboard:
      - total_cves
      - counts for 'critical' and 'high' severities (case-insensitive)
      - avg_cvss (null if no scores)
      - counts by OS: windows, linux, android, other
      - last_import datetime (max(created_at))
    """
    session = get_session()
    try:
        total_row = session.execute(text("SELECT COUNT(*) AS total FROM vulnerabilities")).fetchone()
        total = int(total_row[0]) if total_row and total_row[0] is not None else 0

        critical_row = session.execute(
            text("SELECT COUNT(*) FROM vulnerabilities WHERE LOWER(severity) = 'critical'")
        ).fetchone()
        critical = int(critical_row[0]) if critical_row and critical_row[0] is not None else 0

        high_row = session.execute(
            text("SELECT COUNT(*) FROM vulnerabilities WHERE LOWER(severity) = 'high'")
        ).fetchone()
        high = int(high_row[0]) if high_row and high_row[0] is not None else 0

        avg_cvss = None
        try:
            if hasattr(Vulnerability, "cvss_score"):
                avg_row = session.query(func.avg(Vulnerability.cvss_score)).scalar()
                avg_cvss = float(avg_row) if avg_row is not None else None
            else:
                avg_row = session.query(func.avg(CVE.cvss_v3)) \
                    .select_from(Vulnerability) \
                    .join(CVE, Vulnerability.cve_id == CVE.cve_id, isouter=True) \
                    .scalar()
                avg_cvss = float(avg_row) if avg_row is not None else None
        except Exception:
            avg_cvss = None

        os_row = session.execute(text("""
            SELECT
              SUM(CASE WHEN LOWER(COALESCE(affected_os, '')) LIKE '%windows%' OR LOWER(COALESCE(raw_data,'')) LIKE '%windows%' OR LOWER(COALESCE(description,'')) LIKE '%windows%' THEN 1 ELSE 0 END) AS windows,
              SUM(CASE WHEN LOWER(COALESCE(affected_os, '')) LIKE '%linux%'   OR LOWER(COALESCE(raw_data,'')) LIKE '%linux%'   OR LOWER(COALESCE(description,'')) LIKE '%linux%'   THEN 1 ELSE 0 END) AS linux,
              SUM(CASE WHEN LOWER(COALESCE(affected_os, '')) LIKE '%android%' OR LOWER(COALESCE(raw_data,'')) LIKE '%android%' OR LOWER(COALESCE(description,'')) LIKE '%android%' THEN 1 ELSE 0 END) AS android
            FROM vulnerabilities
        """)).mappings().fetchone()

        if os_row is None:
            win = lin = andr = 0
        else:
            win = int(os_row.get('windows') or 0)
            lin = int(os_row.get('linux') or 0)
            andr = int(os_row.get('android') or 0)

        other = max(0, total - (win + lin + andr))

        last_row = session.execute(text("SELECT MAX(created_at) FROM vulnerabilities")).fetchone()
        last_import = None
        if last_row and last_row[0] is not None:
            if isinstance(last_row[0], datetime):
                last_import = last_row[0].isoformat()
            else:
                last_import = str(last_row[0])

        return jsonify({
            "success": True,
            "total_cves": total,
            "critical_severity": critical,
            "high_severity": high,
            "avg_cvss": round(avg_cvss, 2) if avg_cvss is not None else None,
            "by_os": {
                "windows": win,
                "linux": lin,
                "android": andr,
                "other": other
            },
            "last_import": last_import
        }), 200
    finally:
        session.close()


@bp.route("/import", methods=["POST"])
def import_vulns():
    """
    POST JSON: { "url": "<http(s) or file path or file://...>" }
    """
    payload = None
    try:
        payload = request.get_json(force=True)
    except Exception as e:
        return jsonify({"success": False, "error": "invalid_json", "detail": str(e)}), 400

    feed_url = (payload or {}).get("url")
    if not feed_url:
        return jsonify({"success": False, "error": "no_url_provided"}), 400

    headers = {"User-Agent": "ShieldPatchImporter/1.0"}
    try:
        raw_bytes, source_desc = _read_url_or_file(feed_url, headers=headers, timeout=60)
    except Exception as e:
        app.logger.exception("Failed to read feed: %s", e)
        return jsonify({"success": False, "error": "read_failed", "detail": str(e)}), 500

    try:
        stats = process_feed_bytes(raw_bytes, source_desc)
    except ValueError as ve:
        err_info = ve.args
        if len(err_info) >= 2:
            return jsonify({"success": False, "error": err_info[0], "detail": err_info[1]}), 400
        return jsonify({"success": False, "error": "invalid_feed", "detail": str(ve)}), 400
    except Exception as e:
        app.logger.exception("Import failed: %s", e)
        return jsonify({"success": False, "error": "import_failed", "detail": str(e)}), 500

    return jsonify({"success": True, "imported": stats.get("imported", 0), "source": stats.get("source"), "count_in_feed": stats.get("count_in_feed")}), 200


@bp.route("/import-upload", methods=["POST"])
def import_vulns_upload():
    """
    POST multipart/form-data with file field "file".
    """
    if "file" not in request.files:
        return jsonify({"success": False, "error": "no_file_in_request"}), 400

    f = request.files["file"]
    filename = f.filename or "uploaded_feed"
    try:
        raw_bytes = f.read()
        source_desc = f"upload:{filename}"
    except Exception as e:
        app.logger.exception("Failed to read uploaded file: %s", e)
        return jsonify({"success": False, "error": "read_failed", "detail": str(e)}), 500

    try:
        stats = process_feed_bytes(raw_bytes, source_desc)
    except ValueError as ve:
        err_info = ve.args
        if len(err_info) >= 2:
            return jsonify({"success": False, "error": err_info[0], "detail": err_info[1]}), 400
        return jsonify({"success": False, "error": "invalid_feed", "detail": str(ve)}), 400
    except Exception as e:
        app.logger.exception("Import-upload failed: %s", e)
        return jsonify({"success": False, "error": "import_failed", "detail": str(e)}), 500

    return jsonify({"success": True, "imported": stats.get("imported", 0), "source": stats.get("source"), "count_in_feed": stats.get("count_in_feed")}), 200