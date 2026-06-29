#!/usr/bin/env python3
# merge_os_csv.py
# Merge OS-enriched CSV into existing Vulnerability rows (fills affected_os, cvss_score, description, severity).

import csv
import os
import sys
from decimal import Decimal, InvalidOperation

# adjust this import path if needed to match your project layout
from db import get_session
from models import Vulnerability, CVE
from dateutil import parser as dateparser

# Path you provided
CSV_PATH = "/Users/ajaykumar/Desktop/ShieldPatch/Datasets/combined_work/nvd_vulnerabilities_with_os.csv"

def normalize_cve(raw):
    if raw is None:
        return None
    s = str(raw).strip()
    if s == "":
        return None
    return s.upper()

def to_float_safe(val):
    if val is None:
        return None
    v = str(val).strip()
    if v == "":
        return None
    try:
        # handle values like "9.8" or "7.5"
        return float(v)
    except (ValueError, TypeError):
        # try Decimal then float
        try:
            return float(Decimal(v))
        except Exception:
            return None

def guess_headers(headers):
    """
    Given CSV header list, return best mapping for:
      cve_col, desc_col, cvss_col, os_col, severity_col
    """
    lower = [h.strip().lower() for h in headers]
    mapping = {}
    # CVE
    for cand in ("cve id", "cve_id", "cveid", "cve"):
        if cand in lower:
            mapping["cve_col"] = headers[lower.index(cand)]
            break
    if "cve_col" not in mapping:
        # fallback to first column
        mapping["cve_col"] = headers[0]

    # Description
    for cand in ("description", "desc"):
        if cand in lower:
            mapping["desc_col"] = headers[lower.index(cand)]
            break
    if "desc_col" not in mapping:
        mapping["desc_col"] = None

    # CVSS Score
    for cand in ("cvss score", "cvss_score", "score", "cvss"):
        if cand in lower:
            mapping["cvss_col"] = headers[lower.index(cand)]
            break
    if "cvss_col" not in mapping:
        mapping["cvss_col"] = None

    # Affected OS
    for cand in ("affected os", "affected_os", "os", "affected_os(s)"):
        if cand in lower:
            mapping["os_col"] = headers[lower.index(cand)]
            break
    if "os_col" not in mapping:
        mapping["os_col"] = None

    # Severity
    for cand in ("severity",):
        if cand in lower:
            mapping["severity_col"] = headers[lower.index(cand)]
            break
    if "severity_col" not in mapping:
        mapping["severity_col"] = None

    return mapping

def main(csv_path=CSV_PATH, force_cvss=False):
    if not os.path.exists(csv_path):
        print(f"CSV not found: {csv_path}", file=sys.stderr)
        return 2

    inserted = 0
    updated = 0
    skipped_no_cve = 0
    rows_processed = 0

    session = get_session()
    try:
        with open(csv_path, newline='', encoding='utf-8') as fh:
            reader = csv.DictReader(fh)
            headers = reader.fieldnames or []
            mapping = guess_headers(headers)

            print("Using mapping:", mapping)

            for row in reader:
                rows_processed += 1
                raw_cve = row.get(mapping.get("cve_col")) if mapping.get("cve_col") else None
                cve_id = normalize_cve(raw_cve)
                if not cve_id:
                    skipped_no_cve += 1
                    continue

                desc = row.get(mapping.get("desc_col")) if mapping.get("desc_col") else None
                if desc:
                    desc = desc.strip() or None

                os_val = row.get(mapping.get("os_col")) if mapping.get("os_col") else None
                if os_val:
                    os_val = os_val.strip() or None

                cvss_raw = row.get(mapping.get("cvss_col")) if mapping.get("cvss_col") else None
                cvss_val = to_float_safe(cvss_raw)

                sev_val = row.get(mapping.get("severity_col")) if mapping.get("severity_col") else None
                if sev_val:
                    sev_val = sev_val.strip().upper() or None

                # ensure CVE exists (so FK for vulnerabilities.cve_id won't fail)
                cve_row = session.query(CVE).filter(CVE.cve_id == cve_id).first()
                if not cve_row:
                    # create minimal CVE
                    try:
                        new_cve = CVE(cve_id=cve_id, summary=(desc or None), severity=(sev_val or None))
                        session.add(new_cve)
                        session.flush()
                        cve_row = new_cve
                    except Exception as e:
                        session.rollback()
                        print(f"[WARN] failed to create CVE row for {cve_id}: {e}")
                        continue

                # find vulnerability
                vuln = session.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()

                if not vuln:
                    # create minimal vulnerability record
                    try:
                        vuln = Vulnerability(
                            cve_id=cve_id,
                            description=(desc or None),
                            severity=(sev_val or None),
                            affected_os=(os_val or None),
                            cvss_score=(cvss_val if cvss_val is not None else None)
                        )
                        session.add(vuln)
                        session.flush()
                        inserted += 1
                    except Exception as e:
                        session.rollback()
                        print(f"[WARN] failed to insert vuln for {cve_id}: {e}")
                        continue
                else:
                    changed = False
                    # description: fill if missing
                    if desc and (not getattr(vuln, "description", None) or len(str(vuln.description or "")) < len(desc)):
                        vuln.description = desc
                        changed = True

                    # affected_os: overwrite only if empty or different
                    if os_val and (not getattr(vuln, "affected_os", None) or vuln.affected_os.strip() == "" or vuln.affected_os != os_val):
                        vuln.affected_os = os_val
                        changed = True

                    # severity: fill if missing
                    if sev_val and (not getattr(vuln, "severity", None) or vuln.severity.strip() == ""):
                        vuln.severity = sev_val
                        changed = True

                    # cvss_score: fill if missing or force
                    if cvss_val is not None:
                        current_cvss = getattr(vuln, "cvss_score", None)
                        if current_cvss is None or force_cvss:
                            vuln.cvss_score = cvss_val
                            changed = True

                    if changed:
                        try:
                            session.add(vuln)
                            session.flush()
                            updated += 1
                        except Exception as e:
                            session.rollback()
                            print(f"[WARN] failed to update vuln {cve_id}: {e}")
                            continue

        # final commit
        session.commit()
        print(f"Rows processed: {rows_processed}, inserted: {inserted}, updated: {updated}, skipped_no_cve: {skipped_no_cve}")
        return 0
    except Exception as e:
        session.rollback()
        print("Merge failed:", e, file=sys.stderr)
        return 3
    finally:
        session.close()

if __name__ == "__main__":
    # change to True if you want CSV cvss to overwrite existing DB cvss
    FORCE_CVSS = False
    sys.exit(main(CSV_PATH, force_cvss=FORCE_CVSS))