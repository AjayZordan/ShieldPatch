# merge_csv_to_db.py
import csv
import os
from datetime import datetime
from dateutil import parser as dateparser

# adjust path to match your dataset location
CSV_PATH = "/Users/ajaykumar/Desktop/ShieldPatch/Datasets/combined_work/combined_vulnerabilities.csv"

# import your project's DB/session helper and models
from db import get_session
from models import CVE, Vulnerability

def normalize_cve(s):
    if not s:
        return None
    s = s.strip()
    # sometimes CSV has mixed columns; try to pick the CVE-like token
    if "CVE-" in s.upper():
        # take first token that looks like CVE-YYYY-...
        parts = s.replace(",", " ").split()
        for p in parts:
            if p.upper().startswith("CVE-"):
                return p.upper()
    return None

def to_float_safe(v):
    try:
        if v is None or v == "":
            return None
        return float(v)
    except Exception:
        return None

def main():
    if not os.path.exists(CSV_PATH):
        print("CSV not found:", CSV_PATH)
        return

    session = get_session()
    inserted = 0
    updated = 0
    rows_processed = 0

    try:
        with open(CSV_PATH, newline='', encoding='utf-8') as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                rows_processed += 1
                # common column names in your CSVs
                cve = normalize_cve(row.get("CVE_ID") or row.get("CVE ID") or row.get("CVE") or "")
                desc = (row.get("Description") or "").strip() or None
                cvss = to_float_safe(row.get("CVSS Score") or row.get("Score") or "")
                severity = (row.get("Severity") or "").strip() or None
                src = (row.get("Source") or "").strip() or None
                affected_os = (row.get("Affected OS") or "").strip() or None

                # if no CVE id, skip (you can change this behaviour)
                if not cve:
                    continue

                # ensure CVE row exists
                cve_row = session.query(CVE).filter(CVE.cve_id == cve).first()
                if not cve_row:
                    cve_row = CVE(cve_id=cve, summary=desc if desc else None)
                    if cvss is not None:
                        # store severity if present; cvss stored on vulnerabilities
                        pass
                    session.add(cve_row)
                    try:
                        session.flush()
                    except Exception:
                        session.rollback()
                        continue

                # find vulnerability row (by cve_id)
                vuln = session.query(Vulnerability).filter(Vulnerability.cve_id == cve).first()
                if vuln:
                    changed = False
                    # update fields only if missing or CSV provides something better
                    if desc and (not vuln.description or len(desc) > (len(vuln.description) if vuln.description else 0)):
                        vuln.description = desc
                        changed = True
                    if cvss is not None and (not getattr(vuln, "cvss_score", None)):
                        try:
                            vuln.cvss_score = float(cvss)
                        except Exception:
                            pass
                        changed = True
                    if severity and (not getattr(vuln, "severity", None)):
                        vuln.severity = severity
                        changed = True
                    if src and (not getattr(vuln, "source", None)):
                        vuln.source = src
                        changed = True
                    if affected_os and (not getattr(vuln, "affected_os", None)):
                        vuln.affected_os = affected_os
                        changed = True

                    if changed:
                        session.add(vuln)
                        updated += 1
                else:
                    # create new vulnerability row (attach to existing CVE via cve_id)
                    try:
                        vuln = Vulnerability(
                            cve_id=cve,
                            description=desc,
                            cvss_score=(float(cvss) if cvss is not None else None),
                            severity=severity,
                            source=src,
                            affected_os=affected_os
                        )
                        session.add(vuln)
                        inserted += 1
                    except Exception as ex:
                        session.rollback()
                        continue

                # flush every few hundred rows to keep transactions manageable
                if rows_processed % 200 == 0:
                    try:
                        session.commit()
                    except Exception:
                        session.rollback()
            # final commit
            try:
                session.commit()
            except Exception:
                session.rollback()
    finally:
        session.close()

    print(f"Rows processed: {rows_processed}, inserted: {inserted}, updated: {updated}")

if __name__ == "__main__":
    main()