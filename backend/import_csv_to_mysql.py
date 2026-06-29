# import_csv_to_mysql.py
import os, json
from datetime import datetime
import pandas as pd
from tqdm import tqdm
from dotenv import load_dotenv

load_dotenv()

from db import engine, get_session
from models import Base, Vulnerability

CSV_PATH = os.getenv("COMBINED_CSV_PATH", "combined_vulnerabilities_fixed.csv")
BATCH_SIZE = int(os.getenv("IMPORT_BATCH_SIZE", "200"))

def ensure_tables():
    Base.metadata.create_all(bind=engine)
    print("[DB] tables ensured")

def parse_datetime(value):
    if value is None: return None
    try:
        if pd.isna(value): return None
    except Exception:
        pass
    s = str(value).strip()
    if s == "" or s.lower() in ("nan", "none", "null"): return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    try:
        return pd.to_datetime(s)
    except Exception:
        return None

def normalize_row(row):
    # try many column names
    def get(*keys):
        for k in keys:
            if k in row and not pd.isna(row[k]):
                return row[k]
        return None

    cve = get("cve_id", "CVE ID", "CVE", "cve.id", "id", "cve")
    if cve:
        cve = str(cve).strip()

    published = parse_datetime(get("published", "published_date", "Published"))
    last_modified = parse_datetime(get("lastModified", "last_modified", "Last Modified"))

    desc = get("description", "Description", "summary", "cve.descriptions.value")
    cvss = get("cvss_score", "cvss", "Score", "CVSS Score", "baseScore")
    try:
        cvss = float(cvss) if cvss not in (None, "", "nan") else None
    except Exception:
        cvss = None

    severity = get("severity", "Severity", "baseSeverity")
    source = get("source", "Source")

    cpe = get("cpe", "CPE", "cpeMatch")

    refs = None
    rawrefs = get("references", "References")
    if rawrefs and isinstance(rawrefs, str):
        try:
            refs = json.loads(rawrefs)
        except Exception:
            if "|" in rawrefs:
                refs = [r.strip() for r in rawrefs.split("|") if r.strip()]
            elif ";" in rawrefs:
                refs = [r.strip() for r in rawrefs.split(";") if r.strip()]
            else:
                refs = [rawrefs]
    elif rawrefs:
        refs = rawrefs

    # raw row as dict (convert pandas types to native)
    raw = {}
    for k, v in row.items():
        try:
            raw[k] = None if (pd.isna(v) if hasattr(pd, "isna") else v is None) else v
        except Exception:
            raw[k] = v

    return {
        "cve_id": cve,
        "source": source,
        "published": published,
        "last_modified": last_modified,
        "description": desc,
        "cvss_score": cvss,
        "severity": severity,
        "cpe": cpe,
        "references": refs,
        "raw_data": raw
    }

def upsert(session, data):
    cve = data.get("cve_id")
    if not cve:
        return "skipped_no_cve"
    existing = session.query(Vulnerability).filter(Vulnerability.cve_id == cve).first()
    if existing:
        # update only if provided
        for fld in ("published","last_modified","description","cvss_score","severity","cpe","references"):
            if data.get(fld) is not None:
                setattr(existing, fld, data.get(fld))
        # merge raw_data shallow
        old_raw = existing.raw_data or {}
        new_raw = data.get("raw_data") or {}
        if isinstance(old_raw, dict) and isinstance(new_raw, dict):
            merged = old_raw.copy(); merged.update(new_raw)
            existing.raw_data = merged
        else:
            existing.raw_data = new_raw or old_raw
        session.add(existing)
        return "updated"
    else:
        v = Vulnerability(
            cve_id = data.get("cve_id"),
            source = data.get("source"),
            published = data.get("published"),
            last_modified = data.get("last_modified"),
            description = data.get("description"),
            cvss_score = data.get("cvss_score"),
            severity = data.get("severity"),
            cpe = data.get("cpe"),
            references = data.get("references"),
            raw_data = data.get("raw_data"),
        )
        session.add(v)
        return "inserted"

def main():
    ensure_tables()
    if not os.path.exists(CSV_PATH):
        print("[ERROR] CSV not found:", CSV_PATH)
        return

    df = pd.read_csv(CSV_PATH, dtype=str, low_memory=False)
    print("✅ CSV loaded:", len(df), "rows")

    session = get_session()
    inserted = updated = skipped = errors = 0
    batch = 0

    try:
        for _, row in tqdm(df.iterrows(), total=len(df), desc="Processing rows"):
            try:
                rec = normalize_row(row)
                res = upsert(session, rec)
                if res == "inserted":
                    inserted += 1
                elif res == "updated":
                    updated += 1
                elif res == "skipped_no_cve":
                    skipped += 1
                batch += 1
            except Exception as e:
                errors += 1
                print("[ROW ERROR]", e)
                session.rollback()

            if batch >= BATCH_SIZE:
                session.commit()
                batch = 0
        session.commit()
    except Exception as e:
        print("[FATAL]", e)
        session.rollback()
    finally:
        session.close()

    print(f"Done. inserted={inserted}, updated={updated}, skipped_no_cve={skipped}, errors={errors}")

if __name__ == "__main__":
    main()