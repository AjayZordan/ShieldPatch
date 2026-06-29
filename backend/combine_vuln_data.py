#!/usr/bin/env python3
# combine_vuln_data.py — robust, single-file remerge script
import os
import json
import re
import pandas as pd

# Candidate locations to search for inputs (checked in order)
CANDIDATE_DIRS = [
    "./Datasets",
    "../Datasets",
    "/mnt/data",
    "/Users/"  # quick fallback if you put absolute paths later
]

# Filenames we expect (you can overwrite by placing files with these names)
JSON_FILENAMES = ["nvdcve-2.0-recent.json", "nvdcve-2.0.json"]
CSV_OS_FILENAMES = ["nvd_vulnerabilities_with_os.csv", "nvd_with_os.csv"]
PREV_COMBINED_FILENAMES = ["combined_vulnerabilities.csv", "combined_vulnerabilities_fixed.csv"]

# Output file (kept inside project so no permission issues)
OUT_PATH = os.path.join(os.path.dirname(__file__), "combined_vulnerabilities_fixed.csv")

def find_file(names):
    """Look for any filename (list) inside candidate dirs — return first full path or None."""
    for d in CANDIDATE_DIRS:
        for n in names:
            p = os.path.join(d, n)
            if os.path.exists(p):
                return p
    # also check current dir
    for n in names:
        if os.path.exists(n):
            return os.path.abspath(n)
    return None

CVE_RE = re.compile(r"(CVE[-_ ]?\d{4}[-_ ]?\d+)", re.IGNORECASE)

def normalize_cve(value):
    if value is None:
        return None
    s = str(value).strip()
    if not s or s.lower() in ("nan","none","null"):
        return None
    m = CVE_RE.search(s)
    if not m:
        return None
    c = m.group(1).upper().replace(" ", "-").replace("_", "-")
    return c

def parse_nvd_json(path):
    if not path:
        return {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        j = json.load(f)
    items = j.get("vulnerabilities") or j.get("CVE_Items") or []
    out = {}
    for item in items:
        # flexible extraction for different NVD export shapes
        cve_block = item.get("cve") if isinstance(item, dict) else None
        cve_id = None
        if cve_block and isinstance(cve_block, dict):
            cve_id = cve_block.get("id") or cve_block.get("CVE_data_meta", {}).get("ID")
        if not cve_id:
            cve_id = item.get("id") if isinstance(item, dict) else None
        cve_norm = normalize_cve(cve_id)
        if not cve_norm:
            # try searching in serialized item text
            s = json.dumps(item)
            cve_norm = normalize_cve(s)
        if not cve_norm:
            continue

        # description
        desc = None
        if cve_block:
            descs = cve_block.get("descriptions") or cve_block.get("description")
            if isinstance(descs, list):
                for d in descs:
                    if d.get("lang") == "en":
                        desc = d.get("value"); break
                if not desc and descs:
                    desc = descs[0].get("value")
            elif isinstance(descs, str):
                desc = descs

        # cvss
        cvss = None
        metrics = (cve_block.get("metrics") if cve_block else None) or item.get("metrics") or {}
        if isinstance(metrics, dict):
            for k in ("cvssMetricV31","cvssMetricV3","cvssMetricV40","cvssMetricV2"):
                arr = metrics.get(k)
                if isinstance(arr, list) and arr:
                    cd = arr[0].get("cvssData") or {}
                    cvss = cd.get("baseScore") or cd.get("score") or cvss
                    if cvss:
                        break

        refs = []
        raw_refs = (cve_block.get("references") if cve_block else None) or item.get("references") or []
        if isinstance(raw_refs, list):
            for r in raw_refs:
                if isinstance(r, dict) and r.get("url"):
                    refs.append(r.get("url"))
                elif isinstance(r, str):
                    refs.append(r)

        out[cve_norm] = {
            "cve_id": cve_norm,
            "description": desc,
            "published": (cve_block.get("published") if cve_block else None) or item.get("published"),
            "last_modified": (cve_block.get("lastModified") if cve_block else None) or item.get("lastModified"),
            "cvss_score": cvss,
            "references": refs or None,
            "raw_nvd": item
        }
    print(f"[INFO] Parsed NVD JSON entries: {len(out)}")
    return out

def load_csv_with_cve_key(path):
    if not path:
        return pd.DataFrame()
    df = pd.read_csv(path, dtype=str, low_memory=False)
    # Try to detect CVE column
    candidates = [c for c in df.columns if re.search(r"\b(cve|cve id|cve_id|cve.id)\b", c, re.IGNORECASE)]
    if candidates:
        col = candidates[0]
        df["cve_id_norm"] = df[col].apply(normalize_cve)
        print(f"[INFO] Using CSV column '{col}' for CVE detection in {os.path.basename(path)}")
    else:
        # attempt to auto-detect a column containing CVE pattern
        df["cve_id_norm"] = None
        for col in df.columns:
            try:
                if df[col].astype(str).str.contains(r"CVE[-_ ]?\d{4}[-_ ]?\d+", case=False, na=False).any():
                    df["cve_id_norm"] = df[col].apply(normalize_cve)
                    print(f"[INFO] Auto-detected CVE column '{col}' in {os.path.basename(path)}")
                    break
            except Exception:
                continue
    return df

def main():
    json_path = find_file(JSON_FILENAMES)
    csv_os_path = find_file(CSV_OS_FILENAMES)
    prev_combined_path = find_file(PREV_COMBINED_FILENAMES)

    print("Input files:")
    print("  NVD JSON:", json_path or "[not found]")
    print("  OS CSV:  ", csv_os_path or "[not found]")
    print("  Prev CSV:", prev_combined_path or "[not found]")
    print("Output will be:", OUT_PATH)

    master = {}
    # parse json
    nvd_map = parse_nvd_json(json_path) if json_path else {}
    master.update(nvd_map)

    # overlay OS CSV
    csv_os = load_csv_with_cve_key(csv_os_path) if csv_os_path else pd.DataFrame()
    os_count = 0
    if not csv_os.empty:
        for _, row in csv_os.iterrows():
            cve = row.get("cve_id_norm")
            if not cve:
                # fallback: scan row values
                for col in row.index:
                    val = row[col]
                    if isinstance(val, str) and CVE_RE.search(val):
                        cve = normalize_cve(val); break
            if not cve:
                continue
            os_count += 1
            if cve in master:
                if not master[cve].get("description") and row.get("Description"):
                    master[cve]["description"] = row.get("Description")
                master[cve]["os_row"] = row.to_dict()
            else:
                master[cve] = {
                    "cve_id": cve,
                    "description": row.get("Description") or None,
                    "published": None,
                    "last_modified": None,
                    "cvss_score": None,
                    "references": None,
                    "source": "csv_os",
                    "raw_os_row": row.to_dict()
                }
    print(f"[INFO] Overlayed OS CSV rows with CVE: {os_count}")

    # overlay previous combined
    csv_prev = load_csv_with_cve_key(prev_combined_path) if prev_combined_path else pd.DataFrame()
    prev_count = 0
    no_cve_rows = []
    if not csv_prev.empty:
        for _, row in csv_prev.iterrows():
            cve = row.get("cve_id_norm")
            if not cve:
                for col in row.index:
                    val = row[col]
                    if isinstance(val, str) and CVE_RE.search(val):
                        cve = normalize_cve(val); break
            if cve:
                prev_count += 1
                if cve in master:
                    if not master[cve].get("description") and row.get("Description"):
                        master[cve]["description"] = row.get("Description")
                    master[cve]["prev_row"] = row.to_dict()
                else:
                    master[cve] = {
                        "cve_id": cve,
                        "description": row.get("Description") or None,
                        "published": None,
                        "last_modified": None,
                        "cvss_score": None,
                        "references": None,
                        "source": "prev_combined",
                        "raw_prev_row": row.to_dict()
                    }
            else:
                no_cve_rows.append(row.to_dict())
    print(f"[INFO] Overlayed prev combined CSV entries with CVE: {prev_count}, rows without CVE: {len(no_cve_rows)}")

    # build output rows
    rows = []
    for k, v in master.items():
        rows.append({
            "cve_id": v.get("cve_id"),
            "description": v.get("description"),
            "published": v.get("published"),
            "last_modified": v.get("last_modified"),
            "cvss_score": v.get("cvss_score"),
            "references": ";".join(v.get("references")) if v.get("references") else None,
            "source": v.get("source") or "nvd_json",
            "raw_data": json.dumps(v.get("raw_nvd") or v.get("raw_os_row") or v.get("raw_prev_row") or {})
        })
    for r in no_cve_rows:
        rows.append({
            "cve_id": None,
            "description": r.get("Description") or r.get("description") or None,
            "published": None,
            "last_modified": None,
            "cvss_score": r.get("CVSS Score") or None,
            "references": None,
            "source": "no_cve",
            "raw_data": json.dumps(r)
        })

    if not rows:
        out_df = pd.DataFrame(columns=["cve_id","description","published","last_modified","cvss_score","references","source","raw_data"])
    else:
        out_df = pd.DataFrame(rows)
        if "cve_id" not in out_df.columns:
            out_df["cve_id"] = None

    if "cve_id" in out_df.columns:
        out_df = out_df.sort_values(by=["cve_id"], na_position="last").reset_index(drop=True)
    else:
        out_df = out_df.reset_index(drop=True)

    # ensure directory exists for OUT_PATH
    out_dir = os.path.dirname(OUT_PATH) or "."
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    out_df.to_csv(OUT_PATH, index=False)
    print("\nWrote:", OUT_PATH)
    print("Total rows:", len(out_df))
    with_cve = int(out_df['cve_id'].notna().sum()) if 'cve_id' in out_df.columns else 0
    print("With CVE:", with_cve, "Without CVE:", len(out_df) - with_cve)
    print("\nPreview (top 8):")
    if len(out_df):
        print(out_df.head(8).to_string(index=False))
    else:
        print("[empty dataframe]")

if __name__ == "__main__":
    main()