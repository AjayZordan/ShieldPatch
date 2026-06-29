import json
import os
import pandas as pd
from datetime import datetime

INPUT_DIR = "../data/nvd_processed"
OUTPUT_CSV = "../data/final/cve_dataset.csv"

rows = []
current_year = datetime.now().year


def count_os(cpes):
    os_set = set()
    for cpe in cpes:
        uri = cpe.get("criteria", "").lower()
        if "windows" in uri:
            os_set.add("windows")
        if "linux" in uri:
            os_set.add("linux")
        if "android" in uri:
            os_set.add("android")
    return len(os_set)


for file in os.listdir(INPUT_DIR):
    if not file.endswith(".json"):
        continue

    print(f"Processing {file}")

    with open(os.path.join(INPUT_DIR, file), "r", encoding="utf-8") as f:
        data = json.load(f)

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")

        if not cve_id:
            continue

        # ✅ FIXED DESCRIPTION EXTRACTION (NVD JSON 2.0)
        description_text = None
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description_text = d.get("value")
                break

        if not description_text or description_text.strip() == "":
            continue  # drop rows without description

        # CVSS + severity
        severity = None
        score = None
        metrics = cve.get("metrics", {})

        for k in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40"]:
            if k in metrics and metrics[k]:
                cvss = metrics[k][0].get("cvssData", {})
                severity = cvss.get("baseSeverity")
                score = cvss.get("baseScore")
                break

        if not severity or score is None:
            continue

        # references count
        references_count = len(cve.get("references", []))

        # weaknesses count
        weaknesses_count = len(cve.get("weaknesses", []))

        # OS count
        cpes = []
        for cfg in item.get("configurations", []):
            for node in cfg.get("nodes", []):
                cpes.extend(node.get("cpeMatch", []))
        os_count = count_os(cpes)

        # years since published
        published = cve.get("published", "")
        try:
            year = int(published[:4])
        except Exception:
            year = current_year

        years_since_published = current_year - year

        rows.append({
            "cve_id": cve_id,
            "description_text": description_text,
            "severity": severity.upper(),
            "cvss_score": float(score),
            "references_count": references_count,
            "weaknesses_count": weaknesses_count,
            "os_count": os_count,
            "years_since_published": years_since_published
        })

df = pd.DataFrame(rows)
df.to_csv(
    OUTPUT_CSV,
    index=False,
    encoding="utf-8",
    quoting=1,            # csv.QUOTE_ALL
    escapechar="\\"
)

print(f"\n✅ FINAL DATASET CREATED: {OUTPUT_CSV}")
print("Total rows:", len(df))