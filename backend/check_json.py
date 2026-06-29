# check_json.py
import json
from pathlib import Path

# YOUR EXACT PATH
json_path = Path("/Users/ajaykumar/Desktop/ShieldPatch/Datasets/combined_work/nvdcve-2.0-recent.json")

print("Checking:", json_path)

if not json_path.exists():
    print("❌ JSON file NOT FOUND at path:", json_path)
    exit()

text = json_path.read_text(encoding="utf-8", errors="replace")
data = json.loads(text)

# Detect shape
if isinstance(data, dict) and ("CVE_Items" in data or "vulnerabilities" in data):
    items = data.get("CVE_Items", data.get("vulnerabilities"))
elif isinstance(data, list):
    items = data
else:
    raise SystemExit("❌ Unexpected top-level JSON shape.")

print("✔ Total CVE items:", len(items))

missing_counts = {}
sample_ids = []

for i, it in enumerate(items):
    cve_id = None
    try:
        cve_block = it.get("cve", {})
        cve_id = (
            cve_block.get("id")
            or cve_block.get("CVE_data_meta", {}).get("ID")
            or it.get("cve", {}).get("CVE_data_meta", {}).get("ID")
        )
    except:
        pass

    if not cve_id:
        missing_counts.setdefault("missing_cve_id", 0)
        missing_counts["missing_cve_id"] += 1

    if i < 3:
        sample_ids.append(cve_id)

print("Sample CVE IDs:", sample_ids)
print("Missing fields count:", missing_counts)
print("✔ JSON structure looks OK if missing_cve_id = 0")