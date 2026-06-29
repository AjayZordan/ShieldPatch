# check_csvs.py
import csv
from pathlib import Path

csv_files = [
    "/Users/ajaykumar/Desktop/ShieldPatch/Datasets/combined_work/combined_vulnerabilities.csv",
    "/Users/ajaykumar/Desktop/ShieldPatch/Datasets/combined_work/nvd_vulnerabilities_with_os.csv"
]

def inspect_csv(path):
    p = Path(path)
    print("\nChecking:", path)
    if not p.exists():
        print("❌ FILE NOT FOUND")
        return

    with p.open(newline='', encoding='utf-8', errors='replace') as fh:
        reader = csv.DictReader(fh)
        headers = reader.fieldnames
        print("✔ Headers:", headers)

        missing = {h: 0 for h in headers}
        total = 0
        sample_rows = []

        for row in reader:
            total += 1
            if total <= 3:
                sample_rows.append(row)

            for h in headers:
                val = row.get(h)
                if val is None or str(val).strip() == "":
                    missing[h] += 1

        print("✔ Total rows:", total)
        print("Missing values per column:")
        for h in headers:
            print(f"  {h}: {missing[h]}")

        print("\nSample rows:")
        for r in sample_rows:
            print(r)

for f in csv_files:
    inspect_csv(f)