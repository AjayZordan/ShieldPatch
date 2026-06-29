import pandas as pd
from pathlib import Path

# -----------------------
# Paths
# -----------------------
ROOT = Path(__file__).resolve().parent.parent

CLEAN_PATH  = ROOT / "data/final/cve_dataset_cleaned.csv"
RAW_PATH    = ROOT / "data/final/cve_dataset.csv"
OUT_PATH    = ROOT / "data/final/cve_dataset_merged.csv"

print("[load] reading datasets")

df_clean = pd.read_csv(CLEAN_PATH, low_memory=False)
df_raw   = pd.read_csv(RAW_PATH, low_memory=False)

print(f"[info] clean rows: {len(df_clean)}")
print(f"[info] raw rows: {len(df_raw)}")

# -----------------------
# Normalize CVE IDs
# -----------------------
for df in (df_clean, df_raw):
    df["cve_id"] = df["cve_id"].astype(str).str.upper().str.strip()

# -----------------------
# Keep only needed cols from raw
# -----------------------
df_raw = df_raw[["cve_id", "description_text"]]

# -----------------------
# Merge
# -----------------------
print("[merge] merging datasets")

df = df_clean.merge(
    df_raw,
    on="cve_id",
    how="left",
    suffixes=("_clean", "_raw")
)

# -----------------------
# 🔥 FIX DESCRIPTION PROPERLY
# -----------------------
df["description_text"] = (
    df["description_text_raw"]
    .fillna(df["description_text_clean"])
    .fillna("")
    .astype(str)
    .str.strip()
)

df.loc[
    df["description_text"] == "",
    "description_text"
] = "no_description_available"

# Drop temp columns
df.drop(
    columns=["description_text_clean", "description_text_raw"],
    inplace=True,
    errors="ignore"
)

# -----------------------
# Numeric cleanup
# -----------------------
NUM_COLS = [
    "cvss_score",
    "references_count",
    "weaknesses_count",
    "os_count",
    "years_since_published"
]

for c in NUM_COLS:
    df[c] = pd.to_numeric(df[c], errors="coerce")

df = df[df["cvss_score"].notna()]

# -----------------------
# Coverage report
# -----------------------
coverage = (df["description_text"] != "no_description_available").mean() * 100
print(f"[info] final rows: {len(df)}")
print(f"[info] description coverage: {coverage:.2f} %")

# -----------------------
# Save
# -----------------------
OUT_PATH.parent.mkdir(exist_ok=True)
df.to_csv(OUT_PATH, index=False)

print(f"[save] merged dataset saved to → {OUT_PATH}")
print("[done] preprocessing completed successfully")