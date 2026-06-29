import pandas as pd

INPUT = "../data/final/cve_dataset.csv"
OUTPUT = "../data/final/cve_dataset_cleaned.csv"

df = pd.read_csv(INPUT)

print("Original rows:", len(df))

# 1️⃣ Keep only rows with valid severity + cvss
df = df[df["severity"].notna()]
df = df[df["cvss_score"].notna()]

# 2️⃣ Normalize severity
df["severity"] = df["severity"].astype(str).str.upper().str.strip()
df = df[df["severity"].isin(["LOW", "MEDIUM", "HIGH", "CRITICAL"])]

# 3️⃣ Fill missing values (DO NOT DROP)
df["description_text"] = df["description_text"].fillna("")
df["references_count"] = df["references_count"].fillna(0).astype(int)
df["weaknesses_count"] = df["weaknesses_count"].fillna(0).astype(int)
df["os_count"] = df["os_count"].fillna(0).astype(int)
df["years_since_published"] = df["years_since_published"].fillna(0).astype(int)

print("After cleaning rows:", len(df))
print("\nSeverity distribution:")
print(df["severity"].value_counts())

df.to_csv(OUTPUT, index=False)
print("✅ Cleaned dataset saved:", OUTPUT)