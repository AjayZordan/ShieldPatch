import pandas as pd

INPUT = "../data/final/cve_dataset_cleaned.csv"
OUTPUT = "../data/final/cve_dataset_balanced.csv"

df = pd.read_csv(INPUT)

print("Original distribution:")
print(df["severity"].value_counts())

# Target counts (safe + realistic)
TARGETS = {
    "CRITICAL": df[df["severity"] == "CRITICAL"].shape[0],  # keep all
    "HIGH": 30000,
    "MEDIUM": 30000,
    "LOW": 10000
}

balanced_parts = []

for sev, target in TARGETS.items():
    subset = df[df["severity"] == sev]
    if subset.empty:
        continue

    if len(subset) >= target:
        sampled = subset.sample(target, random_state=42)
    else:
        sampled = subset.sample(target, replace=True, random_state=42)

    balanced_parts.append(sampled)

balanced_df = pd.concat(balanced_parts).sample(frac=1, random_state=42)

print("\nBalanced distribution:")
print(balanced_df["severity"].value_counts())

balanced_df.to_csv(OUTPUT, index=False)
print(f"\n✅ Balanced dataset saved: {OUTPUT}")
print("Total rows:", len(balanced_df))