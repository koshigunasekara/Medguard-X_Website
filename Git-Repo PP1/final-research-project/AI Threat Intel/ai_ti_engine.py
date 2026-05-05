import pandas as pd
import joblib
import os

# Load models
iso_model = joblib.load("X:/AI-TI/models/isolation_forest_model.pkl")
rf_model = joblib.load("X:/AI-TI/models/random_forest_model.pkl")

# Path for incoming logs
INPUT_FILE = "X:/AI-TI/data/combined_dataset.csv"

# Output results
OUTPUT_FILE = "X:/AI-TI/dashboard_output/detection_results.csv"

# Load logs
data = pd.read_csv(INPUT_FILE)

print("Logs loaded:", data.shape)

# Encode categorical data (same as training)
for column in data.columns:
    if data[column].dtype == "object":
        data[column] = data[column].astype("category").cat.codes

# Separate label if exists
if "label" in data.columns:
    X = data.drop("label", axis=1)
else:
    X = data

# Step 1 — Isolation Forest
iso_result = iso_model.predict(X)

# Add anomaly result
data["anomaly_flag"] = iso_result

# Step 2 — Random Forest classification
rf_result = rf_model.predict(X)

data["prediction"] = rf_result

# Convert numeric prediction to readable output
data["prediction"] = data["prediction"].map({0: "BENIGN", 1: "ATTACK"})

# Save results
data.to_csv(OUTPUT_FILE, index=False)

print("Detection completed")
print("Results saved to:", OUTPUT_FILE)