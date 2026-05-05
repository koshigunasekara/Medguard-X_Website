import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest

# ===============================
# 1. Load benign dataset
# ===============================
DATA_PATH = "X:/AI-TI/data/combined_dataset.csv"

df = pd.read_csv(DATA_PATH)

print("Loaded benign dataset:", df.shape)


# ===============================
# 2. Select training features
# ===============================

feature_cols = [
    "timestamp",
    "criticality_tier",
    "dst_port",
    "ecg_raw_value",
    "heart_rate_bpm",
    "accel_x",
    "accel_y",
    "accel_z",
    "gyro_x",
    "gyro_y",
    "gyro_z",
    "temperature_celsius"
]

X = df[feature_cols]

print("\nTraining features:")
print(X.columns)


# ===============================
# 3. Train Isolation Forest
# ===============================

model = IsolationForest(
    n_estimators=100,     # number of trees
    contamination=0.05,   # expected anomaly rate
    random_state=42
)

model.fit(X)

print("\nIsolation Forest training completed")


# ===============================
# 4. Save model
# ===============================

MODEL_PATH = "X:/AI-TI/models/isolation_forest_model.pkl"

joblib.dump(model, MODEL_PATH)

print("Model saved to:", MODEL_PATH)


# ===============================
# 5. Save feature list
# ===============================

FEATURE_PATH = "X:/AI-TI/models/iso_features.pkl"

joblib.dump(feature_cols, FEATURE_PATH)

print("Feature list saved to:", FEATURE_PATH)


print("\nTraining finished successfully.")