import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# ===============================
# Load dataset
# ===============================

DATA_PATH = "X:/AI-TI/data/combined_dataset.csv"

df = pd.read_csv(DATA_PATH)

print("Dataset loaded:", df.shape)

# ===============================
# Encode categorical columns
# ===============================

for column in df.columns:
    if df[column].dtype == "object":
        df[column] = df[column].astype("category").cat.codes

# ===============================
# Separate features and labels
# ===============================

X = df.drop(columns=["is_attack"])
y = df["is_attack"]

print("Training features:")
print(X.columns)

# ===============================
# Train / Test Split
# ===============================

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ===============================
# Train Random Forest
# ===============================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

print("Random Forest training completed")

# ===============================
# Save model
# ===============================

joblib.dump(model, "X:/AI-TI/models/random_forest_model.pkl")

# Save feature list
joblib.dump(X.columns.tolist(), "X:/AI-TI/models/rf_features.pkl")

print("Model saved")
print("Feature list saved")