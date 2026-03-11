import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, classification_report

# Files from Mike's traffic captures
NORMAL_FILE = "normal_traffic_20260304_202911.csv"
ATTACK_FILE = "attack_traffic_20260304_205530.csv"

print("Loading traffic datasets...")

# Load CSV files
normal_data = pd.read_csv(NORMAL_FILE)
attack_data = pd.read_csv(ATTACK_FILE)

# Add labels
normal_data["label"] = 0   # normal
attack_data["label"] = 1   # attack

# Combine datasets
data = pd.concat([normal_data, attack_data], ignore_index=True)

print("\nCombined dataset preview:")
print(data.head())

columns_to_drop = ["timestamp", "src_ip", "dst_ip", "protocol"]
for col in columns_to_drop:
    if col in data.columns:
        data = data.drop(col, axis=1)

# Separate features and labels
X = data.drop("label", axis=1)
y = data["label"]

print("\nFeatures being used:")
print(X.columns.tolist())

# Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("\nTraining Random Forest model...")

# Train model
rf_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)
rf_model.fit(X_train, y_train)

predictions = rf_model.predict(X_test)

# Evaluate model
accuracy = accuracy_score(y_test, predictions)
precision = precision_score(y_test, predictions)
recall = recall_score(y_test, predictions)

print("\nRandom Forest Performance:")
print(f"Accuracy:  {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")

print("\nDetailed Classification Report:")
print(classification_report(y_test, predictions))

# save predictions for review
results = X_test.copy()
results["actual_label"] = y_test.values
results["predicted_label"] = predictions
results.to_csv("rf_results.csv", index=False)

print("\nResults saved to rf_results.csv")