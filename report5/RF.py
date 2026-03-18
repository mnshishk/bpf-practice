import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, classification_report

NORMAL_FILE = "normal_traffic_20260304_202911.csv"
ATTACK_FILE = "attack_traffic_20260304_205530.csv"
MODEL_FILE = "rf_model.pkl"

FEATURE_COLUMNS = ["src_port", "dst_port", "packet_count", "total_bytes", "duration_ms"]


def load_and_prepare_data():
    print("Loading traffic datasets...")

    normal_data = pd.read_csv(NORMAL_FILE)
    attack_data = pd.read_csv(ATTACK_FILE)

    normal_data["label"] = 0
    attack_data["label"] = 1

    # Combine into one dataset
    data = pd.concat([normal_data, attack_data], ignore_index=True)

    print("\nCombined dataset preview:")
    print(data.head())

    columns_to_drop = ["timestamp", "src_ip", "dst_ip", "protocol"]
    for col in columns_to_drop:
        if col in data.columns:
            data = data.drop(col, axis=1)

    X = data[FEATURE_COLUMNS]
    y = data["label"]

    print("\nFeatures being used:")
    print(FEATURE_COLUMNS)

    return X, y


def train_and_save_model():
    X, y = load_and_prepare_data()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\nTraining Random Forest model...")

    rf_model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    rf_model.fit(X_train, y_train)

    predictions = rf_model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions)
    recall = recall_score(y_test, predictions)

    print("\nRandom Forest Performance:")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")

    print("\nDetailed Classification Report:")
    print(classification_report(y_test, predictions))

    # Save trained model
    joblib.dump(rf_model, MODEL_FILE)
    print(f"\nSaved model to: {MODEL_FILE}")

    return rf_model


def predict(flow: dict) -> int:
    """
    Predict a single live flow.
    Returns:
        0 = normal
        1 = suspicious/attack
    """
    if not os.path.exists(MODEL_FILE):
        raise FileNotFoundError("rf_model.pkl not found. Run RF.py first to train and save the model.")

    rf_model = joblib.load(MODEL_FILE)

    row = {}
    for feature in FEATURE_COLUMNS:
        row[feature] = flow.get(feature, 0)

    df = pd.DataFrame([row])

    for col in FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    prediction = rf_model.predict(df)[0]
    return int(prediction)


if __name__ == "__main__":
    train_and_save_model()