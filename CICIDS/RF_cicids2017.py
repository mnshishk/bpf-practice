import sys
import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
from sklearn.svm import SVC

from cicids2017_preprocessing import load_and_split_cicids2017

user_pkg_path = os.path.expanduser('~/.local/lib/python3.10/site-packages')
if user_pkg_path not in sys.path:
    sys.path.insert(0, user_pkg_path)


def train_rf_on_cicids(csv_path, sample_size: int = 50000, n_estimators: int = 100):
    print("=" * 60)
    print("Random Forest Training on CICIDS2017 Dataset")
    print("=" * 60)

    X_train, X_test, y_train, y_test, scaler = load_and_split_cicids2017(
        csv_path, 
        test_size=0.2,
        sample_size=sample_size
    )

    print(f"\nTraining Random Forest with {n_estimators} trees...")
    print("This is typically faster than SVM...")
    
    rf_model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=42,
        n_jobs=-1, 
        verbose=1,  
        max_depth=20,  
        min_samples_split=10,
        min_samples_leaf=5
    )
    
    rf_model.fit(X_train, y_train)
    
    print("\n" + "=" * 60)
    print("Evaluating on Test Set")
    print("=" * 60)
    
    y_pred = rf_model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {accuracy:.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Attack']))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    print(f"\nTrue Negatives:  {cm[0][0]}")
    print(f"False Positives: {cm[0][1]}")
    print(f"False Negatives: {cm[1][0]}")
    print(f"True Positives:  {cm[1][1]}")

    if cm[1][0] + cm[1][1] > 0:
        detection_rate = cm[1][1] / (cm[1][0] + cm[1][1])
        print(f"\nDetection Rate (Recall for Attacks): {detection_rate:.4f}")
    
    if cm[0][1] + cm[0][0] > 0:
        false_positive_rate = cm[0][1] / (cm[0][1] + cm[0][0])
        print(f"False Positive Rate: {false_positive_rate:.4f}")

    print("\n" + "=" * 60)
    print("Top 10 Most Important Features")
    print("=" * 60)

    importances = rf_model.feature_importances_
    indices = np.argsort(importances)[::-1][:10]
    
    print("\nFeature importances (higher = more important):")
    for i, idx in enumerate(indices, 1):
        print(f"{i:2d}. Feature {idx}: {importances[idx]:.4f}")

    print("\n" + "=" * 60)
    print("Saving Model")
    print("=" * 60)
    
    os.makedirs('report4', exist_ok=True)
    
    joblib.dump(rf_model, 'report5/rf_cicids_model.pkl')
    joblib.dump(scaler, 'report5/rf_cicids_scaler.pkl')
    
    print("Saved:")
    print("  - rf_cicids_model.pkl")
    print("  - rf_cicids_scaler.pkl")
    
    return rf_model, scaler


def compare_rf_vs_svm_on_cicids(csv_path):

    from sklearn.model_selection import cross_val_score
    
    print("\n" + "=" * 60)
    print("Comparing RF vs SVM on CICIDS2017")
    print("=" * 60)

    X_train, X_test, y_train, y_test, scaler = load_and_split_cicids2017(
        csv_path, 
        sample_size=5000
    )
    
    print("\nTesting on 5000 samples for quick comparison...")

    print("\nTraining Random Forest...")
    rf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    rf_acc = accuracy_score(y_test, rf.predict(X_test))
    
    print("\nTraining SVM...")
    svm = SVC(kernel='rbf', C=1.0)
    svm.fit(X_train, y_train)
    svm_acc = accuracy_score(y_test, svm.predict(X_test))
    
    print("\n" + "=" * 60)
    print("Results:")
    print("=" * 60)
    print(f"Random Forest Accuracy: {rf_acc:.4f}")
    print(f"SVM Accuracy:           {svm_acc:.4f}")
    
    if rf_acc > svm_acc:
        print("\nRandom Forest performed better on this data.")
    elif svm_acc > rf_acc:
        print("\nSVM performed better on this data.")
    else:
        print("\nBoth models performed equally well.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python RF_cicids2017.py <path_to_cicids_csv> [sample_size] [n_estimators]")
        print("\nExample:")
        print("python RF_cicids2017.py ~/datasets/CICIDS2017/Monday-WorkingHours.pcap_ISCX.csv 50000 100")
        print("\nAvailable CICIDS2017 files:")
        print("  - Monday-WorkingHours.pcap_ISCX.csv (normal traffic)")
        print("  - Tuesday-WorkingHours.pcap_ISCX.csv (FTP-Patator, SSH-Patator)")
        print("  - Wednesday-workingHours.pcap_ISCX.csv (DoS attacks)")
        print("  - Thursday-WorkingHours.pcap_ISCX.csv (Web attacks, Infiltration)")
        print("  - Friday-WorkingHours.pcap_ISCX.csv (Botnet, DDoS)")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    sample_size = int(sys.argv[2]) if len(sys.argv) > 2 else 50000
    n_estimators = int(sys.argv[3]) if len(sys.argv) > 3 else 100
    
    if not os.path.exists(csv_path):
        print(f"Error: File not found: {csv_path}")
        sys.exit(1)

    model, scaler = train_rf_on_cicids(csv_path, sample_size, n_estimators)

    print("\n" + "=" * 60)
    response = input("Run RF vs SVM comparison? (y/n): ")
    if response.lower() == 'y':
        compare_rf_vs_svm_on_cicids(csv_path)
