import sys
import os
import pandas as pd
import numpy as np
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
from cicids2017_preprocessing import load_cicids2017, create_cicids_compatible_format
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from cicids2017_preprocessing import load_and_split_cicids2017

user_pkg_path = os.path.expanduser('~/.local/lib/python3.10/site-packages')
if user_pkg_path not in sys.path:
    sys.path.insert(0, user_pkg_path)


def train_svm_on_cicids(csv_path, sample_size: int = 50000):
    print("=" * 60)
    print("SVM Training on CICIDS2017 Dataset")
    print("=" * 60)
    
    X_train, X_test, y_train, y_test, scaler = load_and_split_cicids2017(
        csv_path, 
        test_size=0.2,
        sample_size=sample_size
    )

    print("\nTraining SVM model (this may take several minutes)...")
    print("Using RBF kernel with C=1.0")
    
    svm_model = SVC(
        kernel='rbf', 
        C=1.0,
        gamma='scale',  
        verbose=True  
    )
    
    svm_model.fit(X_train, y_train)

    print("\n" + "=" * 60)
    print("Evaluating on Test Set")
    print("=" * 60)
    
    y_pred = svm_model.predict(X_test)
    
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
    print("Saving Model")
    print("=" * 60)
    
    os.makedirs('report4', exist_ok=True)
    
    joblib.dump(svm_model, 'report5/svm_cicids_model.pkl')
    joblib.dump(scaler, 'report5/svm_cicids_scaler.pkl')
    
    print("Saved:")
    print("  - svm_cicids_model.pkl")
    print("  - svm_cicids_scaler.pkl")
    
    return svm_model, scaler


def compare_with_custom_features(csv_path):
 
    print("\n" + "=" * 60)
    print("Comparing Full CICIDS vs Simple Features")
    print("=" * 60)
    
    features, labels = load_cicids2017(csv_path, sample_size=10000)
    
    simple_features = create_cicids_compatible_format(features)
    
    print("\nTraining SVM on SIMPLE features (5 features like our eBPF data)...")
    X_simple = simple_features.values
    
    X_train_s, X_test_s, y_train, y_test = train_test_split(
        X_simple, labels.values, test_size=0.2, random_state=42
    )
    
    scaler_simple = StandardScaler()
    X_train_s_scaled = scaler_simple.fit_transform(X_train_s)
    X_test_s_scaled = scaler_simple.transform(X_test_s)
    
    svm_simple = SVC(kernel='rbf', C=1.0)
    svm_simple.fit(X_train_s_scaled, y_train)
    
    y_pred_simple = svm_simple.predict(X_test_s_scaled)
    acc_simple = accuracy_score(y_test, y_pred_simple)
    
    print(f"Simple Features Accuracy: {acc_simple:.4f}")
    print(classification_report(y_test, y_pred_simple, target_names=['Benign', 'Attack']))
    
    print("\n" + "=" * 60)
    print("Key Insight:")
    print("=" * 60)
    print("The difference in accuracy shows the value of richer feature extraction.")
    print("Our eBPF approach prioritizes real-time performance with simpler features,")
    print("while CICIDS2017 captures more detailed flow characteristics.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python SVM_cicids2017.py <path_to_cicids_csv> [sample_size]")
        print("\nExample:")
        print("python SVM_cicids2017.py ~/datasets/CICIDS2017/Monday-WorkingHours.pcap_ISCX.csv 50000")
        print("\nAvailable CICIDS2017 files:")
        print("  - Monday-WorkingHours.pcap_ISCX.csv (normal traffic)")
        print("  - Tuesday-WorkingHours.pcap_ISCX.csv (FTP-Patator, SSH-Patator)")
        print("  - Wednesday-workingHours.pcap_ISCX.csv (DoS attacks)")
        print("  - Thursday-WorkingHours.pcap_ISCX.csv (Web attacks, Infiltration)")
        print("  - Friday-WorkingHours.pcap_ISCX.csv (Botnet, DDoS)")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    sample_size = int(sys.argv[2]) if len(sys.argv) > 2 else 50000
    
    if not os.path.exists(csv_path):
        print(f"Error: File not found: {csv_path}")
        sys.exit(1)

    model, scaler = train_svm_on_cicids(csv_path, sample_size)

    print("\n" + "=" * 60)
    response = input("Run comparison with simple features? (y/n): ")
    if response.lower() == 'y':
        compare_with_custom_features(csv_path)
