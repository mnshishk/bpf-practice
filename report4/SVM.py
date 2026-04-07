# run with: "python3 SVM.py"
import sys
import os

# fix for ModuleNotFoundError
user_pkg_path = os.path.expanduser('~/.local/lib/python3.10/site-packages')
if user_pkg_path not in sys.path:
    sys.path.insert(0, user_pkg_path)

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Load the data captured by Mike
print("Loading eBPF captured traffic...")
normal_df = pd.read_csv('./report4/normal_traffic_20260304_202911.csv')
attack_df = pd.read_csv('./report4/attack_traffic_20260304_205530.csv')

# Combine into one dataset
df = pd.concat([normal_df, attack_df], ignore_index=True)

# Preprocessing & Feature Engineering
def preprocess_ebpf_data(data):
    # Calculate time between packets (time delta)
    data['timestamp'] = pd.to_numeric(data['timestamp'])
    data = data.sort_values('timestamp')
    data['time_delta'] = data['timestamp'].diff().fillna(0)
    
    # Drop raw identifiers that are no longer necessary
    features = data.drop(['timestamp', 'src_ip', 'dst_ip'], axis=1)
    
    le = LabelEncoder()
    features['protocol'] = le.fit_transform(features['protocol'].astype(str))
    
    return features, le

processed_df, proto_encoder = preprocess_ebpf_data(df)

# Split Features (X) and Labels (y)
X = processed_df.drop('label', axis=1)
y = processed_df['label']

# Train/Test Split (80/20)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Scaling
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Training the SVM
print("Training SVM on eBPF data... (this might take a moment)")
svm_model = SVC(kernel='rbf', C=1.0)
svm_model.fit(X_train_scaled, y_train)

# Final Results
y_pred = svm_model.predict(X_test_scaled)

print("\n--- FINAL PERFORMANCE REPORT ---")
print(classification_report(y_test, y_pred))