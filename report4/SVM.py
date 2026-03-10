import sys
import os

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

# 1. Load the data captured by Mikhail
print("Loading eBPF captured traffic...")
normal_df = pd.read_csv('normal_traffic_20260304_202911.csv')
attack_df = pd.read_csv('attack_traffic_20260304_205530.csv')

# Combine into one dataset
df = pd.concat([normal_df, attack_df], ignore_index=True)

# 2. Preprocessing & Feature Engineering
def preprocess_ebpf_data(data):
    # Calculate time between packets (time delta)
    data['timestamp'] = pd.to_numeric(data['timestamp'])
    data = data.sort_values('timestamp')
    data['time_delta'] = data['timestamp'].diff().fillna(0)
    
    # Drop raw identifiers (IPs/Timestamps) to ensure the SVM learns behavior, not addresses. This is common practice when using SVM after time time delta has been calculated.
    features = data.drop(['timestamp', 'src_ip', 'dst_ip'], axis=1)
    
    le = LabelEncoder()
    features['protocol'] = le.fit_transform(features['protocol'].astype(str))
    
    return features, le

processed_df, proto_encoder = preprocess_ebpf_data(df)

# Split Features (X) and Labels (y)
X = processed_df.drop('label', axis=1)
y = processed_df['label']

# 3. Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Scaling
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# 5. Train the SVM
print("Training SVM on eBPF data... (this might take a moment)")
svm_model = SVC(kernel='rbf', C=1.0)
svm_model.fit(X_train_scaled, y_train)

# 6. Final Results
y_pred = svm_model.predict(X_test_scaled)

print("\n--- FINAL CAPSTONE PERFORMANCE REPORT ---")
print(classification_report(y_test, y_pred))

# 7. Save for use by Hunter
joblib.dump(svm_model, 'svm_model.pkl')
joblib.dump(scaler, 'scaler.pkl')
print("\nFiles 'svm_model.pkl' and 'scaler.pkl' saved for the comparison write-up.")