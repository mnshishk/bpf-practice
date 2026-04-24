import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from typing import Tuple

CICIDS_FEATURE_COLUMNS = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
    'Flow IAT Max', 'Flow IAT Min'
]

def load_cicids2017(filepath, sample_size):
    print(f"Loading CICIDS2017 dataset from: {filepath}")
    
    if sample_size:
        df = pd.read_csv(filepath, nrows=sample_size)
    else:
        df = pd.read_csv(filepath)
    
    df.columns = df.columns.str.strip()
    print(f"Loaded {len(df)} samples")
    
    label_col = 'Label'
    if label_col not in df.columns:
        for col in df.columns:
            if 'label' in col.lower():
                label_col = col
                break
    
    labels = df[label_col].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)
    
    features = df.drop(columns=[label_col], errors='ignore')
    
    return features, labels

def create_cicids_compatible_format(df):
    """
    Maps CICIDS2017 columns to the 5-feature eBPF format.
    Ensures output is exactly: [src_port, dst_port, packet_count, total_bytes, duration_ms]
    """
    print("Mapping to 5-feature simple format...")

    df.columns = df.columns.str.strip()
    
    simple_df = pd.DataFrame(index=df.index)

    def get_col_safe(col_name):
        if col_name in df.columns:
            return pd.to_numeric(df[col_name], errors='coerce').fillna(0)
        return pd.Series(0, index=df.index)

    simple_df['src_port'] = get_col_safe('Source Port')
    simple_df['dst_port'] = get_col_safe('Destination Port')

    simple_df['packet_count'] = get_col_safe('Total Fwd Packets') + get_col_safe('Total Backward Packets')

    simple_df['total_bytes'] = get_col_safe('Total Length of Fwd Packets') + get_col_safe('Total Length of Bwd Packets')

    simple_df['duration_ms'] = get_col_safe('Flow Duration') / 1000 
    
    print(f"Conversion complete. Shape: {simple_df.shape}")
    return simple_df

def load_and_split_cicids2017(filepath, test_size: float = 0.2, sample_size: int = None):
    from sklearn.model_selection import train_test_split
    
    features, labels = load_cicids2017(filepath, sample_size)
    X_scaled, y, scaler = preprocess_cicids2017(features, labels)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=test_size, random_state=42, stratify=y
    )
    
    print(f"Train: {len(X_train)} | Test: {len(X_test)}")
    return X_train, X_test, y_train, y_test, scaler

def preprocess_cicids2017(features, labels):
    features = features.replace([np.inf, -np.inf], np.nan)
    features = features.fillna(features.median(numeric_only=True))
    
    available = [f for f in CICIDS_FEATURE_COLUMNS if f in features.columns]
    X = features[available].values
    y = labels.values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    return X_scaled, y, scaler