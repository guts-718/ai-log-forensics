import pandas as pd
import numpy as np

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report


# =========================
# CONFIG
# =========================
FILE_PATH = "../../data/tuesday.csv"   # change to tuesday/wednesday later
CONTAMINATION = 0.02            # expected anomaly ratio
THRESHOLD_PERCENTILE = 15       # custom anomaly cutoff


# =========================
# LOAD DATA
# =========================
def load_data(path):
    print("[INFO] Loading dataset...")
    df = pd.read_csv(path, low_memory=False)
    print(f"[INFO] Shape: {df.shape}")
    return df


# =========================
# SELECT FEATURES
# =========================
def select_features(df):
    print("[INFO] Selecting features...")


    selected_features = [
        "Flow Duration",
        "Total Fwd Packet",
        "Total Bwd packets",
        "Total Length of Fwd Packet",
        "Total Length of Bwd Packet",

        "Flow Bytes/s",
        "Flow Packets/s",

        "Fwd Packets/s",
        "Bwd Packets/s",

        "Packet Length Mean",
        "Packet Length Std",
        "Packet Length Max",
        "Packet Length Min",

        "Flow IAT Mean",
        "Flow IAT Std",

        "Active Mean",
        "Idle Mean",

        "SYN Flag Count",
        "RST Flag Count",
        "ACK Flag Count"
    ]

    df = df[selected_features + ["Label"]]
    df["packet_size_variation"] = df["Packet Length Std"] / (df["Packet Length Mean"] + 1)
    df["activity_ratio"] = df["Active Mean"] / (df["Idle Mean"] + 1)
    df = df[df["Flow Duration"] > 0]
    return df


# =========================
# CLEAN DATA
# =========================
def clean_data(df):
    print("[INFO] Cleaning data...")

    df = df.replace([np.inf, -np.inf], 0)
    df = df.fillna(0)

    return df


# =========================
# FEATURE ENGINEERING
# =========================
def add_derived_features(df):
    print("[INFO] Adding derived features...")

    df["bytes_per_packet"] = df["Flow Bytes/s"] / (df["Flow Packets/s"] + 1)
    df["fwd_bwd_ratio"] = df["Total Fwd Packet"] / (df["Total Bwd packets"] + 1)

    return df


# =========================
# PREPARE DATA
# =========================
def prepare_data(df):
    print("[INFO] Preparing X and y...")

    X = df.drop(columns=["Label"])

    y_true = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

    return X, y_true


# =========================
# SCALE FEATURES
# =========================
def scale_features(X):
    print("[INFO] Scaling features...")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled


# =========================
# TRAIN MODEL
# =========================
def train_model(X):
    print("[INFO] Training Isolation Forest...")

    model = IsolationForest(contamination=CONTAMINATION, random_state=42)
    model.fit(X)

    return model


# =========================
# PREDICT USING THRESHOLD
# =========================
def predict_with_threshold(model, X):
    print("[INFO] Predicting anomalies...")

    scores = model.decision_function(X)

    threshold = np.percentile(scores, THRESHOLD_PERCENTILE)
    print(f"[INFO] Threshold: {threshold}")

    y_pred = (scores < threshold).astype(int)

    return y_pred, scores


# =========================
# EVALUATE
# =========================
def evaluate(y_true, y_pred):
    print("\n[RESULT] Classification Report:\n")
    print(classification_report(y_true, y_pred))


# =========================
# MAIN
# =========================
def main():
    df = load_data(FILE_PATH)

    print("\n[INFO] Label distribution:")
    print(df["Label"].value_counts())

    df = select_features(df)
    df = clean_data(df)
    df = add_derived_features(df)

    X, y_true = prepare_data(df)
    X_scaled = scale_features(X)

    model = train_model(X_scaled)

    y_pred, scores = predict_with_threshold(model, X_scaled)
    print("[INFO] Score stats:")
    print("min:", scores.min())
    print("max:", scores.max())
    print("mean:", scores.mean())
    print("[INFO] Predicted anomalies:", np.sum(y_pred))

    evaluate(y_true, y_pred)
    


if __name__ == "__main__":
    main()