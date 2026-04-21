import pandas as pd
import numpy as np

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report


# =========================
# CONFIG
# =========================
FILE_PATH = "../../data/tuesday.csv"
CONTAMINATION = 0.02
THRESHOLD_PERCENTILE = 15


def load_multiple_days(paths):
    dfs = []

    for path in paths:
        print(f"[INFO] Loading {path}")
        df = pd.read_csv(path, low_memory=False)
        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)
    print("[INFO] Combined shape:", combined.shape)

    return combined

# =========================
# LOAD DATA
# =========================
def load_data(path):
    print("[INFO] Loading dataset...")
    paths = [
    "../../data/tuesday.csv",
    "../../data/wednesday.csv",
    "../../data/thursday.csv"
]

    df = load_multiple_days(paths)
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
# SCALE FEATURES (used for IsolationForest)
# =========================
def scale_features(X):
    print("[INFO] Scaling features...")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled


# =========================
# TRAIN MODEL (Isolation Forest)
# =========================
def train_model(X):
    print("[INFO] Training Isolation Forest...")

    model = IsolationForest(contamination=CONTAMINATION, random_state=42)
    model.fit(X)

    return model


# =========================
# PREDICT USING THRESHOLD (Isolation Forest)
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
# RANDOM FOREST (SUPERVISED)
# =========================
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split


def run_supervised_model(X, y):
    print("[INFO] Running supervised model...")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"

    )

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("\n[RESULT] Random Forest:\n")
    print(classification_report(y_test, y_pred))

    return model, X_test, y_test



# =========================
# MAIN
# =========================


def main():
    # =========================
    # CONFIG
    # =========================
    USE_TIME_SPLIT = True   # 🔥 set False for random split

    TRAIN_PATHS = [
        "../../data/tuesday.csv",
        "../../data/wednesday.csv",
        "../../data/thursday.csv"
    ]

    TEST_PATHS = [
        "../../data/friday.csv"
    ]

    ALL_PATHS = TRAIN_PATHS + TEST_PATHS

    # =========================
    # LOAD DATA
    # =========================
    def load_multiple_days(paths):
        dfs = []
        for path in paths:
            print(f"[INFO] Loading {path}")
            df = pd.read_csv(path, low_memory=False)
            dfs.append(df)
        combined = pd.concat(dfs, ignore_index=True)
        print("[INFO] Combined shape:", combined.shape)
        return combined

    # =========================
    # PIPELINE FUNCTION
    # =========================
    def process(df):
        print("\n[INFO] Label distribution:")
        print(df["Label"].value_counts())

        df = select_features(df)
        df = clean_data(df)
        df = add_derived_features(df)

        X, y = prepare_data(df)

        return X, y

    # =========================
    # SPLIT STRATEGY
    # =========================
    if USE_TIME_SPLIT:
        print("\n[INFO] Using TIME-BASED split")

        df_train = load_multiple_days(TRAIN_PATHS)
        df_test = load_multiple_days(TEST_PATHS)

        X_train, y_train = process(df_train)
        X_test, y_test = process(df_test)

    else:
        print("\n[INFO] Using RANDOM split")

        df_all = load_multiple_days(ALL_PATHS)
        X, y = process(df_all)

        from sklearn.model_selection import train_test_split

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )

    # =========================
    # MODEL TRAINING
    # =========================
    from sklearn.ensemble import RandomForestClassifier

    print("\n[INFO] Training Random Forest...")

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )

    model.fit(X_train, y_train)

    # =========================
    # EVALUATION
    # =========================
    print("\n[INFO] Evaluating on TEST set...")

    y_pred = model.predict(X_test)

    from sklearn.metrics import classification_report

    print("\n[RESULT] Random Forest:\n")
    print(classification_report(y_test, y_pred))

    # =========================
    # OPTIONAL: TRAIN PERFORMANCE (for comparison)
    # =========================
    print("\n[INFO] Training performance (sanity check):")
    y_train_pred = model.predict(X_train)
    print(classification_report(y_train, y_train_pred))





if __name__ == "__main__":
    main()



# [INFO] Using TIME-BASED split
# [INFO] Loading ../../data/tuesday.csv
# [INFO] Loading ../../data/wednesday.csv
# [INFO] Combined shape: (818718, 89)
# [INFO] Loading ../../data/thursday.csv
# [INFO] Combined shape: (362075, 89)

# [INFO] Label distribution:
# Label
# BENIGN                          634225
# DoS Hulk                        158468
# DoS GoldenEye                     7567
# FTP-Patator                       3972
# DoS Slowloris                     3859
# DoS Slowhttptest - Attempted      3368
# SSH-Patator                       2961
# DoS Slowloris - Attempted         1847
# DoS Slowhttptest                  1740
# DoS Hulk - Attempted               581
# DoS GoldenEye - Attempted           80
# SSH-Patator - Attempted             27
# FTP-Patator - Attempted             12
# Heartbleed                          11
# Name: count, dtype: int64
# [INFO] Selecting features...
# [INFO] Cleaning data...
# [INFO] Adding derived features...
# [INFO] Preparing X and y...

# [INFO] Label distribution:
# Label
# BENIGN                                    288171
# Infiltration - Portscan                    71767
# Web Attack - Brute Force - Attempted        1292
# Web Attack - XSS - Attempted                 655
# Web Attack - Brute Force                      73
# Infiltration - Attempted                      45
# Infiltration                                  36
# Web Attack - XSS                              18
# Web Attack - SQL Injection                    13
# Web Attack - SQL Injection - Attempted         5
# Name: count, dtype: int64
# [INFO] Selecting features...
# [INFO] Cleaning data...
# [INFO] Adding derived features...
# [INFO] Preparing X and y...

# [INFO] Training Random Forest...

# [INFO] Evaluating on TEST set...

# [RESULT] Random Forest:

#               precision    recall  f1-score   support

#            0       0.80      1.00      0.89    288171
#            1       0.27      0.00      0.00     73904

#     accuracy                           0.80    362075
#    macro avg       0.53      0.50      0.44    362075
# weighted avg       0.69      0.80      0.71    362075


# [INFO] Training performance (sanity check):
#               precision    recall  f1-score   support

#            0       1.00      1.00      1.00    634225
#            1       1.00      1.00      1.00    184493

#     accuracy                           1.00    818718
#    macro avg       1.00      1.00      1.00    818718
# weighted avg       1.00      1.00      1.00    818718


# ----------------------------



# (venv) PS C:\Users\rahul\OneDrive\Desktop\major_real\backend\app\scripts> python .\cicids_experiment.py

# [INFO] Using TIME-BASED split
# [INFO] Loading ../../data/tuesday.csv
# [INFO] Loading ../../data/wednesday.csv
# [INFO] Loading ../../data/thursday.csv
# [INFO] Combined shape: (1180793, 89)
# [INFO] Loading ../../data/friday.csv
# [INFO] Combined shape: (547557, 89)

# [INFO] Label distribution:
# Label
# BENIGN                                    922396
# DoS Hulk                                  158468
# Infiltration - Portscan                    71767
# DoS GoldenEye                               7567
# FTP-Patator                                 3972
# DoS Slowloris                               3859
# DoS Slowhttptest - Attempted                3368
# SSH-Patator                                 2961
# DoS Slowloris - Attempted                   1847
# DoS Slowhttptest                            1740
# Web Attack - Brute Force - Attempted        1292
# Web Attack - XSS - Attempted                 655
# DoS Hulk - Attempted                         581
# DoS GoldenEye - Attempted                     80
# Web Attack - Brute Force                      73
# Infiltration - Attempted                      45
# Infiltration                                  36
# SSH-Patator - Attempted                       27
# Web Attack - XSS                              18
# Web Attack - SQL Injection                    13
# FTP-Patator - Attempted                       12
# Heartbleed                                    11
# Web Attack - SQL Injection - Attempted         5
# Name: count, dtype: int64
# [INFO] Selecting features...
# [INFO] Cleaning data...
# [INFO] Adding derived features...
# [INFO] Preparing X and y...

# [INFO] Label distribution:
# Label
# BENIGN                288544
# Portscan              159066
# DDoS                   95144
# Botnet - Attempted      4067
# Botnet                   736
# Name: count, dtype: int64
# [INFO] Selecting features...
# [INFO] Cleaning data...
# [INFO] Adding derived features...
# [INFO] Preparing X and y...

# [INFO] Training Random Forest...

# [INFO] Evaluating on TEST set...

# [RESULT] Random Forest:

#               precision    recall  f1-score   support

#            0       0.99      1.00      0.99    288544
#            1       1.00      0.98      0.99    259013

#     accuracy                           0.99    547557
#    macro avg       0.99      0.99      0.99    547557
# weighted avg       0.99      0.99      0.99    547557


# [INFO] Training performance (sanity check):
#               precision    recall  f1-score   support

#            0       1.00      1.00      1.00    922396
#            1       1.00      1.00      1.00    258397

#     accuracy                           1.00   1180793
#    macro avg       1.00      1.00      1.00   1180793
# weighted avg       1.00      1.00      1.00   1180793