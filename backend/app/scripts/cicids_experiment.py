import pandas as pd
import numpy as np

from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

from xgboost import XGBClassifier
from lightgbm import LGBMClassifier


# =========================
# CONFIG
# =========================
USE_TIME_SPLIT = True

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
# LOAD MULTIPLE FILES
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
# FEATURE SELECTION
# =========================
def select_features(df):
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

    # Derived features
    df["packet_size_variation"] = df["Packet Length Std"] / (df["Packet Length Mean"] + 1)
    df["activity_ratio"] = df["Active Mean"] / (df["Idle Mean"] + 1)
    df["bytes_per_packet"] = df["Flow Bytes/s"] / (df["Flow Packets/s"] + 1)
    df["packet_rate_ratio"] = df["Fwd Packets/s"] / (df["Bwd Packets/s"] + 1)
    df["flow_intensity"] = df["Flow Bytes/s"] * df["Flow Packets/s"]
    df["forward_backward_ratio"] = df["Total Fwd Packet"] / (df["Total Bwd packets"] + 1)

    df = df[df["Flow Duration"] > 0]

    return df


# =========================
# CLEAN DATA
# =========================
def clean_data(df):
    df = df.replace([np.inf, -np.inf], 0)
    df = df.fillna(0)
    return df


# =========================
# PREPARE DATA
# =========================
def prepare_data(df):
    X = df.drop(columns=["Label"])
    y = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)
    return X, y


# =========================
# COMPUTE CLASS WEIGHTS
# =========================
def get_class_weights(y):
    classes = np.unique(y)

    weights = compute_class_weight(
        class_weight="balanced",
        classes=classes,
        y=y
    )

    class_weight_dict = dict(zip(classes, weights))
    print("[INFO] Class Weights:", class_weight_dict)

    return class_weight_dict


# =========================
# MODELS
# =========================

def run_logistic_regression(X_train, X_test, y_train, y_test, class_weight):
    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = LogisticRegression(
        max_iter=1000,
        n_jobs=-1,
        class_weight=class_weight
    )

    model.fit(X_train_scaled, y_train)
    y_pred = model.predict(X_test_scaled)

    return y_pred


def run_random_forest(X_train, X_test, y_train, y_test, class_weight):
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight=class_weight
    )

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    return y_pred


def run_gradient_boosting(X_train, X_test, y_train, y_test, class_weight):
    model = GradientBoostingClassifier()

    sample_weights = y_train.map(class_weight)

    model.fit(X_train, y_train, sample_weight=sample_weights)
    y_pred = model.predict(X_test)

    return y_pred


def run_xgboost(X_train, X_test, y_train, y_test, class_weight):
    # scale_pos_weight = imbalance ratio
    neg, pos = np.bincount(y_train)
    scale_pos_weight = neg / pos

    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        scale_pos_weight=scale_pos_weight,
        n_jobs=-1,
        random_state=42
    )

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    return y_pred


def run_lightgbm(X_train, X_test, y_train, y_test, class_weight):
    model = LGBMClassifier(
        n_estimators=200,
        learning_rate=0.1,
        class_weight=class_weight,
        n_jobs=-1,
        random_state=42
    )

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    return y_pred


# =========================
# EVALUATION
# =========================
def evaluate_model(name, y_true, y_pred):
    print(f"\n[RESULT] {name}:\n")
    print(classification_report(y_true, y_pred, digits=4))
    print("Confusion Matrix:")
    print(confusion_matrix(y_true, y_pred))


# =========================
# MAIN PIPELINE
# =========================
def main():

    if USE_TIME_SPLIT:
        print("\n[INFO] Using TIME-BASED split")

        df_train = load_multiple_days(TRAIN_PATHS)
        df_test = load_multiple_days(TEST_PATHS)

        df_train = clean_data(select_features(df_train))
        df_test = clean_data(select_features(df_test))

        X_train, y_train = prepare_data(df_train)
        X_test, y_test = prepare_data(df_test)

    else:
        print("\n[INFO] Using RANDOM split")

        df_all = load_multiple_days(ALL_PATHS)
        df_all = clean_data(select_features(df_all))

        X, y = prepare_data(df_all)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, stratify=y, random_state=42
        )

    # =========================
    # CLASS WEIGHTS
    # =========================
    class_weight = get_class_weights(y_train)

    # =========================
    # RUN MODELS
    # =========================
    evaluate_model(
        "Logistic Regression",
        y_test,
        run_logistic_regression(X_train, X_test, y_train, y_test, class_weight)
    )

    evaluate_model(
        "Random Forest",
        y_test,
        run_random_forest(X_train, X_test, y_train, y_test, class_weight)
    )

    evaluate_model(
        "Gradient Boosting",
        y_test,
        run_gradient_boosting(X_train, X_test, y_train, y_test, class_weight)
    )

    evaluate_model(
        "XGBoost",
        y_test,
        run_xgboost(X_train, X_test, y_train, y_test, class_weight)
    )

    evaluate_model(
        "LightGBM",
        y_test,
        run_lightgbm(X_train, X_test, y_train, y_test, class_weight)
    )


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