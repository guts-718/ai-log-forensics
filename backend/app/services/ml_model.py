import joblib
import os
import numpy as np

from .ml_features import FEATURE_COLUMNS

# =========================
# LOAD MODEL (once at startup)
# =========================

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
print(f"[INFO] Loading ML model from {BASE_DIR}...")
MODEL_PATH = os.path.join(BASE_DIR, "scripts","app","models", "random_forest.pkl")

model = joblib.load(MODEL_PATH)

print("[INFO] ML model loaded successfully")


# =========================
# PREDICTION FUNCTION
# =========================

def predict_with_confidence(features_list):
    """
    features_list: list of feature dicts
    """

    X = []

    for f in features_list:
        row = [f.get(col, 0) for col in FEATURE_COLUMNS]
        X.append(row)

    # X = np.array(X)

    import pandas as pd
    X_df = pd.DataFrame(X, columns=FEATURE_COLUMNS)
    probs=model.predict_proba(X_df)


    results = []

    for p in probs:
        confidence = float(max(p))
        label = int(p[1] > 0.5)

        results.append({
            "prediction": label,
            "confidence": round(confidence, 3)
        })

    return results