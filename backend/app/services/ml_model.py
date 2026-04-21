from sklearn.ensemble import IsolationForest
import numpy as np

def run_isolation_forest(features):
    X = []

    users = []

    for f in features:
        users.append(f["user"])
        X.append([
            f["event_count"],
            f["file_access_count"],
            f["login_count"],
            f["unique_ip_count"]
        ])

    X = np.array(X)

    model = IsolationForest(contamination=0.2)
    preds = model.fit_predict(X)

    results = []

    for i, pred in enumerate(preds):
        if pred == -1:
            results.append({
                "user": users[i],
                "type": "ml_anomaly",
                "details": "unusual behavior detected"
            })

    return results