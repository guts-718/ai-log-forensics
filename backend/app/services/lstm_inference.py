import numpy as np
from tensorflow.keras.models import load_model
from app.services.sequence_preparation import build_sequences
import numpy as np

model = load_model("lstm_model.h5")

def predict_sequence_anomaly(logs):

    sequences = build_sequences(logs)

    if not sequences:
        return None

    X = np.array(sequences)

    preds = model.predict(X)

    confidences = np.max(preds, axis=1)

    anomaly_score = 1 - np.mean(confidences)

    return float(anomaly_score)