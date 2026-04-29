import numpy as np
from app.services.sequence_preparation import build_sequences
from app.services.lstm_model import build_lstm_model
from app.services.storage_utils import get_logs_from_es
print("[INFO] Loading logs...")
logs = get_logs_from_es()

print("[INFO] Building sequences...")
X = build_sequences(logs)

# Dummy labels for now (upgrade later)
y = [0] * len(X)

X = np.array(X)
y = np.array(y)

print("[INFO] Training LSTM...")
model = build_lstm_model()
model.fit(X, y, epochs=3, batch_size=32)

model.save("lstm_model.h5")
print("[INFO] Model saved")