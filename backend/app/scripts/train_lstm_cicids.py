import pandas as pd
import numpy as np

from app.services.cicids_sequence_encoder import build_cicids_sequences
from app.services.lstm_model import build_lstm_model

print("[INFO] Loading CICIDS...")

df = pd.read_csv("./data/tuesday.csv")

print("[INFO] Building sequences...")
sequences = build_cicids_sequences(df)

X = np.array([s[0] for s in sequences])
y = np.array([s[1] for s in sequences])

print("[INFO] Training LSTM...")

model = build_lstm_model()
model.fit(X, y, epochs=5, batch_size=64)

model.save("lstm_cicids.h5")

print("[INFO] Model saved")