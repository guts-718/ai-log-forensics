import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Embedding

VOCAB_SIZE = 10
SEQ_LEN = 5


def build_lstm_model():
    model = Sequential([
        Embedding(input_dim=VOCAB_SIZE, output_dim=16, input_length=SEQ_LEN),
        LSTM(32, return_sequences=False),
        Dense(16, activation="relu"),
        Dense(1, activation="sigmoid")  # anomaly / normal
    ])

    model.compile(
        optimizer="adam",
        loss="binary_crossentropy",
        metrics=["accuracy"]
    )

    return model