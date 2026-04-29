import numpy as np

def encode_flow(row):
    """
    Convert CICIDS row → discrete token
    """

    # Example logic (can expand later)
    if row["Label"] != "BENIGN":
        return 2  # attack

    if row["Flow Bytes/s"] > 10000:
        return 1  # high traffic

    return 0  # normal


def build_cicids_sequences(df, window_size=5):

    sequences = []

    encoded = [encode_flow(row) for _, row in df.iterrows()]

    for i in range(len(encoded) - window_size):
        seq = encoded[i:i+window_size+1]

        X = seq[:-1]
        y = seq[-1]

        sequences.append((X, y))

    return sequences