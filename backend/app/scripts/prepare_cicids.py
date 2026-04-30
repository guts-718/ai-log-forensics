import pandas as pd
import numpy as np

def load_and_merge():
    files = [
        "./data/tuesday.csv",
         "./data/tuesday_plus.csv",
        "./data/wednesday.csv",
        "./data/wednesday_plus.csv",
        "./data/thursday.csv",
        "./data/thursday_plus.csv",
        "./data/friday.csv",
        "./data/friday_plus.csv"
    ]

    dfs = []
    for f in files:
        df = pd.read_csv(f, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        dfs.append(df)

    return pd.concat(dfs, ignore_index=True)


def clean(df):
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    df = df[df["Flow Duration"] > 0]
    return df


def select_features(df):
    selected = [
    # Flow
    "Flow Duration",
    "Flow Bytes/s",
    "Flow Packets/s",

    # Packet stats
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Max",
    "Packet Length Min",

    # Direction
    "Total Fwd Packet",
    "Total Bwd packets",
    "Total Length of Fwd Packet",
    "Total Length of Bwd Packet",

    # Timing
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",

    # Flags
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "PSH Flag Count",

    # Activity
    "Active Mean",
    "Idle Mean",
    "Src IP dec", 
    "Dst IP dec",
    "Src Port", 
    "Dst Port", 
    "Protocol",
    "Timestamp"
]

    df = df[selected + ["Label"]]

    # derived features
    df["bytes_per_packet"] = df["Flow Bytes/s"] / (df["Flow Packets/s"] + 1)
    df["flow_intensity"] = df["Flow Bytes/s"] * df["Flow Packets/s"]
    df["packet_size_variation"] = df["Packet Length Std"] / (df["Packet Length Mean"] + 1)
    df["forward_backward_ratio"] = df["Total Fwd Packet"] / (df["Total Bwd packets"] + 1)
    print(f"this is from the select_features function: {df.describe()}")
    return df


if __name__ == "__main__":
    df = load_and_merge()
    df = clean(df)
    df = select_features(df)

    print("[INFO] Final shape:", df.shape)


    df.to_csv("./data/cicids_selected.csv", index=False)
    print(df.head())
    print(df.describe())