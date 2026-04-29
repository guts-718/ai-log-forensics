def select_features(df):

    print("[INFO] Selecting features...")

    selected = [
        # ===== Flow =====
        "Flow Duration",
        "Flow Bytes/s",
        "Flow Packets/s",

        # ===== Packets =====
        "Packet Length Mean",
        "Packet Length Std",
        "Packet Length Max",
        "Packet Length Min",

        # ===== Temporal =====
        "Flow IAT Mean",
        "Flow IAT Std",

        # ===== Direction =====
        "Total Fwd Packet",
        "Total Bwd packets",

        # ===== Flags =====
        "SYN Flag Count",
        "ACK Flag Count",
        "RST Flag Count",

        # ===== Activity =====
        "Active Mean",
        "Idle Mean",
    ]

    df = df[selected + ["Label"]]

    # ===== Derived features =====
    df["bytes_per_packet"] = df["Flow Bytes/s"] / (df["Flow Packets/s"] + 1)
    df["flow_intensity"] = df["Flow Bytes/s"] * df["Flow Packets/s"]
    df["packet_size_variation"] = df["Packet Length Std"] / (df["Packet Length Mean"] + 1)
    df["forward_backward_ratio"] = df["Total Fwd Packet"] / (df["Total Bwd packets"] + 1)

    print("[INFO] Final columns:", len(df.columns))
    return df