def compute_risk_score(logs, features, alert, ml_confidence=None):

    score = 0
    reasons = []

    events = [l.get("event_type") for l in logs]
    sources = [l.get("source") for l in logs]

    # =========================
    # 1. RULE-BASED SIGNALS
    # =========================
    if "usb" in events:
        score += 2
        reasons.append("USB activity detected")

    if events.count("file_access") >= 2:
        score += 2
        reasons.append("Multiple file accesses")

    if events.count("login_failed") >= 3:
        score += 3
        reasons.append("Brute force pattern")

    # =========================
    # 2. ML SIGNAL (VERY IMPORTANT)
    # =========================
    if ml_confidence is not None:
        ml_score = int(ml_confidence * 5)  # scale 0–5
        score += ml_score
        reasons.append(f"ML anomaly score: {ml_confidence:.2f}")

    # =========================
    # 3. NETWORK FEATURES
    # =========================
    if features:
        if features.get("Flow Bytes/s", 0) > 10000:
            score += 2
            reasons.append("High network traffic")

        if features.get("packet_size_variation", 0) > 5:
            score += 1
            reasons.append("Unusual packet variation")

    # =========================
    # 4. CORRELATION BOOST
    # =========================
    if alert["type"] == "cross_source_exfiltration":
        score += 4
        reasons.append("Cross-source correlation detected")

    if alert["type"] == "possible_exfiltration":
        score += 3

    if alert["type"] == "burst_activity":
        score += 1

    # =========================
    # 5. SOURCE MIX BONUS
    # =========================
    if len(set(sources)) > 1:
        score += 2
        reasons.append("Multiple data sources involved")

    return score, reasons

def normalize_score(score):
    return min(score, 10)

def get_risk_level(score):
    if score >= 7:
        return "high"
    elif score >= 4:
        return "medium"
    else:
        return "low"
    

def add_baseline_score(score, anomalies):

    reasons = []

    for a in anomalies:
        if "First-time USB" in a:
            score += 3
        elif "new IP" in a:
            score += 2
        elif "spike" in a:
            score += 2
        else:
            score += 1

        reasons.append(a)

    return score, reasons


def add_chain_score(score, chains):

    reasons = []

    for c in chains:
        if c["type"] == "data_exfiltration_chain":
            score += 4
            reasons.append("Attack chain: data exfiltration sequence")

        elif c["type"] == "brute_force_chain":
            score += 3
            reasons.append("Attack chain: brute force sequence")

        elif c["type"] == "cross_source_chain":
            score += 2
            reasons.append("Cross-source attack chain detected")

    return score, reasons


def add_lstm_score(score, lstm_score):
    reasons = []

    if lstm_score is None:
        return score, reasons

    if lstm_score > 0.7:
        score += 3
        reasons.append("LSTM detected anomalous sequence")

    elif lstm_score > 0.5:
        score += 1
        reasons.append("Moderate sequence anomaly")

    return score, reasons