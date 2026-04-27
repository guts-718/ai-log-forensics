def build_attack_graph(user_logs):
    """
    Build directed graph from user timeline
    """

    if not user_logs:
        return {"nodes": [], "edges": []}

    # sort by time
    logs = sorted(user_logs, key=lambda x: x.get("timestamp", ""))

    nodes = []
    edges = []

    for i, log in enumerate(logs):
        node = {
            "id": i,
            "event": log.get("event_type"),
            "timestamp": log.get("timestamp"),
            "source": log.get("source"),
            "user": log.get("user")
        }
        nodes.append(node)

        # create edge to next event
        if i > 0:
            edges.append({
                "from": i - 1,
                "to": i,
                "relation": "sequence"
            })

    return {
        "nodes": nodes,
        "edges": edges
    }




def detect_attack_chains(graph):
    """
    Identify meaningful sequences (attack chains)
    """

    nodes = graph["nodes"]
    events = [n["event"] for n in nodes]

    chains = []

    # ===== 1. Exfiltration chain =====
    if "login" in events and "file_access" in events and "usb" in events:
        chains.append({
            "type": "data_exfiltration_chain",
            "sequence": ["login", "file_access", "usb"]
        })

    # ===== 2. Brute force chain =====
    if events.count("login_failed") >= 3:
        chains.append({
            "type": "brute_force_chain",
            "sequence": ["login_failed", "login_failed", "login_failed"]
        })

    # ===== 3. Multi-source chain =====
    sources = [n["source"] for n in nodes]
    if "system" in sources and "network" in sources:
        chains.append({
            "type": "cross_source_chain",
            "sequence": list(set(events))
        })

    return chains