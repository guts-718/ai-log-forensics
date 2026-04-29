from fastapi import APIRouter

from app.services.storage_utils import get_logs_from_es
from app.services.detection.base import run_detection

from app.services.timeline import build_user_timelines, build_timeline_summary

from app.services.feature_engineering import extract_network_features
from app.services.ml_model import predict_with_confidence

from app.services.explanation.classifier import classify_event
from app.services.explanation.explainer import generate_reasoning
from app.services.explanation.llm_explainer import generate_llm_explanation

from app.services.correlation_engine import correlate_events

from app.services.baseline import build_user_baselines, detect_user_anomaly
from app.services.graph_engine import build_attack_graph, detect_attack_chains

from app.services.scoring_engine import (
    add_chain_score,
    add_lstm_score,
    compute_risk_score,
    normalize_score,
    get_risk_level
)
from app.services.lstm_inference import predict_sequence_anomaly
router = APIRouter()


# Rule-based fallback confidence
def get_rule_confidence(alert_type):
    return {
        "burst_activity": 0.6,
        "possible_exfiltration": 0.8
    }.get(alert_type, 0.5)

# Simple anomaly detector
def detect_anomaly(features):
    if not features:
        return False

    if features.get("event_count", 0) > 10:
        return True

    if features.get("Flow Bytes/s", 0) > 20000:
        return True

    return False

# MAIN DETECT ENDPOINT
@router.get("/")
def detect():

    print("\n========== 🚀 DETECT ENDPOINT START ==========\n")

    # ===== FETCH LOGS =====
    logs = get_logs_from_es()
    print(f"[STEP 1] Total logs fetched: {len(logs)}")

    if not logs:
        print("❌ No logs found from Elasticsearch")
        return {"status": "no_logs", "results": []}

    print("Sample log:", logs[0])

    # ===== BUILD USER TIMELINES =====
    user_groups = build_user_timelines(logs)
    print(f"[STEP 2] Total users detected: {len(user_groups)}")

    for user, user_logs in list(user_groups.items())[:3]:
        print(f"   → user={user}, logs={len(user_logs)}")

    # ===== BASELINES =====
    baselines = build_user_baselines(logs)
    print(f"[STEP 3] Baselines built for users: {len(baselines)}")

    alerts = []

    # 1. Generate alerts
    print("\n[STEP 4] generating alerts...\n")

    for user, user_logs in user_groups.items():

        print(f"\n--- Processing user: {user} ---")
        print(f"Logs count: {len(user_logs)}")
        print(f"user logs: {user_logs}")

        base_alerts = run_detection(user_logs)
        print(f"Base alerts: {len(base_alerts)}")

        for a in base_alerts:
            a["user"] = user

        correlated_alerts = correlate_events(user_logs, base_alerts)
        print(f"Correlated alerts: {len(correlated_alerts)}")

        for c in correlated_alerts:
            c["user"] = user

        alerts.extend(base_alerts)
        alerts.extend(correlated_alerts)

    print(f"\n[STEP 4 RESULT] Total alerts generated: {len(alerts)}")

    # if not alerts:
    #     print("No alerts generated → ROOT ISSUE HERE")
    #     return {"status": "no_alerts", "results": []}

    # ===== TIMELINES AGAIN =====
    timelines = build_user_timelines(logs)

    results = []
    llm_limit = 5
    llm_count = 0

    print("\n[STEP 5] Processing alerts...\n")

    # 2. Process alerts
    for i, alert in enumerate(alerts):

        print(f"\n⚡ Alert {i+1}/{len(alerts)} → {alert}")

        user = alert.get("user", "unknown")
        user_logs = timelines.get(user, [])

        print(f"User: {user}, Logs available: {len(user_logs)}")

        # ===== BASELINE =====
        baseline = baselines.get(user, {})
        baseline_anomalies = detect_user_anomaly(user_logs, baseline)
        print(f"Baseline anomalies: {baseline_anomalies}")

        # ===== FEATURE EXTRACTION =====
        features = None
        confidence = None

        is_network_data = any(l.get("source") == "network" for l in user_logs)
        print(f"Is network data: {is_network_data}")

        if is_network_data:
            features = extract_network_features(user_logs)
            print(f"Extracted features: {features}")

            if features:
                ml_results = predict_with_confidence([features])
                confidence = ml_results[0]["confidence"]
                print(f"ML confidence: {confidence}")
            else:
                confidence = get_rule_confidence(alert["type"])
                print(f"Fallback rule confidence: {confidence}")
        else:
            confidence = get_rule_confidence(alert["type"])
            print(f"Rule-based confidence: {confidence}")

        # ===== SCORING =====
        ml_conf = confidence if is_network_data else None

        score, score_reasons = compute_risk_score(
            user_logs,
            features,
            alert,
            ml_confidence=ml_conf
        )

        print(f"Raw score: {score}, reasons: {score_reasons}")

        score = normalize_score(score)
        risk_level = get_risk_level(score)

        print(f"Normalized score: {score}, Risk level: {risk_level}")

        # ===== CLASSIFICATION =====
        attack_type = classify_event(user_logs, features or {})

        if detect_anomaly(features):
            attack_type = "Anomalous Behavior"

        print(f"Attack type: {attack_type}")

        # ===== REASONING =====
        reasons = generate_reasoning(features, user_logs)
        print(f"Initial reasons: {reasons}")

        lstm_score = predict_sequence_anomaly(user_logs)
        score, lstm_reasons = add_lstm_score(score, lstm_score)
        reasons = list(set(reasons + lstm_reasons))

        print("LSTM SCORE:", lstm_score)
        # ===== TIMELINE =====

        timeline = build_timeline_summary(user_logs)

        # ===== GRAPH =====
        graph = build_attack_graph(user_logs)
        attack_chains = detect_attack_chains(graph)

        print(f"Attack chains: {attack_chains}")

        # ===== MERGE REASONS =====
        score, chain_reasons = add_chain_score(score, attack_chains)
        reasons = list(set(reasons + score_reasons + baseline_anomalies + chain_reasons))

        # ===== LLM EVENT =====
        event = {
            "user": user,
            "attack_type": attack_type,
            "timeline": timeline,
            "reasons": reasons,
            "alert_type": alert["type"],
            "source_mix": list(set(l.get("source") for l in user_logs))
        }

        # ===== LLM =====
        if llm_count < llm_limit:
            print("Calling LLM...")
            llm_explanation = generate_llm_explanation(event)
            llm_count += 1
        else:
            llm_explanation = "Skipped (LLM call limit)"

        # ===== FINAL OUTPUT =====
        results.append({
            "user": user,
            "attack_type": attack_type,
            "confidence": confidence,
            "risk_score": score,
            "risk_level": risk_level,
            "alert": alert,
            "baseline_anomalies": baseline_anomalies,
            "reasons": reasons,
            "timeline": timeline,
            "llm_explanation": llm_explanation,
            "attack_chains": attack_chains,
            "event_graph": graph,
        })

    print(f"\n✅ FINAL RESULTS COUNT:{len(results)}")
    print("\n✅ DETECT END END\n")

    return results