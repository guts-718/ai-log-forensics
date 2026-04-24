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

from app.services.scoring_engine import (
    compute_risk_score,
    normalize_score,
    get_risk_level
)

router = APIRouter()


# =========================
# Rule-based fallback confidence
# =========================
def get_rule_confidence(alert_type):
    return {
        "burst_activity": 0.6,
        "possible_exfiltration": 0.8
    }.get(alert_type, 0.5)


# =========================
# Simple anomaly detector
# =========================
def detect_anomaly(features):
    if not features:
        return False

    if features.get("event_count", 0) > 10:
        return True

    if features.get("Flow Bytes/s", 0) > 20000:
        return True

    return False


# =========================
# MAIN DETECT ENDPOINT
# =========================
@router.get("/")
def detect():

    logs = get_logs_from_es()
    user_groups = build_user_timelines(logs)

    baselines = build_user_baselines(logs)

    alerts = []

    # =========================
    # 1. Generate alerts (rule + correlation)
    # =========================
    for user, user_logs in user_groups.items():

        base_alerts = run_detection(user_logs)

        for a in base_alerts:
            a["user"] = user

        correlated_alerts = correlate_events(user_logs, base_alerts)

        for c in correlated_alerts:
            c["user"] = user

        alerts.extend(base_alerts)
        alerts.extend(correlated_alerts)

    timelines = build_user_timelines(logs)

    results = []
    llm_limit = 5
    llm_count = 0

    # =========================
    # 2. Process alerts
    # =========================
    for alert in alerts:

        user = alert.get("user", "unknown")
        user_logs = timelines.get(user, [])

        # ===== BASELINE =====
        baseline = baselines.get(user, {})
        baseline_anomalies = detect_user_anomaly(user_logs, baseline)

        # ===== FEATURE EXTRACTION =====
        features = None
        confidence = None

        is_network_data = any(l.get("source") == "network" for l in user_logs)

        if is_network_data:
            features = extract_network_features(user_logs)

            if features:
                ml_results = predict_with_confidence([features])
                confidence = ml_results[0]["confidence"]
            else:
                confidence = get_rule_confidence(alert["type"])
        else:
            confidence = get_rule_confidence(alert["type"])

        # ===== SCORING (HYBRID) =====
        ml_conf = confidence if is_network_data else None

        score, score_reasons = compute_risk_score(
            user_logs,
            features,
            alert,
            ml_confidence=ml_conf
        )

        score = normalize_score(score)
        risk_level = get_risk_level(score)

        # ===== CLASSIFICATION =====
        attack_type = classify_event(user_logs, features or {})

        if detect_anomaly(features):
            attack_type = "Anomalous Behavior"

        # ===== REASONING =====
        reasons = generate_reasoning(features, user_logs)

        # merge all reasoning sources
        reasons = list(set(reasons + score_reasons + baseline_anomalies))

        # ===== TIMELINE =====
        timeline = build_timeline_summary(user_logs)

        # ===== LLM EVENT =====
        event = {
            "user": user,
            "attack_type": attack_type,
            "timeline": timeline,
            "reasons": reasons,
            "alert_type": alert["type"],
            "source_mix": list(set(l.get("source") for l in user_logs))
        }

        # ===== LLM (limited calls) =====
        if llm_count < llm_limit:
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
            "llm_explanation": llm_explanation
        })

    return results