from pyexpat import features

from fastapi import APIRouter
from app.services.storage import search_logs
from app.services.detection.base import run_detection

from app.services.explanation.classifier import classify_event
from app.services.explanation.explainer import generate_reasoning
from app.services.timeline import build_timeline
from app.services.feature_engineering import extract_features
from app.services.timeline import build_user_timelines, build_timeline_summary
from app.services.storage_utils import get_logs_from_es
from app.services.explanation.llm_explainer import generate_llm_explanation
from app.services.ml_model import predict_with_confidence
from app.services.feature_engineering import extract_network_features


from app.services.feature_engineering import extract_network_features
from app.services.ml_model import predict_with_confidence
from app.services.correlation_engine import correlate_events

router = APIRouter()
def get_rule_confidence(alert_type):
    return {
        "burst_activity": 0.6,
        "possible_exfiltration": 0.8
    }.get(alert_type, 0.5)


@router.get("/")
def detect():

    logs = get_logs_from_es()
    print("logs: ", logs)
    user_groups = build_user_timelines(logs)

    alerts = []

    for user, user_logs in user_groups.items():

        base_alerts = run_detection(user_logs)

        # attach user
        for a in base_alerts:
            a["user"] = user

        # 🔥 NEW: correlation
        correlated = correlate_events(user_logs, base_alerts)

        for c in correlated:
            c["user"] = user

        alerts.extend(base_alerts)
        alerts.extend(correlated)


    print("alerts: ", alerts)
    timelines = build_user_timelines(logs)

    results = []
    cnt=0
    for alert in alerts:
        user = alert.get("user", "unknown")

        user_logs = [l for l in logs if l.get("user") == user]

        # Decide if ML should be used
        features = None
        confidence = None

        is_network_data = any(l.get("source") == "network" for l in user_logs)

        if is_network_data:
            features = extract_network_features(user_logs)

            if features is not None:
                ml_results = predict_with_confidence([features])
                confidence = ml_results[0]["confidence"]
            else:
                # network logs exist but no usable features
                confidence = get_rule_confidence(alert["type"])
        else:
            # pure system logs
            confidence = get_rule_confidence(alert["type"])

        attack_type = classify_event(user_logs, features or {})
        reasons = generate_reasoning(features,user_logs)
        timeline = build_timeline_summary(timelines.get(user, []))

        event = {
            "user": user,
            "attack_type": attack_type,
            "timeline": timeline,
            "reasons": reasons,
            "alert_type": alert["type"],
            "source_mix": list(set([l.get("source") for l in user_logs]))
        }
        cnt+=1
        if cnt>5:
            print("Limiting to 5 events for LLM explanation")
            break

        # if attack_type != "Unknown":
        llm_explanation = generate_llm_explanation(event)
    
        results.append({
            "user": user,
            "attack_type": attack_type,
            "confidence": confidence,
            "alert": alert,
            "reasons": reasons,
            "timeline": timeline,
            "llm_explanation": llm_explanation
        })

    return results