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

router = APIRouter()

@router.get("/")
def detect():

    logs = get_logs_from_es()

    alerts = run_detection(logs)
    timelines = build_user_timelines(logs)

    results = []
    cnt=0
    for alert in alerts:
        user = alert.get("user", "unknown")

        confidence = alert.get("score", None)

        if confidence is None:
            confidence = "medium"  

        user_logs = [l for l in logs if l.get("user") == user]

        features = extract_network_features(user_logs)
        ml_results = predict_with_confidence([features])

        confidence = ml_results[0]["confidence"]

        attack_type = classify_event(user_logs, features)
        reasons = generate_reasoning(features)
        timeline = build_timeline_summary(timelines.get(user, []))

        event = {
            "user": user,
            "attack_type": attack_type,
            "timeline": timeline,
            "reasons": reasons
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