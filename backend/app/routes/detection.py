from fastapi import APIRouter
from app.services.storage import search_logs
from app.services.detection.base import run_detection


from app.services.feature_engineering import extract_features
from app.services.ml_model import run_isolation_forest

router = APIRouter()

@router.get("/")
def detect():

    query = {
        "query": {"match_all": {}},
        "size": 1000
    }

    res = search_logs(query)
    logs = [hit["_source"] for hit in res["hits"]["hits"]]

    # Rule-based
    alerts = run_detection(logs)

    # ML-based
    features = extract_features(logs)
    ml_alerts = run_isolation_forest(features)

    return {
        "rule_based": alerts,
        "ml_based": ml_alerts
    }