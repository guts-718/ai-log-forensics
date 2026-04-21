from fastapi import APIRouter
from app.services.storage import search_logs
from app.services.detection import run_detection

router = APIRouter()

@router.get("/")
def detect():

    query = {
        "query": {
            "match_all": {}
        },
        "size": 1000
    }

    res = search_logs(query)
    logs = [hit["_source"] for hit in res["hits"]["hits"]]

    alerts = run_detection(logs)

    return alerts