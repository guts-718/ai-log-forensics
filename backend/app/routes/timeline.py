from fastapi import APIRouter
from app.services.storage import search_logs
from app.services.timeline import build_user_timelines

router = APIRouter()

@router.get("/")
def get_timeline():

    query = {
        "query": {
            "match_all": {}
        },
        "size": 1000
    }

    res = search_logs(query)
    logs = [hit["_source"] for hit in res["hits"]["hits"]]

    timelines = build_user_timelines(logs)

    return timelines