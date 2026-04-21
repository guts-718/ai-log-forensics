from fastapi import APIRouter, Query
from app.services.storage import search_logs

router = APIRouter()

@router.get("/")
def get_logs(user: str = None, event_type: str = None):

    must = []

    if user:
        must.append({"match": {"user": user}})
    if event_type:
        must.append({"match": {"event_type": event_type}})

    query = {
        "query": {
            "bool": {
                "must": must if must else [{"match_all": {}}]
            }
        }
    }

    res = search_logs(query)

    return [hit["_source"] for hit in res["hits"]["hits"]]