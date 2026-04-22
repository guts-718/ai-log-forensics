def get_logs_from_es(size=1000):
    from app.services.storage import search_logs

    query = {
        "query": {"match_all": {}},
        "size": size
    }

    res = search_logs(query)

    logs = [hit["_source"] for hit in res["hits"]["hits"]]

    return logs