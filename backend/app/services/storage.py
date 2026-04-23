from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")

INDEX = "logs"

def store_log(log):
    es.index(index=INDEX, document=log)

def search_logs(query):
    return es.search(index=INDEX_NAME, body=query)

from elasticsearch import Elasticsearch

# Initialize client
es = Elasticsearch("http://localhost:9200")

INDEX_NAME = "logs_index"


def bulk_insert(logs):
    """
    Insert multiple logs into Elasticsearch using bulk API
    """

    if not logs:
        return

    actions = []

    for log in logs:
        actions.append({"index": {"_index": INDEX_NAME}})
        actions.append(log)

    response = es.bulk(body=actions)

    if response.get("errors"):
        print("[ERROR] Bulk insert had errors")
    else:
        print(f"[INFO] Inserted {len(logs)} logs successfully")



def create_index_if_not_exists():
    if not es.indices.exists(index=INDEX_NAME):
        es.indices.create(index=INDEX_NAME)
        print(f"[INFO] Created index: {INDEX_NAME}")