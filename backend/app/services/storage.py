from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")

INDEX = "logs"

def store_log(log):
    es.index(index=INDEX, document=log)

def search_logs(query):
    return es.search(index=INDEX, body=query)