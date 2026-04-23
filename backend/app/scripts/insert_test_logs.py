import json
import requests

API_URL = "http://localhost:8000/ingest"  # adjust if needed

with open("app/data/test_logs.json", "r") as f:
    logs = json.load(f)

print(f"[INFO] Inserting {len(logs)} logs...")

response = []
print(f"[DEBUG] Inserting log: {logs}")
requests.post(API_URL, json=logs)

# print("[INFO] Response:", response[0].status_code)
# print(response[0].text)