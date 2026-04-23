from fastapi import APIRouter, UploadFile
from app.services.parser import parse_log
from app.services.normalizer import normalize_log
from app.services.storage import store_log
from app.services.storage import bulk_insert
# router = APIRouter()

# @router.post("/")
# async def ingest(file: UploadFile):
#     content = await file.read()
#     lines = content.decode().split("\n")

#     count = 0

#     for line in lines:
#         if not line.strip():
#             continue

#         parsed = parse_log(line)
#         normalized = normalize_log(parsed)
#         store_log(normalized)
#         count += 1

#     return {"message": f"{count} logs ingested"}

from fastapi import APIRouter
from typing import List

router = APIRouter()

@router.post("/")
def ingest(logs: List[dict]):

    processed = []

    for raw in logs:
        parsed = parse_log(raw)
        normalized = normalize_log(parsed)

        processed.append(normalized)

    bulk_insert(processed)

    return {
        "status": "success",
        "count": len(processed)
    }