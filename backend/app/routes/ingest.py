from fastapi import APIRouter, UploadFile
from app.services.parser import parse_log
from app.services.normalizer import normalize
from app.services.storage import store_log

router = APIRouter()

@router.post("/")
async def ingest(file: UploadFile):
    content = await file.read()
    lines = content.decode().split("\n")

    count = 0

    for line in lines:
        if not line.strip():
            continue

        parsed = parse_log(line)
        normalized = normalize(parsed)
        store_log(normalized)
        count += 1

    return {"message": f"{count} logs ingested"}