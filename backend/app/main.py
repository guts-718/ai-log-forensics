from fastapi import FastAPI
from app.routes import ingest, query
from app.routes import timeline


app = FastAPI(title="AI Forensics Backend")

app.include_router(ingest.router, prefix="/ingest")
app.include_router(query.router, prefix="/logs")
app.include_router(timeline.router, prefix="/timeline")