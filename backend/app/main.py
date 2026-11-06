"""Punto de entrada FastAPI."""
from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()  # carga backend/.env antes que nada (GEMINI_API_KEY, etc.)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.routes import router
from .db.database import init_db
from .agents.gemini_client import GeminiClient

app = FastAPI(title="SOC-IA Analyzer", version="0.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/api/health")
def health() -> dict:
    """Estado del backend y si la IA está conectada a Gemini o en modo mock."""
    c = GeminiClient()
    return {"status": "ok", "ai_mode": c.mode, "ai_model": c.model_name}


app.include_router(router)
