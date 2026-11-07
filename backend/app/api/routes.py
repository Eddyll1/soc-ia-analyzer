"""Rutas de la API: carga, análisis, historial."""
from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from ..db import crud
from ..db.database import get_db
from ..ingest.parser import ContractError, build_events, load_raw
from ..detection.engine import run_detection
from ..detection.correlate import correlate
from ..agents.orchestrator import run_agents

router = APIRouter(prefix="/api")

_UPLOAD_DIR = Path(tempfile.gettempdir()) / "soc_uploads"
_UPLOAD_DIR.mkdir(exist_ok=True)


@router.post("/upload")
async def upload(file: UploadFile = File(...), profile: str = Form("CIS"),
                 db: Session = Depends(get_db)):
    """Sube un .xlsx, valida el contrato y devuelve preview + id del análisis."""
    if not file.filename.lower().endswith((".xlsx", ".xls")):
        raise HTTPException(400, "Solo se aceptan archivos Excel (.xlsx)")
    dest = _UPLOAD_DIR / file.filename
    dest.write_bytes(await file.read())
    try:
        raw = load_raw(dest)
    except ContractError as e:
        raise HTTPException(422, f"El archivo no cumple el contrato de datos: {e}")

    a = crud.create_draft(db, file.filename, profile)
    (_UPLOAD_DIR / f"analysis_{a.id}.xlsx").write_bytes(dest.read_bytes())
    return {
        "analysis_id": a.id,
        "filename": file.filename,
        "columns": list(raw.columns),
        "row_count": int(len(raw)),
        "preview": raw.head(10).fillna("").to_dict("records"),
        "profile": profile,
    }


@router.post("/analyze")
def analyze(analysis_id: int = Form(...), profile: str = Form("CIS"),
            db: Session = Depends(get_db)):
    """Corre ingesta + motor de reglas + correlación + agentes IA y persiste todo."""
    src = _UPLOAD_DIR / f"analysis_{analysis_id}.xlsx"
    if not src.exists():
        raise HTTPException(404, "No se encontró el archivo del análisis; vuelve a subirlo")
    try:
        ing = build_events(src)
    except ContractError as e:
        raise HTTPException(422, str(e))

    det = run_detection(ing.events, profile=profile)
    incidents = correlate(det.findings)
    report = run_agents(ing.events, incidents, det=det, ing=ing)

    crud.save_events(db, analysis_id, ing.events)
    crud.save_analysis_result(db, analysis_id, det=det, incidents=incidents,
                              report=report, ing=ing)
    return crud.get_full_analysis(db, analysis_id)


@router.get("/analyses")
def analyses(db: Session = Depends(get_db)):
    return crud.list_analyses(db)


@router.get("/analysis/{analysis_id}/events")
def events(analysis_id: int, db: Session = Depends(get_db)):
    return crud.get_events(db, analysis_id)


@router.get("/analysis/{analysis_id}")
def analysis(analysis_id: int, db: Session = Depends(get_db)):
    data = crud.get_full_analysis(db, analysis_id)
    if not data:
        raise HTTPException(404, "Análisis no encontrado")
    return data


@router.delete("/analysis/{analysis_id}")
def delete(analysis_id: int, db: Session = Depends(get_db)):
    if not crud.delete_analysis(db, analysis_id):
        raise HTTPException(404, "Análisis no encontrado")
    return {"deleted": analysis_id}
