"""Operaciones de persistencia: guardar y recuperar análisis completos."""
from __future__ import annotations

import math

import pandas as pd
from sqlalchemy.orm import Session

from . import models
from ..agents import reports


def _json_safe(obj):
    """Reemplaza NaN/NA/Inf por None recursivamente para que el JSON sea válido."""
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if obj is None:
        return None
    try:
        if isinstance(obj, float) and (math.isnan(obj) or math.isinf(obj)):
            return None
    except TypeError:
        pass
    if pd.api.types.is_scalar(obj) and pd.isna(obj):
        return None
    return obj

# Columnas normalizadas → campo canónico de la tabla event
_EVENT_MAP = {
    "Log_ID": "log_id", "Timestamp": "timestamp", "Host_Normalized": "host",
    "Event_ID": "event_id", "User_Normalized": "user", "Source_IP": "source_ip",
    "Destination": "destination", "Log_Source": "log_source",
    "Event_Description": "description", "Process_CommandLine": "command_line",
    "Result": "result", "Severity_Original": "severity",
}
# columnas que, si existen, van a extra_json (no se pierde nada)
_EXTRA_COLS = ["Logon_Type", "Meta_Source", "Meta_Parent", "Meta_Process",
               "User_Alias_Flag", "Hostname", "User"]


def create_draft(db: Session, filename: str, profile: str) -> models.Analysis:
    a = models.Analysis(filename=filename, profile=profile, status="draft")
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


def save_events(db: Session, analysis_id: int, df: pd.DataFrame) -> None:
    rows = []
    for _, r in df.iterrows():
        extra = {c: (None if pd.isna(r.get(c)) else str(r.get(c)))
                 for c in _EXTRA_COLS if c in df.columns}
        rec = {dst: (None if pd.isna(r.get(src)) else str(r.get(src)))
               for src, dst in _EVENT_MAP.items() if src in df.columns}
        rows.append(models.Event(analysis_id=analysis_id, extra_json=extra, **rec))
    db.bulk_save_objects(rows)
    db.commit()


def save_analysis_result(db: Session, analysis_id: int, *, det, incidents,
                         report, ing) -> None:
    a = db.get(models.Analysis, analysis_id)
    a.status = "analyzed"
    a.profile = det.profile
    a.event_count = det.stats["total_events"]
    a.time_start = det.stats["time_start"]
    a.time_end = det.stats["time_end"]
    a.stats_json = _json_safe(det.stats)
    a.normalizations_json = _json_safe(ing.normalizations)
    a.limitations_json = ing.limitations
    a.ai_mode = report.mode
    a.security_log_json = report.security_log

    cls_by_inc = {c["incident_id"]: c for c in report.classifications}
    inc_by_id = {i["id"]: i for i in report.incidents}
    max_rank, max_sev = 0, None
    rank = {"Crítico": 4, "Alto": 3, "Medio": 2, "Bajo": 1}

    for f in det.findings:
        # a qué incidente pertenece cada finding
        inc_code = next((inc.id for inc in incidents if f in inc.findings), None)
        db.add(models.Finding(
            analysis_id=analysis_id, incident_id=inc_code, rule_id=f.rule_id,
            title=f.title, severity_hint=f.severity_hint, evidence_json=f.evidence,
            summary=f.summary, entity_json=_json_safe(f.entity)))

    for inc in incidents:
        c = cls_by_inc.get(inc.id, {})
        n = inc_by_id.get(inc.id, {})
        sev = c.get("risk", "Medio")
        if rank.get(sev, 0) > max_rank:
            max_rank, max_sev = rank[sev], sev
        db.add(models.Incident(
            analysis_id=analysis_id, code=inc.id, severity=sev,
            headline=n.get("headline"), window=n.get("window"),
            ai_narrative=n.get("ai_narrative"), phases_json=_json_safe(n.get("phases")),
            timeline_json=_json_safe(n.get("timeline")), event_count=n.get("event_count"),
            entities_json=_json_safe(n.get("affected")), evidence_json=inc.evidence(),
            justification=c.get("justification"), impact=c.get("impact"),
            recommended_action=c.get("recommended_action")))

    a.max_severity = max_sev
    for ioc in det.iocs:
        db.add(models.Ioc(analysis_id=analysis_id, type=ioc["type"],
                          value=ioc["value"], context=ioc.get("context")))
    db.add(models.Report(analysis_id=analysis_id, kind="ejecutivo",
                        content_md=report.executive_md, generated_by=report.mode))
    db.add(models.Report(analysis_id=analysis_id, kind="tecnico",
                        content_md=report.technical_md, generated_by=report.mode))
    db.commit()


def get_full_analysis(db: Session, analysis_id: int) -> dict | None:
    a = db.get(models.Analysis, analysis_id)
    if not a:
        return None
    rules_by_inc: dict[str, set[str]] = {}
    for f in a.findings:
        if f.incident_id:
            rules_by_inc.setdefault(f.incident_id, set()).add(f.rule_id)
    iocs = [{"type": i.type, "value": i.value, "context": i.context} for i in a.iocs]
    inc_dicts = [{"id": i.code, "risk": i.severity, "affected": i.entities_json or {},
                  "rule_ids": sorted(rules_by_inc.get(i.code, set()))} for i in a.incidents]
    return _json_safe({
        "id": a.id, "filename": a.filename, "status": a.status, "profile": a.profile,
        "uploaded_at": a.uploaded_at.isoformat() if a.uploaded_at else None,
        "event_count": a.event_count, "time_start": a.time_start, "time_end": a.time_end,
        "max_severity": a.max_severity, "stats": a.stats_json,
        "normalizations": a.normalizations_json, "limitations": a.limitations_json,
        "ai_mode": a.ai_mode, "security_log": a.security_log_json,
        "findings": [{"rule_id": f.rule_id, "title": f.title, "severity_hint": f.severity_hint,
                      "incident_id": f.incident_id, "evidence": f.evidence_json,
                      "summary": f.summary, "entity": f.entity_json} for f in a.findings],
        "incidents": [{"code": i.code, "severity": i.severity, "headline": i.headline,
                       "window": i.window, "ai_narrative": i.ai_narrative, "phases": i.phases_json,
                       "timeline": i.timeline_json, "event_count": i.event_count,
                       "affected": i.entities_json, "evidence": i.evidence_json,
                       "justification": i.justification, "impact": i.impact,
                       "recommended_action": i.recommended_action}
                      for i in a.incidents],
        "iocs": iocs,
        "mitigation": reports.mitigation_plan(inc_dicts, iocs),
        "reports": {r.kind: r.content_md for r in a.reports},
    })


def list_analyses(db: Session) -> list[dict]:
    rows = db.query(models.Analysis).order_by(models.Analysis.id.desc()).all()
    return [{"id": a.id, "filename": a.filename, "status": a.status, "profile": a.profile,
             "uploaded_at": a.uploaded_at.isoformat() if a.uploaded_at else None,
             "event_count": a.event_count, "max_severity": a.max_severity,
             "incident_count": len(a.incidents)} for a in rows]


def delete_analysis(db: Session, analysis_id: int) -> bool:
    a = db.get(models.Analysis, analysis_id)
    if not a:
        return False
    db.delete(a)
    db.commit()
    return True
