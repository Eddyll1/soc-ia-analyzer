"""Orquestador de agentes IA, con todas las defensas aplicadas en orden.

Flujo por análisis:
  1. Construye un payload SANEADO: solo las filas citadas por las reglas,
     neutralizadas campo a campo, dentro de un bloque con centinela aleatorio.
  2. Correlador (narra) → Clasificador → Redactor ejecutivo → Redactor técnico.
  3. Cada salida pasa por: parse_strict_json + validate_citations.
  4. La clasificación pasa por enforce_severity_floor (la IA no puede degradar).
  5. Devuelve resultado + un 'security_log' de lo que se neutralizó/bloqueó.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field

import pandas as pd

from ..detection.correlate import Incident
from . import prompts
from .gemini_client import GeminiClient
from .validators import (
    enforce_severity_floor, neutralize, parse_strict_json,
    scan_injection, validate_citations,
)

_SEV_ES = {"Critical": "Crítico", "High": "Alto", "Medium": "Medio", "Low": "Bajo"}


@dataclass
class AgentReport:
    incidents: list[dict] = field(default_factory=list)
    classifications: list[dict] = field(default_factory=list)
    executive_md: str = ""
    technical_md: str = ""
    security_log: list[dict] = field(default_factory=list)
    mode: str = "mock"


def _evidence_rows(df: pd.DataFrame, log_ids: list[str]) -> pd.DataFrame:
    return df[df["Log_ID"].isin(log_ids)]


def _build_timeline(df: pd.DataFrame, log_ids: list[str]) -> list[dict]:
    """Línea de tiempo determinística con fecha/hora REALES (no las inventa la IA)."""
    rows = _evidence_rows(df, log_ids).sort_values("Timestamp")
    tl: list[dict] = []
    for _, r in rows.iterrows():
        ts = r.get("Timestamp")
        tl.append({
            "ts": ts.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(ts) else None,
            "log_id": r.get("Log_ID"),
            "host": r.get("Host_Normalized"),
            "user": r.get("User_Normalized"),
            "event_id": r.get("Event_ID"),
            "src_ip": r.get("Source_IP"),
            "fact": neutralize(r.get("Event_Description"))[:160],
        })
    return tl


def _collapse_milestones(timeline: list[dict]) -> list[dict]:
    """Agrupa corridas consecutivas de eventos iguales en hitos legibles.

    Evita volcar 100+ filas casi idénticas: 33 fallos seguidos se vuelven un
    solo hito "08:25–08:31 · 33× 4625 fallo de login desde 203.0.113.74".
    """
    if not timeline:
        return []
    ms: list[dict] = []
    cur = None
    for e in timeline:
        key = (e.get("event_id"), e.get("host"), e.get("src_ip"), e.get("fact"))
        if cur and cur["_key"] == key:
            cur["count"] += 1
            cur["ts_end"] = e.get("ts")
            cur["log_ids"].append(e.get("log_id"))
        else:
            if cur:
                ms.append(cur)
            cur = {"_key": key, "count": 1, "ts_start": e.get("ts"), "ts_end": e.get("ts"),
                   "event_id": e.get("event_id"), "host": e.get("host"),
                   "src_ip": e.get("src_ip"), "user": e.get("user"),
                   "fact": e.get("fact"), "log_ids": [e.get("log_id")]}
    if cur:
        ms.append(cur)
    for m in ms:
        m.pop("_key", None)
        m["log_ref"] = m["log_ids"][0] + (f"…{m['log_ids'][-1]}" if m["count"] > 1 else "")
    return ms


def _narrative(incident: Incident, timeline: list[dict]) -> str:
    """Relato en cadena construido por código (hechos, no inventado por la IA)."""
    t0 = timeline[0]["ts"] if timeline else "?"
    t1 = timeline[-1]["ts"] if timeline else "?"
    by_rule = {}
    for f in incident.findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    parts = [f"Incidente {incident.id}: actividad entre {t0} y {t1}."]

    order = ["WEB_ATTACK", "WEB_SHELL", "BRUTE_FORCE_SPRAY", "BRUTE_FORCE",
             "SUCCESS_AFTER_FAILS", "PRIV_ESCALATION", "SUSPICIOUS_EXEC",
             "PERSIST_SERVICE", "PERSIST_TASK", "DISCOVERY", "LATERAL_MOVEMENT",
             "DATA_COLLECTION", "STAGING_EXFIL", "OUTBOUND_EXFIL"]
    for rid in order:
        for f in by_rule.get(rid, []):
            ev_ts = [e["ts"] for e in timeline if e["log_id"] in f.evidence]
            span = f" ({ev_ts[0]}→{ev_ts[-1]})" if len(ev_ts) > 1 else (f" ({ev_ts[0]})" if ev_ts else "")
            parts.append(f"{f.summary}{span} [{', '.join(f.evidence[:3])}{'…' if len(f.evidence) > 3 else ''}].")
    return " ".join(parts)


def _sanitize_payload(incidents: list[Incident], timelines: dict, sentinel: str,
                      security_log: list[dict]) -> tuple[str, list[dict], set[str]]:
    """Bloque COMPACTO para la IA: resúmenes de hallazgos + hitos, no logs crudos."""
    hint_incidents: list[dict] = []
    valid_ids: set[str] = set()
    compact: list[dict] = []

    for inc in incidents:
        ev = inc.evidence()
        valid_ids.update(ev)
        flags: list[str] = []
        findings_c = []
        for f in inc.findings:
            s = neutralize(f.summary)
            hits = scan_injection(f.summary)
            if hits:
                flags.append(f"{f.rule_id}: {hits[:3]}")
                security_log.append({"type": "injection_detected", "rule": f.rule_id, "matches": hits[:3]})
            findings_c.append({"rule": f.rule_id, "summary": s, "evidence": f.evidence[:5]})
        # hitos ya neutralizados en el timeline; escaneamos sus 'fact'
        ms = timelines[inc.id]
        for m in ms:
            hits = scan_injection(str(m.get("fact")))
            if hits:
                security_log.append({"type": "injection_detected", "log_id": m.get("log_ref"), "matches": hits[:3]})
        compact.append({"id": inc.id, "severity_hint_es": _SEV_ES.get(inc.max_severity_hint, "Medio"),
                        "findings": findings_c,
                        "milestones": [{"t": f"{m['ts_start']}→{m['ts_end']}", "n": m["count"],
                                        "event_id": m["event_id"], "host": m["host"],
                                        "src_ip": m["src_ip"], "fact": m["fact"]} for m in ms]})
        hint_incidents.append({"id": inc.id, "evidence": ev,
                               "hosts": inc.entities.get("hosts", []) + inc.entities.get("host", []),
                               "severity_hint_es": _SEV_ES.get(inc.max_severity_hint, "Medio"),
                               "injection_flags": flags,
                               "rule_ids": sorted({f.rule_id for f in inc.findings})})

    block = f"{sentinel}\n{compact}\n{sentinel}"
    return block, hint_incidents, valid_ids


def run_agents(df: pd.DataFrame, incidents: list[Incident],
               client: GeminiClient | None = None) -> AgentReport:
    client = client or GeminiClient()
    security_log: list[dict] = []
    sentinel = "DATA-" + secrets.token_hex(8)       # centinela aleatorio por ejecución

    # Timelines y relato se construyen SIEMPRE por código (no dependen de la IA).
    full_timelines = {inc.id: _build_timeline(df, inc.evidence()) for inc in incidents}
    milestones = {inc.id: _collapse_milestones(full_timelines[inc.id]) for inc in incidents}
    code_narrative = {inc.id: _narrative(inc, full_timelines[inc.id]) for inc in incidents}

    block, hint_incidents, valid_ids = _sanitize_payload(incidents, milestones, sentinel, security_log)
    sys_base = prompts.SYSTEM_PREAMBLE.format(sentinel=sentinel)

    def _call(role_prompt: str, hint: dict) -> dict | None:
        raw = client.generate(sys_base + "\n" + role_prompt, block, mock_hint=hint)
        obj = parse_strict_json(raw)
        if obj is None:
            security_log.append({"type": "bad_json", "role": role_prompt[:40]})
            return None
        cite = validate_citations(raw, valid_ids)
        if not cite["ok"]:
            security_log.append({"type": "invalid_citation_blocked",
                                 "role": role_prompt[:40], "invalid": cite["invalid"]})
        return obj

    report = AgentReport(mode=client.mode)

    corr = _call(prompts.CORRELATOR, {"incidents": hint_incidents})
    narr_by_inc = {i.get("id"): i for i in (corr.get("incidents", []) if corr else [])}
    # La línea de tiempo (con horas reales) la fija el CÓDIGO; la IA solo narra.
    report.incidents = []
    for inc in incidents:
        n = narr_by_inc.get(inc.id, {})
        ai_narr = (n.get("narrative") or "").strip()
        report.incidents.append({
            "id": inc.id,
            "narrative": code_narrative[inc.id],       # relato factual (siempre)
            "ai_narrative": ai_narr if client.mode == "live" else "",  # prosa IA (opcional)
            "mitre": n.get("mitre", []),
            "confidence": n.get("confidence"),
            "timeline": milestones[inc.id],            # hitos condensados
            "event_count": len(full_timelines[inc.id]),
        })

    cls = _call(prompts.CLASSIFIER, {"incidents": hint_incidents})
    raw_cls = cls.get("classifications", []) if cls else []
    rule_by_inc = {h["id"]: h["rule_ids"] for h in hint_incidents}
    for c in raw_cls:
        final, note = enforce_severity_floor(rule_by_inc.get(c.get("incident_id"), []),
                                             c.get("risk", ""))
        if note:
            security_log.append({"type": "severity_floor_applied",
                                 "incident_id": c.get("incident_id"), "note": note})
        c["risk"] = final
    report.classifications = raw_cls

    ex = _call(prompts.REDACTOR_EJECUTIVO, {})
    report.executive_md = ex.get("markdown", "") if ex else ""
    tec = _call(prompts.REDACTOR_TECNICO, {})
    report.technical_md = tec.get("markdown", "") if tec else ""

    if client.last_error:
        security_log.append({"type": "ai_fallback", "note": client.last_error})
    report.mode = client.mode
    report.security_log = security_log
    return report
