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


def _sanitize_payload(df: pd.DataFrame, incidents: list[Incident], sentinel: str,
                      security_log: list[dict]) -> tuple[str, list[dict], set[str]]:
    """Construye el bloque de datos saneado y detecta inyecciones en los logs."""
    fields = ["Log_ID", "Timestamp", "Host_Normalized", "User_Normalized",
              "Event_ID", "Source_IP", "Destination", "Event_Description",
              "Process_CommandLine", "Result"]
    hint_incidents: list[dict] = []
    valid_ids: set[str] = set()
    lines: list[str] = []

    for inc in incidents:
        ev = inc.evidence()
        valid_ids.update(ev)
        rows = _evidence_rows(df, ev)
        flags: list[str] = []
        for _, r in rows.iterrows():
            rec = {}
            for f in fields:
                val = r.get(f)
                clean = neutralize(val)
                rec[f] = clean
                hits = scan_injection(str(val))
                if hits:
                    flags.append(f"{r['Log_ID']}: {hits[:3]}")
                    security_log.append({"type": "injection_detected",
                                         "log_id": r["Log_ID"], "field": f, "matches": hits[:3]})
            lines.append(str(rec))
        hint_incidents.append({
            "id": inc.id,
            "evidence": ev,
            "hosts": inc.entities.get("hosts", []) + inc.entities.get("host", []),
            "severity_hint_es": _SEV_ES.get(inc.max_severity_hint, "Medio"),
            "injection_flags": flags,
            "rule_ids": sorted({f.rule_id for f in inc.findings}),
        })

    block = (f"{sentinel}\n" + "\n".join(lines) + f"\n{sentinel}")
    return block, hint_incidents, valid_ids


def run_agents(df: pd.DataFrame, incidents: list[Incident],
               client: GeminiClient | None = None) -> AgentReport:
    client = client or GeminiClient()
    security_log: list[dict] = []
    sentinel = "DATA-" + secrets.token_hex(8)       # centinela aleatorio por ejecución

    block, hint_incidents, valid_ids = _sanitize_payload(df, incidents, sentinel, security_log)
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
    report.incidents = corr.get("incidents", []) if corr else []

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

    report.security_log = security_log
    return report
