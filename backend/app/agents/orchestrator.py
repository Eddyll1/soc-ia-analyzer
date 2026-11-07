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
from ..detection.rules import _is_external
from . import prompts, reports
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


def _affected(df: pd.DataFrame, incident: Incident) -> dict:
    """Entidades afectadas para decisiones del SOC: hosts+IPs (aislar), usuarios (resetear)."""
    rows = _evidence_rows(df, incident.evidence())
    hosts = sorted(x for x in rows["Host_Normalized"].dropna().unique())
    users = sorted(x for x in rows["User_Normalized"].dropna().unique())
    ips = sorted(x for x in rows["Source_IP"].dropna().unique() if x and x != "-")
    host_ips = {}
    for h, g in rows.groupby("Host_Normalized"):
        host_ips[h] = sorted(x for x in g["Source_IP"].dropna().unique() if x and x != "-")
    dest = sorted({d for f in incident.findings for d in (f.entity.get("dest") or [])})
    return {
        "hosts": hosts, "users": users,
        "external_ips": [i for i in ips if _is_external(i)],
        "internal_ips": [i for i in ips if not _is_external(i)],
        "host_ips": host_ips, "exfil_dest": dest,
    }


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


# Fases tipo kill-chain, en orden. Cada regla cae en una fase.
_PHASE_DEF = [
    (["WEB_ATTACK", "WEB_SHELL"], "Ataque web"),
    (["BRUTE_FORCE_SPRAY", "BRUTE_FORCE"], "Acceso inicial — fuerza bruta"),
    (["SUCCESS_AFTER_FAILS"], "Compromiso de credencial"),
    (["PRIV_ESCALATION"], "Escalada de privilegios"),
    (["SUSPICIOUS_EXEC"], "Ejecución de código"),
    (["DISCOVERY"], "Descubrimiento"),
    (["LATERAL_MOVEMENT"], "Movimiento lateral"),
    (["PERSIST_SERVICE", "PERSIST_TASK"], "Persistencia"),
    (["DATA_COLLECTION"], "Colección de datos sensibles"),
    (["STAGING_EXFIL", "OUTBOUND_EXFIL"], "Exfiltración"),
]


def _ent_values(findings, *keys) -> list[str]:
    """Reúne valores de entidad (escalares o listas) de un conjunto de hallazgos."""
    out: list[str] = []
    for f in findings:
        for k in keys:
            v = f.entity.get(k)
            if isinstance(v, list):
                out += [str(x) for x in v]
            elif v not in (None, "-", True, False):
                out.append(str(v))
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x); uniq.append(x)
    return uniq


def _phase_detail(label: str, findings: list) -> str:
    """Detalle conciso por fase: lo esencial, no cada evento."""
    users = _ent_values(findings, "user", "users")
    hosts = _ent_values(findings, "host", "hosts", "to")
    ips = _ent_values(findings, "src_ip", "src_ips")
    dest = _ent_values(findings, "dest")
    n_ev = sum(len(f.evidence) for f in findings)
    if "fuerza bruta" in label:
        tgts = _ent_values(findings, "targets")
        return f"{n_ev} intentos desde {', '.join(ips) or '?'} contra {len(tgts) or '?'} usuario(s)."
    if "Compromiso" in label:
        return f"{len(findings)} cuenta(s) con login exitoso tras fallos: {', '.join(users[:6])}" + \
               (f" (origen {', '.join(ips)})" if ips else "") + "."
    if "Exfiltración" in label:
        return f"Datos comprimidos y enviados a {', '.join(dest) or 'IP externa'}."
    if "Movimiento lateral" in label:
        froms = _ent_values(findings, "from")
        return f"Salto de {', '.join(froms) or '?'} a {', '.join(hosts) or '?'}."
    if "Ataque web" in label:
        return f"Peticiones anómalas desde {', '.join(ips) or '?'} contra {', '.join(hosts) or '?'}."
    # genérico
    bits = []
    if hosts:
        bits.append(f"hosts: {', '.join(hosts[:5])}")
    if users:
        bits.append(f"usuarios: {', '.join(users[:5])}")
    return f"{len(findings)} evento(s). " + "; ".join(bits) + "."


def _narrative(incident: Incident, timeline: list[dict]) -> dict:
    """Relato estructurado por fases (la pepa), construido por código."""
    ts_of = {e["log_id"]: e["ts"] for e in timeline}
    by_rule: dict[str, list] = {}
    for f in incident.findings:
        by_rule.setdefault(f.rule_id, []).append(f)

    phases = []
    for rule_ids, label in _PHASE_DEF:
        fs = [f for rid in rule_ids for f in by_rule.get(rid, [])]
        if not fs:
            continue
        ev_ts = sorted(t for f in fs for e in f.evidence if (t := ts_of.get(e)))
        phases.append({
            "phase": label,
            "t0": ev_ts[0] if ev_ts else None,
            "t1": ev_ts[-1] if ev_ts else None,
            "detail": _phase_detail(label, fs),
            "evidence": sorted({e for f in fs for e in f.evidence}),
        })

    t0 = timeline[0]["ts"] if timeline else "?"
    t1 = timeline[-1]["ts"] if timeline else "?"
    chain = " → ".join(p["phase"].split(" — ")[0] for p in phases)
    ext_ips = [ip for ip in _ent_values(incident.findings, "src_ip", "src_ips")
               if not ip.startswith("10.")]
    headline = f"{chain}." if chain else "Actividad anómala."
    if ext_ips:
        headline += f" Origen externo: {', '.join(ext_ips[:3])}."
    return {"headline": headline, "window": f"{t0} — {t1}", "phases": phases}


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
               client: GeminiClient | None = None, *, det=None, ing=None) -> AgentReport:
    client = client or GeminiClient()
    security_log: list[dict] = []
    sentinel = "DATA-" + secrets.token_hex(8)       # centinela aleatorio por ejecución

    # Timelines, relato y entidades afectadas: SIEMPRE por código (no dependen de la IA).
    full_timelines = {inc.id: _build_timeline(df, inc.evidence()) for inc in incidents}
    milestones = {inc.id: _collapse_milestones(full_timelines[inc.id]) for inc in incidents}
    code_narrative = {inc.id: _narrative(inc, full_timelines[inc.id]) for inc in incidents}
    affected = {inc.id: _affected(df, inc) for inc in incidents}

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

    # --- Narrativa y clasificación: DETERMINÍSTICAS (sin IA) ---
    # El código ya correlacionó y narró; la severidad sale del piso de reglas.
    report.incidents = []
    report.classifications = []
    rule_by_inc = {h["id"]: h["rule_ids"] for h in hint_incidents}
    _IMPACT = {"Crítico": "Compromiso con impacto en activos y posible exfiltración.",
               "Alto": "Compromiso confirmado; contención urgente.",
               "Medio": "Intento serio o anomalía; requiere revisión.",
               "Bajo": "Actividad de bajo impacto / ruido probable."}
    for inc in incidents:
        narr = code_narrative[inc.id]
        risk, _ = enforce_severity_floor(rule_by_inc.get(inc.id, []), "")
        report.incidents.append({
            "id": inc.id,
            "headline": narr["headline"],
            "window": narr["window"],
            "phases": narr["phases"],
            "affected": affected[inc.id],
            "rule_ids": sorted(rule_by_inc.get(inc.id, [])),
            "risk": risk,
            "ai_narrative": "",
            "timeline": milestones[inc.id],
            "event_count": len(full_timelines[inc.id]),
        })
        report.classifications.append({
            "incident_id": inc.id, "risk": risk,
            "justification": narr["headline"],
            "impact": _IMPACT.get(risk, ""),
            "recommended_action": "Contener hosts/IPs afectados, resetear cuentas comprometidas.",
        })

    # --- Informes: SIEMPRE se construyen por código (ricos, estructurados) ---
    stats = det.stats if det else {}
    report_ctx = {"incidents": report.incidents, "stats": stats,
                  "iocs": det.iocs if det else [], "profile": det.profile if det else "",
                  "normalizations": ing.normalizations if ing else [],
                  "limitations": ing.limitations if ing else []}
    report.executive_md = reports.build_executive(report_ctx)
    report.technical_md = reports.build_technical(report_ctx)

    # --- Única llamada a IA: pulir ambos informes. Si falla (429/504), se queda el de código ---
    if client.mode == "live":
        rblock = (f"=== INFORME EJECUTIVO BASE ===\n{report.executive_md}\n\n"
                  f"=== INFORME TÉCNICO BASE ===\n{report.technical_md}")
        raw = client.generate(sys_base + "\n" + prompts.REDACTOR_DUAL, rblock,
                              mock_hint={"ejecutivo_md": report.executive_md,
                                         "tecnico_md": report.technical_md})
        out = parse_strict_json(raw)
        if out and out.get("ejecutivo_md") and out.get("tecnico_md"):
            cite = validate_citations(raw, valid_ids)
            if cite["ok"]:
                report.executive_md = out["ejecutivo_md"]
                report.technical_md = out["tecnico_md"]
            else:
                security_log.append({"type": "invalid_citation_blocked",
                                     "role": "REDACTOR_DUAL", "invalid": cite["invalid"]})

    if client.last_error:
        security_log.append({"type": "ai_fallback", "note": client.last_error})
    report.mode = client.mode
    report.security_log = security_log
    return report
