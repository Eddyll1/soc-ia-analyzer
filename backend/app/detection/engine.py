"""Motor de detección: ejecuta todas las reglas aplicables y calcula stats + IoCs."""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from .profiles import Thresholds, get_profile
from .rules import ALL_RULES, Finding, NOISE_EVENT_IDS, _is_external


@dataclass
class DetectionResult:
    findings: list[Finding]
    stats: dict
    iocs: list[dict]
    profile: str
    thresholds: dict
    skipped_rules: list[str] = field(default_factory=list)


def _stats(df: pd.DataFrame) -> dict:
    ts = df["Timestamp"].dropna()
    return {
        "total_events": int(len(df)),
        "time_start": str(ts.min()) if not ts.empty else None,
        "time_end": str(ts.max()) if not ts.empty else None,
        "hosts": int(df["Host_Normalized"].nunique()),
        "users": int(df["User_Normalized"].nunique()),
        "by_event_id": df["Event_ID"].value_counts().to_dict(),
        "by_hour": df.dropna(subset=["Timestamp"]).groupby(
            df["Timestamp"].dt.strftime("%H:00")).size().to_dict(),
        "top_failed_ips": df[df["Event_ID"] == "4625"]["Source_IP"].value_counts().head(5).to_dict(),
        "noise_events": int(df["Event_ID"].isin(NOISE_EVENT_IDS).sum()),
    }


def _iocs(df: pd.DataFrame, findings: list[Finding]) -> list[dict]:
    iocs: list[dict] = []
    ext_ips = sorted({ip for ip in df["Source_IP"].dropna().unique() if _is_external(ip)})
    for ip in ext_ips:
        iocs.append({"type": "ip", "value": ip, "context": "IP externa observada en los logs"})
    # binarios/rutas sospechosas citadas por reglas de ejecución
    for f in findings:
        if f.rule_id == "SUSPICIOUS_EXEC" and f.extra.get("command"):
            iocs.append({"type": "command", "value": f.extra["command"],
                         "context": f.title, "evidence": f.evidence})
    return iocs


def run_detection(df: pd.DataFrame, profile: str = "CIS") -> DetectionResult:
    t: Thresholds = get_profile(profile)
    findings: list[Finding] = []
    skipped: list[str] = []

    has_cmd = not df["Process_CommandLine"].isna().all()
    for rule in ALL_RULES:
        # degradación elegante: reglas que dependen de command_line se saltan si no hay
        if rule.__name__ in ("rule_suspicious_exec",) and not has_cmd:
            skipped.append(f"{rule.__name__} (sin Process_CommandLine)")
            continue
        findings.extend(rule(df, t))

    return DetectionResult(
        findings=findings,
        stats=_stats(df),
        iocs=_iocs(df, findings),
        profile=profile,
        thresholds=t.to_dict(),
        skipped_rules=skipped,
    )
