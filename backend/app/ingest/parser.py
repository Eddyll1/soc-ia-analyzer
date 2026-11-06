"""Ingesta y normalización de exports SIEM (Excel).

Fase 1 del pipeline: valida el contrato de datos, tipa las columnas,
unifica alias de host y parsea los metadatos embebidos en Event_Description.
No detecta nada: es determinístico y no usa IA.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

REQUIRED_COLUMNS = [
    "Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP",
    "Destination", "Log_Source", "Event_Description", "Process_CommandLine",
    "Result", "Severity",
]

# Pares de cuentas que pueden ser la misma entidad. NO se fusionan:
# se marcan como "alias a revisar" para que el analista decida (ver doc §4.1).
SUSPECT_USER_ALIASES = [
    ("CORP\\backupsvc", "CORP\\svc_backup"),
]

_KV_LOGON = re.compile(r"LogonType=(\d+)")
_KV_SOURCE = re.compile(r"source=([^;)\s]+)")
_KV_PARENT = re.compile(r"parent=([^;)\s]+)")
_KV_PROCESS = re.compile(r"process=([^;)\s]+)")


class ContractError(ValueError):
    """El Excel no cumple el contrato de datos."""


@dataclass
class IngestResult:
    events: pd.DataFrame
    normalizations: list[dict] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def load_raw(path: str | Path) -> pd.DataFrame:
    """Lee la primera hoja como texto y valida que existan las 12 columnas."""
    df = pd.read_excel(path, sheet_name=0, dtype=str)
    df = df.dropna(how="all")
    df.columns = [str(c).strip() for c in df.columns]

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ContractError(f"Faltan columnas requeridas: {missing}")
    return df[REQUIRED_COLUMNS].copy()


def _host_key(name: str) -> str:
    """DC-01, DC01 y dc_01 colapsan a la misma clave: DC01."""
    return re.sub(r"[^A-Z0-9]", "", str(name).upper())


def normalize_hosts(df: pd.DataFrame, log: list[dict]) -> pd.DataFrame:
    """Unifica variantes del mismo host usando la forma más frecuente como canónica."""
    raw = df["Hostname"].fillna("")
    groups: dict[str, dict[str, int]] = {}
    for h in raw:
        if not h:
            continue
        groups.setdefault(_host_key(h), {})
        groups[_host_key(h)][h] = groups[_host_key(h)].get(h, 0) + 1

    canonical: dict[str, str] = {}
    for key, variants in groups.items():
        best = max(variants.items(), key=lambda kv: kv[1])[0]
        for v in variants:
            canonical[v] = best
            if v != best:
                log.append({
                    "tipo": "host_alias",
                    "original": v,
                    "normalizado": best,
                    "filas": variants[v],
                })

    df["Host_Normalized"] = raw.map(lambda h: canonical.get(h, h) if h else None)
    return df


def normalize_users(df: pd.DataFrame, log: list[dict]) -> pd.DataFrame:
    """Marca (no fusiona) cuentas sospechosas de ser alias."""
    users = df["User"].fillna("")
    df["User_Alias_Flag"] = None
    for a, b in SUSPECT_USER_ALIASES:
        mask_a, mask_b = users == a, users == b
        if mask_a.any() and mask_b.any():
            flag = f"alias a revisar: {a} ~ {b}"
            df.loc[mask_a | mask_b, "User_Alias_Flag"] = flag
            log.append({
                "tipo": "user_alias_a_revisar",
                "cuentas": [a, b],
                "filas": int(mask_a.sum() + mask_b.sum()),
                "accion": "no fusionadas; marcadas para revisión",
            })
    df["User_Normalized"] = users.replace({"": None, "-": None})
    return df


def parse_description(df: pd.DataFrame) -> pd.DataFrame:
    """Extrae LogonType, source, parent y process del texto de Event_Description."""
    desc = df["Event_Description"].fillna("")
    df["Logon_Type"] = pd.to_numeric(
        desc.str.extract(_KV_LOGON, expand=False), errors="coerce"
    ).astype("Int64")
    df["Meta_Source"] = desc.str.extract(_KV_SOURCE, expand=False)
    df["Meta_Parent"] = desc.str.extract(_KV_PARENT, expand=False)
    df["Meta_Process"] = desc.str.extract(_KV_PROCESS, expand=False)
    return df


def normalize_timestamps(df: pd.DataFrame, log: list[dict]) -> pd.DataFrame:
    parsed = pd.to_datetime(df["Timestamp"], errors="coerce")
    bad = parsed.isna()
    if bad.any():
        log.append({
            "tipo": "timestamp_invalido",
            "filas": int(bad.sum()),
            "ejemplos": df.loc[bad, "Log_ID"].head(5).tolist(),
            "accion": "excluidas del análisis temporal",
        })
    df["Timestamp"] = parsed
    return df


def build_events(path: str | Path) -> IngestResult:
    """Pipeline de ingesta completo: contrato → tipado → normalización → metadatos."""
    log: list[dict] = []
    limitations: list[str] = []

    df = load_raw(path)

    dup = df["Log_ID"].duplicated().sum()
    if dup:
        limitations.append(f"{dup} Log_ID duplicados; se conserva la primera aparición")
        df = df.drop_duplicates(subset="Log_ID", keep="first")

    df["Event_ID"] = df["Event_ID"].astype("string").str.strip()
    df["Severity_Original"] = df["Severity"]  # se conserva, pero NO se usa para clasificar

    df = normalize_timestamps(df, log)
    df = normalize_hosts(df, log)
    df = normalize_users(df, log)
    df = parse_description(df)

    df = df.sort_values("Timestamp", kind="stable").reset_index(drop=True)

    limitations.append("Severity del SIEM no se usa para clasificar; el riesgo se recalcula por reglas")
    if df["Process_CommandLine"].isna().all():
        limitations.append("Sin Process_CommandLine: no hay análisis de procesos")

    return IngestResult(events=df, normalizations=log, limitations=limitations)
