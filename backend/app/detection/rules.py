"""Catálogo de reglas de detección (determinístico, SIN IA).

Cada regla recibe el DataFrame normalizado + los umbrales del perfil y devuelve
una lista de Findings. Cada Finding cita los Log_ID exactos que lo sustentan:
si una regla no puede citar evidencia, no emite hallazgo.

Las reglas son generales (no dependen de Log_ID fijos), así que funcionan con
cualquier export mapeado al esquema canónico.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from .profiles import Thresholds

# Event_ID de Windows usados por las reglas (se tratan como string)
FAILED_LOGON = "4625"
SUCCESS_LOGON = "4624"
SPECIAL_PRIVS = "4672"
SERVICE_INSTALLED = "7045"
SCHEDULED_TASK = "4698"
PROCESS_CREATED = "4688"
PS_SCRIPTBLOCK = "4104"
SHARE_ACCESS = "5140"
DETAILED_SHARE = "5145"
OBJECT_ACCESS = "4663"
OUTBOUND_CONN = "5156"
WEB_EVENTS = ("HTTP_ACCESS", "PROXY_ACCESS")

# Ruido conocido a descartar explícitamente
NOISE_EVENT_IDS = {"7036"}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity_hint: str                       # pista; el riesgo final lo fija el clasificador
    entity: dict
    evidence: list[str]                      # Log_ID
    summary: str
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "title": self.title,
            "severity_hint": self.severity_hint, "entity": self.entity,
            "evidence": self.evidence, "summary": self.summary, "extra": self.extra,
        }


_IPV4 = __import__("re").compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def _is_external(value) -> bool:
    """True solo si 'value' es una IPv4 pública enrutable.

    Interno = 10.x, 192.168.x, 172.16–31.x, 127.x. Un hostname (p. ej.
    'APP-SRV01') NO es externo: el campo Destination a veces trae host, no IP.
    """
    if not isinstance(value, str) or not value:
        return False
    host = value.split(":")[0].strip()          # quita el puerto si lo trae
    m = _IPV4.match(host)
    if not m:
        return False                             # no es IP → no es "externo"
    a, b = int(m.group(1)), int(m.group(2))
    if a == 10 or a == 127:
        return False
    if a == 192 and b == 168:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    return True


# --------------------------------------------------------------------------- A
def rule_bruteforce(df: pd.DataFrame, t: Thresholds) -> list[Finding]:
    """Fuerza bruta / password spray: ≥N fallos (4625) de la misma IP en ventana."""
    out: list[Finding] = []
    fails = df[df["Event_ID"] == FAILED_LOGON].dropna(subset=["Timestamp"])
    if fails.empty:
        return out
    for ip, g in fails.groupby("Source_IP"):
        if not ip or ip == "-":
            continue
        g = g.sort_values("Timestamp")
        ts = g["Timestamp"].tolist()
        # ventana deslizante
        best: list[int] = []
        i = 0
        for j in range(len(ts)):
            while (ts[j] - ts[i]).total_seconds() > t.bruteforce_window_min * 60:
                i += 1
            if j - i + 1 > len(best):
                best = list(range(i, j + 1))
        if len(best) >= t.bruteforce_min_fails:
            window = g.iloc[best]
            targets = sorted(x for x in window["User_Normalized"].dropna().unique())
            is_spray = len(targets) >= t.spray_min_targets
            out.append(Finding(
                rule_id="BRUTE_FORCE_SPRAY" if is_spray else "BRUTE_FORCE",
                title="Password spray" if is_spray else "Fuerza bruta de autenticación",
                severity_hint="High" if is_spray else "Medium",
                entity={"src_ip": ip, "external": _is_external(ip), "targets": targets},
                evidence=window["Log_ID"].tolist(),
                summary=f"{len(best)} fallos de login desde {ip} "
                        f"en ≤{t.bruteforce_window_min} min contra {len(targets)} usuario(s)",
            ))
    return out


# --------------------------------------------------------------------------- B
def rule_success_after_fails(df: pd.DataFrame, t: Thresholds) -> list[Finding]:
    """Compromiso de credencial: 4624 exitoso tras varios 4625 del mismo origen."""
    out: list[Finding] = []
    rel = df[df["Event_ID"].isin([FAILED_LOGON, SUCCESS_LOGON])].dropna(subset=["Timestamp"])
    if rel.empty:
        return out
    for ip, g in rel.groupby("Source_IP"):
        if not ip or ip == "-":
            continue
        g = g.sort_values("Timestamp")
        rows = g.to_dict("records")
        for k, r in enumerate(rows):
            if r["Event_ID"] != SUCCESS_LOGON:
                continue
            win_start = r["Timestamp"] - pd.Timedelta(minutes=t.success_after_fails_window_min)
            prior_fails = [p for p in rows[:k]
                           if p["Event_ID"] == FAILED_LOGON and p["Timestamp"] >= win_start]
            if len(prior_fails) >= t.success_after_fails_min:
                ev = [p["Log_ID"] for p in prior_fails] + [r["Log_ID"]]
                out.append(Finding(
                    rule_id="SUCCESS_AFTER_FAILS",
                    title="Acceso exitoso tras múltiples fallos",
                    severity_hint="High",
                    entity={"src_ip": ip, "external": _is_external(ip),
                            "user": r.get("User_Normalized"), "host": r.get("Host_Normalized"),
                            "logon_type": r.get("Logon_Type")},
                    evidence=ev,
                    summary=f"Login exitoso de {r.get('User_Normalized')} desde {ip} "
                            f"tras {len(prior_fails)} fallos previos (posible compromiso)",
                ))
    return out


# --------------------------------------------------------------------------- C
def rule_privilege_persistence(df: pd.DataFrame, t: Thresholds) -> list[Finding]:
    """Escalamiento/persistencia: 4672 (privilegios), 7045 (servicio), 4698 (tarea)."""
    out: list[Finding] = []
    mapping = {
        SPECIAL_PRIVS: ("PRIV_ESCALATION", "Privilegios especiales asignados", "High"),
        SERVICE_INSTALLED: ("PERSIST_SERVICE", "Servicio instalado (persistencia)", "High"),
        SCHEDULED_TASK: ("PERSIST_TASK", "Tarea programada creada (persistencia)", "High"),
    }
    for eid, (rid, title, sev) in mapping.items():
        g = df[df["Event_ID"] == eid]
        for _, r in g.iterrows():
            out.append(Finding(
                rule_id=rid, title=title, severity_hint=sev,
                entity={"host": r.get("Host_Normalized"), "user": r.get("User_Normalized")},
                evidence=[r["Log_ID"]],
                summary=f"{title} en {r.get('Host_Normalized')} ({r.get('User_Normalized')})",
            ))
    return out


# --------------------------------------------------------------------------- D
def rule_suspicious_exec(df: pd.DataFrame, t: Thresholds) -> list[Finding]:
    """Ejecución sospechosa: EncodedCommand, rutas no estándar, parent anómalo."""
    out: list[Finding] = []
    proc = df[df["Event_ID"].isin([PROCESS_CREATED, PS_SCRIPTBLOCK])].copy()
    cmd = proc["Process_CommandLine"].fillna("")
    desc = proc["Event_Description"].fillna("")
    blob = (cmd + " " + desc).str.lower()
    patterns = {
        "encodedcommand": ("Ejecución PowerShell ofuscada (EncodedCommand)", "High"),
        "wuhelper.exe": ("Binario sospechoso wuhelper.exe (malware disfrazado)", "High"),
        r"\programdata\\": ("Ejecución desde ruta no estándar (ProgramData)", "Medium"),
    }
    for pat, (title, sev) in patterns.items():
        mask = blob.str.contains(pat, regex=False, na=False)
        g = proc[mask]
        for _, r in g.iterrows():
            out.append(Finding(
                rule_id="SUSPICIOUS_EXEC", title=title, severity_hint=sev,
                entity={"host": r.get("Host_Normalized"), "user": r.get("User_Normalized"),
                        "parent": r.get("Meta_Parent")},
                evidence=[r["Log_ID"]],
                summary=f"{title} en {r.get('Host_Normalized')}",
                extra={"command": r.get("Process_CommandLine")},
            ))
    return out


# --------------------------------------------------------------------------- E
def rule_discovery(df: pd.DataFrame, t: Thresholds) -> list[Finding]:
    """Reconocimiento: net view, enumeración de grupos/shares."""
    out: list[Finding] = []
    blob = (df["Process_CommandLine"].fillna("") + " " + df["Event_Description"].fillna("")).str.lower()
    mask = blob.str.contains(r"net\.exe view|net view|get-localgroupmember|get-smbshare|enumera", regex=True, na=False)
    g = df[mask]
    for _, r in g.iterrows():
        out.append(Finding(
            rule_id="DISCOVERY", title="Actividad de descubrimiento/reconocimiento",
            severity_hint="Medium",
            entity={"host": r.get("Host_Normalized"), "user": r.get("User_Normalized")},
            evidence=[r["Log_ID"]],
            summary=f"Enumeración/reconocimiento en {r.get('Host_Normalized')}",
        ))
    return out


# --------------------------------------------------------------------------- F
def rule_lateral_movement(df: pd.DataFrame, t: Thresholds) -> list[Finding]:
    """Movimiento lateral: logon tipo 3 cuyo source= es otro host interno."""
    out: list[Finding] = []
    g = df[(df["Logon_Type"] == 3) & (df["Meta_Source"].notna())]
    for _, r in g.iterrows():
        src, dst = r.get("Meta_Source"), r.get("Host_Normalized")
        if src and dst and str(src).upper().replace("-", "") != str(dst).upper().replace("-", ""):
            out.append(Finding(
                rule_id="LATERAL_MOVEMENT", title="Movimiento lateral (logon de red)",
                severity_hint="High",
                entity={"from": src, "to": dst, "user": r.get("User_Normalized")},
                evidence=[r["Log_ID"]],
                summary=f"{r.get('User_Normalized')} salta de {src} a {dst} (LogonType=3)",
            ))
    return out


# --------------------------------------------------------------------------- G
def rule_data_collection(df: pd.DataFrame, t: Thresholds) -> list[Finding]:
    """Colección: acceso a archivos/shares en rutas sensibles (4663/5145/5140)."""
    out: list[Finding] = []
    rel = df[df["Event_ID"].isin([OBJECT_ACCESS, DETAILED_SHARE, SHARE_ACCESS])]
    blob = rel["Event_Description"].fillna("").str.lower()
    mask = blob.apply(lambda s: any(k in s for k in t.sensitive_path_keywords))
    g = rel[mask]
    if not g.empty:
        out.append(Finding(
            rule_id="DATA_COLLECTION", title="Acceso a datos sensibles",
            severity_hint="High",
            entity={"hosts": sorted(x for x in g["Host_Normalized"].dropna().unique()),
                    "users": sorted(x for x in g["User_Normalized"].dropna().unique())},
            evidence=g["Log_ID"].tolist(),
            summary=f"{len(g)} acceso(s) a rutas sensibles (p. ej. Finance)",
        ))
    return out


# --------------------------------------------------------------------------- H
def _external_outbound(df: pd.DataFrame) -> pd.DataFrame:
    """Conexiones salientes (5156 o PROXY_ACCESS) cuyo Destination es IP pública."""
    cand = df[df["Event_ID"].isin([OUTBOUND_CONN, "PROXY_ACCESS"])].copy()
    return cand[cand["Destination"].apply(lambda d: _is_external(d) if pd.notna(d) else False)]


def rule_staging_exfil(df: pd.DataFrame, t: Thresholds) -> list[Finding]:
    """Staging + exfiltración: compresión a temporal + conexión saliente a IP pública."""
    out: list[Finding] = []
    blob = (df["Process_CommandLine"].fillna("") + " " + df["Event_Description"].fillna("")).str.lower()
    staging = df[blob.str.contains(r"tar\.exe|7z\.exe|\.zip|\.7z\b|\brar\b|staging archive",
                                   regex=True, na=False)]
    ext = _external_outbound(df)

    if not staging.empty and not ext.empty:
        out.append(Finding(
            rule_id="STAGING_EXFIL", title="Staging y exfiltración de datos",
            severity_hint="Critical",
            entity={"hosts": sorted(x for x in staging["Host_Normalized"].dropna().unique()),
                    "dest": sorted(x for x in ext["Destination"].dropna().unique())},
            evidence=staging["Log_ID"].tolist() + ext["Log_ID"].tolist(),
            summary="Compresión a archivo temporal seguida de conexión saliente a IP pública",
        ))
    elif not ext.empty:
        # canal de salida a IP pública sin staging probado (p. ej. HTTPS POST repetido)
        for dest, g in ext.groupby("Destination"):
            out.append(Finding(
                rule_id="OUTBOUND_EXFIL", title="Conexión saliente sostenida a IP pública",
                severity_hint="High",
                entity={"dest": dest,
                        "src_ips": sorted(x for x in g["Source_IP"].dropna().unique()),
                        "hosts": sorted(x for x in g["Host_Normalized"].dropna().unique())},
                evidence=g["Log_ID"].tolist(),
                summary=f"{len(g)} conexión(es) saliente(s) a {dest} (posible exfiltración/C2)",
            ))
    return out


# --------------------------------------------------------------------------- I
def rule_web_attack(df: pd.DataFrame, t: Thresholds) -> list[Finding]:
    """Ataque web / webshell: rutas anómalas o códigos de error en eventos web."""
    out: list[Finding] = []
    http = df[df["Event_ID"] == "HTTP_ACCESS"].copy()
    if http.empty:
        return out

    # 1) Patrones de webshell/inyección en la URI (si el dataset los trae)
    blob = (http["Event_Description"].fillna("") + " " + http["Destination"].fillna("")).str.lower()
    susp = http[blob.str.contains(r"\.aspx\?cmd=|/uploads/|whoami|cmd=|union select|\.\./|webshell",
                                  regex=True, na=False)]
    if not susp.empty:
        out.append(Finding(
            rule_id="WEB_SHELL", title="Posible webshell / ejecución de comandos vía web",
            severity_hint="High",
            entity={"hosts": sorted(x for x in susp["Host_Normalized"].dropna().unique()),
                    "src_ips": sorted(x for x in susp["Source_IP"].dropna().unique())},
            evidence=susp["Log_ID"].tolist(),
            summary=f"{len(susp)} petición(es) web con patrón de ejecución (cmd=, /uploads, whoami)",
        ))

    # 2) Escaneo/ataque web: IP pública contra host web con muchos errores 404/500
    for ip, g in http.groupby("Source_IP"):
        if not _is_external(ip):
            continue
        errors = g[g["Result"].isin(["404", "500"])]
        if len(errors) >= 5:
            out.append(Finding(
                rule_id="WEB_ATTACK", title="Ataque/escaneo web desde IP pública",
                severity_hint="High",
                entity={"src_ip": ip, "external": True,
                        "hosts": sorted(x for x in g["Host_Normalized"].dropna().unique()),
                        "targets": sorted(x for x in g["Destination"].dropna().unique())},
                evidence=g["Log_ID"].tolist(),
                summary=f"{len(g)} peticiones desde {ip} contra host web, "
                        f"{len(errors)} con error 404/500 (escaneo/explotación)",
            ))
    return out


ALL_RULES = [
    rule_bruteforce, rule_success_after_fails, rule_privilege_persistence,
    rule_suspicious_exec, rule_discovery, rule_lateral_movement,
    rule_data_collection, rule_staging_exfil, rule_web_attack,
]
