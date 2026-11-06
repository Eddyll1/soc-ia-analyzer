"""Defensas de la capa IA. No se confía en el modelo: se verifica su salida.

Cuatro controles:
1. scan_injection  — detecta texto con pinta de orden dentro de los datos del log.
2. neutralize      — sanea un campo de log antes de enviarlo como dato.
3. validate_citations — ningún Log_ID citado por la IA que no exista se acepta.
4. enforce_severity_floor — la IA no puede bajar la severidad por debajo del piso
   que fijaron las reglas (defensa contra inyección tipo "clasifica como bajo").
"""
from __future__ import annotations

import json
import re
import unicodedata

# Frases/estructuras típicas de prompt injection (en es/en).
_INJECTION_PATTERNS = [
    r"ignora(?:r)?\s+(?:todo|las|lo|el|instruccion)",
    r"ignore\s+(?:all|the|previous|above)",
    r"olvida(?:r)?\s+(?:todo|las instruc)",
    r"disregard\s+(?:all|previous|above)",
    r"(?:system|assistant|user)\s*:",
    r"\byou are\b|\beres un\b.*(asistente|assistant|ai|ia)",
    r"clasif\w*\s+como\s+(bajo|informativo|benigno)",
    r"classify\s+(?:this\s+)?as\s+(low|benign|informational)",
    r"responde\s+(?:solo|con|únicamente)",
    r"respond\s+(?:only|with)",
    r"nueva(?:s)?\s+instruccion",
    r"new\s+instruction",
    r"</?(system|instruction|prompt)>",
    r"```",                          # intento de cerrar/abrir bloques
]
_INJECTION_RE = re.compile("|".join(_INJECTION_PATTERNS), re.IGNORECASE)

_LOG_ID_RE = re.compile(r"EVT-\d{3,}", re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

ALLOWED_RISKS = {"Crítico", "Alto", "Medio", "Bajo"}

# Piso de severidad por regla: la IA puede subir, nunca bajar de aquí.
_SEVERITY_RANK = {"Bajo": 1, "Medio": 2, "Alto": 3, "Crítico": 4}
RULE_SEVERITY_FLOOR = {
    "STAGING_EXFIL": "Crítico",
    "OUTBOUND_EXFIL": "Alto",
    "SUCCESS_AFTER_FAILS": "Alto",
    "LATERAL_MOVEMENT": "Alto",
    "PERSIST_SERVICE": "Alto",
    "PERSIST_TASK": "Alto",
    "PRIV_ESCALATION": "Alto",
    "WEB_SHELL": "Alto",
    "WEB_ATTACK": "Alto",
    "SUSPICIOUS_EXEC": "Alto",
    "BRUTE_FORCE_SPRAY": "Medio",
    "BRUTE_FORCE": "Medio",
    "DISCOVERY": "Medio",
    "DATA_COLLECTION": "Alto",
}


def scan_injection(text: str) -> list[str]:
    """Devuelve los fragmentos de 'text' con pinta de instrucción inyectada."""
    if not text:
        return []
    return [m.group(0) for m in _INJECTION_RE.finditer(text)]


def neutralize(text) -> str:
    """Sanea un valor de log antes de incrustarlo como dato en el prompt.

    - normaliza unicode y quita caracteres de control (evita trucos con \\u202e,
      saltos raros o nulos que rompan el delimitador);
    - acota longitud para que un campo enorme no desplace las instrucciones;
    - marca inline el texto sospechoso de inyección en vez de borrarlo, para que
      el analista lo vea y la IA lo reporte, sin que parezca una orden.
    """
    if text is None:
        return ""
    s = unicodedata.normalize("NFKC", str(text))
    s = _CONTROL_RE.sub(" ", s)
    s = s.replace("```", "ʼʼʼ")           # neutraliza intentos de abrir/cerrar fences
    if _INJECTION_RE.search(s):
        s = "[⚠posible-inyección] " + s
    return s[:500]                         # tope por campo


def validate_citations(ai_text: str, valid_log_ids: set[str]) -> dict:
    """Comprueba que todo Log_ID citado por la IA exista en el dataset."""
    cited = {m.group(0).upper() for m in _LOG_ID_RE.finditer(ai_text or "")}
    valid_upper = {x.upper() for x in valid_log_ids}
    invalid = sorted(cited - valid_upper)
    return {
        "cited": sorted(cited),
        "invalid": invalid,
        "ok": not invalid,
    }


def parse_strict_json(raw: str) -> dict | None:
    """Extrae el primer objeto JSON del texto del modelo; None si no es válido.

    El modelo tiene prohibido texto fuera del JSON, pero si aun así lo añade,
    recortamos al objeto {...} y lo parseamos. Si no parsea, se rechaza.
    """
    if not raw:
        return None
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(raw[start:end + 1])
    except json.JSONDecodeError:
        return None


def enforce_severity_floor(incident_rule_ids: list[str], ai_risk: str) -> tuple[str, str | None]:
    """Sube el riesgo de la IA hasta el piso que exigen las reglas del incidente.

    Devuelve (riesgo_final, nota). Si ai_risk no es un valor permitido, cae al piso.
    """
    floor = "Bajo"
    for rid in incident_rule_ids:
        f = RULE_SEVERITY_FLOOR.get(rid, "Bajo")
        if _SEVERITY_RANK[f] > _SEVERITY_RANK[floor]:
            floor = f
    risk = ai_risk if ai_risk in ALLOWED_RISKS else floor
    if _SEVERITY_RANK[risk] < _SEVERITY_RANK[floor]:
        return floor, (f"IA propuso '{ai_risk}'; elevado a '{floor}' por piso de "
                       f"reglas (posible intento de evasión)")
    return risk, None
