"""Correlación determinística de hallazgos en incidentes.

Agrupa findings que comparten una entidad (IP, usuario o host) usando union-find.
Es a propósito determinístico: la IA NO reagrupa, solo narra lo que el código unió.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .rules import Finding

_SEV_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}


@dataclass
class Incident:
    id: str
    findings: list[Finding]
    entities: dict = field(default_factory=dict)
    max_severity_hint: str = "Low"

    def evidence(self) -> list[str]:
        seen: list[str] = []
        for f in self.findings:
            for e in f.evidence:
                if e not in seen:
                    seen.append(e)
        return seen


def _keys(f: Finding) -> set[str]:
    """Claves de entidad por las que un finding puede unirse a otros."""
    k: set[str] = set()
    e = f.entity
    for field_name in ("src_ip", "user", "host", "from", "to"):
        v = e.get(field_name)
        if v and v != "-":
            k.add(f"{field_name}:{v}" if field_name in ("src_ip",) else f"ent:{v}")
    # 'targets' (víctimas de un spray) y 'dest' (IP destino) son vínculos débiles:
    # no se usan para fusionar incidentes (evita el "hairball").
    for list_field in ("hosts", "users", "src_ips"):
        for v in e.get(list_field, []) or []:
            if v and v != "-":
                k.add(f"ent:{v}")
    return k


def correlate(findings: list[Finding]) -> list[Incident]:
    """Union-find sobre claves de entidad compartidas."""
    parent = list(range(len(findings)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a: int, b: int) -> None:
        parent[find(a)] = find(b)

    key_owner: dict[str, int] = {}
    for idx, f in enumerate(findings):
        for key in _keys(f):
            if key in key_owner:
                union(idx, key_owner[key])
            else:
                key_owner[key] = idx

    groups: dict[int, list[int]] = {}
    for idx in range(len(findings)):
        groups.setdefault(find(idx), []).append(idx)

    incidents: list[Incident] = []
    # ordenar por severidad descendente para numerar INC-A al más grave
    ordered = sorted(
        groups.values(),
        key=lambda g: max(_SEV_ORDER.get(findings[i].severity_hint, 0) for i in g),
        reverse=True,
    )
    for n, g in enumerate(ordered):
        fs = [findings[i] for i in g]
        ents: dict[str, set] = {}
        for f in fs:
            for kk, vv in f.entity.items():
                if isinstance(vv, list):
                    ents.setdefault(kk, set()).update(str(x) for x in vv)
                elif vv not in (None, "-", False, True):
                    ents.setdefault(kk, set()).add(str(vv))
        max_sev = max(fs, key=lambda f: _SEV_ORDER.get(f.severity_hint, 0)).severity_hint
        incidents.append(Incident(
            id=f"INC-{chr(65 + n)}" if n < 26 else f"INC-{n+1}",
            findings=fs,
            entities={k: sorted(v) for k, v in ents.items()},
            max_severity_hint=max_sev,
        ))
    return incidents
