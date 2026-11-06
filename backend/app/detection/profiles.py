"""Perfiles de umbrales de detección.

PCI-DSS, CIS y NIST NO prescriben un número exacto de fallos para "fuerza
bruta". Estos son valores de arranque inspirados en el espíritu de cada marco,
defendibles como criterio de analista y 100% ajustables (perfil Personalizado).
"""
from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass
class Thresholds:
    # Fuerza bruta / password spray
    bruteforce_min_fails: int = 5          # nº de 4625 para disparar
    bruteforce_window_min: int = 15        # ventana en minutos
    spray_min_targets: int = 3             # nº de usuarios distintos para "spray"
    # Acceso exitoso tras fallos
    success_after_fails_min: int = 3       # fallos previos para marcar compromiso
    success_after_fails_window_min: int = 10
    # Rutas sensibles (colección de datos)
    sensitive_path_keywords: tuple[str, ...] = ("finance", "budget", "nomina", "payroll", "confidential")

    def to_dict(self) -> dict:
        return asdict(self)


PROFILES: dict[str, Thresholds] = {
    "PCI-DSS": Thresholds(bruteforce_min_fails=6, bruteforce_window_min=10,
                          success_after_fails_min=3, success_after_fails_window_min=10),
    "CIS": Thresholds(bruteforce_min_fails=5, bruteforce_window_min=15,
                      success_after_fails_min=3, success_after_fails_window_min=10),
    "NIST": Thresholds(bruteforce_min_fails=10, bruteforce_window_min=30,
                       success_after_fails_min=2, success_after_fails_window_min=15),
}


def get_profile(name: str) -> Thresholds:
    """Devuelve el perfil pedido; 'Personalizado' parte de CIS como base editable."""
    if name in PROFILES:
        return PROFILES[name]
    return Thresholds()  # Personalizado = base por defecto, ajustable
