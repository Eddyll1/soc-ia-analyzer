"""CLI: pipeline determinístico completo (ingesta → reglas → correlación).

Uso:
    python scripts/analyze_siem.py ruta/al/export.xlsx [--profile CIS] [--json salida.json]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ingest.parser import ContractError, build_events          # noqa: E402
from app.detection.engine import run_detection                      # noqa: E402
from app.detection.correlate import correlate                       # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("excel", type=Path)
    ap.add_argument("--profile", default="CIS", help="PCI-DSS | CIS | NIST | Personalizado")
    ap.add_argument("--json", type=Path, help="volcar resultado completo a JSON")
    args = ap.parse_args()

    try:
        ing = build_events(args.excel)
    except ContractError as e:
        print(f"[ERROR contrato] {e}", file=sys.stderr)
        return 2

    det = run_detection(ing.events, profile=args.profile)
    incidents = correlate(det.findings)

    print(f"Perfil: {det.profile}  |  Eventos: {det.stats['total_events']}  "
          f"|  Ventana: {det.stats['time_start']} → {det.stats['time_end']}")
    print(f"Hallazgos: {len(det.findings)}  |  Incidentes correlacionados: {len(incidents)}")
    if det.skipped_rules:
        print(f"Reglas omitidas: {', '.join(det.skipped_rules)}")

    print("\n== HALLAZGOS ==")
    for f in det.findings:
        ev = ", ".join(f.evidence[:6]) + (" …" if len(f.evidence) > 6 else "")
        print(f"  [{f.severity_hint:8}] {f.rule_id:20} {f.summary}")
        print(f"             evidencia: {ev}")

    print("\n== INCIDENTES ==")
    for inc in incidents:
        print(f"  {inc.id}  (sev≈{inc.max_severity_hint})  reglas: "
              f"{', '.join(sorted({f.rule_id for f in inc.findings}))}")
        print(f"       entidades: {inc.entities}")
        print(f"       {len(inc.evidence())} eventos citados")

    if args.json:
        payload = {
            "profile": det.profile, "thresholds": det.thresholds,
            "stats": det.stats, "iocs": det.iocs,
            "findings": [f.to_dict() for f in det.findings],
            "incidents": [{"id": i.id, "max_severity_hint": i.max_severity_hint,
                           "entities": i.entities, "evidence": i.evidence(),
                           "findings": [f.to_dict() for f in i.findings]} for i in incidents],
            "normalizations": ing.normalizations, "limitations": ing.limitations,
        }
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        print(f"\nJSON: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
