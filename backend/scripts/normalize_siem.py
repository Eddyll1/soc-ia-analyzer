"""CLI: normaliza un export SIEM y muestra el resumen de ingesta.

Uso:
    python scripts/normalize_siem.py ruta/al/export.xlsx [--out salida]

Genera (si --out):
    <out>_events.csv          eventos normalizados
    <out>_normalizations.json log de normalizaciones aplicadas
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ingest.parser import ContractError, build_events  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("excel", type=Path)
    ap.add_argument("--out", type=Path, help="prefijo de los archivos de salida")
    args = ap.parse_args()

    try:
        res = build_events(args.excel)
    except ContractError as e:
        print(f"[ERROR contrato] {e}", file=sys.stderr)
        return 2

    ev = res.events
    print(f"Eventos: {len(ev)}")
    print(f"Rango:   {ev['Timestamp'].min()} → {ev['Timestamp'].max()}")
    print(f"Hosts normalizados: {ev['Host_Normalized'].nunique()} (raw: {ev['Hostname'].nunique()})")
    print("\nNormalizaciones:")
    for n in res.normalizations:
        print(f"  - {json.dumps(n, ensure_ascii=False)}")
    print("\nLimitaciones:")
    for l in res.limitations:
        print(f"  - {l}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        ev.to_csv(f"{args.out}_events.csv", index=False)
        Path(f"{args.out}_normalizations.json").write_text(
            json.dumps({"normalizations": res.normalizations, "limitations": res.limitations},
                       ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        print(f"\nEscrito: {args.out}_events.csv, {args.out}_normalizations.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
