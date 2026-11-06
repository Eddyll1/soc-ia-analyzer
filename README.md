# SOC-IA Analyzer

Plataforma web de investigación de incidentes SOC Nivel 2: importa un export de
SIEM (Excel), lo analiza con un **motor de reglas determinístico** y usa **IA
(Gemini)** solo para correlacionar, clasificar y redactar informes. Reto final
del Bootcamp Analista SOC N2.

> **Principio rector:** la IA no detecta, razona sobre lo ya detectado. Todo
> hallazgo se rastrea a uno o más `Log_ID` del Excel. Un validador de citas
> confirma que ningún `Log_ID` mencionado por la IA sea inventado.

## Estado actual

| Capa | Estado |
|---|---|
| Ingesta + normalización (`backend/app/ingest/`) | ✅ Funcional |
| Motor de reglas A–I (`backend/app/detection/`) | ✅ Funcional |
| Correlación en incidentes | ✅ Funcional (determinística) |
| Orquestador de agentes IA (Gemini) | ⬜ Pendiente |
| Validador de citas | ⬜ Pendiente |
| API FastAPI + SQLite | ⬜ Pendiente |
| Frontend React + dashboard + PDF | ⬜ Pendiente |

## Pipeline determinístico (ya usable por CLI)

```
Excel (.xlsx) → Normalizador → Motor de reglas → Correlación → JSON
```

- **Normalizador:** valida el contrato de 12 columnas, tipa timestamps, unifica
  alias de host (`DC01` → `DC-01`), marca cuentas de servicio sospechosas de ser
  alias (`backupsvc`/`svc_backup`) sin fusionarlas, y extrae metadatos embebidos
  en `Event_Description` (`LogonType`, `source=`, `parent=`).
- **Motor de reglas:** fuerza bruta / password spray, acceso exitoso tras fallos,
  escalamiento y persistencia, ejecución sospechosa (EncodedCommand, wuhelper.exe),
  descubrimiento, movimiento lateral, colección de datos sensibles, staging +
  exfiltración, y ataque web. La severidad se **recalcula por reglas**, no se copia
  de la columna `Severity` del SIEM.
- **Perfiles de umbrales:** PCI-DSS, CIS, NIST y Personalizado.

### Uso

```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Solo normalizar y ver el log de normalizaciones
python scripts/normalize_siem.py ruta/al/export.xlsx --out ../out/siem

# Pipeline completo (reglas + correlación), vuelca JSON
python scripts/analyze_siem.py ruta/al/export.xlsx --profile CIS --json ../out/analysis.json
```

## Arquitectura

Ver `docs/` para el diseño completo (componentes, agentes IA, esquema SQLite,
endpoints) y el catálogo de reglas anclado a los datos.

## Entregables del reto

1. Repositorio GitHub (código + README + docs).
2. PDF del informe generado por la app.
3. Video del flujo: cargar Excel → analizar → dashboard → informes → PDF.
