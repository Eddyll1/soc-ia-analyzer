# Diagramas de arquitectura — SOC-IA Analyzer

Documentación visual de la plataforma, pensada para lectura de cliente: cada
elemento está etiquetado en lenguaje claro. Los diagramas están en Mermaid y
**se renderizan automáticamente en GitHub** (no hace falta ninguna herramienta
extra para verlos).

Contenido:
1. [Casos de uso — cómo interactúa el usuario](#1-casos-de-uso)
2. [Secuencia — cómo viaja la información](#2-secuencia-de-datos)
3. [Navegación — qué hace cada ventana](#3-navegación-de-ventanas)
4. [Base de datos — cómo se guarda todo](#4-modelo-de-base-de-datos)

---

## 1. Casos de uso

Qué puede hacer el analista con la aplicación. El muñeco es el usuario; cada
caja es una acción disponible.

```mermaid
flowchart LR
    A(["Analista SOC"])
    subgraph SIS["SOC-IA Analyzer"]
        direction TB
        U1["Cargar el Excel del SIEM"]
        U2["Elegir perfil de umbrales<br/>PCI / CIS / NIST"]
        U3["Ejecutar el análisis"]
        U4["Ver el tablero<br/>KPIs, gráficos y filtros"]
        U5["Revisar incidentes y<br/>cadena de ataque"]
        U6["Consultar plan de acción e IoCs"]
        U7["Exportar informe a PDF"]
        U8["Reabrir un análisis guardado"]
    end
    A --> U1
    A --> U2
    A --> U3
    A --> U4
    A --> U5
    A --> U6
    A --> U7
    A --> U8
```

---

## 2. Secuencia de datos

El viaje completo de la información, desde que el analista sube el archivo hasta
que descarga el PDF. Muestra cómo se comunican el navegador, el servidor, el
motor de reglas, la IA y la base de datos.

```mermaid
sequenceDiagram
    actor A as Analista SOC
    participant FE as App web React
    participant BE as Servidor FastAPI
    participant RG as Motor de reglas
    participant IA as Agentes IA Gemini
    participant DB as Base de datos SQLite

    A->>FE: Sube el Excel del SIEM
    FE->>BE: POST /api/upload
    BE->>BE: Valida la estructura del archivo
    BE-->>FE: Columnas, vista previa y mapeo sugerido
    A->>FE: Confirma mapeo y perfil, pulsa Analizar
    FE->>BE: POST /api/analyze
    BE->>BE: Normaliza eventos (unifica hosts y usuarios)
    BE->>RG: Entrega los eventos ya limpios
    RG-->>BE: Hallazgos, cada uno con sus Log_ID
    BE->>BE: Agrupa hallazgos en incidentes
    BE->>IA: Resúmenes y evidencia citada
    IA-->>BE: Narrativa, clasificación y redacción
    BE->>BE: Verifica que cada Log_ID exista (anti-invención)
    BE->>DB: Guarda análisis, eventos, incidentes e informes
    BE-->>FE: Resultado completo en JSON
    FE-->>A: Pinta tablero, incidentes e informes
    A->>FE: Pulsa Exportar PDF
    FE-->>A: Abre el diálogo de impresión para guardar en PDF
```

---

## 3. Navegación de ventanas

Las seis pestañas de la aplicación y qué hace cada una. Las pestañas de análisis
se desbloquean cuando hay un análisis cargado; el historial está siempre
disponible.

```mermaid
flowchart TB
    INICIO(["Inicio"]) --> CARGAR
    CARGAR["CARGAR<br/>Sube el Excel y elige el perfil de umbrales"]
    CARGAR -->|análisis listo| DASH
    DASH["DASHBOARD<br/>KPIs, gráficos, explorador filtrable y plan de acción"]
    DASH --> INC["INCIDENTES<br/>Cada incidente con su cadena de ataque y fases"]
    DASH --> INF["INFORMES<br/>Ejecutivo y Técnico, con Exportar PDF"]
    DASH --> SEG["SEGURIDAD<br/>Defensas de la IA: validación de citas y anti-inyección"]
    HIST["HISTORIAL<br/>Reabre análisis guardados sin volver a subir el Excel"]
    CARGAR -. siempre disponible .-> HIST
    HIST -->|abrir uno| DASH
```

---

## 4. Modelo de base de datos

Cómo se guarda la información en SQLite. Un **análisis** es el centro: de él
cuelgan sus eventos, hallazgos, incidentes, indicadores e informes.

> **Nota de diseño (modelo híbrido):** las columnas marcadas como `json` guardan
> estructuras anidadas del análisis (métricas, fases, hitos, entidades). Es una
> decisión deliberada: las entidades principales están normalizadas en tablas,
> pero los resultados anidados del análisis se guardan como JSON para no
> fragmentar en decenas de tablas auxiliares. No es 3FN estricta en esas
> columnas; es el patrón habitual para payloads de análisis.

Se muestra un subconjunto representativo de columnas por legibilidad.

```mermaid
erDiagram
    ANALYSIS ||--o{ EVENT : "contiene"
    ANALYSIS ||--o{ FINDING : "detecta"
    ANALYSIS ||--o{ INCIDENT : "correlaciona"
    ANALYSIS ||--o{ IOC : "extrae"
    ANALYSIS ||--o{ REPORT : "genera"

    ANALYSIS {
        int id PK
        string filename "nombre del Excel"
        string profile "PCI / CIS / NIST"
        string status "draft / analyzed"
        int event_count
        string max_severity
        json stats_json "metricas (anidado)"
        json security_log_json "defensas IA (anidado)"
    }
    EVENT {
        int id PK
        int analysis_id FK
        string log_id "EVT-#####"
        string timestamp
        string host
        string event_id
        string user
        string source_ip
        string result
        json extra_json "columnas no mapeadas"
    }
    FINDING {
        int id PK
        int analysis_id FK
        string incident_id "a que incidente pertenece"
        string rule_id "regla que disparo"
        string severity_hint
        json evidence_json "lista de Log_ID"
    }
    INCIDENT {
        int id PK
        int analysis_id FK
        string code "INC-A, INC-B"
        string severity "Critico / Alto / Medio / Bajo"
        text headline "titular"
        json phases_json "fases del ataque"
        json entities_json "hosts, usuarios, IPs"
    }
    IOC {
        int id PK
        int analysis_id FK
        string type "ip / command"
        string value
        string context
    }
    REPORT {
        int id PK
        int analysis_id FK
        string kind "ejecutivo / tecnico"
        text content_md "informe en Markdown"
    }
```
