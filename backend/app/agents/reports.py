"""Generación determinística de informes (ejecutivo y técnico) en Markdown.

Siguen una estructura corporativa fija: el ejecutivo para la Alta Dirección
(resumen, matriz de riesgo, métricas, conclusión estratégica) y el técnico
forense (metadatos, cronología UTC, telemetría/vectores, IoCs con severidad,
mitigación/hardening). Se construyen SIEMPRE por código; Gemini solo los pule.
"""
from __future__ import annotations

_RANK = {"Crítico": 4, "Alto": 3, "Medio": 2, "Bajo": 1}
_EMOJI = {"Crítico": "🔴", "Alto": "🟠", "Medio": "🟡", "Bajo": "🟢"}


def _risk_rank(r: str) -> int:
    return _RANK.get(r, 0)


def _badge(risk: str) -> str:
    return f"{_EMOJI.get(risk, '⚪')} {risk}"


def _ioc_severity(ioc: dict) -> str:
    v = str(ioc.get("value", "")).lower()
    if "wuhelper" in v or "encodedcommand" in v:
        return "🔴 Crítico"
    if ioc.get("type") == "ip":
        return "🟠 Alto"
    return "🟡 Medio"


# ---- Contención y lecciones derivadas de las reglas que dispararon ----
def _containment(rule_ids: set[str], affected: dict) -> list[str]:
    acts: list[str] = []
    hosts = ", ".join(affected.get("hosts", [])) or "los hosts afectados"
    users = ", ".join(affected.get("users", [])) or "las cuentas afectadas"
    ext = ", ".join(affected.get("external_ips", [])) or "las IPs externas observadas"
    dest = ", ".join(affected.get("exfil_dest", []))
    if rule_ids & {"LATERAL_MOVEMENT", "SUCCESS_AFTER_FAILS", "PRIV_ESCALATION"}:
        acts.append(f"**Aislar de la red** los hosts comprometidos ({hosts}) para frenar el avance.")
    if rule_ids & {"SUCCESS_AFTER_FAILS", "BRUTE_FORCE", "BRUTE_FORCE_SPRAY"}:
        acts.append(f"**Resetear credenciales** de las cuentas involucradas ({users}) y forzar reautenticación.")
    if rule_ids & {"STAGING_EXFIL", "OUTBOUND_EXFIL"}:
        acts.append(f"**Bloquear en el firewall** las IPs externas de destino ({dest or ext}) y revisar egress.")
    if rule_ids & {"BRUTE_FORCE", "BRUTE_FORCE_SPRAY", "WEB_ATTACK"}:
        acts.append(f"**Bloquear las IPs externas de origen** del ataque ({ext}).")
    if rule_ids & {"PERSIST_SERVICE", "PERSIST_TASK", "SUSPICIOUS_EXEC"}:
        acts.append("**Erradicar la persistencia**: eliminar servicios/tareas creados y el binario "
                    "`C:\\ProgramData\\wuhelper.exe` donde aparezca.")
    if "WEB_SHELL" in rule_ids or "WEB_ATTACK" in rule_ids:
        acts.append("**Revisar el servidor web**: buscar webshells en rutas de carga (p. ej. `/uploads`) y sanear.")
    if not acts:
        acts.append("Revisar los eventos citados y monitorear las entidades afectadas.")
    return acts


def _lessons(rule_ids: set[str]) -> list[str]:
    out: list[str] = []
    if rule_ids & {"BRUTE_FORCE", "BRUTE_FORCE_SPRAY", "SUCCESS_AFTER_FAILS"}:
        out.append("Aplicar **MFA** y bloqueo por intentos fallidos en accesos remotos (RDP/VPN).")
    if rule_ids & {"STAGING_EXFIL", "OUTBOUND_EXFIL"}:
        out.append("Implementar **filtrado de salida (egress) y DLP** hacia destinos no aprobados.")
    if rule_ids & {"SUSPICIOUS_EXEC"}:
        out.append("Alertar sobre **PowerShell `-EncodedCommand`** y binarios en rutas no estándar; activar ScriptBlock logging (Event ID 4104).")
    if rule_ids & {"PERSIST_SERVICE", "PERSIST_TASK"}:
        out.append("Monitorear creación de **servicios (7045)** y **tareas programadas (4698)**.")
    if rule_ids & {"LATERAL_MOVEMENT"}:
        out.append("**Segmentar la red** y limitar cuentas con acceso administrativo entre servidores.")
    if rule_ids & {"WEB_ATTACK", "WEB_SHELL"}:
        out.append("Reforzar el **WAF** y revisar permisos de escritura en el servidor web.")
    if not out:
        out.append("Mantener la correlación de eventos y la revisión periódica de accesos.")
    return out


# =============================== EJECUTIVO ===============================
def build_executive(ctx: dict) -> str:
    incs = ctx["incidents"]
    stats = ctx["stats"]
    max_sev = max((c["risk"] for c in incs), key=_risk_rank, default="—")
    crit = [i for i in incs if i["risk"] in ("Crítico", "Alto")]
    exfil = any("Exfiltración" in [p["phase"] for p in i.get("phases", [])] for i in incs)
    L: list[str] = []

    L += ["# 🛡️ Informe Ejecutivo de Seguridad", "",
          f"**Ventana analizada:** {stats.get('time_start')} — {stats.get('time_end')} (UTC)  ",
          f"**Clasificación del documento:** Confidencial · **Preparado por:** SOC / Inteligencia Operativa", "",
          "---", ""]

    # 1. Resumen Ejecutivo (3-4 líneas)
    L += ["## 1. Resumen Ejecutivo", ""]
    estado = "requiere contención inmediata" if crit else "bajo control"
    L.append(f"Se detectaron **{len(incs)} incidente(s)** de seguridad en el entorno, con una gravedad "
             f"máxima **{_badge(max_sev)}**. "
             + ("Existe evidencia de acceso no autorizado y posible **salida de información**, lo que "
                "representa un riesgo directo para la continuidad del negocio y el cumplimiento (PCI-DSS). "
                if exfil else
                "Se observó actividad de intrusión que fue detectada por el monitoreo. ")
             + f"El estado actual {estado}; a continuación se detallan los riesgos y las decisiones recomendadas.")
    L.append("")

    # 2. Matriz de Hallazgos y Riesgo
    L += ["## 2. Matriz de Hallazgos y Riesgo", "",
          "| Incidente | Severidad | Sistemas afectados | Origen | Estado |",
          "|-----------|-----------|--------------------|--------|--------|"]
    for i in incs:
        aff = i.get("affected", {})
        hosts = ", ".join(aff.get("hosts", [])[:3]) or "—"
        ext = ", ".join(aff.get("external_ips", [])[:2]) or "interno"
        est = "Contención requerida" if i["risk"] in ("Crítico", "Alto") else "En revisión"
        L.append(f"| {i['id']} | {_badge(i['risk'])} | {hosts} | {ext} | {est} |")
    L.append("")

    # 3. Análisis de Métricas Clave
    sev_count: dict[str, int] = {}
    for i in incs:
        sev_count[i["risk"]] = sev_count.get(i["risk"], 0) + 1
    top_ip = next(iter(stats.get("top_failed_ips", {}).items()), ("—", "—"))
    L += ["## 3. Análisis de Métricas Clave", "",
          "| Métrica | Valor | Lectura |",
          "|---------|-------|---------|",
          f"| Eventos procesados | {stats.get('total_events')} | Volumen analizado en la ventana |",
          f"| Incidentes correlacionados | {len(incs)} | {len(crit)} de prioridad alta/crítica |",
          f"| Severidad máxima | {_badge(max_sev)} | Define la urgencia de respuesta |",
          f"| IP con más fallos de acceso | `{top_ip[0]}` ({top_ip[1]}) | Principal foco de ataque |", "",
          "[GRAFICO: distribucion_incidentes_criticidad]", "",
          "[GRAFICO: eventos_por_hora]", ""]

    # 4. Conclusión Estratégica y Próximos Pasos
    L += ["## 4. Conclusión Estratégica y Próximos Pasos", "",
          f"El entorno presenta **{len(crit)} incidente(s) de prioridad alta o crítica**. La no actuación "
          f"en las próximas horas incrementa el riesgo de pérdida de datos, interrupción operativa y "
          f"exposición regulatoria.", "",
          "| Acción | Responsable | Plazo |",
          "|--------|-------------|-------|",
          "| Autorizar contención (aislamiento y bloqueo de IPs) | SOC / Infraestructura | Inmediato |",
          "| Reseteo de credenciales comprometidas | SOC / Service Desk | < 4 horas |"]
    if exfil:
        L.append("| Activar protocolo de notificación por fuga de datos | Legal / Cumplimiento | < 24 horas |")
    L.append("| Investigación forense y refuerzo de controles (MFA, segmentación) | SOC / Ingeniería | < 72 horas |")
    L.append("")
    return "\n".join(L)


# =============================== TÉCNICO ===============================
def build_technical(ctx: dict) -> str:
    incs = ctx["incidents"]
    stats = ctx["stats"]
    iocs = ctx.get("iocs", [])
    norm = ctx.get("normalizations", [])
    lim = ctx.get("limitations", [])
    all_rules: set[str] = set()
    for i in incs:
        all_rules |= set(i.get("rule_ids", []))

    L: list[str] = []
    L += ["# 🧪 Informe Técnico de Respuesta a Incidentes", "",
          f"**Ventana:** {stats.get('time_start')} — {stats.get('time_end')} (UTC) · "
          f"**Perfil:** {ctx.get('profile')} · **Eventos:** {stats.get('total_events')}  ",
          "**Fuentes:** export SIEM (Security, System, Proxy, IIS, PowerShell, Firewall). "
          "**Método:** motor de reglas determinístico + correlación por entidad + IA con validación de citas.",
          "", "---", ""]

    # 1. Resumen Técnico (metadatos)
    L += ["## 1. Resumen Técnico del Incidente", "",
          "| ID | Severidad | Sistemas afectados | Usuarios | Eventos | Ventana (UTC) |",
          "|----|-----------|--------------------|----------|---------|---------------|"]
    for i in incs:
        aff = i.get("affected", {})
        hosts = ", ".join(aff.get("hosts", [])[:4]) or "—"
        nusr = len(aff.get("users", []))
        L.append(f"| {i['id']} | {_badge(i['risk'])} | {hosts} | {nusr} | {i.get('event_count','—')} | {i['window']} |")
    L.append("")

    # 2. Cronología de Eventos (UTC) por incidente
    L += ["## 2. Cronología de Eventos (UTC)", ""]
    for i in incs:
        L += [f"### {i['id']} — {_badge(i['risk'])}",
              f"*Cadena:* {i['headline'].replace(' → ', ' > ')}", "",
              "| Hora (UTC) | Fase | Detalle | Evidencia (Log_ID) |",
              "|------------|------|---------|--------------------|"]
        for p in i.get("phases", []):
            rango = f"{(p.get('t0') or '')[11:]}–{(p.get('t1') or '')[11:]}"
            ev = ", ".join(p.get("evidence", [])[:4]) + ("…" if len(p.get("evidence", [])) > 4 else "")
            L.append(f"| {rango} | {p['phase']} | {p['detail']} | {ev} |")
        L.append("")

    # 3. Análisis de Telemetría y Vectores (consultas SIEM de validación)
    all_ext = sorted({ip for i in incs for ip in i.get("affected", {}).get("external_ips", [])})
    L += ["## 3. Análisis de Telemetría y Vectores", "",
          "Vectores observados: fuerza bruta/credential stuffing, uso de credenciales válidas, ejecución "
          "ofuscada (PowerShell `-EncodedCommand`), persistencia por servicio/tarea y exfiltración por canal "
          "saliente. Consultas de validación sugeridas:", "",
          "```sql", "-- QRadar AQL: actividad de las IPs atacantes en 24h"]
    if all_ext:
        ips_sql = "', '".join(all_ext)
        L.append(f"SELECT sourceip, destinationip, username, eventcount "
                 f"FROM events WHERE sourceip IN ('{ips_sql}') LAST 24 HOURS")
    L += ["```", "",
          "```powershell",
          "# CrowdStrike/EDR: localizar el binario de persistencia en los hosts",
          "Get-ChildItem -Path 'C:\\ProgramData\\wuhelper.exe' -ErrorAction SilentlyContinue |",
          "  Select-Object FullName, Length, CreationTimeUtc",
          "```", "",
          "```bash",
          "# Firewall/Proxy: conexiones salientes a los destinos de exfiltración",
          "grep -E '198\\.51\\.100\\.88|203\\.0\\.113\\.88' /var/log/firewall/egress.log",
          "```", ""]

    # 4. Indicadores de Compromiso (IoCs) con severidad
    L += ["## 4. Indicadores de Compromiso (IoCs)", "",
          "| Tipo | Indicador / Valor | Contexto | Severidad |",
          "|------|-------------------|----------|-----------|"]
    seen = set()
    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key in seen:
            continue
        seen.add(key)
        L.append(f"| {ioc['type']} | `{ioc['value']}` | {ioc.get('context','')} | {_ioc_severity(ioc)} |")
    L.append("")

    # 5. Acciones de Mitigación, Hardening y Recomendaciones
    L += ["## 5. Acciones de Mitigación, Hardening y Recomendaciones", ""]
    for i in incs:
        aff = i.get("affected", {})
        L.append(f"**{i['id']} ({_badge(i['risk'])}):**")
        for a in _containment(set(i.get("rule_ids", [])), aff):
            L.append(f"- {a}")
        L.append("")
    L += ["### Hardening y lecciones aprendidas", ""]
    for l in _lessons(all_rules):
        L.append(f"- {l}")
    L.append("")

    # Anexo
    L += ["## Anexo: normalización y limitaciones", ""]
    if norm:
        L.append("**Normalizaciones aplicadas:**")
        for n in norm[:10]:
            L.append(f"- {n}")
        L.append("")
    if lim:
        L.append("**Limitaciones del análisis:**")
        for x in lim:
            L.append(f"- {x}")
    return "\n".join(L)
