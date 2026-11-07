"""Generación determinística de informes (ejecutivo y técnico) en Markdown.

Se construyen SIEMPRE por código, con estructura profesional (introducción,
historia por incidente, entidades afectadas, contención, lecciones aprendidas,
métricas y conclusiones). Gemini, cuando está disponible, solo los pule. Así el
analista nunca recibe texto de relleno aunque el free tier falle.
"""
from __future__ import annotations

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
        out.append("Alertar sobre **PowerShell `-EncodedCommand`** y binarios en rutas no estándar; activar ScriptBlock logging.")
    if rule_ids & {"PERSIST_SERVICE", "PERSIST_TASK"}:
        out.append("Monitorear creación de **servicios (7045)** y **tareas programadas (4698)**.")
    if rule_ids & {"LATERAL_MOVEMENT"}:
        out.append("**Segmentar la red** y limitar cuentas con acceso administrativo entre servidores.")
    if rule_ids & {"WEB_ATTACK", "WEB_SHELL"}:
        out.append("Reforzar el **WAF** y revisar permisos de escritura en el servidor web.")
    if not out:
        out.append("Mantener la correlación de eventos y la revisión periódica de accesos.")
    return out


def _risk_rank(r: str) -> int:
    return {"Crítico": 4, "Alto": 3, "Medio": 2, "Bajo": 1}.get(r, 0)


# ------------------------------- EJECUTIVO -------------------------------
def build_executive(ctx: dict) -> str:
    incs = ctx["incidents"]
    stats = ctx["stats"]
    max_sev = max((c["risk"] for c in incs), key=_risk_rank, default="—")
    crit = [i for i in incs if i["risk"] in ("Crítico", "Alto")]
    L: list[str] = []
    L += ["# Informe ejecutivo de seguridad", "",
          f"**Ventana analizada:** {stats.get('time_start')} — {stats.get('time_end')}  ",
          f"**Eventos procesados:** {stats.get('total_events')} · **Incidentes:** {len(incs)} · "
          f"**Gravedad máxima:** {max_sev}", "", "---", ""]

    L += ["## Panorama general", ""]
    if crit:
        L.append(f"Durante la ventana analizada, el monitoreo del SOC identificó **{len(incs)} incidente(s)** "
                 f"de seguridad, de los cuales **{len(crit)}** requieren atención inmediata. El de mayor "
                 f"gravedad alcanza el nivel **{max_sev}**, lo que implica un posible acceso no autorizado "
                 f"a sistemas del entorno y, en el peor caso, salida de información. A continuación se resume, "
                 f"en lenguaje no técnico, qué ocurrió y qué decisiones se recomiendan.")
    else:
        L.append(f"Durante la ventana analizada se identificaron **{len(incs)} evento(s)** de interés, "
                 f"sin compromiso confirmado. Se recomienda revisión de rutina.")
    L.append("")

    L += ["## Incidentes en pocas palabras", ""]
    for i in incs:
        aff = i.get("affected", {})
        hosts = ", ".join(aff.get("hosts", [])[:5]) or "—"
        L += [f"### {i['id']} — Riesgo {i['risk']}", "",
              f"**La historia:** {_exec_story(i)}", "",
              f"- **Sistemas afectados:** {hosts}",
              f"- **Cuándo:** {i['window']}",
              f"- **Qué está en juego:** {_exec_impact(i['risk'])}", ""]

    L += ["## Qué significa para el negocio", "",
          "Un incidente de esta naturaleza puede derivar en interrupción de servicios, pérdida o fuga "
          "de información sensible y afectación reputacional y regulatoria (p. ej. PCI-DSS). Actuar en "
          "las próximas horas reduce significativamente el impacto potencial.", ""]

    L += ["## Decisiones recomendadas", ""]
    for a in _exec_decisions(incs):
        L.append(f"- {a}")
    L += ["", "## Conclusión", "",
          f"El entorno presenta **{len(crit)} incidente(s) de prioridad alta o crítica** que deben "
          f"contenerse de inmediato por el equipo técnico. La dirección debe respaldar las acciones de "
          f"contención y, de confirmarse exfiltración, activar el protocolo de notificación correspondiente.", ""]
    return "\n".join(L)


def _exec_story(i: dict) -> str:
    phases = [p["phase"].split(" — ")[0] for p in i.get("phases", [])]
    aff = i.get("affected", {})
    ext = ", ".join(aff.get("external_ips", [])[:2])
    if "Exfiltración" in phases:
        return (f"Un atacante externo ({ext or 'origen externo'}) logró entrar a los sistemas, moverse "
                f"entre servidores y extraer información hacia fuera de la organización.")
    if "Compromiso de credencial" in phases:
        return (f"Un atacante ({ext or 'origen externo'}) consiguió credenciales válidas y accedió a los "
                f"sistemas sin autorización.")
    if "Ataque web" in phases:
        return f"Se detectaron intentos de ataque contra el servidor web desde {ext or 'una IP externa'}."
    return "Se detectó actividad sospechosa que requiere revisión del equipo de seguridad."


def _exec_impact(risk: str) -> str:
    return {"Crítico": "Posible fuga de datos y compromiso de sistemas críticos.",
            "Alto": "Compromiso confirmado de sistemas; riesgo de escalamiento.",
            "Medio": "Intento de ataque; riesgo si no se contiene.",
            "Bajo": "Impacto limitado."}.get(risk, "Requiere evaluación.")


def _exec_decisions(incs: list[dict]) -> list[str]:
    acts = ["**Autorizar la contención inmediata** (aislamiento de equipos y bloqueo de IPs) por parte del SOC.",
            "**Respaldar el reseteo de credenciales** de las cuentas afectadas, aun si implica interrupción temporal."]
    if any("Exfiltración" in [p["phase"] for p in i.get("phases", [])] for i in incs):
        acts.append("**Activar el protocolo de notificación** (legal/cumplimiento) ante posible fuga de datos.")
    acts.append("**Asignar recursos** para la investigación forense y el refuerzo de controles (MFA, segmentación).")
    return acts


# ------------------------------- TÉCNICO -------------------------------
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
    L += ["# Informe técnico de respuesta a incidentes", "",
          f"**Ventana:** {stats.get('time_start')} — {stats.get('time_end')}  ",
          f"**Eventos:** {stats.get('total_events')} · **Perfil de umbrales:** {ctx.get('profile')} · "
          f"**Incidentes:** {len(incs)}  ",
          "**Método:** motor de reglas determinístico + correlación por entidad + asistencia de IA "
          "(con validación de citas).", "", "---", ""]

    # 1. Introducción
    L += ["## 1. Introducción y alcance", "",
          "Este informe documenta los incidentes de seguridad detectados a partir de la exportación del "
          "SIEM indicada. El análisis se limita a la ventana temporal y a los campos disponibles en el "
          "registro; no incluye telemetría de red completa ni EDR. Cada afirmación se sustenta en uno o "
          "más `Log_ID` del origen.", ""]

    # 2. Resumen (tabla)
    L += ["## 2. Resumen de incidentes", "",
          "| ID | Riesgo | Ventana | Hosts afectados | Eventos |",
          "|----|--------|---------|-----------------|---------|"]
    for i in incs:
        hosts = ", ".join(i.get("affected", {}).get("hosts", [])[:4]) or "—"
        L.append(f"| {i['id']} | {i['risk']} | {i['window']} | {hosts} | {i.get('event_count','—')} |")
    L.append("")

    # 3. Detalle por incidente
    L += ["## 3. Detalle por incidente", ""]
    for i in incs:
        aff = i.get("affected", {})
        L += [f"### {i['id']} — Riesgo {i['risk']}", "",
              f"**Resumen de la cadena:** {i['headline'].replace(' → ', ' > ')}", ""]

        # Entidades afectadas (para decisiones de aislamiento)
        L += ["#### Entidades afectadas", "",
              "| Host | IPs asociadas |", "|------|---------------|"]
        host_ips = aff.get("host_ips", {})
        for h in aff.get("hosts", []):
            L.append(f"| {h} | {', '.join(host_ips.get(h, [])) or '—'} |")
        L.append("")
        L.append(f"- **Usuarios involucrados (resetear):** {', '.join(aff.get('users', [])) or '—'}")
        L.append(f"- **IPs externas (bloquear):** {', '.join(aff.get('external_ips', [])) or '—'}")
        if aff.get("exfil_dest"):
            L.append(f"- **Destinos de exfiltración:** {', '.join(aff['exfil_dest'])}")
        L.append("")

        # Fases
        L += ["#### Fases del ataque", "",
              "| Hora | Fase | Detalle | Evidencia |", "|------|------|---------|-----------|"]
        for p in i.get("phases", []):
            rango = f"{(p.get('t0') or '')[11:]}–{(p.get('t1') or '')[11:]}"
            ev = ", ".join(p.get("evidence", [])[:3]) + ("…" if len(p.get("evidence", [])) > 3 else "")
            L.append(f"| {rango} | {p['phase']} | {p['detail']} | {ev} |")
        L.append("")

    # 4. IoC
    L += ["## 4. Indicadores de compromiso (IoC)", "",
          "| Tipo | Valor | Contexto |", "|------|-------|----------|"]
    seen = set()
    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key in seen:
            continue
        seen.add(key)
        L.append(f"| {ioc['type']} | `{ioc['value']}` | {ioc.get('context','')} |")
    L.append("")

    # 5. Contención y erradicación
    L += ["## 5. Contención y erradicación", ""]
    for i in incs:
        aff = i.get("affected", {})
        L.append(f"**{i['id']}:**")
        for a in _containment(set(i.get("rule_ids", [])), aff):
            L.append(f"- {a}")
        L.append("")

    # 6. Lecciones aprendidas
    L += ["## 6. Lecciones aprendidas", ""]
    for l in _lessons(all_rules):
        L.append(f"- {l}")
    L.append("")

    # 7. Métricas
    sev_count: dict[str, int] = {}
    for i in incs:
        sev_count[i["risk"]] = sev_count.get(i["risk"], 0) + 1
    L += ["## 7. Métricas del análisis", "",
          "| Métrica | Valor |", "|---------|-------|",
          f"| Eventos totales | {stats.get('total_events')} |",
          f"| Incidentes | {len(incs)} |",
          f"| Ruido descartado (7036, etc.) | {stats.get('noise_events','—')} |"]
    for s, n in sorted(sev_count.items(), key=lambda kv: -_risk_rank(kv[0])):
        L.append(f"| Incidentes {s} | {n} |")
    L.append("")
    tips = stats.get("top_failed_ips", {})
    if tips:
        L += ["**Top IPs con fallos de autenticación:**", ""]
        for ip, n in tips.items():
            L.append(f"- `{ip}` — {n} fallos")
        L.append("")

    # 8. Conclusión
    L += ["## 8. Conclusión y próximos pasos operativos", "",
          "Los incidentes documentados cuentan con evidencia trazable a los registros del SIEM. El equipo "
          "SOC debe ejecutar la contención descrita, validar la erradicación de la persistencia y dejar "
          "monitoreo reforzado sobre las entidades afectadas. Se recomienda una revisión forense de los "
          "hosts comprometidos antes de reincorporarlos a producción.", ""]

    # Anexo
    L += ["## Anexo: normalizaciones y limitaciones", ""]
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
