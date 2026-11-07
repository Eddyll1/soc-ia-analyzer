"""Wrapper mínimo de Gemini con modo mock offline.

Diseño de seguridad:
- El modelo NO recibe herramientas ni function-calling: es texto→texto puro.
  No puede tocar la red, la BD ni el sistema de archivos. Mínimo privilegio.
- Se fuerza salida JSON y temperatura baja (determinismo).
- Si no hay GEMINI_API_KEY o falta el SDK, cae a MODO MOCK: genera una salida
  válida y determinista derivada de los hallazgos, para probar el pipeline y los
  validadores sin depender de la nube.
"""
from __future__ import annotations

import json
import os
import time


# Preferencia de modelos: del más capaz/eco al genérico. Se cruza con los que
# la cuenta tiene realmente disponibles (los nombres cambian entre versiones).
# Preferimos *flash-lite* vigente (mayor cuota en free tier, ≈15 RPM vs 5).
# 2.5-flash-lite quedó retirado para cuentas nuevas → se evita; se prioriza el 3.x.
_MODEL_PREFERENCE = ("3.5-flash-lite", "3.1-flash-lite", "flash-lite-latest",
                     "flash-latest", "2.5-flash", "flash", "pro")


class GeminiClient:
    def __init__(self, model: str | None = None):
        # Vacío = autodescubrir. La key nueva de AI Studio empieza con "AQ." o "AIza";
        # ambos formatos son válidos, no se valida por prefijo.
        self.model_name = model or os.getenv("GEMINI_MODEL", "")
        self.api_key = os.getenv("GEMINI_API_KEY")
        self._model = None
        self.mode = "mock"
        self.last_error: str | None = None
        if self.api_key:
            try:
                import google.generativeai as genai  # type: ignore
                genai.configure(api_key=self.api_key)
                self._genai = genai
                self.model_name = self._resolve_model(self.model_name)
                self._model = genai.GenerativeModel(self.model_name)
                self.mode = "live"
            except Exception as e:
                self.mode = "mock"
                self.last_error = f"No se pudo inicializar Gemini: {e}"

    def _resolve_model(self, preferred: str) -> str:
        """Elige un modelo que exista en la cuenta y soporte generateContent."""
        try:
            available = [m.name.split("/")[-1] for m in self._genai.list_models()
                         if "generateContent" in getattr(m, "supported_generation_methods", [])]
        except Exception:
            return preferred or "gemini-2.0-flash"
        if not available:
            return preferred or "gemini-2.0-flash"
        if preferred and preferred in available:
            return preferred
        if preferred:                       # el pedido no existe → avisamos y seguimos
            self.last_error = (f"Modelo '{preferred}' no disponible; se usa uno vigente. "
                               f"Disponibles (flash/pro): {', '.join(available[:6])}")
        for pat in _MODEL_PREFERENCE:
            for m in available:
                if pat in m:
                    return m
        return available[0]

    def generate(self, system: str, data_block: str, *, mock_hint: dict | None = None) -> str:
        """Devuelve el texto crudo del modelo. Reintenta 1 vez ante errores
        transitorios (503/504/timeout); si aun así falla, cae a mock."""
        if self.mode == "live":
            for attempt in range(2):
                try:
                    cfg = self._genai.types.GenerationConfig(
                        temperature=0.2, response_mime_type="application/json",
                    )
                    resp = self._model.generate_content(
                        [system, data_block], generation_config=cfg,
                        request_options={"timeout": 90},
                    )
                    return resp.text or ""
                except Exception as e:
                    msg = str(e)
                    transient = any(x in msg for x in ("503", "504", "Deadline", "timeout", "Timeout"))
                    if attempt == 0 and transient:
                        time.sleep(3)
                        continue
                    self.last_error = f"Fallo en llamada a Gemini: {e}"
                    self.mode = "mock"
        return self._mock(system, mock_hint or {})

    @staticmethod
    def _mock(system: str, hint: dict) -> str:
        """Respaldo sin nube. Para el editor dual, devuelve los informes base intactos."""
        if "ejecutivo_md" in hint and "tecnico_md" in hint:
            return json.dumps({"ejecutivo_md": hint["ejecutivo_md"],
                               "tecnico_md": hint["tecnico_md"]}, ensure_ascii=False)
        incs = hint.get("incidentes", [])
        es_ejec = "ejecutivo" in system or "Ejecutivo" in system
        if es_ejec:
            lines = ["# Resumen ejecutivo", "",
                     f"Se identificaron **{len(incs)} incidente(s)** de seguridad.", ""]
            for i in incs:
                lines += [f"## {i['id']} — Riesgo {i.get('riesgo', '?')}",
                          f"{i.get('titular', '')}", f"*Ventana:* {i.get('ventana', '')}", ""]
            lines += ["## Acciones recomendadas",
                      "- Contener los hosts e IPs afectados.",
                      "- Resetear las cuentas comprometidas.",
                      "- Erradicar persistencia detectada."]
            return json.dumps({"markdown": "\n".join(lines)}, ensure_ascii=False)
        # técnico
        lines = ["# Informe técnico de incidentes", ""]
        for i in incs:
            lines += [f"## {i['id']} — Riesgo {i.get('riesgo', '?')}",
                      f"**Resumen:** {i.get('titular', '')}  ",
                      f"**Ventana:** {i.get('ventana', '')}", "", "### Fases del ataque", ""]
            for p in i.get("fases", []):
                rango = f"{p.get('t0', '')}–{p.get('t1', '')}"
                ev = ", ".join(p.get("evidence", [])[:4])
                lines.append(f"- **{p['phase']}** ({rango}): {p['detail']} _[{ev}]_")
            lines.append("")
        return json.dumps({"markdown": "\n".join(lines)}, ensure_ascii=False)
