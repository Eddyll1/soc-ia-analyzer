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


# Preferencia de modelos: del más capaz/eco al genérico. Se cruza con los que
# la cuenta tiene realmente disponibles (los nombres cambian entre versiones).
_MODEL_PREFERENCE = ("flash-latest", "2.5-flash", "2.0-flash", "flash",
                     "pro-latest", "2.5-pro", "pro")


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
        """Devuelve el texto crudo del modelo. Si la llamada live falla, cae a mock."""
        if self.mode == "live":
            try:
                cfg = self._genai.types.GenerationConfig(
                    temperature=0.1, response_mime_type="application/json",
                )
                resp = self._model.generate_content(
                    [system, data_block], generation_config=cfg,
                    request_options={"timeout": 120},
                )
                return resp.text or ""
            except Exception as e:
                # Una key inválida o un fallo de red no debe tumbar el análisis.
                self.last_error = f"Fallo en llamada a Gemini: {e}"
                self.mode = "mock"
        return self._mock(system, mock_hint or {})

    @staticmethod
    def _mock(system: str, hint: dict) -> str:
        """Salida mock válida por tipo de agente (se detecta por el rol en 'system')."""
        if "Correlacionador" in system:
            return json.dumps({"incidents": [
                {"id": i["id"],
                 "narrative": f"Cadena observada en {', '.join(i.get('hosts', [])) or 'el entorno'}.",
                 "timeline": [{"log_id": e, "phase": "—", "fact": "evento citado"}
                              for e in i.get("evidence", [])[:8]],
                 "mitre": [], "confidence": "media", "injection_flags": i.get("injection_flags", [])}
                for i in hint.get("incidents", [])]}, ensure_ascii=False)
        if "Clasificador" in system:
            return json.dumps({"classifications": [
                {"incident_id": i["id"], "risk": i.get("severity_hint_es", "Medio"),
                 "justification": f"Factor decisivo en {i.get('evidence', ['?'])[0]}.",
                 "impact": "Ver evidencia.", "recommended_action": "Contener y revisar."}
                for i in hint.get("incidents", [])]}, ensure_ascii=False)
        if "ejecutivo" in system or "Ejecutivo" in system:
            return json.dumps({"markdown": "# Resumen ejecutivo\n\n(generado en modo mock)"},
                              ensure_ascii=False)
        return json.dumps({"markdown": "# Informe técnico\n\n(generado en modo mock)"},
                          ensure_ascii=False)
