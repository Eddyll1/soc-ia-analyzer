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


class GeminiClient:
    def __init__(self, model: str | None = None):
        self.model_name = model or os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
        self.api_key = os.getenv("GEMINI_API_KEY")
        self._model = None
        self.mode = "mock"
        if self.api_key:
            try:
                import google.generativeai as genai  # type: ignore
                genai.configure(api_key=self.api_key)
                self._genai = genai
                self._model = genai.GenerativeModel(self.model_name)
                self.mode = "live"
            except Exception:
                self.mode = "mock"

    def generate(self, system: str, data_block: str, *, mock_hint: dict | None = None) -> str:
        """Devuelve el texto crudo del modelo (se valida después, fuera de aquí)."""
        if self.mode == "live":
            cfg = self._genai.types.GenerationConfig(
                temperature=0.1, response_mime_type="application/json",
            )
            resp = self._model.generate_content(
                [system, data_block], generation_config=cfg, request_options={"timeout": 60},
            )
            return resp.text or ""
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
