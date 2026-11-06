import { useState } from 'react'
import { uploadFile, analyze } from '../api/client'

const PROFILES = ['PCI-DSS', 'CIS', 'NIST', 'Personalizado']

export default function UploadForm({ onAnalyzed }) {
  const [file, setFile] = useState(null)
  const [profile, setProfile] = useState('CIS')
  const [preview, setPreview] = useState(null)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')

  const doUpload = async () => {
    if (!file) return
    setError(''); setBusy('Subiendo y validando contrato...')
    try {
      setPreview(await uploadFile(file, profile))
    } catch (e) {
      setError(e?.response?.data?.detail || 'Error al subir el archivo')
    } finally { setBusy('') }
  }

  const doAnalyze = async () => {
    setError(''); setBusy('Analizando: reglas + correlación + agentes IA...')
    try {
      onAnalyzed(await analyze(preview.analysis_id, profile))
    } catch (e) {
      setError(e?.response?.data?.detail || 'Error al analizar')
    } finally { setBusy('') }
  }

  return (
    <div className="max-w-3xl">
      <h2 className="text-xl font-semibold mb-1">Cargar export de SIEM</h2>
      <p className="text-slate-400 text-sm mb-4">Archivo Excel (.xlsx). Se valida el contrato de 12 columnas antes de analizar.</p>

      <div className="flex flex-wrap gap-3 items-end mb-4">
        <div>
          <label className="block text-xs text-slate-400 mb-1">Archivo</label>
          <input type="file" accept=".xlsx,.xls"
            onChange={(e) => { setFile(e.target.files[0]); setPreview(null) }}
            className="text-sm file:mr-3 file:px-3 file:py-1.5 file:rounded file:border-0 file:bg-sky-600 file:text-white" />
        </div>
        <div>
          <label className="block text-xs text-slate-400 mb-1">Perfil de umbrales</label>
          <select value={profile} onChange={(e) => setProfile(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm">
            {PROFILES.map((p) => <option key={p}>{p}</option>)}
          </select>
        </div>
        <button onClick={doUpload} disabled={!file || !!busy}
          className="px-4 py-2 rounded bg-slate-700 hover:bg-slate-600 disabled:opacity-40 text-sm">
          Validar y previsualizar
        </button>
      </div>

      {busy && <div className="text-sky-400 text-sm mb-3 animate-pulse">{busy}</div>}
      {error && <div className="text-red-400 text-sm mb-3 bg-red-950/40 border border-red-900 rounded px-3 py-2">{error}</div>}

      {preview && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex justify-between items-center mb-3">
            <div className="text-sm text-slate-300">
              <b>{preview.filename}</b> · {preview.row_count} filas · {preview.columns.length} columnas
            </div>
            <button onClick={doAnalyze} disabled={!!busy}
              className="px-4 py-2 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-sm font-medium">
              Analizar
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="text-xs w-full">
              <thead><tr className="text-slate-400 text-left">
                {preview.columns.slice(0, 8).map((c) => <th key={c} className="pr-3 pb-1 font-medium">{c}</th>)}
              </tr></thead>
              <tbody>
                {preview.preview.slice(0, 5).map((row, i) => (
                  <tr key={i} className="border-t border-slate-800">
                    {preview.columns.slice(0, 8).map((c) => (
                      <td key={c} className="pr-3 py-1 text-slate-300 truncate max-w-[120px]">{String(row[c] ?? '')}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
