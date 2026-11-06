import { useEffect, useState } from 'react'
import { listAnalyses, getAnalysis, deleteAnalysis } from './api/client'
import UploadForm from './components/UploadForm'
import Dashboard from './components/Dashboard'
import IncidentList from './components/IncidentList'
import ReportView from './components/ReportView'
import HistoryList from './components/HistoryList'
import SecurityLog from './components/SecurityLog'

const TABS = ['Cargar', 'Dashboard', 'Incidentes', 'Informes', 'Seguridad', 'Historial']

export default function App() {
  const [tab, setTab] = useState('Cargar')
  const [data, setData] = useState(null)
  const [history, setHistory] = useState([])

  const refreshHistory = () => listAnalyses().then(setHistory).catch(() => {})
  useEffect(() => { refreshHistory() }, [])

  const onAnalyzed = (d) => { setData(d); setTab('Dashboard'); refreshHistory() }
  const openOne = async (id) => { setData(await getAnalysis(id)); setTab('Dashboard') }
  const removeOne = async (id) => { await deleteAnalysis(id); if (data?.id === id) setData(null); refreshHistory() }

  const ready = !!data
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-800 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-lg font-bold text-sky-400">SOC-IA</span>
          <span className="text-slate-500 text-sm">Analyzer</span>
        </div>
        {data && <div className="text-xs text-slate-500">{data.filename} · {data.event_count} eventos · perfil {data.profile}</div>}
      </header>

      <nav className="px-6 pt-4 flex gap-1 flex-wrap">
        {TABS.map((t) => {
          const locked = t !== 'Cargar' && t !== 'Historial' && !ready
          return (
            <button key={t} disabled={locked} onClick={() => setTab(t)}
              className={`px-4 py-1.5 rounded text-sm ${tab === t ? 'bg-slate-700 text-white' : 'text-slate-400 hover:text-slate-200'} ${locked ? 'opacity-30 cursor-not-allowed' : ''}`}>
              {t}
            </button>
          )
        })}
      </nav>

      <main className="p-6">
        {tab === 'Cargar' && <UploadForm onAnalyzed={onAnalyzed} />}
        {tab === 'Dashboard' && <Dashboard data={data} />}
        {tab === 'Incidentes' && <IncidentList data={data} />}
        {tab === 'Informes' && <ReportView data={data} />}
        {tab === 'Seguridad' && <SecurityLog data={data} />}
        {tab === 'Historial' && <HistoryList items={history} onOpen={openOne} onDelete={removeOne} />}
      </main>
    </div>
  )
}
