import { useState } from 'react'

/**
 * Acciones de respuesta (playbook) SIMULADAS. No ejecutan nada real: muestran
 * la llamada que se enviaría a un EDR/Firewall/AD. La integración real
 * (CrowdStrike, firewall, Active Directory, SOAR) es alcance futuro — ver README.
 */
export default function PlaybookActions({ affected }) {
  const [log, setLog] = useState([])
  if (!affected) return null

  const hosts = affected.hosts || []
  const users = affected.users || []
  const ips = [...(affected.external_ips || []), ...(affected.exfil_dest || [])]

  const run = (label, detail) =>
    setLog((l) => [{ label, detail, ts: new Date().toLocaleTimeString() }, ...l].slice(0, 6))

  const Btn = ({ onClick, children, disabled }) => (
    <button onClick={onClick} disabled={disabled}
      className="px-3 py-1.5 rounded text-xs font-medium bg-slate-800 hover:bg-slate-700 border border-slate-600 disabled:opacity-30">
      {children}
    </button>
  )

  return (
    <div className="mt-2">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-xs text-slate-400">Respuesta (playbook)</span>
        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-900/40 text-amber-300 border border-amber-800">
          SIMULADO · DEMO
        </span>
      </div>
      <div className="flex flex-wrap gap-2">
        <Btn disabled={!hosts.length}
          onClick={() => run('Aislar hosts (EDR)',
            `POST crowdstrike/devices/actions/contain → ${hosts.join(', ')}`)}>
          🛡️ Aislar {hosts.length} host(s)
        </Btn>
        <Btn disabled={!users.length}
          onClick={() => run('Resetear credenciales (AD)',
            `Disable-ADAccount + reset → ${users.join(', ')}`)}>
          🔑 Resetear {users.length} cuenta(s)
        </Btn>
        <Btn disabled={!ips.length}
          onClick={() => run('Bloquear IPs (Firewall)',
            `firewall deny src/dst → ${ips.join(', ')}`)}>
          ⛔ Bloquear {ips.length} IP(s)
        </Btn>
      </div>
      {log.length > 0 && (
        <div className="mt-2 space-y-1">
          {log.map((e, i) => (
            <div key={i} className="text-[11px] font-mono bg-slate-950/60 border border-slate-800 rounded px-2 py-1">
              <span className="text-emerald-400">[{e.ts}] {e.label}:</span>{' '}
              <span className="text-slate-400">{e.detail}</span>{' '}
              <span className="text-amber-400">(no ejecutado — demo)</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
