import { useState } from 'react'
import { marked } from 'marked'
import { sevColor, sevBadge } from '../lib/format'

// Negrita de Markdown (**x**) → <strong> con color de acento, para las acciones.
const inline = (t) => ({
  __html: marked.parseInline(String(t || '')),
})

function Section({ title, children }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <div className="text-sm text-slate-300 mb-3">{title}</div>
      {children}
    </div>
  )
}

function QueryBlock({ q }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard?.writeText(q.code).then(() => {
      setCopied(true); setTimeout(() => setCopied(false), 1200)
    })
  }
  return (
    <div className="rounded border border-slate-800 overflow-hidden">
      <div className="flex items-center justify-between bg-slate-950/60 px-3 py-1.5">
        <span className="text-xs text-slate-300">{q.title}</span>
        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-wide text-sky-500 font-mono">{q.lang}</span>
          <button onClick={copy} className="text-[11px] px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300">
            {copied ? 'Copiado' : 'Copiar'}
          </button>
        </div>
      </div>
      <pre className="bg-[#0F172A] text-slate-200 text-xs p-3 overflow-x-auto m-0 font-mono whitespace-pre-wrap break-words">{q.code}</pre>
    </div>
  )
}

// Plan de acción técnico para el analista SOC: lo mismo del informe técnico,
// en la paleta del dashboard, para "mirar y ejecutar".
export default function ActionPlan({ data }) {
  const plan = data?.mitigation
  if (!plan) return null
  const { incidents = [], lessons = [], iocs = [], queries = [] } = plan

  return (
    <div className="space-y-4">
      <div>
        <div className="text-base font-semibold text-slate-200">Plan de acción del analista</div>
        <p className="text-xs text-slate-500">Contención, erradicación e IoCs derivados de las reglas que dispararon. Para mirar y ejecutar.</p>
      </div>

      <Section title="Acciones de contención por incidente">
        <div className="space-y-3">
          {incidents.map((inc) => (
            <div key={inc.id} className="border-l-2 pl-3" style={{ borderColor: sevColor(inc.risk) }}>
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-sky-400 text-sm">{inc.id}</span>
                <span className="px-2 py-0.5 rounded text-xs font-medium" style={sevBadge(inc.risk)}>{inc.risk}</span>
              </div>
              <ul className="space-y-1">
                {inc.actions.map((a, i) => (
                  <li key={i} className="flex gap-2 text-sm text-slate-300">
                    <span className="text-sky-500 shrink-0">▸</span>
                    <span dangerouslySetInnerHTML={inline(a)} />
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </Section>

      <div className="grid md:grid-cols-2 gap-4">
        <Section title="Indicadores de compromiso (IoCs)">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-slate-500 text-left">
                <th className="pb-1 font-normal">Tipo</th>
                <th className="pb-1 font-normal">Indicador</th>
                <th className="pb-1 font-normal text-right">Severidad</th>
              </tr>
            </thead>
            <tbody>
              {iocs.map((ioc, i) => (
                <tr key={i} className="border-t border-slate-800 align-top">
                  <td className="py-1.5 text-slate-400">{ioc.type}</td>
                  <td className="py-1.5 font-mono text-slate-200 break-all pr-2">{ioc.value}</td>
                  <td className="py-1.5 text-right whitespace-nowrap">
                    <span className="font-medium" style={{ color: sevColor(ioc.severity) }}>{ioc.severity}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>

        <Section title="Hardening y lecciones aprendidas">
          <ul className="space-y-1.5">
            {lessons.map((l, i) => (
              <li key={i} className="flex gap-2 text-sm text-slate-300">
                <span className="text-emerald-500 shrink-0">✓</span>
                <span dangerouslySetInnerHTML={inline(l)} />
              </li>
            ))}
          </ul>
        </Section>
      </div>

      {queries.length > 0 && (
        <Section title="Consultas de validación (SIEM / EDR / firewall)">
          <div className="space-y-2">
            {queries.map((q, i) => <QueryBlock key={i} q={q} />)}
          </div>
        </Section>
      )}
    </div>
  )
}
