import { marked } from 'marked'

// CSS de impresión: misma paleta corporativa del informe web, con tablas y
// bloques de código que no se desbordan ni se parten mal entre páginas.
const PRINT_CSS = `
  @page { size: A4; margin: 16mm 14mm; }
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: #fff; }
  body { color: #334155; font-family: "Segoe UI", Helvetica, Arial, sans-serif; font-size: 11pt; line-height: 1.5; }
  h1 { font-size: 20pt; font-weight: 700; color: #0F172A; margin: 0 0 .5rem;
       border-bottom: 3px solid #1E3A8A; padding-bottom: .3rem; }
  h2 { font-size: 14pt; font-weight: 700; color: #1E3A8A; margin: 1.1rem 0 .4rem;
       border-bottom: 1px solid #e2e8f0; padding-bottom: .2rem; break-after: avoid; }
  h3 { font-size: 12pt; font-weight: 600; color: #334155; margin: .8rem 0 .3rem; break-after: avoid; }
  p { margin: .4rem 0; }
  ul, ol { margin: .4rem 0; padding-left: 1.3rem; }
  li { margin: .2rem 0; }
  strong { color: #1E3A8A; }
  hr { border: none; border-top: 2px solid #e2e8f0; margin: .8rem 0; }
  code { background: #f1f5f9; color: #0284C7; padding: .08rem .3rem; border-radius: 3px;
         font-family: "Consolas", monospace; font-size: .85em; word-break: break-word; }
  pre { background: #0F172A; color: #e2e8f0; padding: .6rem .8rem; border-radius: 6px;
        margin: .5rem 0; white-space: pre-wrap; word-break: break-word; break-inside: avoid; }
  pre code { background: transparent; color: #e2e8f0; padding: 0; font-size: .82em; }
  table { border-collapse: collapse; margin: .6rem 0; width: 100%; font-size: .82em;
          table-layout: fixed; break-inside: auto; }
  thead { display: table-header-group; }
  tr { break-inside: avoid; }
  th, td { border: 1px solid #cbd5e1; padding: .3rem .5rem; text-align: left;
           vertical-align: top; word-break: break-word; overflow-wrap: anywhere; }
  thead th { background: #1E3A8A !important; color: #fff !important; font-weight: 600; }
  tbody tr:nth-child(even) { background: #f8fafc !important; }
`

// Exporta un informe Markdown a PDF usando la impresión del navegador (Guardar como PDF).
// A diferencia de rasterizar con jsPDF, conserva texto nítido, tablas alineadas,
// colores de la paleta y evita los glifos ilegibles.
export async function exportMarkdownToPdf(markdown, filename) {
  // Los marcadores de gráfico son interactivos (van en la web); fuera del PDF de texto.
  const clean = (markdown || '_Sin contenido_').replace(/\[GRAFICO:[^\]]+\]/g, '')
  const html = marked.parse(clean)
  const title = (filename || 'informe').replace(/\.pdf$/i, '')

  const frame = document.createElement('iframe')
  frame.style.position = 'fixed'
  frame.style.right = '0'
  frame.style.bottom = '0'
  frame.style.width = '0'
  frame.style.height = '0'
  frame.style.border = '0'
  document.body.appendChild(frame)

  const doc = frame.contentWindow.document
  doc.open()
  doc.write(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>${title}</title><style>${PRINT_CSS}</style></head><body>${html}</body></html>`)
  doc.close()

  await new Promise((r) => setTimeout(r, 250)) // deja renderizar fuentes y tablas
  frame.contentWindow.focus()
  frame.contentWindow.print()
  // El navegador abre el diálogo de impresión → "Guardar como PDF".
  setTimeout(() => document.body.removeChild(frame), 1000)
}
