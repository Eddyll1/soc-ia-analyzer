import { jsPDF } from 'jspdf'
import { marked } from 'marked'

// Exporta un Markdown a PDF renderizándolo como HTML. Descarga solo el informe pedido.
export async function exportMarkdownToPdf(markdown, filename) {
  const doc = new jsPDF({ unit: 'pt', format: 'a4' })
  const container = document.createElement('div')
  container.className = 'report-body'      // hereda la paleta corporativa
  container.style.width = '520px'
  container.style.padding = '12px'
  container.style.fontSize = '12px'
  container.style.background = '#ffffff'
  // quita los marcadores de gráfico (van en la vista web, no en el PDF de texto)
  const clean = (markdown || '_Sin contenido_').replace(/\[GRAFICO:[^\]]+\]/g, '')
  container.innerHTML = marked.parse(clean)
  document.body.appendChild(container)
  try {
    await doc.html(container, {
      callback: (d) => d.save(filename),
      margin: [36, 36, 36, 36],
      autoPaging: 'text',
      html2canvas: { scale: 0.75, backgroundColor: '#ffffff' },
    })
  } finally {
    document.body.removeChild(container)
  }
}
