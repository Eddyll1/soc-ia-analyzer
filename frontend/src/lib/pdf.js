import { jsPDF } from 'jspdf'
import { marked } from 'marked'

// Exporta un Markdown a PDF renderizándolo como HTML. Descarga solo el informe pedido.
export async function exportMarkdownToPdf(markdown, filename) {
  const doc = new jsPDF({ unit: 'pt', format: 'a4' })
  const container = document.createElement('div')
  container.style.width = '520px'
  container.style.padding = '8px'
  container.style.fontFamily = 'Helvetica, Arial, sans-serif'
  container.style.fontSize = '12px'
  container.style.color = '#111'
  container.innerHTML = marked.parse(markdown || '_Sin contenido_')
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
