export const SEV_COLORS = {
  'Crítico': '#dc2626', 'Alto': '#ea580c', 'Medio': '#ca8a04', 'Bajo': '#16a34a',
  Critical: '#dc2626', High: '#ea580c', Medium: '#ca8a04', Low: '#16a34a',
}
export const sevColor = (s) => SEV_COLORS[s] || '#64748b'

export const sevBadge = (s) => {
  const c = sevColor(s)
  return { backgroundColor: c + '22', color: c, border: `1px solid ${c}55` }
}
