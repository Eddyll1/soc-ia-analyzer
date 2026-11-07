import axios from 'axios'

const baseURL = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const api = axios.create({ baseURL })

export const uploadFile = (file, profile) => {
  const fd = new FormData()
  fd.append('file', file)
  fd.append('profile', profile)
  return api.post('/api/upload', fd).then((r) => r.data)
}

export const analyze = (analysisId, profile) => {
  const fd = new FormData()
  fd.append('analysis_id', analysisId)
  fd.append('profile', profile)
  return api.post('/api/analyze', fd).then((r) => r.data)
}

export const listAnalyses = () => api.get('/api/analyses').then((r) => r.data)
export const getAnalysis = (id) => api.get(`/api/analysis/${id}`).then((r) => r.data)
export const getEvents = (id) => api.get(`/api/analysis/${id}/events`).then((r) => r.data)
export const deleteAnalysis = (id) => api.delete(`/api/analysis/${id}`).then((r) => r.data)
