import axios from 'axios'

export function getDictList(params?: any) {
  return axios.get('/api/dict/list', { params })
}

export function syncDicts() {
  return axios.post('/api/dict/sync')
}

export function viewDict(id: number) {
  return axios.get('/api/dict/view', { params: { id } })
}

export function downloadDict(id: number) {
  return axios.get('/api/dict/download', {
    params: { id },
    responseType: 'blob', // Important for downloading small/mid files
  })
}

export function deleteDict(id: number) {
  return axios.delete(`/api/dict/delete/${id}`)
}
