import axios from 'axios'
export const api = axios.create({ baseURL: 'http://127.0.0.1:5000/api', timeout: 10000 })
export const downloadFile = async (kind) => {
  const response = await api.get(`/export/${kind}`, { responseType: 'blob' })
  const url = URL.createObjectURL(response.data)
  const a = document.createElement('a'); a.href = url
  a.download = kind === 'csv' ? 'netwatch_packets.csv' : 'netwatch_report.pdf'
  a.click(); URL.revokeObjectURL(url)
}
