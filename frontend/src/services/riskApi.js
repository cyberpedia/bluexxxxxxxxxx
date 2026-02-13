import { apiClient } from './apiClient'

export async function getRiskDashboard() {
  const { data } = await apiClient.get('/risk/dashboard')
  return data
}

export async function exportSuspiciousReport() {
  const { data } = await apiClient.get('/risk/reports/suspicious')
  return data
}

export async function flagUser(userId) {
  const { data } = await apiClient.post(`/risk/flag/${userId}`)
  return data
}
