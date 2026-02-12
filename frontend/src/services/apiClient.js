import axios from 'axios'

const baseURL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1'
const timeoutMs = Number(import.meta.env.VITE_API_TIMEOUT_MS || '10000')

export const apiClient = axios.create({
  baseURL,
  timeout: timeoutMs,
  headers: {
    'Content-Type': 'application/json'
  }
})
