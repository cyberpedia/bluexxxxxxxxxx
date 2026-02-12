import { apiClient } from './apiClient'

export async function getLeaderboard(mode = 'individual') {
  const { data } = await apiClient.get(`/leaderboards/${mode}`)
  return data
}

export async function getSpectatorDashboard() {
  const { data } = await apiClient.get('/spectator/dashboard')
  return data
}

export function connectSpectatorWs(onEvent) {
  const base = import.meta.env.VITE_API_WS_BASE_URL || 'ws://localhost:8000/api/v1'
  const ws = new WebSocket(`${base}/ws/spectator`)
  ws.onmessage = (event) => {
    try {
      onEvent(JSON.parse(event.data))
    } catch {
      // ignore
    }
  }
  ws.onopen = () => ws.send('subscribe')
  return ws
}
