import { apiClient } from './apiClient'

export async function listChallenges() {
  const { data } = await apiClient.get('/challenges')
  return data.items || []
}

export async function createChallenge(payload) {
  const { data } = await apiClient.post('/challenges', payload)
  return data
}

export async function addChallengeFlag(challengeId, payload) {
  const { data } = await apiClient.post(`/challenges/${challengeId}/flags`, payload)
  return data
}
