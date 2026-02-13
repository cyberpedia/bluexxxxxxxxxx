import { useState } from 'react'

import { AppLayout } from './layouts/AppLayout'
import { ChallengeAdmin } from './pages/ChallengeAdmin'
import { LeaderboardDashboard } from './pages/LeaderboardDashboard'
import { ThemeProvider } from './providers/ThemeProvider'
import { RiskDashboard } from './pages/RiskDashboard'

function App() {
  const [tab, setTab] = useState('leaderboard')

  return (
    <ThemeProvider>
      <AppLayout>
        <div className="mb-4 flex gap-2">
          <button onClick={() => setTab('leaderboard')} className="rounded bg-slate-800 px-3 py-2">Leaderboards</button>
          <button onClick={() => setTab('challenges')} className="rounded bg-slate-800 px-3 py-2">Challenges</button>
          <button onClick={() => setTab('risk')} className="rounded bg-slate-800 px-3 py-2">Risk</button>
        </div>
        {tab === 'leaderboard' ? <LeaderboardDashboard /> : tab === 'risk' ? <RiskDashboard /> : <ChallengeAdmin />}
      </AppLayout>
    </ThemeProvider>
  )
}

export default App
