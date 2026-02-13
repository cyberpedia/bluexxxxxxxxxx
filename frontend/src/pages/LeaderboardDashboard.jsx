import { useEffect, useMemo, useState } from 'react'

import { connectSpectatorWs, getLeaderboard, getSpectatorDashboard } from '../services/leaderboardApi'

export function LeaderboardDashboard() {
  const [mode, setMode] = useState('individual')
  const [board, setBoard] = useState([])
  const [frozen, setFrozen] = useState(false)
  const [feed, setFeed] = useState([])

  useEffect(() => {
    let ws
    const load = async () => {
      const lb = await getLeaderboard(mode)
      setBoard(lb.items || [])
      setFrozen(Boolean(lb.frozen))

      const spec = await getSpectatorDashboard()
      setFeed(spec.live_solves || [])

      ws = connectSpectatorWs((ev) => {
        if (ev.type === 'solve' || ev.type === 'first_blood') {
          setFeed((prev) => [ev, ...prev].slice(0, 20))
        }
      })
    }
    load()
    return () => ws?.close()
  }, [mode])

  const title = useMemo(() => `${mode[0].toUpperCase()}${mode.slice(1)} Leaderboard`, [mode])

  return (
    <section className="space-y-6">
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-xl font-semibold">{title}</h2>
          <div className="flex items-center gap-2">
            <select value={mode} onChange={(e) => setMode(e.target.value)} className="rounded bg-slate-800 p-2">
              <option value="individual">Individual</option>
              <option value="teams">Teams</option>
              <option value="categories">Categories</option>
              <option value="orgs">Orgs</option>
            </select>
            {frozen ? <span className="rounded bg-amber-600 px-2 py-1 text-xs">Frozen</span> : null}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-slate-300">
                <th className="py-2">#</th>
                <th>Name</th>
                <th className="text-right">Score</th>
              </tr>
            </thead>
            <tbody>
              {board.map((row) => (
                <tr key={row.id} className="border-t border-slate-800">
                  <td className="py-2">{row.rank}</td>
                  <td>{row.name}</td>
                  <td className="text-right">{row.score}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h3 className="mb-2 text-lg font-semibold">Spectator Live Feed (OBS/Big Screen)</h3>
        <div className="max-h-80 space-y-2 overflow-y-auto text-sm">
          {feed.map((ev, idx) => (
            <div key={`${ev.ts}-${idx}`} className="rounded border border-slate-800 bg-slate-950 p-2">
              <span className="font-medium">{ev.type === 'first_blood' ? '🥇 First Blood' : '✅ Solve'}</span>
              <span className="ml-2 text-slate-300">challenge={ev.challenge_id} user={ev.user_id}</span>
              {ev.points ? <span className="ml-2 text-brand-500">+{ev.points}</span> : null}
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
