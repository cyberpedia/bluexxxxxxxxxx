import { useEffect, useState } from 'react'

import { exportSuspiciousReport, flagUser, getRiskDashboard } from '../services/riskApi'

export function RiskDashboard() {
  const [data, setData] = useState({ top_users: [], top_teams: [], ip_clusters: [] })
  const [reportPreview, setReportPreview] = useState('')

  const load = async () => {
    try {
      setData(await getRiskDashboard())
    } catch {
      setData({ top_users: [], top_teams: [], ip_clusters: [] })
    }
  }

  useEffect(() => {
    load()
  }, [])

  const onFlag = async (userId) => {
    await flagUser(userId)
    await load()
  }

  const onExport = async () => {
    const report = await exportSuspiciousReport()
    setReportPreview(JSON.stringify(report, null, 2).slice(0, 1200))
  }

  return (
    <section className="space-y-6">
      <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-xl font-semibold">Risk Admin Dashboard</h2>
          <button onClick={onExport} className="rounded bg-brand-600 px-3 py-2">Export Suspicious Report</button>
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          <div>
            <h3 className="mb-2 font-medium">Top User Risk</h3>
            <ul className="space-y-2 text-sm">
              {data.top_users.map((u) => (
                <li key={u.user_id} className="rounded border border-slate-800 p-2">
                  <div className="flex items-center justify-between">
                    <span>{u.user_id}</span>
                    <span className="font-semibold text-amber-400">{u.risk_score}</span>
                  </div>
                  <button onClick={() => onFlag(u.user_id)} className="mt-1 rounded bg-slate-800 px-2 py-1 text-xs">Flag for review</button>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="mb-2 font-medium">IP Clusters</h3>
            <ul className="space-y-2 text-sm">
              {data.ip_clusters.map((c) => (
                <li key={c.ip} className="rounded border border-slate-800 p-2">
                  <div>{c.ip}</div>
                  <div className="text-slate-400">users: {c.user_count}</div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {reportPreview ? (
        <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900 p-4 text-xs text-slate-300">{reportPreview}</pre>
      ) : null}
    </section>
  )
}
