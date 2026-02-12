import { useEffect, useState } from 'react'

import { addChallengeFlag, createChallenge, listChallenges } from '../services/challengesApi'

const initial = {
  title: '',
  description: '',
  category: 'web',
  lifecycle: 'draft',
  scoring_mode: 'static',
  base_points: 500,
  min_points: 100,
  first_blood_bonus: 50
}

export function ChallengeAdmin() {
  const [items, setItems] = useState([])
  const [form, setForm] = useState(initial)
  const [flagValue, setFlagValue] = useState('')
  const [selected, setSelected] = useState('')

  const refresh = async () => {
    try {
      setItems(await listChallenges())
    } catch {
      setItems([])
    }
  }

  useEffect(() => {
    refresh()
  }, [])

  const onCreate = async (e) => {
    e.preventDefault()
    const res = await createChallenge(form)
    setSelected(res.challenge_id)
    setForm(initial)
    await refresh()
  }

  const onAddFlag = async (e) => {
    e.preventDefault()
    if (!selected) return
    await addChallengeFlag(selected, { mode: 'exact', value: flagValue })
    setFlagValue('')
  }

  return (
    <section className="grid gap-6 lg:grid-cols-2">
      <form onSubmit={onCreate} className="space-y-3 rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-lg font-semibold">Create Challenge</h2>
        <input className="w-full rounded bg-slate-800 p-2" placeholder="Title" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} required />
        <textarea className="w-full rounded bg-slate-800 p-2" placeholder="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} required />
        <div className="grid grid-cols-2 gap-2">
          <input className="rounded bg-slate-800 p-2" placeholder="Category" value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} />
          <select className="rounded bg-slate-800 p-2" value={form.lifecycle} onChange={(e) => setForm({ ...form, lifecycle: e.target.value })}>
            <option>draft</option><option>review</option><option>approved</option><option>published</option><option>archived</option>
          </select>
        </div>
        <button className="rounded bg-brand-600 px-4 py-2">Create</button>
      </form>

      <div className="space-y-3 rounded-lg border border-slate-800 bg-slate-900 p-4">
        <h2 className="text-lg font-semibold">Challenges</h2>
        <select className="w-full rounded bg-slate-800 p-2" value={selected} onChange={(e) => setSelected(e.target.value)}>
          <option value="">Select challenge</option>
          {items.map((c) => (
            <option key={c.id} value={c.id}>{c.title} ({c.lifecycle})</option>
          ))}
        </select>
        <form onSubmit={onAddFlag} className="space-y-2">
          <input className="w-full rounded bg-slate-800 p-2" placeholder="Flag value" value={flagValue} onChange={(e) => setFlagValue(e.target.value)} />
          <button className="rounded bg-slate-700 px-3 py-2">Add Exact Flag</button>
        </form>
        <ul className="space-y-1 text-sm text-slate-300">
          {items.map((c) => (
            <li key={c.id}>• {c.title} — {c.scoring_mode}</li>
          ))}
        </ul>
      </div>
    </section>
  )
}
