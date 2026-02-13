from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass
class RiskSignal:
    key: str
    score: int
    detail: str


def _recent(events: list[dict], minutes: int = 60) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    out = []
    for e in events:
        ts = e['ts']
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        if ts >= cutoff:
            out.append(e)
    return out


def user_risk(store, user_id: str) -> dict:
    events = [e for e in _recent(store.risk_events, 120) if e.get('user_id') == user_id]
    signals: list[RiskSignal] = []

    rapid_submits = [e for e in events if e['type'] == 'submission']
    if len(rapid_submits) >= 12:
        signals.append(RiskSignal('rapid_submissions', min(40, len(rapid_submits)), f'{len(rapid_submits)} in 2h'))

    hint_reads = [e for e in events if e['type'] == 'hint_view']
    if len(hint_reads) >= 15:
        signals.append(RiskSignal('hint_abuse', min(25, len(hint_reads)), f'{len(hint_reads)} hints viewed'))

    bursts = 0
    by_minute: dict[str, int] = defaultdict(int)
    for e in rapid_submits:
        by_minute[e['ts'].strftime('%Y-%m-%d %H:%M')] += 1
    for c in by_minute.values():
        if c >= 4:
            bursts += 1
    if bursts:
        signals.append(RiskSignal('burst_activity', min(20, bursts * 8), f'{bursts} high-burst windows'))

    ips = {e.get('ip') for e in events if e.get('ip')}
    if len(ips) >= 4:
        signals.append(RiskSignal('ip_hopping', min(20, len(ips) * 4), f'{len(ips)} IPs observed'))

    total = min(100, sum(s.score for s in signals))
    return {'user_id': user_id, 'risk_score': total, 'signals': [s.__dict__ for s in signals]}


def team_risk(store, team_id: str) -> dict:
    team = store.teams.get(team_id)
    if not team:
        return {'team_id': team_id, 'risk_score': 0, 'signals': []}
    risks = [user_risk(store, uid) for uid in team.members.keys()]
    total = int(sum(r['risk_score'] for r in risks) / max(1, len(risks)))
    signals = []

    # Solve timing correlation heuristic (same minute solves across team)
    team_solves = [s for s in store.solves.values() if s.user_id in team.members and not s.revoked]
    minute_buckets: dict[str, int] = defaultdict(int)
    for s in team_solves:
        minute_buckets[s.solved_at.strftime('%Y-%m-%d %H:%M')] += 1
    correlated = sum(1 for c in minute_buckets.values() if c >= 2)
    if correlated:
        signals.append({'key': 'solve_timing_correlation', 'score': min(20, correlated * 5), 'detail': f'{correlated} correlated windows'})
        total = min(100, total + min(20, correlated * 5))

    return {'team_id': team_id, 'risk_score': total, 'signals': signals, 'member_risks': risks}


def ip_cluster_findings(store) -> list[dict]:
    clusters: dict[str, set[str]] = defaultdict(set)
    for e in _recent(store.risk_events, 180):
        ip = e.get('ip')
        uid = e.get('user_id')
        if ip and uid:
            clusters[ip].add(uid)
    out = []
    for ip, users in clusters.items():
        if len(users) >= 3:
            out.append({'ip': ip, 'user_count': len(users), 'users': sorted(users)})
    return out


def suspicious_report(store) -> dict:
    users = [user_risk(store, uid) for uid in store.users.keys()]
    teams = [team_risk(store, tid) for tid in store.teams.keys()]
    flagged_users = [u for u in users if u['risk_score'] >= 60 or u['user_id'] in store.review_flags]
    flagged_teams = [t for t in teams if t['risk_score'] >= 60]
    return {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'flagged_users': flagged_users,
        'flagged_teams': flagged_teams,
        'ip_clusters': ip_cluster_findings(store),
    }
