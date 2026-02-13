from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json


@dataclass
class ScoreAdjustment:
    id: str
    target_type: str  # user|team|org
    target_id: str
    delta: int
    reason: str
    admin_user_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _sorted_board(rows: list[dict]) -> list[dict]:
    rows = sorted(rows, key=lambda r: (-r['score'], r['name']))
    for i, row in enumerate(rows, start=1):
        row['rank'] = i
    return rows


def build_individual_board(store) -> list[dict]:
    score_by_user: dict[str, int] = defaultdict(int)
    for solve in store.solves.values():
        if solve.revoked:
            continue
        score_by_user[solve.user_id] += solve.awarded_points

    for adj in store.score_adjustments.values():
        if adj.target_type == 'user':
            score_by_user[adj.target_id] += adj.delta

    rows = []
    for uid, score in score_by_user.items():
        user = store.users.get(uid)
        if not user:
            continue
        rows.append({'id': uid, 'name': user.username, 'score': score})
    return _sorted_board(rows)


def build_team_board(store) -> list[dict]:
    individual = {r['id']: r['score'] for r in build_individual_board(store)}
    rows = []
    for team in store.teams.values():
        if team.id in store.hidden_teams:
            continue
        score = sum(individual.get(uid, 0) for uid in team.members.keys())
        for adj in store.score_adjustments.values():
            if adj.target_type == 'team' and adj.target_id == team.id:
                score += adj.delta
        rows.append({'id': team.id, 'name': team.name, 'score': score, 'member_count': len(team.members)})
    return _sorted_board(rows)


def build_category_board(store) -> list[dict]:
    category_scores: dict[str, int] = defaultdict(int)
    challenge_by_id = store.challenges
    for solve in store.solves.values():
        if solve.revoked:
            continue
        challenge = challenge_by_id.get(solve.challenge_id)
        if not challenge:
            continue
        category_scores[challenge.category] += solve.awarded_points

    rows = [{'id': c, 'name': c, 'score': s} for c, s in category_scores.items()]
    return _sorted_board(rows)


def build_org_board(store) -> list[dict]:
    org_scores: dict[str, int] = defaultdict(int)
    for solve in store.solves.values():
        if solve.revoked:
            continue
        user = store.users.get(solve.user_id)
        if not user:
            continue
        org = user.email.split('@')[-1]
        org_scores[org] += solve.awarded_points
    for adj in store.score_adjustments.values():
        if adj.target_type == 'org':
            org_scores[adj.target_id] += adj.delta
    rows = [{'id': o, 'name': o, 'score': s} for o, s in org_scores.items()]
    return _sorted_board(rows)


def maybe_freeze(board: list[dict], store) -> list[dict]:
    if not store.leaderboard_frozen:
        return board
    return [dict(row, score='frozen') for row in board]


def export_csv_signed(rows: list[dict], secret: str) -> tuple[str, str]:
    if not rows:
        csv = 'rank,name,score\n'
    else:
        csv = 'rank,name,score\n' + '\n'.join(f"{r.get('rank','')},{r['name']},{r['score']}" for r in rows)
    sig = hmac.new(secret.encode('utf-8'), csv.encode('utf-8'), hashlib.sha256).hexdigest()
    return csv, sig


def export_pdf_signed(rows: list[dict], secret: str) -> tuple[str, str]:
    # Minimal text-based pseudo-pdf payload for prototype mode.
    payload = {'title': 'Cerberus Leaderboard', 'generated_at': datetime.now(timezone.utc).isoformat(), 'rows': rows}
    text = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    sig = hmac.new(secret.encode('utf-8'), text.encode('utf-8'), hashlib.sha256).hexdigest()
    return text, sig


def verify_integrity(payload: str, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def score_progression(store, user_id: str) -> list[dict]:
    running = 0
    events = []
    solves = sorted(
        [s for s in store.solves.values() if s.user_id == user_id and not s.revoked],
        key=lambda s: s.solved_at,
    )
    for solve in solves:
        running += solve.awarded_points
        events.append({'ts': solve.solved_at.isoformat(), 'score': running})
    return events


def solve_velocity(store) -> list[dict]:
    buckets: dict[str, int] = defaultdict(int)
    for solve in store.solves.values():
        if solve.revoked:
            continue
        key = solve.solved_at.strftime('%Y-%m-%d %H:%M')
        buckets[key] += 1
    return [{'bucket': k, 'count': buckets[k]} for k in sorted(buckets.keys())]


def category_dominance(store) -> list[dict]:
    cat = build_category_board(store)
    total = sum(r['score'] for r in cat) or 1
    return [{'category': r['name'], 'score': r['score'], 'pct': round(r['score'] * 100 / total, 2)} for r in cat]
