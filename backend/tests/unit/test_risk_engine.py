from datetime import datetime, timezone

from app.services.risk_engine import ip_cluster_findings, team_risk, user_risk
from app.services.store import InMemoryStore, TeamRecord, UserRecord


def _mk_user(uid: str, email: str):
    return UserRecord(id=uid, email=email, username=uid, password_hash='x')


def test_user_risk_rapid_submissions_and_hint_abuse() -> None:
    store = InMemoryStore()
    store.users['u1'] = _mk_user('u1', 'u1@example.com')
    for _ in range(13):
        store.risk_events.append({'type': 'submission', 'user_id': 'u1', 'ip': '1.1.1.1', 'details': {}, 'ts': datetime.now(timezone.utc)})
    for _ in range(16):
        store.risk_events.append({'type': 'hint_view', 'user_id': 'u1', 'ip': '1.1.1.1', 'details': {}, 'ts': datetime.now(timezone.utc)})

    r = user_risk(store, 'u1')
    assert r['risk_score'] > 0
    keys = {s['key'] for s in r['signals']}
    assert 'rapid_submissions' in keys
    assert 'hint_abuse' in keys


def test_team_risk_and_ip_cluster() -> None:
    store = InMemoryStore()
    store.users['u1'] = _mk_user('u1', 'u1@a.com')
    store.users['u2'] = _mk_user('u2', 'u2@a.com')
    store.users['u3'] = _mk_user('u3', 'u3@a.com')
    store.teams['t1'] = TeamRecord(id='t1', event_id='e', name='T1', captain_id='u1', members={'u1': 'captain', 'u2': 'member'})

    now = datetime.now(timezone.utc)
    for uid in ('u1', 'u2', 'u3'):
        store.risk_events.append({'type': 'submission', 'user_id': uid, 'ip': '9.9.9.9', 'details': {}, 'ts': now})

    clusters = ip_cluster_findings(store)
    assert clusters and clusters[0]['ip'] == '9.9.9.9'

    tr = team_risk(store, 't1')
    assert 'risk_score' in tr
