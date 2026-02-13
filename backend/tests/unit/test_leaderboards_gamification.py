from fastapi.testclient import TestClient

from app.main import app
from app.services.store import store


client = TestClient(app)


def reset_store() -> None:
    store.users.clear()
    store.user_by_email.clear()
    store.user_by_username.clear()
    store.sessions.clear()
    store.teams.clear()
    store.api_keys.clear()
    store.audit_logs.clear()
    store.ip_blacklist.clear()
    store.ip_whitelist.clear()
    store.rate_limit.clear()
    store.challenges.clear()
    store.hints.clear()
    store.solves.clear()
    store.score_adjustments.clear()
    store.hidden_teams.clear()
    store.leaderboard_frozen = False


def reg_verify_login(email: str, username: str):
    reg = client.post('/api/v1/auth/register', json={'email': email, 'username': username, 'password': 'StrongPass!123'})
    code = reg.json()['verification_code']
    client.post('/api/v1/auth/verify-email', json={'email': email, 'code': code})
    return client.post('/api/v1/auth/login', json={'email': email, 'password': 'StrongPass!123'})


def test_multi_mode_leaderboards_and_adjustments_exports() -> None:
    reset_store()
    reg_verify_login('admin@example.com', 'admin')
    admin = store.find_user_by_email('admin@example.com')
    assert admin
    admin.capabilities.update({'challenge:write', 'leaderboard:admin', 'challenge:score:admin'})

    c = client.post('/api/v1/challenges', json={
        'title': 'Forensics', 'description': 'desc', 'category': 'forensics', 'lifecycle': 'published',
        'scoring_mode': 'static', 'base_points': 300, 'min_points': 100, 'first_blood_bonus': 0,
    })
    cid = c.json()['challenge_id']
    client.post(f'/api/v1/challenges/{cid}/flags', json={'mode': 'exact', 'value': 'flag{1}'})

    solve = client.post(f'/api/v1/challenges/{cid}/submit', json={'submitted_flag': 'flag{1}'})
    assert solve.status_code == 200

    ind = client.get('/api/v1/leaderboards/individual')
    cat = client.get('/api/v1/leaderboards/categories')
    org = client.get('/api/v1/leaderboards/orgs')
    assert ind.status_code == 200 and cat.status_code == 200 and org.status_code == 200

    freeze = client.post('/api/v1/leaderboards/freeze')
    assert freeze.status_code == 200
    frozen = client.get('/api/v1/leaderboards/individual')
    assert frozen.json()['items'][0]['score'] == 'frozen'

    unfreeze = client.post('/api/v1/leaderboards/unfreeze')
    assert unfreeze.status_code == 200

    adj = client.post('/api/v1/leaderboards/adjust', json={'target_type': 'user', 'target_id': admin.id, 'delta': 25, 'reason': 'bonus'})
    assert adj.status_code == 200

    export_csv = client.get('/api/v1/leaderboards/export/csv?mode=individual')
    assert export_csv.status_code == 200
    verify = client.post('/api/v1/leaderboards/integrity/verify', json=export_csv.json())
    assert verify.json()['valid'] is True


def test_gamification_and_ws_feed() -> None:
    reset_store()
    reg_verify_login('player@example.com', 'player')
    user = store.find_user_by_email('player@example.com')
    assert user
    user.capabilities.update({'challenge:write'})

    c = client.post('/api/v1/challenges', json={
        'title': 'Web', 'description': 'desc', 'category': 'web', 'lifecycle': 'published',
        'scoring_mode': 'first_blood', 'base_points': 200, 'min_points': 100, 'first_blood_bonus': 50,
    })
    cid = c.json()['challenge_id']
    client.post(f'/api/v1/challenges/{cid}/flags', json={'mode': 'exact', 'value': 'flag{ws}'})

    solve = client.post(f'/api/v1/challenges/{cid}/submit', json={'submitted_flag': 'flag{ws}'})
    assert solve.status_code == 200

    dashboard = client.get('/api/v1/spectator/dashboard')
    assert dashboard.status_code == 200
    assert len(dashboard.json()['live_solves']) >= 1

    me = client.get('/api/v1/gamification/me')
    assert me.status_code == 200
    assert me.json()['xp'] > 0

    overlay = client.get('/api/v1/spectator/overlay')
    assert overlay.status_code == 200
    assert 'top' in overlay.json()


def test_risk_dashboard_and_flagging() -> None:
    reset_store()
    reg_verify_login('riskadmin@example.com', 'riskadmin')
    admin = store.find_user_by_email('riskadmin@example.com')
    assert admin
    admin.capabilities.update({'challenge:write', 'risk:read', 'risk:write'})

    c = client.post('/api/v1/challenges', json={
        'title': 'Risk', 'description': 'desc', 'category': 'misc', 'lifecycle': 'published',
        'scoring_mode': 'static', 'base_points': 100, 'min_points': 50, 'first_blood_bonus': 0,
    })
    cid = c.json()['challenge_id']
    client.post(f'/api/v1/challenges/{cid}/flags', json={'mode': 'exact', 'value': 'flag{risk}'})
    for _ in range(14):
        client.post(f'/api/v1/challenges/{cid}/submit', json={'submitted_flag': 'wrong'})

    dash = client.get('/api/v1/risk/dashboard')
    assert dash.status_code == 200
    assert 'top_users' in dash.json()

    flag = client.post(f"/api/v1/risk/flag/{admin.id}")
    assert flag.status_code == 200

    report = client.get('/api/v1/risk/reports/suspicious')
    assert report.status_code == 200
    assert 'flagged_users' in report.json()
