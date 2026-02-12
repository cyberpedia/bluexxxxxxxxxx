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


def register_and_verify(email: str, username: str, password: str):
    reg = client.post('/api/v1/auth/register', json={'email': email, 'username': username, 'password': password})
    assert reg.status_code == 200
    code = reg.json()['verification_code']
    verify = client.post('/api/v1/auth/verify-email', json={'email': email, 'code': code})
    assert verify.status_code == 200


def login(email: str, password: str):
    return client.post('/api/v1/auth/login', json={'email': email, 'password': password})


def test_auth_and_session_and_global_logout() -> None:
    reset_store()
    register_and_verify('captain@example.com', 'captain', 'StrongPass!123')
    res = login('captain@example.com', 'StrongPass!123')
    assert res.status_code == 200

    logout_all = client.post('/api/v1/auth/logout-all')
    assert logout_all.status_code == 200

    refresh = client.post('/api/v1/auth/refresh')
    assert refresh.status_code == 401


def test_rbac_and_ip_blacklist() -> None:
    reset_store()
    register_and_verify('admin@example.com', 'admin', 'StrongPass!123')
    login('admin@example.com', 'StrongPass!123')
    admin = store.find_user_by_email('admin@example.com')
    assert admin
    admin.capabilities.update({'security:ip:blacklist', 'security:ip:whitelist', 'user:state:update'})

    banned = client.post('/api/v1/security/ip/blacklist/testclient')
    assert banned.status_code == 200

    denied = client.get('/api/v1/status')
    assert denied.status_code == 403


def test_team_management_constraints_and_audit() -> None:
    reset_store()
    register_and_verify('captain@example.com', 'captain', 'StrongPass!123')
    register_and_verify('member1@example.com', 'member1', 'StrongPass!123')

    login('captain@example.com', 'StrongPass!123')
    captain = store.find_user_by_email('captain@example.com')
    member = store.find_user_by_email('member1@example.com')
    assert captain and member

    created = client.post('/api/v1/teams', json={'event_id': 'evt-1', 'name': 'BlueTeam', 'invite_approval': True})
    assert created.status_code == 200
    team_id = created.json()['team_id']

    add = client.post(f'/api/v1/teams/{team_id}/members', json={'user_id': member.id, 'role': 'member'})
    assert add.status_code == 200

    lock = client.post(f'/api/v1/teams/{team_id}/lock')
    assert lock.status_code == 200

    fail_after_lock = client.post(f'/api/v1/teams/{team_id}/members', json={'user_id': 'user-x', 'role': 'member'})
    assert fail_after_lock.status_code == 403

    logs = client.get(f'/api/v1/team-audit/{team_id}')
    assert logs.status_code == 200
    actions = [entry['action'] for entry in logs.json()['logs']]
    assert 'team.created' in actions
    assert 'team.member_added' in actions
    assert 'team.roster_locked' in actions
