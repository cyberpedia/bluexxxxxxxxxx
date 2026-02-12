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


def register_login_editor() -> str:
    reg = client.post('/api/v1/auth/register', json={'email': 'editor@example.com', 'username': 'editor', 'password': 'StrongPass!123'})
    code = reg.json()['verification_code']
    client.post('/api/v1/auth/verify-email', json={'email': 'editor@example.com', 'code': code})
    user = store.find_user_by_email('editor@example.com')
    assert user
    user.capabilities.update({'challenge:write', 'challenge:score:admin'})
    login = client.post('/api/v1/auth/login', json={'email': 'editor@example.com', 'password': 'StrongPass!123'})
    assert login.status_code == 200
    return user.id


def test_challenge_crud_and_submission_scoring() -> None:
    reset_store()
    register_login_editor()

    created = client.post(
        '/api/v1/challenges',
        json={
            'title': 'Crypto 101',
            'description': 'basic crypto',
            'category': 'crypto',
            'lifecycle': 'published',
            'scoring_mode': 'first_blood',
            'base_points': 400,
            'min_points': 100,
            'first_blood_bonus': 75,
        },
    )
    assert created.status_code == 200
    cid = created.json()['challenge_id']

    add_flag = client.post(f'/api/v1/challenges/{cid}/flags', json={'mode': 'exact', 'value': 'flag{one}'})
    assert add_flag.status_code == 200

    first_solve = client.post(f'/api/v1/challenges/{cid}/submit', json={'submitted_flag': 'flag{one}'})
    assert first_solve.status_code == 200
    assert first_solve.json()['points'] == 475

    second_try = client.post(f'/api/v1/challenges/{cid}/submit', json={'submitted_flag': 'flag{one}'})
    assert second_try.status_code == 200
    assert second_try.json()['already_solved'] is True

    analytics = client.get(f'/api/v1/challenges/{cid}/analytics')
    assert analytics.status_code == 200
    assert analytics.json()['solve_count'] == 1


def test_hint_release_and_solve_controls() -> None:
    reset_store()
    user_id = register_login_editor()

    created = client.post(
        '/api/v1/challenges',
        json={
            'title': 'Web 201',
            'description': 'web exploit',
            'category': 'web',
            'lifecycle': 'published',
            'scoring_mode': 'dynamic',
            'base_points': 500,
            'min_points': 250,
        },
    )
    cid = created.json()['challenge_id']

    client.post(f'/api/v1/challenges/{cid}/flags', json={'mode': 'partial', 'value': 'ctf'})
    h = client.post(
        f'/api/v1/challenges/{cid}/hints',
        json={'content': 'Look into headers', 'cost': 25, 'enabled': True, 'auto_after_solves': 1},
    )
    assert h.status_code == 200

    hint_before = client.get(f'/api/v1/challenges/{cid}/hints')
    assert hint_before.status_code == 200
    assert len(hint_before.json()['hints']) == 1  # editor can always view

    solve = client.post(f'/api/v1/challenges/{cid}/submit', json={'submitted_flag': 'xxctfxx'})
    assert solve.status_code == 200
    assert solve.json()['points'] == 500

    manual = client.post(f'/api/v1/challenges/{cid}/manual-award', json={'user_id': user_id, 'points': 900})
    assert manual.status_code == 200
    solve_id = manual.json()['solve_id']

    adj = client.post(
        f'/api/v1/challenges/{cid}/solve-controls',
        json={'solve_id': solve_id, 'revoke': True, 'retroactive_points': 300},
    )
    assert adj.status_code == 200


def test_import_export_duplicate() -> None:
    reset_store()
    register_login_editor()
    created = client.post(
        '/api/v1/challenges',
        json={
            'title': 'Pwn 1',
            'description': 'stack',
            'category': 'pwn',
            'lifecycle': 'draft',
            'scoring_mode': 'static',
            'base_points': 200,
            'min_points': 100,
            'first_blood_bonus': 0,
        },
    )
    cid = created.json()['challenge_id']
    client.post(f'/api/v1/challenges/{cid}/hints', json={'content': 'gdb', 'cost': 10})

    exported = client.get(f'/api/v1/challenges/{cid}/export')
    assert exported.status_code == 200

    imported = client.post('/api/v1/challenges/import', json=exported.json())
    assert imported.status_code == 200

    dup = client.post(f'/api/v1/challenges/{cid}/duplicate')
    assert dup.status_code == 200
