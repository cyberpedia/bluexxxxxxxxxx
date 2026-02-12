# Cerberus - Modular Security Platform

## Backend features (Phase 3)

- JWT auth with access + refresh cookies (`HttpOnly`, `SameSite=Strict`, configurable `Secure`).
- User registration/login/logout, refresh, global logout.
- Email verification toggle.
- MFA with TOTP + backup codes.
- Password policy enforcement.
- Account states: active/suspended/banned/shadow.
- RBAC capability checks.
- API key lifecycle management.
- IP blacklist/whitelist enforcement.
- Rate limiting middleware.
- Team management with captain/co-captain roles, invite approval, max size, roster lock.
- Identity/team audit logging.

## Run backend

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
cp backend/.env.example backend/.env
uvicorn app.main:app --app-dir backend --reload
```

## Tests

```bash
PYTHONPATH=backend pytest -q backend/tests
```
