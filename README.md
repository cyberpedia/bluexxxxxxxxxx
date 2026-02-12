# Cerberus - Modular Security Platform

## Backend features (Phase 4)

- Secure auth: JWT access/refresh, email verification toggle, MFA (TOTP + backup), password policy.
- RBAC capability enforcement, session management, IP allow/deny, rate limiting, API keys.
- Team management: captain/co-captain roles, invite approval, roster lock, audit trail.
- Challenge engine:
  - Challenge CRUD + lifecycle (`draft/review/approved/published/archived`)
  - Scoring (`static/dynamic/progressive/first_blood/time_decay`)
  - Flags (`exact/regex/partial/file/api`) with rotation + expiration controls
  - Unlock logic (solve threshold, score threshold, time unlock, admin override)
  - Multi-part hooks (`parts`) and visibility scheduling
  - Hints with enable/disable, progressive release, auto-release, usage analytics
  - Solve controls (manual award, revoke, timestamp adjust, retroactive points)
  - Import/export + duplication
- Security and consistency:
  - Input constraints via Pydantic models
  - Atomic in-memory writes using lock guards for challenge mutations
  - Identity and challenge action audit logging

## Frontend features (Phase 4)

- Challenge CRUD admin page (create/list/add-flag) built with React + Tailwind.
- Axios API client integration for challenge endpoints.

## Run backend

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
cp backend/.env.example backend/.env
uvicorn app.main:app --app-dir backend --reload
```

## Run frontend

```bash
cd frontend
npm install
npm run dev
```

## Tests

```bash
PYTHONPATH=backend pytest -q backend/tests
```
