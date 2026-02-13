# Cerberus - Modular Security Platform

## Backend features (Phase 6)
## Backend features (Phase 5)

- Secure auth and RBAC with JWT, sessions, MFA, API keys, rate limiting, and IP allow/deny.
- Team management with roster controls and audit logs.
- Challenge engine with lifecycle, scoring modes, flexible flag validators, unlock logic, hints, and solve controls.
- Leaderboards & gamification:
  - Multi-mode boards: individual, teams, categories, orgs
  - Freeze/unfreeze, manual score adjustments, hide/show teams
  - Signed CSV/PDF exports + integrity verification endpoint
  - Analytics: score progression, solve velocity, category dominance
  - Gamification profile: XP, badges, achievements, streaks, trophies
- Real-time spectator:
  - WebSocket live solve feed
  - First blood announcements
  - OBS/overlay endpoint and big-screen dashboard payload
- Anti-cheat & risk engine:
  - Detection: rapid submissions, IP-cluster solves, hint abuse, solve timing correlation, burst activity
  - User/team risk scoring, admin risk dashboard, account flagging for review
  - Suspicious activity report export

## Frontend features (Phase 5)

- Challenge Admin UI for challenge CRUD-lite and flag assignment.
- Leaderboard + spectator dashboard with multi-mode boards and live WebSocket feed.

## Run backend
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
# Cerberus - Phase 1 Project Skeleton

Cerberus is organized as a modular security platform with clear separation between backend services, frontend UI, and operational artifacts.

## Repository layout

```text
.
├── backend/
│   ├── alembic/
│   │   └── versions/
│   ├── app/
│   │   ├── api/
│   │   ├── audit/
│   │   ├── config/
│   │   ├── db/
│   │   ├── labs/
│   │   ├── models/
│   │   ├── monitoring/
│   │   ├── notifications/
│   │   ├── rbac/
│   │   ├── risk_engine/
│   │   ├── scoring/
│   │   ├── security/
│   │   └── services/
│   ├── tests/
│   ├── .env.example
│   ├── alembic.ini
│   └── requirements.txt
├── frontend/
├── docs/
├── scripts/
└── systemd/
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── layouts/
│   │   ├── pages/
│   │   ├── providers/
│   │   ├── services/
│   │   ├── styles/
│   │   └── utils/
│   ├── .env.example
│   ├── package.json
│   ├── postcss.config.js
│   ├── tailwind.config.js
│   └── vite.config.js
├── docs/
├── scripts/
├── .env.example
├── .flake8
├── .prettierrc
└── eslint.config.js
```

## Backend quick start

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
cp .env.example .env
npm run dev
npm run dev
## Database and migrations

```bash
cd backend
alembic upgrade head
```

## Tests

```bash
PYTHONPATH=backend pytest -q backend/tests
```

## Security defaults

- Secrets are env-driven (`.env.example` placeholders only).
- Password hashing uses bcrypt via Passlib.
- Flag checking uses constant-time comparison via `hmac.compare_digest`.
- Core sensitive entities include soft-delete columns and audit-oriented timestamps.
1. Create and activate a virtual environment.
2. Install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```
3. Copy environment template and set real secret values:
   ```bash
   cp backend/.env.example backend/.env
   ```
4. Run API:
   ```bash
   uvicorn app.main:app --app-dir backend --reload
   ```

## Frontend quick start

1. Install dependencies:
   ```bash
   cd frontend && npm install
   ```
2. Copy environment template:
   ```bash
   cp .env.example .env
   ```
3. Start development server:
   ```bash
   npm run dev
   ```

## Linting and formatting

- Python linting (Flake8 config in root):
  ```bash
  flake8 backend
  ```
- Frontend linting:
  ```bash
  npm run lint --prefix frontend
  ```
- Prettier formatting:
  ```bash
  npm run format --prefix frontend
  ```

## Security defaults

- No credentials or secrets are hardcoded in source files.
- `.env.example` templates are placeholders only and must be replaced per environment.
- Backend defaults to `DEBUG=false` and `ENVIRONMENT=production`.
- API client endpoint is configurable via `VITE_API_BASE_URL`.

