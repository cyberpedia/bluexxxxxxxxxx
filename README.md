# Cerberus - Modular Security Platform

## Backend features (Phase 6)

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
```

## Tests

```bash
PYTHONPATH=backend pytest -q backend/tests
```
