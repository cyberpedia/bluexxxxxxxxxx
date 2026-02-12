# Cerberus - Modular Security Platform

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
```

## Backend quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
cp backend/.env.example backend/.env
uvicorn app.main:app --app-dir backend --reload
```

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
