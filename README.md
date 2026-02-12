# Cerberus - Modular Security Platform
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

