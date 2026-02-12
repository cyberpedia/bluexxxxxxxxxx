from fastapi import FastAPI

from app.api.router import api_router
from app.config.settings import settings


app = FastAPI(title=settings.app_name, debug=settings.debug)
app.include_router(api_router, prefix=settings.api_prefix)


@app.get('/healthz', tags=['health'])
def healthcheck() -> dict[str, str]:
    return {'status': 'ok'}
