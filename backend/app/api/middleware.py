import time

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config.settings import settings
from app.security.jwt import decode_token
from app.services.store import store


class IPControlMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else 'unknown'
        if store.ip_whitelist and ip not in store.ip_whitelist:
            return JSONResponse(status_code=403, content={'detail': 'IP not whitelisted'})
        if ip in store.ip_blacklist:
            return JSONResponse(status_code=403, content={'detail': 'IP blacklisted'})
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else 'unknown'
        now = time.time()
        window = now - 60
        bucket = store.rate_limit.setdefault(ip, [])
        store.rate_limit[ip] = [ts for ts in bucket if ts >= window]
        if len(store.rate_limit[ip]) >= settings.rate_limit_per_minute:
            store.audit(None, 'security.rate_limited', {'ip': ip, 'path': request.url.path})
            return JSONResponse(status_code=429, content={'detail': 'Rate limit exceeded'})
        store.rate_limit[ip].append(now)
        return await call_next(request)


class JWTMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = request.cookies.get('access_token')
        auth = request.headers.get('authorization', '')
        if auth.lower().startswith('bearer '):
            token = auth.split(' ', 1)[1]
        if token:
            try:
                payload = decode_token(token)
                request.state.token_payload = payload
            except Exception:  # noqa: BLE001
                request.state.token_payload = None
        return await call_next(request)


def assert_ip_allowed(request: Request) -> str:
    ip = request.client.host if request.client else 'unknown'
    if store.ip_whitelist and ip not in store.ip_whitelist:
        raise HTTPException(status_code=403, detail='IP not whitelisted')
    if ip in store.ip_blacklist:
        raise HTTPException(status_code=403, detail='IP blacklisted')
    return ip
