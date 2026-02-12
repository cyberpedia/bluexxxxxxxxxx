from datetime import datetime, timedelta, timezone

from jose import jwt

from app.config.settings import settings


def create_access_token(user_id: str, capabilities: list[str]) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_access_expiry_minutes)
    return jwt.encode({'sub': user_id, 'type': 'access', 'cap': capabilities, 'exp': exp}, settings.jwt_secret, settings.jwt_algorithm)


def create_refresh_token(user_id: str, session_id: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_refresh_expiry_minutes)
    return jwt.encode({'sub': user_id, 'sid': session_id, 'type': 'refresh', 'exp': exp}, settings.jwt_secret, settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
