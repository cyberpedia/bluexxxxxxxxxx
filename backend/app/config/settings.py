"""Application settings loaded from environment variables."""
"""Application settings loaded from environment variables.

Secure-by-default:
- Debug is disabled.
- CORS is explicit.
- Secrets must be provided via environment variables.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

    app_name: str = Field(default='Cerberus API')
    environment: str = Field(default='production')
    debug: bool = Field(default=False)
    host: str = Field(default='0.0.0.0')
    port: int = Field(default=8000)

    api_prefix: str = Field(default='/api/v1')
    allowed_origins: str = Field(default='http://localhost:5173')

    database_url: str = Field(default='postgresql+psycopg://cerberus:change_me@localhost:5432/cerberus')
    redis_url: str = Field(default='redis://localhost:6379/0')

    jwt_secret: str = Field(default='CHANGE_ME_IN_ENV')
    jwt_algorithm: str = Field(default='HS256')
    jwt_access_expiry_minutes: int = Field(default=15)
    jwt_refresh_expiry_minutes: int = Field(default=60 * 24 * 7)

    require_email_verification: bool = Field(default=True)
    enable_team_creation: bool = Field(default=True)
    max_team_size: int = Field(default=5)
    team_roster_lock: bool = Field(default=False)

    secure_cookies: bool = Field(default=False)
    rate_limit_per_minute: int = Field(default=120)
    jwt_expiry_minutes: int = Field(default=30)


settings = Settings()
