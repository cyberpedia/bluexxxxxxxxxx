import secrets

import pyotp

from app.services.store import InMemoryStore, UserRecord


def setup_totp(user: UserRecord) -> str:
    secret = pyotp.random_base32()
    user.mfa_secret = secret
    return secret


def verify_totp(user: UserRecord, code: str) -> bool:
    if not user.mfa_secret:
        return False
    return pyotp.TOTP(user.mfa_secret).verify(code, valid_window=1)


def generate_backup_codes(store: InMemoryStore, user: UserRecord, count: int = 8) -> list[str]:
    codes: list[str] = []
    hashes: list[str] = []
    for _ in range(count):
        code = secrets.token_hex(4)
        codes.append(code)
        hashes.append(store.digest(code))
    user.mfa_backup_hashes = hashes
    return codes


def use_backup_code(store: InMemoryStore, user: UserRecord, code: str) -> bool:
    digest = store.digest(code)
    if digest in user.mfa_backup_hashes:
        user.mfa_backup_hashes.remove(digest)
        return True
    return False
