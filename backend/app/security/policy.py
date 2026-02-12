import re


def enforce_password_policy(password: str) -> None:
    if len(password) < 12:
        raise ValueError('Password must be at least 12 characters.')
    if not re.search(r'[A-Z]', password):
        raise ValueError('Password must include an uppercase letter.')
    if not re.search(r'[a-z]', password):
        raise ValueError('Password must include a lowercase letter.')
    if not re.search(r'\d', password):
        raise ValueError('Password must include a number.')
    if not re.search(r'[^A-Za-z0-9]', password):
        raise ValueError('Password must include a symbol.')
