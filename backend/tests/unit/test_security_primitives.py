from app.security.flags import constant_time_flag_compare
from app.security.passwords import hash_password, verify_password


def test_password_hash_and_verify() -> None:
    hashed = hash_password('Cerberus!Secure123')
    assert hashed != 'Cerberus!Secure123'
    assert verify_password('Cerberus!Secure123', hashed)
    assert not verify_password('wrong', hashed)


def test_constant_time_flag_compare() -> None:
    assert constant_time_flag_compare('flag{abc123}', 'flag{abc123}')
    assert not constant_time_flag_compare('flag{abc123}', 'flag{zzz999}')
