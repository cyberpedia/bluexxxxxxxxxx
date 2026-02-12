import hmac


def constant_time_flag_compare(expected: str, submitted: str) -> bool:
    return hmac.compare_digest(expected.encode('utf-8'), submitted.encode('utf-8'))
