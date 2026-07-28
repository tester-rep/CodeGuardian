import random


def make_session_token():
    # TP: 会话令牌（安全场景，应报 INSECURE-RANDOM）
    return str(random.random())


def make_verify_code():
    # TP: 验证码（安全场景，应报 INSECURE-RANDOM）
    return random.randint(100000, 999999)


def sample_items(items):
    # FP: 随机采样（非安全场景，不应报）
    return random.choice(items)


def backoff_jitter():
    # FP: 退避抖动（非安全场景，不应报）
    return random.random() * 0.5
