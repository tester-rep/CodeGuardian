import hashlib


def store_password(pw):
    # TP: 密码哈希（安全场景，应报 WEAK-HASH）
    return hashlib.md5(pw.encode()).hexdigest()


def file_checksum(content):
    # FP: 文件校验和（非安全场景，不应报）
    return hashlib.md5(content).hexdigest()


def cache_key(data):
    # FP: 缓存键（非安全场景，不应报）
    return hashlib.sha1(data.encode()).hexdigest()
