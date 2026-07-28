def fetch_direct(d):
    # TP-1: 无 guard 直接解引用（应报 POSSIBLE-NONE-DEREF）
    x = d.get("key")
    return x.value


def fetch_ternary(d):
    # FP-1: 三元表达式 guard（不应报）
    x = d.get("key")
    return x.signature if x else None


def fetch_with_default(d):
    # FP-2: get 带默认值（不应报）
    x = d.get("key", {})
    return x.items()


def fetch_if_guard(d):
    # FP-3: if 语句 guard（不应报）
    x = d.get("key")
    if x:
        return x.name
    return None
