def connect(host):
    # TP-1: while 重试同一操作且无退避（应报 RETRY-WITHOUT-BACKOFF）
    while True:
        try:
            return open_conn(host)
        except IOError:
            pass


def parse_all(files):
    # FP-1: for 遍历 + 容错跳过失败元素（非重试，不应报）
    results = []
    for f in files:
        try:
            results.append(parse(f))
        except ValueError:
            continue
    return results
