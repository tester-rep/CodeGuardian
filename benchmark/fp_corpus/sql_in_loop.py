def load_users(ids, cursor):
    # TP-1: 标准 N+1（应报 SQL-IN-LOOP）
    for uid in ids:
        cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))


def load_items(users, cursor):
    # TP-2: 嵌套循环 N+1（应报 SQL-IN-LOOP）
    for u in users:
        for oid in u.order_ids:
            cursor.execute("SELECT * FROM orders WHERE id=%s", (oid,))


def load_batch(ids, cursor):
    # FP-1: 循环结束后的批量查询（非 N+1，不应报）
    for uid in ids:
        print(uid)
    cursor.execute("SELECT * FROM users WHERE id = ANY(%s)", (ids,))


def describe():
    # FP-2: "execute/query" 出现在字符串/message 里（非 SQL 调用，不应报）
    for msg in messages:
        note = "the loop body will never execute"
        print(note)
