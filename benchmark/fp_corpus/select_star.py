def get_all(cursor):
    # TP-1: SELECT * 无限制（应报 SELECT-STAR-NO-LIMIT）
    cursor.execute("SELECT * FROM users")


def get_top(cursor):
    # FP-1: SELECT * 带 LIMIT（不应报）
    cursor.execute("SELECT * FROM users LIMIT 10")


def get_by_id(cursor, uid):
    # FP-2: SELECT * 带 WHERE（不应报）
    cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))


def get_sorted(cursor):
    # FP-3: SELECT * + ORDER BY + LIMIT（LIMIT 在 ORDER 后，不应报）
    cursor.execute("SELECT * FROM users ORDER BY name LIMIT 10")
