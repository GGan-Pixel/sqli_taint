def build_static_query():
    base = "SELECT id, name FROM users WHERE active = ?"
    return base


def query_via_safe_helper(cursor, is_active):
    sql = build_static_query()
    cursor.execute(sql, (is_active,))  # EXPECT: SAFE

