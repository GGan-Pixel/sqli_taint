def query_reassigned(cursor, user_id):
    raw_id = user_id
    normalized = raw_id.strip()
    target = normalized
    cursor.execute(f"SELECT * FROM users WHERE id = '{target}'")  # EXPECT: SQLI

