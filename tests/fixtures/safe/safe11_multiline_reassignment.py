def query_reassigned_safe(cursor, user_id):
    target = user_id
    target = "guest"
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (target,))  # EXPECT: SAFE

