def query_user(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # EXPECT: SAFE
