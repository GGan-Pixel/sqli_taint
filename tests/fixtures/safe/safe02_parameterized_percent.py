def query_name(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))  # EXPECT: SAFE
