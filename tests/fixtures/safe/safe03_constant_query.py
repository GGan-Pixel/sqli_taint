def list_active(cursor):
    cursor.execute("SELECT id, name FROM users WHERE active = 1")  # EXPECT: SAFE
