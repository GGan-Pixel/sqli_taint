def fetch_all(cursor):
    cursor.execute("SELECT id " + "FROM users " + "WHERE active = 1")  # EXPECT: SAFE
