def query_fixed(cursor):
    cursor.execute("SELECT * FROM users WHERE role = '{}'".format("admin"))  # EXPECT: SAFE
