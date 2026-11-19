def query_role(cursor, role):
    cursor.execute("SELECT * FROM users WHERE role = '%s'" % role)  # EXPECT: SQLI
