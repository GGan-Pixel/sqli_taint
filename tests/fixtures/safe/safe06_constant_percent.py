def query_static(cursor):
    cursor.execute("SELECT * FROM users WHERE status = '%s'" % "verified")  # EXPECT: SAFE
