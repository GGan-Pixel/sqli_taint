def query_email(cursor, email):
    cursor.execute("SELECT * FROM users WHERE email = '{}'".format(email))  # EXPECT: SQLI
