def query_from_list(cursor, user_input):
    candidates = ["default", user_input]
    chosen = candidates[1]
    cursor.execute("SELECT * FROM items WHERE name = '%s'" % chosen)  # EXPECT: SQLI

