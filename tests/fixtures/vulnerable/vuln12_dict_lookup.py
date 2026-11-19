def query_from_dict(cursor, payload):
    filters = {"user_id": payload, "active": "1"}
    selected_id = filters["user_id"]
    cursor.execute("SELECT * FROM users WHERE id = '" + selected_id + "'")  # EXPECT: SQLI

