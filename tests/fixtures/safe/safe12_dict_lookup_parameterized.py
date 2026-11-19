def query_dict_safe(cursor, payload):
    filters = {"user_id": payload, "status": "active"}
    selected_id = filters["user_id"]
    cursor.execute("SELECT * FROM users WHERE id = ?", (selected_id,))  # EXPECT: SAFE

