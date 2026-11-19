def query_list_safe(cursor, item_id):
    queries = [
        "SELECT * FROM items WHERE id = ?",
        "SELECT * FROM items WHERE archived = 0",
    ]
    sql = queries[0]
    cursor.execute(sql, (item_id,))  # EXPECT: SAFE

