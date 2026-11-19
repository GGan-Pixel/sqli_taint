def query_fstring(cursor):
    cursor.execute(f"SELECT * FROM items WHERE in_stock = 1")  # EXPECT: SAFE
