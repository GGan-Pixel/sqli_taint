def run_named(cursor, search):
    cursor.execute(sql=f"SELECT * FROM logs WHERE term = '{search}'")  # EXPECT: SQLI
