def insert_bulk(cursor, table, rows):
    cursor.executemany("INSERT INTO " + table + " VALUES (%s)", rows)  # EXPECT: SQLI
