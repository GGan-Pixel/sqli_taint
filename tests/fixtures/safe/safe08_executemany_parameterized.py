def insert_logs(cursor, rows):
    cursor.executemany("INSERT INTO logs (entry) VALUES (%s)", rows)  # EXPECT: SAFE
