import pandas as pd

def load_data(conn, tbl):
    pd.read_sql("SELECT * FROM " + tbl, conn)  # EXPECT: SQLI
