import pandas as pd

def load_metrics(conn, cat):
    pd.read_sql("SELECT * FROM metrics WHERE category = %s", conn, params=(cat,))  # EXPECT: SAFE
