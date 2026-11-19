from sqlalchemy import text

def build_query(col):
    text("SELECT {} FROM items".format(col))  # EXPECT: SQLI
