from sqlalchemy import text

def get_item(engine, item_id):
    stmt = text("SELECT * FROM items WHERE id = :item_id")  # EXPECT: SAFE
