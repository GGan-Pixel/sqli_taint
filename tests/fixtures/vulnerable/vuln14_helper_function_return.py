def extract_search_term(raw_value):
    cleaned = raw_value.strip()
    return cleaned


def query_via_helper(cursor, search):
    term = extract_search_term(search)
    cursor.execute("SELECT * FROM logs WHERE message = '{}'".format(term))  # EXPECT: SQLI

