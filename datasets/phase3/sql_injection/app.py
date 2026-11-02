def find_user(cursor, name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return cursor.execute(query).fetchall()
