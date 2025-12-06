import sqlite3

db = 'users.db'

def create_table():
    connect_obj = sqlite3.connect(db)
    cursor_obj = connect_obj.cursor()
    cursor_obj.execute("DROP TABLE IF EXISTS users")
    create_table_query = """
        CREATE TABLE users (
            username CHAR(25) NOT NULL UNIQUE,
            argon2_hash TEXT NOT NULL,
            bcrypt_hash TEXT NOT NULL,
            sha256_hash TEXT NOT NULL,
            md5_hash TEXT NOT NULL
        );
    """
    cursor_obj.execute(create_table_query)
    connect_obj.commit()
    connect_obj.close()

def insert_user(username, hash_list):
    connect_obj = sqlite3.connect(db)
    cursor_obj = connect_obj.cursor()
    insert_query = f"""INSERT INTO users VALUES ('{username}',
                                                 '{hash_list[0]}',
                                                 '{hash_list[1]}',
                                                 '{hash_list[2]}',
                                                 '{hash_list[3]}')"""
    try:
        cursor_obj.execute(insert_query)
    except:
        return False
    else:
        return True
    finally:
        connect_obj.commit()
        connect_obj.close()

def get_user(username):
    connect_obj = sqlite3.connect(db)
    cursor_obj = connect_obj.cursor()
    select_query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor_obj.execute(select_query)
    user = cursor_obj.fetchone()
    connect_obj.close()
    return user