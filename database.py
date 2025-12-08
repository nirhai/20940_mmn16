import sqlite3
from hash_func import generate_hash, check_hash

db = 'users.db'

def create_table(users=None):
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
    if users:
        insert_users(users)

def insert_user(username, password):
    connect_obj = sqlite3.connect(db)
    cursor_obj = connect_obj.cursor()
    insert_query = f"""INSERT INTO users VALUES ('{username}',
                                                 '{generate_hash("argon2", password)}',
                                                 '{generate_hash("bcrypt", password)}',
                                                 '{generate_hash("sha256", password)}',
                                                 '{generate_hash("md5", password)}')"""
    try:
        cursor_obj.execute(insert_query)
    except:
        return False
    else:
        return True
    finally:
        connect_obj.commit()
        connect_obj.close()

def insert_users(users):
    for user in users:
        insert_user(user['username'], user['password'])

def _get_password_hash(hashfunc, hashlist):
    match hashfunc:
        case "argon2":
            return hashlist[0]
        case "bcrypt":
            return hashlist[1]
        case "sha256":
            return hashlist[2]
        case "md5":
            return hashlist[3]

def check_user(username, password, hashfunc):
    connect_obj = sqlite3.connect(db)
    cursor_obj = connect_obj.cursor()
    select_query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor_obj.execute(select_query)
    user = cursor_obj.fetchone()
    connect_obj.close()
    if user:
        password_hash = _get_password_hash(hashfunc, user[1:])
        if check_hash(hashfunc, password_hash, password):
            return True
    return False