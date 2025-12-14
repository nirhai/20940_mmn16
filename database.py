import sqlite3
import time
from hash_func import generate_hash, check_hash

SECONDS_IN_MINUTE = 60.0

class Database:
    def __init__(self, filename, pepper=None):
        self.filename = filename
        self.pepper = pepper
        self._create_table()

    def _create_table(self):
        connect_obj = sqlite3.connect(self.filename)
        cursor_obj = connect_obj.cursor()
        cursor_obj.execute("DROP TABLE IF EXISTS users")
        create_table_query = """CREATE TABLE users (username CHAR(25) NOT NULL UNIQUE,
                                                    argon2_hash TEXT NOT NULL,
                                                    bcrypt_hash TEXT NOT NULL,
                                                    sha256_hash TEXT NOT NULL,
                                                    md5_hash TEXT NOT NULL,
                                                    failed_attempts INTEGER NOT NULL,
                                                    failed_attempts_per_minute INTEGER NOT NULL,
                                                    first_attempt_time INTEGER);"""
        cursor_obj.execute(create_table_query)
        connect_obj.commit()
        connect_obj.close()

    def insert_user(self, username, password):
        connect_obj = sqlite3.connect(self.filename)
        cursor_obj = connect_obj.cursor()
        password_with_pepper = password + ("" if self.pepper is None else self.pepper)
        insert_query = """INSERT INTO users (username, argon2_hash, bcrypt_hash, sha256_hash, md5_hash, failed_attempts, failed_attempts_per_minute, first_attempt_time)
                          VALUES (?, ?, ?, ?, ?, 0, 0, NULL)"""
        user_data = (username, generate_hash("argon2", password_with_pepper), generate_hash("bcrypt", password_with_pepper),
                     generate_hash("sha256", password_with_pepper), generate_hash("md5", password_with_pepper))
        try:
            cursor_obj.execute(insert_query, user_data)
        except:
            return False
        else:
            return True
        finally:
            connect_obj.commit()
            connect_obj.close()

    def check_user(self, username, password, hashfunc, max_attempts=None, attempts_per_minute=None):
        connect_obj = sqlite3.connect(self.filename)
        cursor_obj = connect_obj.cursor()
        select_query = "SELECT * FROM users WHERE username = ?"
        cursor_obj.execute(select_query, (username,))
        user = cursor_obj.fetchone()
        result = False
        if user is not None:
            failed_attempts = user[5]
            failed_attempts_per_minute = user[6]
            first_attempt_time = user[7]
            if max_attempts is not None and failed_attempts >= max_attempts:
                result = None
            elif attempts_per_minute is not None:
                curr_attempt_time = int(time.time())
                if first_attempt_time is None or curr_attempt_time - first_attempt_time > SECONDS_IN_MINUTE:
                    first_attempt_time = curr_attempt_time
                    failed_attempts_per_minute = 0
                elif failed_attempts_per_minute >= attempts_per_minute:
                    result = None
            if result is not None:
                password_hash = _get_password_hash(hashfunc, user[1:5])
                password_with_pepper = password + ("" if self.pepper is None else self.pepper)
                if check_hash(hashfunc, password_hash, password_with_pepper):
                    first_attempt_time = None
                    failed_attempts = 0
                    failed_attempts_per_minute = 0
                    result = True
                else:
                    failed_attempts += 1
                    failed_attempts_per_minute += 1
                if max_attempts is not None:
                    update_query = "UPDATE users SET failed_attempts = ? WHERE username = ?"
                    cursor_obj.execute(update_query, (failed_attempts, username))
                if attempts_per_minute is not None:
                    update_query = "UPDATE users SET failed_attempts_per_minute = ?, first_attempt_time = ? WHERE username = ?"
                    cursor_obj.execute(update_query, (failed_attempts_per_minute, first_attempt_time, username))
                connect_obj.commit()
        connect_obj.close()
        return result

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
