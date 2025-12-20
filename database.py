import sqlite3
import time
from hash_func import HashFunctionFactory

SECONDS_IN_MINUTE = 60.0

class Database:
    def __init__(self, filename, hashfunc, pepper=None):
        self.filename = filename
        self.hashfunc = HashFunctionFactory(hashfunc)
        self.pepper = pepper
        self._create_table()

    def _create_table(self):
        connect_obj = sqlite3.connect(self.filename)
        cursor_obj = connect_obj.cursor()
        cursor_obj.execute("DROP TABLE IF EXISTS users")
        create_table_query = """CREATE TABLE users (username CHAR(25) NOT NULL UNIQUE,
                                                    password_hash TEXT NOT NULL,
                                                    failed_attempts INTEGER NOT NULL,
                                                    failed_attempts_per_minute INTEGER NOT NULL,
                                                    first_attempt_time INTEGER,
                                                    totp_secret TEXT);"""
        cursor_obj.execute(create_table_query)
        connect_obj.commit()
        connect_obj.close()

    def insert_user(self, username, password, totp=False):
        connect_obj = sqlite3.connect(self.filename)
        cursor_obj = connect_obj.cursor()
        password_with_pepper = password + ("" if self.pepper is None else self.pepper)

        
        totp_secret = 1111111111111111 if totp else None


        insert_query = """INSERT INTO users (username, password_hash, failed_attempts, failed_attempts_per_minute)
                          VALUES (?, ?, 0, 0)"""
        user_data = (username, self.hashfunc.generate_hash(password_with_pepper))
        try:
            cursor_obj.execute(insert_query, user_data)
        except:
            return False
        else:
            return True
        finally:
            connect_obj.commit()
            connect_obj.close()

    def check_user(self, username, password, max_attempts=None, attempts_per_minute=None, totp=False):
        connect_obj = sqlite3.connect(self.filename)
        cursor_obj = connect_obj.cursor()
        select_query = "SELECT * FROM users WHERE username = ?"
        cursor_obj.execute(select_query, (username,))
        user = cursor_obj.fetchone()
        result = False
        if user is not None:
            failed_attempts, failed_attempts_per_minute, first_attempt_time, totp_secret = user[2:]
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
                password_with_pepper = password + ("" if self.pepper is None else self.pepper)
                if self.hashfunc.check_hash(user[1], password_with_pepper):
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

