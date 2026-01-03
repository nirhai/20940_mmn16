import sqlite3
from time import time
from hash_func import HashFunctionFactory
from totp_auth import generate_secret, validate_totp

class Database:
    def __init__(self, filename, config):
        self.filename = filename
        self.hashfunc = HashFunctionFactory(config.hashfunc)
        self.pepper = config.pepper
        self.ratelimit = config.ratelimit
        self.userlock = config.userlock
        self.totp = config.totp
        self._init_database()

    def _init_database(self):
        with sqlite3.connect(self.filename) as connection:
            cursor = connection.cursor()
            cursor.execute("PRAGMA journal_mode = WAL;")
            cursor.execute("DROP TABLE IF EXISTS users;")
            cursor.execute("DROP TABLE IF EXISTS ratelimit;")
            cursor.execute("DROP TABLE IF EXISTS userlock;")
            cursor.execute("DROP TABLE IF EXISTS totp;")
            create_users_query = """CREATE TABLE users (uid INTEGER PRIMARY KEY AUTOINCREMENT,
                                                        username CHAR(25) NOT NULL UNIQUE,
                                                        password_hash TEXT NOT NULL );"""
            cursor.execute(create_users_query)

            if self.ratelimit is not None:
                create_ratelimit_query = """CREATE TABLE ratelimit (uid INTEGER PRIMARY KEY,
                                                                    failed_attempts INTEGER NOT NULL,
                                                                    first_fail_time INTEGER NOT NULL);"""
                cursor.execute(create_ratelimit_query)

            if self.userlock is not None:
                create_userlock_query = """CREATE TABLE userlock (uid INTEGER PRIMARY KEY,
                                                                  failed_attempts INTEGER NOT NULL);"""
                cursor.execute(create_userlock_query)

            if self.totp is not None:
                create_totp_query = """CREATE TABLE totp (uid INTEGER PRIMARY KEY,
                                                          totp_secret TEXT NOT NULL);"""
                cursor.execute(create_totp_query)

            connection.commit()

    def insert_user(self, username, password, totp=False):
        with sqlite3.connect(self.filename) as connection:
            cursor = connection.cursor()
            password_with_pepper = password + ("" if self.pepper is None else self.pepper)
            try:
                cursor.execute("BEGIN;")
                insert_query = "INSERT INTO users (username, password_hash) VALUES (?, ?)"
                cursor.execute(insert_query, (username, self.hashfunc.generate_hash(password_with_pepper)))
                uid = cursor.lastrowid
                if totp_user := self.totp is not None and totp:
                    secret = generate_secret()
                    insert_query = "INSERT INTO totp (uid, totp_secret) VALUES (?, ?)"
                    cursor.execute(insert_query, (uid, secret))
                connection.commit()
                return ["registered", f"secret: {secret}"] if totp_user else ["registered"]
            except:
                connection.rollback()
                return ["user exists"]
    
    def check_user(self, username, password, otp=None):
        with sqlite3.connect(self.filename) as connection:
            if (uid := _get_uid(connection, username)) is None:
                return "user does not exist"
            password_with_pepper = password + ("" if self.pepper is None else self.pepper)
            worng_pass = not _check_password(connection, uid, password_with_pepper, self.hashfunc)
            wrong_otp = self.totp is not None and not _check_otp(connection, uid, otp)
            if self.userlock is not None and not _check_userlock(connection, uid, self.userlock):
                return "locked"
            if self.ratelimit is not None and (lock_time := _check_ratelimit(connection, uid, self.ratelimit)) > 0:
                return f"locked for {lock_time} seconds"
            if worng_pass or wrong_otp:
                if self.userlock is not None: _inc_userlock(connection, uid)
                if self.ratelimit is not None: _inc_ratelimit(connection, uid)
                return "wrong password" if worng_pass else "wrong OTP"
            if self.userlock is not None: _del_record(connection, uid, 'userlock')
            if self.ratelimit is not None: _del_record(connection, uid, 'ratelimit')
            return "logged in"

    def unlock_user(self, username, password):
        with sqlite3.connect(self.filename) as connection:
            if (uid := _get_uid(connection, username)) is None:
                return "user does not exist"
            if not _check_password(connection, uid, password, self.hashfunc):
                return "wrong password"
            if self.userlock is not None: _del_record(connection, uid, 'userlock')
            if self.ratelimit is not None: _del_record(connection, uid, 'ratelimit')
            return "user unlocked"

def _get_uid(connection, username):
    cursor = connection.cursor()
    select_query = "SELECT uid FROM users WHERE username = ? "
    cursor.execute(select_query, (username,))
    uid = cursor.fetchone()
    return None if uid is None else uid[0]

def _check_password(connection, uid, password, hashfunc):
    cursor = connection.cursor()
    select_query = "SELECT password_hash FROM users WHERE uid = ? "
    cursor.execute(select_query, (uid,))
    password_hash = cursor.fetchone()
    return False if password_hash is None else hashfunc.check_hash(password_hash[0], password)

def _check_ratelimit(connection, uid, max_attempts):
    TIMEFRAME_SEC = 60
    cursor = connection.cursor()
    select_query = """SELECT failed_attempts, first_fail_time FROM ratelimit WHERE uid = ? """
    cursor.execute(select_query, (uid,))
    record = cursor.fetchone()
    if record is not None:
        failed_attempts, first_fail_time = record
        lock_time = TIMEFRAME_SEC + first_fail_time - int(time())
        if lock_time <= 0:
            _del_record(connection, uid, 'ratelimit')
        elif failed_attempts >= max_attempts:
            return lock_time
    return 0

def _check_userlock(connection, uid, max_attempts):
    cursor = connection.cursor()
    select_query = "SELECT failed_attempts FROM userlock WHERE uid = ? "
    cursor.execute(select_query, (uid,))
    failed_attempts = cursor.fetchone()
    return False if failed_attempts is not None and failed_attempts[0] >= max_attempts else True

def _check_otp(connection, uid, otp):
    cursor = connection.cursor()
    select_query = "SELECT totp_secret FROM totp WHERE uid = ? "
    cursor.execute(select_query, (uid,))
    secret = cursor.fetchone()
    return False if secret is not None and (otp is None or not validate_totp(otp, secret[0])) else True

def _inc_ratelimit(connection, uid):
    cursor = connection.cursor()
    inc_query = """INSERT INTO ratelimit (uid, failed_attempts, first_fail_time) VALUES (?, 1, ?)
                   ON CONFLICT(uid) DO UPDATE SET failed_attempts = failed_attempts + 1 """
    cursor.execute(inc_query, (uid, int(time())))
    connection.commit()

def _inc_userlock(connection, uid):
    cursor = connection.cursor()
    inc_query = """INSERT INTO userlock (uid, failed_attempts) VALUES (?, 1)
                   ON CONFLICT(uid) DO UPDATE SET failed_attempts = failed_attempts + 1 """
    cursor.execute(inc_query, (uid,))
    connection.commit()

def _del_record(connection, uid, table):
    cursor = connection.cursor()
    delete_query = f"DELETE FROM {table} WHERE uid = ?"
    cursor.execute(delete_query, (uid,))
    connection.commit()
