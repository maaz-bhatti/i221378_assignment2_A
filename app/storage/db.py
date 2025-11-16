import mysql.connector
import os
import hashlib

DB_CONF = {
    'host': os.environ.get('DB_HOST', '127.0.0.1'),
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASS', ''),
    'database': os.environ.get('DB_NAME', 'securechat')
}

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS users (
    email VARCHAR(255) NOT NULL,
    username VARCHAR(100) NOT NULL UNIQUE,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    PRIMARY KEY (email)
);
"""

class DB:
    def __init__(self):
        self.conn = mysql.connector.connect(**DB_CONF)
        self.init()

    def init(self):
        cur = self.conn.cursor()
        cur.execute(CREATE_TABLE_SQL)
        self.conn.commit()
        cur.close()

    def create_user(self, email, username, pwd_plain):
        salt = os.urandom(16)
        pwd_hash = hashlib.sha256(salt + pwd_plain.encode('utf-8')).hexdigest()
        cur = self.conn.cursor()
        try:
            cur.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                        (email, username, salt, pwd_hash))
            self.conn.commit()
            return True
        except mysql.connector.IntegrityError:
            return False
        finally:
            cur.close()

    def verify_user(self, email, pwd_plain):
        cur = self.conn.cursor()
        cur.execute("SELECT salt, pwd_hash FROM users WHERE email=%s", (email,))
        row = cur.fetchone()
        cur.close()
        if not row:
            return False
        salt, stored = row
        computed = hashlib.sha256(salt + pwd_plain.encode('utf-8')).hexdigest()
        return computed == stored

    def close(self):
        self.conn.close()
