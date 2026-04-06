"""SAST fixture: SQL injection patterns."""

import sqlite3


def setup_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
    cur.execute("INSERT INTO users (username) VALUES ('alice'), ('bob')")
    conn.commit()
    return conn


def vulnerable_query(conn: sqlite3.Connection) -> list[tuple]:
    username = input("Username: ")
    sql = f"SELECT id, username FROM users WHERE username = '{username}'"
    return conn.execute(sql).fetchall()


def safe_query(conn: sqlite3.Connection) -> list[tuple]:
    username = input("Username: ")
    sql = "SELECT id, username FROM users WHERE username = ?"
    return conn.execute(sql, (username,)).fetchall()


if __name__ == "__main__":
    connection = setup_db()
    print(vulnerable_query(connection))
