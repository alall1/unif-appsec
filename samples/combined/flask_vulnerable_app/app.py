import os
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)
BASE_DIR = Path(".").resolve()


def cli_command_helper() -> None:
    # SAST-friendly source/sink combination not tied to framework request modeling.
    cmd = input("Enter command: ")
    os.system(cmd)


def cli_eval_helper() -> None:
    expression = input("Expression: ")
    eval(expression)


def cli_sql_helper(user_value: str) -> list[tuple]:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
    conn.execute("INSERT INTO users (username) VALUES ('alice'), ('bob')")
    sql = f"SELECT * FROM users WHERE username = '{user_value}'"
    return conn.execute(sql).fetchall()


@app.get("/")
def index():
    return jsonify(service="flask_vulnerable_app")


@app.get("/reflect")
def reflect():
    value = request.args.get("q", "")
    return jsonify(reflect=value)


@app.get("/error")
def error():
    if "'" in request.args.get("id", ""):
        return (
            "Unhandled exception: SQL syntax error near input. "
            "Traceback (most recent call last): ...",
            500,
        )
    return jsonify(ok=True)


@app.get("/file")
def file_read():
    requested = request.args.get("name", "README.md")
    content = (BASE_DIR / requested).read_text(encoding="utf-8")
    return jsonify(path=requested, preview=content[:80])


@app.get("/headers")
def headers():
    return jsonify(note="no strict security headers set")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5201, debug=False)
