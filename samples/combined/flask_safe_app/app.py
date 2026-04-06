import ast
import hashlib
import sqlite3
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)
SAFE_BASE = Path(".").resolve()


def safe_eval_replacement(expression: str) -> int:
    # Literal-only parsing avoids code execution.
    return int(ast.literal_eval(expression))


def safe_sql_lookup(user_value: str) -> list[tuple]:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
    conn.execute("INSERT INTO users (username) VALUES ('alice'), ('bob')")
    return conn.execute("SELECT * FROM users WHERE username = ?", (user_value,)).fetchall()


def safe_hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/")
def index():
    return jsonify(service="flask_safe_app")


@app.get("/reflect")
def reflect():
    value = request.args.get("q", "")
    # Reflection remains explicit for route parity, but returned as plain JSON data.
    return jsonify(reflect=value)


@app.get("/file")
def file_read():
    requested = request.args.get("name", "README.md")
    resolved = (SAFE_BASE / requested).resolve()
    if SAFE_BASE not in resolved.parents and resolved != SAFE_BASE:
        return jsonify(error="invalid path"), 400
    return jsonify(path=str(resolved.relative_to(SAFE_BASE)))


@app.get("/user")
def user():
    username = request.args.get("name", "")
    return jsonify(rows=safe_sql_lookup(username))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5202, debug=False)
