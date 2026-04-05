import sys


class Cursor:
    def execute(self, query: str, params: tuple) -> None:
        _ = (query, params)


def safe(cur: Cursor) -> None:
    user = sys.argv[1]
    cur.execute("SELECT * FROM users WHERE name = ?", (user,))
