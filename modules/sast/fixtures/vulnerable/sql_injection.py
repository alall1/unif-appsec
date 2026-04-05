import sys


class Cursor:
    def execute(self, query: str) -> None:
        _ = query


def vulnerable(cur: Cursor) -> None:
    user = sys.argv[1]
    cur.execute("SELECT * FROM users WHERE name = '" + user + "'")
