from flask import Flask, jsonify, request

app = Flask(__name__)


@app.get("/")
def index():
    return jsonify(message="error leak sample")


@app.get("/search")
def search():
    term = request.args.get("q", "")
    if "'" in term:
        # Intentional SQL-like error marker for active response analysis tests.
        return (
            "SQLSTATE[42000]: Syntax error or access violation: 1064 "
            "You have an error in your SQL syntax near ''",
            500,
        )
    return jsonify(results=[], query=term)


@app.get("/debug")
def debug():
    return (
        "Traceback (most recent call last):\n"
        "File \"app.py\", line 20, in debug\n"
        "RuntimeError: debug info leak sample",
        500,
        {"Content-Type": "text/plain"},
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5103, debug=False)
