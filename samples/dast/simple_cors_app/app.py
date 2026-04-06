from flask import Flask, jsonify, request

app = Flask(__name__)


def _cors_headers():
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
        "Access-Control-Allow-Credentials": "true",
    }


@app.route("/profile", methods=["GET", "OPTIONS"])
def profile():
    if request.method == "OPTIONS":
        return ("", 204, _cors_headers())
    return (jsonify(user="demo", role="user"), 200, _cors_headers())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5104, debug=False)
