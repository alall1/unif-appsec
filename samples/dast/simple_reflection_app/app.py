from flask import Flask, jsonify, request

app = Flask(__name__)


@app.get("/")
def index():
    q = request.args.get("q", "")
    return jsonify(message=f"you sent: {q}")


@app.post("/echo")
def echo():
    body = request.get_json(silent=True) or {}
    value = body.get("input", "")
    return jsonify(echo=value)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5102, debug=False)
