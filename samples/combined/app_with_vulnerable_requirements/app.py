from flask import Flask, jsonify, request

app = Flask(__name__)


@app.get("/")
def index():
    return jsonify(service="app_with_vulnerable_requirements")


@app.get("/reflect")
def reflect():
    value = request.args.get("q", "")
    return jsonify(reflect=value)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5203, debug=False)
