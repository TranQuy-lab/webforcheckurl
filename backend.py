from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route("/link", methods=["POST"])
def link():
    data = request.get_json()              # nhận JSON từ frontend
    user_message = data.get("message")     # lấy dữ liệu người nhập
    return jsonify({"reply": user_message})

@app.route("/")
def home():
    return render_template("html.html")

if __name__ == "__main__":
    app.run(port=3000, debug=True)
