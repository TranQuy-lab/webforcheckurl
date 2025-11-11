import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from dotenv import load_dotenv
from config import db
from flask import Flask, request,render_template
from routers.taskRouter import taskRouter

app = Flask(
    __name__,
    template_folder="../../frontend/templates",
    static_folder="../../frontend/static"
)

app.register_blueprint(taskRouter)

@app.route("/")
def home():
    return render_template("html.html")

if __name__ == "__main__":
    print (" server is running in port 5001")
    app.run(port=5001,debug=True)


