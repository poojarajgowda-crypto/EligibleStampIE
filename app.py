from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "EligibleStampIE is starting!"

if __name__ == "__main__":
    app.run(debug=True)