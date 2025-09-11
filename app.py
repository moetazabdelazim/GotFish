from flask import Flask, render_template, request
from Phishing_Analyzer import analyze_url, analyze_email

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    input_type = None
    input_value = ""

    if request.method == "POST":
        input_type = request.form.get("input_type")
        input_value = request.form.get("input_value", "").strip()

        if input_value:  #analyze if not empty
            if input_type == "url":
                result = analyze_url(input_value)
            elif input_type == "email":
                result = analyze_email(input_value)

    return render_template("index.html", result=result, input_type=input_type, input_value=input_value)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
