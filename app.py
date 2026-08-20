from flask import Flask, render_template, request, jsonify
from Phishing_Analyzer import analyze_url, analyze_email, detect_input_type

app = Flask(__name__)

# Security: Limit input size
MAX_INPUT_LENGTH = 100


def _route_analysis(input_value: str):
    """Auto-detect input type and run the appropriate analyzer."""
    input_type = detect_input_type(input_value)
    if input_type == "email":
        return analyze_email(input_value)
    return analyze_url(input_value)


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    input_value = ""

    if request.method == "POST":
        input_value = request.form.get("input_value", "").strip()

        if len(input_value) > MAX_INPUT_LENGTH:
            result = {
                "spelled_out": {"raw_input": input_value[:200]},
                "observations": [f"Input too long (max {MAX_INPUT_LENGTH} characters)."],
                "homograph_and_brand_similarity": {},
                "subdomain_spoofing": {},
                "idn_and_non_ascii": {},
                "dnstwist_it": {},
            }
        elif input_value:
            result = _route_analysis(input_value)

    return render_template(
        "index.html",
        result=result,
        input_value=input_value,
    )


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json()

    if not data or "input_value" not in data:
        return jsonify({"error": "Missing required field: input_value"}), 400

    input_value = data["input_value"].strip()

    if len(input_value) > MAX_INPUT_LENGTH:
        return jsonify({"error": f"Input too long (max {MAX_INPUT_LENGTH} characters)"}), 400

    input_type = data.get("input_type") or detect_input_type(input_value)
    if input_type == "email":
        result = analyze_email(input_value)
    else:
        result = analyze_url(input_value)

    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
