from flask import Flask, render_template, request, jsonify
from Phishing_Analyzer import analyze_url, analyze_email, load_dnstwist_database
from generate_permutations import generate_permutation_database
import sys

app = Flask(__name__)

# Security: Limit input size
MAX_INPUT_LENGTH = 100

def initialize_dnstwist():
    print("\n" + "="*70)
    print("INITIALIZING GOTFISH PHISHING ANALYZER")
    print("="*70)

    loaded = load_dnstwist_database()
    
    if not loaded:
        print("Generating DNSTwist permutation database")
        success = generate_permutation_database()
        
        if success:
            # Try loading again
            load_dnstwist_database()
        else:
            print("WARNING: DNSTwist database generation failed")
            print("App will run with reduced detection capabilities")
    
    print("="*70 + "\n")

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    input_type = None
    input_value = ""

    if request.method == "POST":
        input_type = request.form.get("input_type")
        input_value = request.form.get("input_value", "").strip()

        # Input validation
        if len(input_value) > MAX_INPUT_LENGTH:
            result = {
                'verdict': 'ERROR',
                'score': 0,
                'color': '#ff0000',
                'reasons': [f'Input too long (max {MAX_INPUT_LENGTH} characters)'],
                'domain_info': {}
            }
        elif input_value:
            if input_type == "url":
                result = analyze_url(input_value)
            elif input_type == "email":
                result = analyze_email(input_value)

    return render_template("index.html", result=result, input_type=input_type, input_value=input_value)

@app.route("/api/analyze", methods=["POST"])
def api_analyze():

    data = request.get_json()
    """input validation"""    
    if not data or 'input_value' not in data or 'input_type' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    input_value = data['input_value'].strip()
    input_type = data['input_type']
    
    if len(input_value) > MAX_INPUT_LENGTH:
        return jsonify({'error': f'Input too long (max {MAX_INPUT_LENGTH} characters)'}), 400
    
    if input_type == "url":
        result = analyze_url(input_value)
    elif input_type == "email":
        result = analyze_email(input_value)
    else:
        return jsonify({'error': 'Invalid input_type'}), 400
    
    return jsonify(result)

if __name__ == "__main__":
    # Initialize DNSTwist database before starting server
    initialize_dnstwist()
    
    app.run(host="0.0.0.0", port=8080, debug=False)
