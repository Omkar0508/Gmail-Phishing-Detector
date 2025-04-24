# app.py (Main Flask application)
from flask import Flask, redirect, url_for, session, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import os
import json
import numpy as np
from services.auth_service import get_oauth_flow, creds_to_dict
from services.gmail_service import fetch_and_process_emails
from services.ml_service import load_models

# Load environment variables
load_dotenv()

# Custom JSON encoder for NumPy types
class NumpyJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, (bool, np.bool_)):
            return bool(obj)
        return super().default(obj)

# Function to safely convert all values to JSON serializable types
def make_json_serializable(obj):
    if isinstance(obj, dict):
        return {k: make_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_serializable(v) for v in obj]
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, (bool, np.bool_)):
        return bool(obj)
    elif obj is None:
        return None
    else:
        try:
            json.dumps(obj)
            return obj
        except (TypeError, OverflowError):
            return str(obj)

app = Flask(__name__)
# Fix CORS configuration to properly allow requests from the extension
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your_default_secret_key") 

# Ensure JSON responses properly handle NumPy types
app.json_encoder = NumpyJSONEncoder

# Add CORS headers to all responses
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Load ML models during startup (once)
print("Loading ML models...")
models = load_models()
print("Models loaded successfully!")

@app.route("/test_urls", methods=["POST"])
def test_urls():
    """
    Test endpoint to directly analyze URLs without going through Gmail
    
    Request format: 
    {
        "urls": ["http://example.com", "http://malicious-site.com"]
    }
    """
    # Get URLs from request
    data = request.get_json()
    if not data or not data.get("urls"):
        return jsonify({"error": "Please provide URLs to test in 'urls' array"}), 400
    
    urls = data.get("urls")
    if not isinstance(urls, list):
        return jsonify({"error": "URLs must be provided as an array"}), 400
    
    # Analyze URLs
    print(f"Testing {len(urls)} URLs...")
    for url in urls:
        print(f"URL: {url}")
        
        # Extract features
        from services.ml_service import extract_features
        features = extract_features(url)
        print(f"Features: {features}")
        
        # Specific feature checks
        from services.ml_service import contains_ip_address, suspicious_words, shortening_service
        print(f"- Contains IP: {contains_ip_address(url)}")
        print(f"- Suspicious words: {suspicious_words(url)}")
        print(f"- Shortening service: {shortening_service(url)}")
    
    # Run full classification
    from services.ml_service import classify_urls_batch
    results = classify_urls_batch(urls, models)
    
    # Make results serializable
    results_serialized = make_json_serializable(results)
    
    return jsonify({
        "results": results_serialized,
        "analysis_details": {
            "urls_analyzed": len(urls),
            "malicious_detected": sum(1 for r in results.values() if r.get("is_malicious")),
            "high_confidence": sum(1 for r in results.values() if r.get("high_confidence"))
        }
    })

@app.route("/fetch_emails")
def fetch_emails():
    if "Authorization" not in request.headers:
        return jsonify({"error": "Authorization header missing"}), 401

    # Extract token from header
    token = request.headers["Authorization"].split(" ")[1]
    
    # Process days parameter (default: 3)
    days = request.args.get('days', default=3, type=int)
    max_emails = request.args.get('max_emails', default=100, type=int)
    
    try:
        result = fetch_and_process_emails(token, days, max_emails, models)
        
        # Pre-process the result to ensure all values are JSON serializable
        serializable_result = make_json_serializable(result)
        
        return jsonify(serializable_result)
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

        

if __name__ == "__main__":
    app.run(port=5000, debug=os.getenv("FLASK_DEBUG", "False").lower() == "true")