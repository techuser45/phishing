from flask import Flask, render_template, request, jsonify
from logic.detector import analyze_url, analyze_email, analyze_file
from logic.database import init_db, store_email_scan, store_scan_log, store_feedback
import time

app = Flask(__name__)

# Initialize database
init_db()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/what-is-phishing')
def what_is_phishing():
    return render_template('what_is_phishing.html')

@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    data = request.json
    url = data.get('url', '')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    # Simulate processing time
    time.sleep(1.5)
    result = analyze_url(url)
    
    # Store in database logs
    store_scan_log('url', float(result['score']), result['verdict'])
    
    return jsonify(result)

@app.route('/api/scan/email', methods=['POST'])
def scan_email():
    data = request.json
    text = data.get('text', '')
    if not text:
        return jsonify({"error": "No email content provided"}), 400
    
    # Simulate processing time
    time.sleep(1.5)
    result = analyze_email(text)
    
    # Store in database
    store_email_scan({
        "subject": "Email Scan", # Subject is not provided in text-only scan
        "sender": "Web Interface",
        "body": text,
        "phishing_probability": result['phishing_probability'],
        "emotional_deception_score": result['emotional_deception_score'],
        "verdict": result['verdict'],
        "confidence": result['confidence']
    }, result['eds_breakdown'])
    
    return jsonify(result)

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    # In a real app we'd handle the file upload, 
    # but based on the JS version it's just analyzing the filename
    file_name = request.json.get('fileName', '')
    if not file_name:
        return jsonify({"error": "No file name provided"}), 400
        
    # Simulate processing time
    time.sleep(1.5)
    result = analyze_file(file_name)
    
    # Store in database logs
    store_scan_log('file', float(result['score']), result['verdict'])
    
    return jsonify(result)

@app.route('/api/feedback', methods=['POST'])
def submit_feedback():
    data = request.json
    name = data.get('name', 'Anonymous')
    message = data.get('message', '')
    rating = data.get('rating', 5)
    
    if not message:
        return jsonify({"success": False, "error": "Message is required"}), 400
        
    success = store_feedback(name, message, int(rating))
    if success:
        return jsonify({"success": True, "message": "Feedback stored successfully"})
    else:
        return jsonify({"success": False, "error": "Failed to store feedback"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
