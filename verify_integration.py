from logic.database import init_db, store_email_scan, store_scan_log, store_feedback, get_db_connection
from logic.detector import analyze_email
import os

def test_integration():
    print("--- Starting Integration Test ---")
    
    # 1. Initialize DB
    print("Testing DB Initialization...")
    if init_db():
        print("SUCCESS: Database initialized.")
    else:
        print("FAILED: Database initialization.")
        return

    # 2. Test Email Storage
    print("\nTesting Email Storage...")
    sample_text = "URGENT: Your account is locked! Please verify your password immediately at http://bit.ly/fake-login"
    result = analyze_email(sample_text)
    email_id = store_email_scan({
        "subject": "Test Email",
        "sender": "test@example.com",
        "body": sample_text,
        "phishing_probability": result['phishing_probability'],
        "emotional_deception_score": result['emotional_deception_score'],
        "verdict": result['verdict'],
        "confidence": result['confidence']
    }, result['eds_breakdown'])
    
    if email_id:
        print(f"SUCCESS: Email stored with ID: {email_id}")
    else:
        print("FAILED: Email storage.")

    # 3. Test Scan Log
    print("\nTesting Scan Log Storage...")
    if store_scan_log('url', 25.0, 'warning'):
        print("SUCCESS: Scan log stored.")
    else:
        print("FAILED: Scan log storage.")

    # 4. Test Feedback
    print("\nTesting Feedback Storage...")
    if store_feedback("Tester", "This is a test message", 5):
        print("SUCCESS: Feedback stored.")
    else:
        print("FAILED: Feedback storage.")

    # 5. Verify Insertion
    print("\nVerifying data in DB...")
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM emails")
        email_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM feedback")
        feedback_count = cursor.fetchone()[0]
        print(f"Total Emails: {email_count}")
        print(f"Total Feedback: {feedback_count}")
        cursor.close()
        conn.close()
    
    print("\n--- Integration Test Complete ---")

if __name__ == "__main__":
    test_integration()
