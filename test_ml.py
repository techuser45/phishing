from logic.detector import analyze_email, analyze_file

def test_ml():
    print("--- Testing Email ML ---")
    phish_email = "Urgent action required! Your account has been suspended. Click here to verify."
    legit_email = "Hey, let's meet for coffee tomorrow at 10 AM at the usual spot."
    
    res1 = analyze_email(phish_email)
    print(f"Phish Test: Verdict={res1['verdict']}, Score={res1['score']}")
    for step in res1['steps']:
        if step['name'] == 'AI Prediction':
            print(f"AI Detail: {step['details']}")

    res2 = analyze_email(legit_email)
    print(f"Legit Test: Verdict={res2['verdict']}, Score={res2['score']}")
    for step in res2['steps']:
        if step['name'] == 'AI Prediction':
            print(f"AI Detail: {step['details']}")

    print("\n--- Testing File ML ---")
    phish_file = "update_patch.exe"
    legit_file = "vacation_photo.jpg"
    
    res3 = analyze_file(phish_file)
    print(f"Phish File: Verdict={res3['verdict']}, Score={res3['score']}")
    res4 = analyze_file(legit_file)
    print(f"Legit File: Verdict={res4['verdict']}, Score={res4['score']}")

if __name__ == "__main__":
    test_ml()
