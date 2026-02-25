import mysql.connector
from mysql.connector import errorcode
import os
from dotenv import load_dotenv

load_dotenv()

def get_db_connection():
    """Establishes and returns a connection to the MySQL database."""
    try:
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', ''),
            database=os.getenv('DB_NAME', 'ped_eds_db')
        )
        return conn
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_BAD_DB_ERROR:
            # Create database if it doesn't exist
            return create_database()
        else:
            print(f"Error: {err}")
            return None

def create_database():
    """Creates the database and returns a connection."""
    try:
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', '')
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {os.getenv('DB_NAME', 'ped_eds_db')}")
        conn.database = os.getenv('DB_NAME', 'ped_eds_db')
        return conn
    except mysql.connector.Error as err:
        print(f"Failed creating database: {err}")
        return None

def init_db():
    """Initializes the database schema."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = conn.cursor()
    
    tables = {}
    
    tables['emails'] = (
        "CREATE TABLE IF NOT EXISTS emails ("
        "  id INT AUTO_INCREMENT PRIMARY KEY,"
        "  subject TEXT,"
        "  sender VARCHAR(255),"
        "  body LONGTEXT,"
        "  phishing_probability FLOAT,"
        "  emotional_deception_score FLOAT,"
        "  verdict VARCHAR(50),"
        "  confidence FLOAT,"
        "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ") ENGINE=InnoDB"
    )
    
    tables['emotion_scores'] = (
        "CREATE TABLE IF NOT EXISTS emotion_scores ("
        "  id INT AUTO_INCREMENT PRIMARY KEY,"
        "  email_id INT,"
        "  fear FLOAT,"
        "  urgency FLOAT,"
        "  trust FLOAT,"
        "  greed FLOAT,"
        "  authority FLOAT,"
        "  FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE"
        ") ENGINE=InnoDB"
    )
    
    tables['training_data'] = (
        "CREATE TABLE IF NOT EXISTS training_data ("
        "  id INT AUTO_INCREMENT PRIMARY KEY,"
        "  text LONGTEXT,"
        "  label VARCHAR(50),"
        "  dataset_version VARCHAR(50),"
        "  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ") ENGINE=InnoDB"
    )
    
    tables['scan_logs'] = (
        "CREATE TABLE IF NOT EXISTS scan_logs ("
        "  id INT AUTO_INCREMENT PRIMARY KEY,"
        "  scan_type VARCHAR(50),"
        "  risk_score FLOAT,"
        "  verdict VARCHAR(50),"
        "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ") ENGINE=InnoDB"
    )
    
    tables['feedback'] = (
        "CREATE TABLE IF NOT EXISTS feedback ("
        "  id INT AUTO_INCREMENT PRIMARY KEY,"
        "  name VARCHAR(255),"
        "  message TEXT,"
        "  rating INT,"
        "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ") ENGINE=InnoDB"
    )
    
    for table_name in tables:
        table_description = tables[table_name]
        try:
            print(f"Creating table {table_name}: ", end='')
            cursor.execute(table_description)
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_TABLE_EXISTS_ERROR:
                print("already exists.")
            else:
                print(err.msg)
        else:
            print("OK")

    cursor.close()
    conn.close()
    return True

def store_email_scan(data, emotion_breakdown):
    """Stores email scan results and emotion scores."""
    conn = get_db_connection()
    if not conn:
        return None
    
    cursor = conn.cursor()
    
    # Store email
    add_email = (
        "INSERT INTO emails "
        "(subject, sender, body, phishing_probability, emotional_deception_score, verdict, confidence) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)"
    )
    email_data = (
        data.get('subject', 'Unknown Subject'),
        data.get('sender', 'Unknown Sender'),
        data.get('body', ''),
        data.get('phishing_probability', 0.0),
        data.get('emotional_deception_score', 0.0),
        data.get('verdict', 'safe'),
        data.get('confidence', 0.0)
    )
    
    try:
        cursor.execute(add_email, email_data)
        email_id = cursor.lastrowid
        
        # Store emotion scores
        add_emotions = (
            "INSERT INTO emotion_scores "
            "(email_id, fear, urgency, trust, greed, authority) "
            "VALUES (%s, %s, %s, %s, %s, %s)"
        )
        emotion_data = (
            email_id,
            emotion_breakdown.get('fear', 0.0),
            emotion_breakdown.get('urgency', 0.0),
            emotion_breakdown.get('trust', 0.0),
            emotion_breakdown.get('greed', 0.0),
            emotion_breakdown.get('authority', 0.0)
        )
        cursor.execute(add_emotions, emotion_data)
        
        conn.commit()
        return email_id
    except mysql.connector.Error as err:
        print(f"Error storing email scan: {err}")
        conn.rollback()
        return None
    finally:
        cursor.close()
        conn.close()

def store_scan_log(scan_type, risk_score, verdict):
    """Stores a log of a URL or File scan."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = conn.cursor()
    add_log = (
        "INSERT INTO scan_logs "
        "(scan_type, risk_score, verdict) "
        "VALUES (%s, %s, %s)"
    )
    log_data = (scan_type, risk_score, verdict)
    
    try:
        cursor.execute(add_log, log_data)
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error storing scan log: {err}")
        return False
    finally:
        cursor.close()
        conn.close()

def store_feedback(name, message, rating):
    """Stores user feedback."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cursor = conn.cursor()
    add_feedback = (
        "INSERT INTO feedback "
        "(name, message, rating) "
        "VALUES (%s, %s, %s)"
    )
    feedback_data = (name, message, rating)
    
    try:
        cursor.execute(add_feedback, feedback_data)
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error storing feedback: {err}")
        return False
    finally:
        cursor.close()
        conn.close()
