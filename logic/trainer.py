import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import joblib
import os

def train_models():
    # 1. Create models directory if not exists
    if not os.path.exists('models'):
        os.makedirs('models')

    # 2. Train Email Model
    print("Training Email Model...")
    email_data = pd.read_csv('data/emails.csv')
    email_pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(stop_words='english')),
        ('nb', MultinomialNB())
    ])
    email_pipeline.fit(email_data['text'], email_data['label'])
    joblib.dump(email_pipeline, 'models/email_model.joblib')
    print("Email Model trained and saved.")

    # 3. Train File Model
    print("Training File Model...")
    file_data = pd.read_csv('data/files.csv')
    file_pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(analyzer='char', ngram_range=(2, 4))),
        ('nb', MultinomialNB())
    ])
    file_pipeline.fit(file_data['filename'], file_data['label'])
    joblib.dump(file_pipeline, 'models/file_model.joblib')
    print("File Model trained and saved.")

if __name__ == "__main__":
    train_models()
