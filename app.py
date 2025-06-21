import os
import warnings
import pickle
import sqlite3
import numpy as np
import pandas as pd

from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, session
from feature import FeatureExtraction
# from werkzeug.urls import url
# Ignore warnings
warnings.filterwarnings('ignore')

# Load the phishing detection model
with open("model.pkl", "rb") as file:
    gbc = pickle.load(file)

# Database file path
DATABASE = 'userdb.db'

# Initialize Flask app
app = Flask(__name__)

# Secure Flask session settings
app.config["SECRET_KEY"] = "your_secret_key_here"

# Configure Upload Folder
# UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# # Ensure the upload directory exists
# os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ----------------- ROUTES -----------------

# Initialize database if it doesn't exist
def init_db():

    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE userdb (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()
        
@app.route('/')
@app.route('/first')
def first():
    return render_template('first.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    print("registered")
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']
        print("username"+username)
        try:
            # Add user to database
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            print("conn done")
            c.execute("INSERT INTO userdb (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            flash('User ' + username + ' is registered successfully! User can login to the system now.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different username.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/performance')
def performance():
    return render_template('performance.html')

@app.route('/chart')
def chart():
    return render_template('chart.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        password = request.form['password']

        # Validate credentials
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT * FROM userdb WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            # Set session variables
            session['logged_in'] = True
            session['username'] = username
            return jsonify({'success': True, 'redirect_url': url_for('upload')})
        else:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

    return render_template('login.html')


@app.route('/upload')
def upload():
    print("upload")
    if not session.get('logged_in'):
        print("Ifff")
        flash('You must log in to access this page.', 'danger')
        return redirect(url_for('login'))
    if request.method == "POST":
        print("POST")
        return redirect(url_for('preview'))  # Redirect to preview function after upload
    return render_template('upload.html')

DEFAULT_FILE_PATH = "upload.csv"

@app.route('/preview', methods=["POST"])
def preview():
    if 'datasetfile' in request.files and request.files['datasetfile'].filename != '':
        # Case 1: User uploaded a file
        dataset = request.files['datasetfile']
        print("User uploaded file: {}".format(dataset.filename))
    else:
        # Case 2: Use default dataset
        dataset = DEFAULT_FILE_PATH
        print("Using default file: {}".format(DEFAULT_FILE_PATH))

    # Load dataset into a pandas DataFrame
    df = pd.read_csv(dataset, encoding='unicode_escape')
    df.set_index('Id', inplace=True)
    print("Done uploading")
    return render_template("preview.html", df_view=df)

# @app.route('/preview', methods=["POST"])
# def preview():
#     if 'datasetfile' in request.files and request.files['datasetfile'].filename != '':
#         # Case 1: User uploaded a file
#         dataset = request.files['datasetfile']
#         print("User uploaded file: {}".format(dataset.filename))
#         df = pd.read_csv(dataset, encoding='unicode_escape')
#     else:
#         # Case 2: Use default dataset
#         dataset = DEFAULT_FILE_PATH
#         print("Using default file: {}".format(DEFAULT_FILE_PATH))
#         df = pd.read_csv(dataset, encoding='unicode_escape')

    # # Check if 'URL' column exists
    # if 'URL' not in df.columns:
    #     flash("The uploaded CSV must contain a 'URL' column.", "danger")
    #     return redirect(url_for('upload'))
    #
    # # Perform batch feature extraction and prediction
    # features = []
    # for url in df['URL']:
    #     fe = FeatureExtraction(url)
    #     features.append(fe.getFeaturesList())
    #
    # X = np.array(features)
    # predictions = gbc.predict(X)
    # confidences = np.max(gbc.predict_proba(X), axis=1)

    # # Add results to the DataFrame
    # df['Prediction'] = predictions
    # df['Confidence (%)'] = (confidences * 100).round(2)
    #
    # # Optional: Map 1/0 to labels
    # df['Prediction'] = df['Prediction'].map({0: 'Phishing', 1: 'Legitimate'})
    #
    # # Optional: Set index if 'Id' exists
    # if 'Id' in df.columns:
    #     df.set_index('Id', inplace=True)
    #
    # print("Done processing file and predictions.")
    # return render_template("preview.html", df_view=df)

@app.route('/index')
def index():
    return render_template('index.html')

@app.route("/posts", methods=["GET", "POST"])
def posts():
    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if not url:
            return "Error: URL is required", 400  

        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)

        y_pred = gbc.predict(x)[0]
        y_pro_phishing = gbc.predict_proba(x)[0, 0]
        y_pro_non_phishing = gbc.predict_proba(x)[0, 1]

        pred = "It is {0:.2f}% safe to go".format(y_pro_phishing * 100)
        return render_template('result.html', xx=round(y_pro_non_phishing, 2), url=url)

    return render_template("result.html", xx=-1)

# Run Flask app
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
