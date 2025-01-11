from flask import Blueprint, request, jsonify, render_template, redirect, url_for, session, flash
from models import db, User
from flask_bcrypt import Bcrypt
import jwt
import datetime
import requests
from transformers import pipeline
from bs4 import BeautifulSoup
from forms import RegistrationForm, LoginForm
from functools import wraps
from flask import make_response

def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return no_cache

bcrypt = Bcrypt()
routes = Blueprint('routes', __name__)

# Load summarization model
try:
    summarizer = pipeline("summarization", model="facebook/bart-large-cnn")
    print("Model loaded successfully")
except Exception as e:
    print("Error loading model:", e)

@routes.get('/')
@nocache
def index():
    return render_template('index.html')

@routes.route('/register', methods=['GET', 'POST'])
@nocache
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('User already exists', 'danger')
            return redirect(url_for('routes.register'))
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('User registered successfully', 'success')
        return redirect(url_for('routes.login'))
    return render_template('index.html', form=form)

@routes.route('/login', methods=['GET', 'POST'])
@nocache
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            token = jwt.encode({
                'email': user.email,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }, 'your_secret_key', algorithm='HS256')
            session['token'] = token
            flash('Login successful', 'success')
            return redirect(url_for('routes.home'))
        flash('Invalid credentials', 'danger')
    return render_template('index.html', form=form)

@routes.route('/home')
@nocache
def home():
    token = session.get('token')
    if not token:
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('routes.login'))
    try:
        data = jwt.decode(token, 'your_secret_key', algorithms=['HS256'])
        return render_template('home.html', email=data['email'])
    except jwt.ExpiredSignatureError:
        flash('Token has expired', 'danger')
        return redirect(url_for('routes.login'))
    except jwt.InvalidTokenError:
        flash('Invalid token', 'danger')
        return redirect(url_for('routes.login'))

@routes.route('/logout')
@nocache
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('routes.login'))

@routes.route('/protected')
@nocache
def protected():
    token = session.get('token')
    if not token:
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('routes.login'))
    try:
        data = jwt.decode(token, 'your_secret_key', algorithms=['HS256'])
        return jsonify({'message': 'This is a protected route', 'email': data['email']})
    except jwt.ExpiredSignatureError:
        flash('Token has expired', 'danger')
        return redirect(url_for('routes.login'))
    except jwt.InvalidTokenError:
        flash('Invalid token', 'danger')
        return redirect(url_for('routes.login'))

@routes.route('/summarize', methods=['POST'])
@nocache
def summarize():
    token = session.get('token')
    if not token:
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('routes.login'))
    try:
        data = jwt.decode(token, 'your_secret_key', algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        flash('Token has expired', 'danger')
        return redirect(url_for('routes.login'))
    except jwt.InvalidTokenError:
        flash('Invalid token', 'danger')
        return redirect(url_for('routes.login'))

    try:
        url = request.form.get('url')
        manual_text = request.form.get('manual_text')
        start = int(request.form['start'])
        end = int(request.form['end'])

        if url:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            paragraphs = soup.find_all('p')
            text = ' '.join(p.get_text() for p in paragraphs)
        elif manual_text:
            text = manual_text
        else:
            flash('Please provide a URL or enter text manually', 'danger')
            return redirect(url_for('routes.home'))

        if len(text) > end:
            text = text[start:end]
        else:
            text = text[start:]
    except Exception as e:
        return jsonify({"error": "Failed to fetch the webpage or process the text", "details": str(e)})

    try:
        summary = summarizer(text, max_length=400, min_length=100, do_sample=False)[0]['summary_text']
        summary_sentences = summary.split('. ')
    except Exception as e:
        return jsonify({"error": "Failed to summarize the content", "details": str(e)})

    return render_template('summary.html', summary_sentences=summary_sentences)

@routes.before_request
def check_authentication():
    if request.endpoint in ['routes.home', 'routes.protected', 'routes.summarize'] and 'token' not in session:
        flash('Please log in to access this page', 'danger')
        return redirect(url_for('routes.login'))