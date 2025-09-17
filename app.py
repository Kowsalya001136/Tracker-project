from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure random key in production

# In-memory user store: {username: {password_hash: ..., email: ...}}
users = {}

# Decorator to require login
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')

        user = users.get(username)
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        accept_terms = request.form.get('accept_terms')

        if not username or not email or not password or not confirm_password:
            flash('Please fill out all fields.', 'warning')
        elif password != confirm_password:
            flash('Passwords do not match.', 'warning')
        elif username in users:
            flash('Username already exists.', 'warning')
        elif accept_terms != 'on':
            flash('You must accept the terms and conditions.', 'warning')
        else:
            password_hash = generate_password_hash(password)
            users[username] = {'password_hash': password_hash, 'email': email}
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    username = session.get('username')
    return render_template('home.html', username=username)

# Feature routes (placeholders)
@app.route('/feature/<name>')
@login_required
def feature(name):
    # Validate feature name
    valid_features = ['mood-music', 'motivation-chatbot', 'food-bot', 'period-tracker', 'bmi-calculator']
    if name not in valid_features:
        flash('Feature not found.', 'danger')
        return redirect(url_for('home'))
    return render_template('feature.html', feature_name=name.replace('-', ' ').title())

if __name__ == '__main__':
    app.run(debug=True)
