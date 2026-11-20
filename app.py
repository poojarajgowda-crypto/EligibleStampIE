from flask import Flask, render_template_string, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# A secret key is required for sessions and flash messages
app.config['SECRET_KEY'] = 'super-secret-dev-key-change-later' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eligiblestamp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Force users to login if they try to access a protected page

# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='student') # student, verifier, employer, admin

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- ROUTES ---
@app.route("/")
def home():
    if current_user.is_authenticated:
        return f"<h1>Dashboard</h1><p>Welcome {current_user.email}! You are logged in as a <b>{current_user.role}</b>.</p><a href='/logout'>Logout</a>"
    return "<h1>Welcome to EligibleStampIE</h1><a href='/register'>Register</a> | <a href='/login'>Login</a>"

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        # Check if user already exists
        user = User.query.filter_by(email=email).first()
        if user:
            return "Email already exists. <a href='/register'>Try again</a>"
        
        # Create new user with secure password hashing
        new_user = User(
            email=email, 
            password_hash=generate_password_hash(password, method='scrypt'), 
            role=role
        )
        db.session.add(new_user)
        db.session.commit()
        
        return "Registration successful! <a href='/login'>Login here</a>"
        
    return '''
        <h2>Register</h2>
        <form method="POST">
            Email: <input type="email" name="email" required><br><br>
            Password: <input type="password" name="password" required><br><br>
            Role: 
            <select name="role">
                <option value="student">Student</option>
                <option value="verifier">Verifier (College)</option>
                <option value="employer">Employer</option>
                <option value="admin">Admin</option>
            </select><br><br>
            <button type="submit">Register</button>
        </form>
    '''

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        # Check if user exists AND the password matches the hash
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            return "Invalid credentials. <a href='/login'>Try again</a>"
            
    return '''
        <h2>Login</h2>
        <form method="POST">
            Email: <input type="email" name="email" required><br><br>
            Password: <input type="password" name="password" required><br><br>
            <button type="submit">Login</button>
        </form>
    '''

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# --- INITIALIZE DATABASE ---
# This creates the database file on first run
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)