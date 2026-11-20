import os
from flask import Flask, render_template_string, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-dev-key-change-later' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eligiblestamp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- UPLOAD CONFIGURATION (Security) ---
# Store files in an 'uploads' folder outside the main app code
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 # Max 5MB file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='student')
    # New fields for IRP
    irp_filename = db.Column(db.String(200), nullable=True) # Stores the unique filename
    is_verified = db.Column(db.Boolean, default=False) # Verifier changes this to True

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- ROUTES ---
@app.route("/")
def home():
    if current_user.is_authenticated:
        # Redirect based on role
        if current_user.role == 'student':
            return redirect(url_for('student_dashboard'))
        return f"<h1>Dashboard</h1><p>Welcome {current_user.email}! You are logged in as a <b>{current_user.role}</b>.</p><a href='/logout'>Logout</a>"
    
    return "<h1>Welcome to EligibleStampIE</h1><a href='/register'>Register</a> | <a href='/login'>Login</a>"

@app.route("/student", methods=['GET', 'POST'])
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return "Access Denied. You are not a student.", 403

    if request.method == 'POST':
        # Handle file upload securely
        if 'irp_file' not in request.files:
            return "No file part"
        file = request.files['irp_file']
        if file.filename == '':
            return "No selected file"
        
        if file and allowed_file(file.filename):
            # Secure the filename so hackers can't use path traversal (e.g., ../../etc/passwd)
            filename = secure_filename(file.filename)
            # Add user ID to filename so files don't overwrite each other
            unique_filename = f"user_{current_user.id}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            file.save(filepath)
            
            # Save filename to database
            current_user.irp_filename = unique_filename
            current_user.is_verified = False # Reset to false if they upload a new one
            db.session.commit()
            return f"File uploaded securely! <a href='/student'>Go back</a>"
        else:
            return "Invalid file type. Only PNG, JPG, and PDF allowed."

    # Display the page
    verification_status = "✅ Verified by College" if current_user.is_verified else "⏳ Pending Verification"
    if not current_user.irp_filename:
        verification_status = "❌ No document uploaded"

    return f'''
        <h2>Student Dashboard</h2>
        <p>Welcome, {current_user.email}</p>
        <p><b>Status:</b> {verification_status}</p>
        <hr>
        <h3>Upload IRP Document</h3>
        <p>(For privacy, your document is stored securely and deleted after verification)</p>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="irp_file" required>
            <button type="submit">Upload</button>
        </form>
        <br>
        <a href="/logout">Logout</a>
    '''

# (Login, Register, Logout routes remain the same)
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        user = User.query.filter_by(email=email).first()
        if user:
            return "Email already exists. <a href='/register'>Try again</a>"
        new_user = User(email=email, password_hash=generate_password_hash(password, method='scrypt'), role=role)
        db.session.add(new_user)
        db.session.commit()
        return "Registration successful! <a href='/login'>Login here</a>"
    return '''
        <h2>Register</h2>
        <form method="POST">
            Email: <input type="email" name="email" required><br><br>
            Password: <input type="password" name="password" required><br><br>
            Role: <select name="role"><option value="student">Student</option><option value="verifier">Verifier (College)</option><option value="employer">Employer</option></select><br><br>
            <button type="submit">Register</button>
        </form>
    '''

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
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
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)