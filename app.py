import os
import secrets
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
from flask import Flask, render_template_string, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-dev-key-change-later' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eligiblestamp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='student')
    irp_filename = db.Column(db.String(200), nullable=True) 
    is_verified = db.Column(db.Boolean, default=False) 
    share_token = db.Column(db.String(100), unique=True, nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)
    mfa_secret = db.Column(db.String(32), nullable=True) # NEW: For MFA

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route("/")
def home():
    if current_user.is_authenticated:
        if current_user.role == 'student':
            return redirect(url_for('student_dashboard'))
        elif current_user.role == 'verifier':
            return redirect(url_for('verifier_dashboard'))
        elif current_user.role == 'employer':
            return redirect(url_for('employer_dashboard'))
        elif current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return f"<h1>Dashboard</h1><p>Welcome {current_user.email}!</p><a href='/logout'>Logout</a>"
    return "<h1>Welcome to EligibleStampIE</h1><a href='/register'>Register</a> | <a href='/login'>Login</a>"

# --- STUDENT ROUTE ---
@app.route("/student", methods=['GET', 'POST'])
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return "Access Denied.", 403

    if request.method == 'POST':
        if 'irp_file' not in request.files:
            return "No file part"
        file = request.files['irp_file']
        if file.filename == '':
            return "No selected file"
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"user_{current_user.id}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)
            
            current_user.irp_filename = unique_filename
            current_user.is_verified = False 
            db.session.commit()
            return f"File uploaded securely! <a href='/student'>Go back</a>"

    if current_user.is_verified:
        status = "✅ Verified by College"
    elif current_user.irp_filename:
        status = "⏳ Pending Verification"
    else:
        status = "❌ No document uploaded"

    share_link_html = ""
    if current_user.is_verified:
        if not current_user.share_token:
            current_user.share_token = secrets.token_urlsafe(32)
            current_user.token_expiry = datetime.utcnow() + timedelta(days=31)
            db.session.commit()
        
        if current_user.token_expiry and current_user.token_expiry > datetime.utcnow():
            share_link_html = f'''
                <div style="border:1px solid green; padding:10px; margin-top:20px; background:#e8f5e9;">
                    <h3>Share with Employer</h3>
                    <p>Send this secure link to your employer:</p>
                    <code>http://127.0.0.1:5000/verify/{current_user.share_token}</code>
                    <p><small>Expires on: {current_user.token_expiry.strftime('%Y-%m-%d %H:%M')}</small></p>
                </div>
            '''
        else:
             share_link_html = "<p style='color:red;'>Share link expired. Please refresh to generate a new one.</p>"
             current_user.share_token = None
             current_user.token_expiry = None
             db.session.commit()

    return f'''
        <h2>Student Dashboard</h2>
        <p>Welcome, {current_user.email}</p>
        <p><b>Status:</b> {status}</p><hr>
        <h3>Upload IRP Document</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="irp_file" required>
            <button type="submit">Upload</button>
        </form><br>
        {share_link_html}
        <br><a href="/logout">Logout</a>
    '''

# --- VERIFIER ROUTE ---
@app.route("/verifier", methods=['GET', 'POST'])
@login_required
def verifier_dashboard():
    if current_user.role != 'verifier':
        return "Access Denied. Only verifiers can see this.", 403

    if request.method == 'POST':
        student_id = request.form.get('student_id')
        student = db.session.get(User, int(student_id))
        
        if student and student.irp_filename:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], student.irp_filename)
            if os.path.exists(filepath):
                os.remove(filepath) 
            student.is_verified = True
            student.irp_filename = None 
            db.session.commit()
            return f"Student {student.email} approved. Document securely deleted. <a href='/verifier'>Go back</a>"

    pending_students = User.query.filter_by(role='student', is_verified=False).all()
    html = "<h2>Verifier Dashboard</h2>"
    if not pending_students:
        html += "<p>No pending verifications.</p>"
    else:
        for s in pending_students:
            if s.irp_filename:
                html += f'''
                <div style="border:1px solid black; padding:10px; margin:10px;">
                    <p>Student: <b>{s.email}</b></p>
                    <form method="POST">
                        <input type="hidden" name="student_id" value="{s.id}">
                        <button type="submit" style="background:green; color:white;">Approve & Delete File</button>
                    </form>
                </div>
                '''
    html += "<br><a href='/logout'>Logout</a>"
    return html

# --- EMPLOYER ROUTE ---
@app.route("/employer")
@login_required
def employer_dashboard():
    if current_user.role != 'employer':
        return "Access Denied.", 403
   
    # MFA Setup Link
    mfa_status = "<p style='color:green;'>✅ MFA is enabled</p>" if current_user.mfa_secret else "<p style='color:red;'><a href='/setup_mfa'>Setup MFA (Required for Security)</a></p>"
        
    return f'''
            <h2>Employer Dashboard</h2>
            <p>Welcome, {current_user.email}.</p>
            {mfa_status}
            <p>Please enter the share link provided by the student to verify their eligibility.</p>
            <br><a href="/logout">Logout</a>
        '''

# --- ADMIN ROUTE ---
@app.route("/admin")
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return "Access Denied. Only Admins can see this.", 403
    
    # Get all users from the database
    all_users = User.query.all()
    
    html = "<h2>Admin Dashboard</h2>"
    html += "<p>Welcome, System Administrator.</p>"
    html += "<table border='1' style='border-collapse: collapse; width: 100%;'>"
    html += "<tr><th>ID</th><th>Email</th><th>Role</th><th>Verified Status</th></tr>"
    
    for u in all_users:
        status = "✅ Verified" if u.is_verified else "❌ Not Verified"
        if u.role != 'student':
            status = "N/A"
        html += f"<tr><td>{u.id}</td><td>{u.email}</td><td>{u.role.capitalize()}</td><td>{status}</td></tr>"
        
    html += "</table><br>"
    html += "<a href='/logout'>Logout</a>"

    return html

# --- PUBLIC VERIFICATION ROUTE (The Share Link) ---
@app.route("/verify/<token>")
def verify_student(token):
    student = User.query.filter_by(share_token=token).first()
    
    if not student:
        return "<h2>❌ Invalid or Expired Link</h2><p>This share link does not exist or has been revoked.</p>"
    
    if student.token_expiry < datetime.utcnow():
        return "<h2>❌ Link Expired</h2><p>This share link was only valid for 24 hours.</p>"

    return f'''
        <div style="text-align:center; margin-top:50px; font-family:Arial;">
            <h1 style="color:green;">✅ Verified Student</h1>
            <h2>{student.email}</h2>
            <p style="font-size:20px;"><b>Status:</b> Stamp 2 (Verified by College)</p>
            <p style="font-size:20px;"><b>Work Allowance:</b> 20 hours/week (Term Time)</p>
            <p style="color:gray;"><small>This link expires at: {student.token_expiry.strftime('%Y-%m-%d %H:%M')}</small></p>
        </div>
    '''

# --- MFA SETUP ROUTE ---
@app.route("/setup_mfa")
@login_required
def setup_mfa():
    if current_user.role != 'employer':
        return "Only employers need MFA.", 403
    
    if not current_user.mfa_secret:
        current_user.mfa_secret = pyotp.random_base32()
        db.session.commit()
    
    # Generate QR Code
    totp_uri = pyotp.totp.TOTP(current_user.mfa_secret).provisioning_uri(name=current_user.email, issuer_name="EligibleStampIE")
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf)
    image_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    return f'''
        <div style="text-align:center; margin-top:50px; font-family:Arial;">
            <h2>Setup Multi-Factor Authentication</h2>
            <p>1. Scan this QR code with Google Authenticator or Microsoft Authenticator:</p>
            <img src="data:image/png;base64,{image_base64}" style="border:1px solid black;">
            
            <p style="margin-top: 30px;">2. Or enter this setup key manually:</p>
            <h3 style="color:blue;">{current_user.mfa_secret}</h3>
            
            <br><br>
            <p><a href="/employer">Go back to Dashboard</a></p>
        </div>
    '''

# --- MFA VERIFY ROUTE ---
@app.route("/verify_2fa", methods=['GET', 'POST'])
def verify_2fa():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    user = db.session.get(User, user_id)
    
    if request.method == 'POST':
        code = request.form.get('code')
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(code):
            login_user(user)
            session.pop('pre_2fa_user_id', None)
            return redirect(url_for('home'))
        else:
            return "Invalid code. <a href='/verify_2fa'>Try again</a>"
            
    return '''
        <h2>Enter Authenticator Code</h2>
        <p>Open Google Authenticator and enter the 6-digit code.</p>
        <form method="POST">
            <input type="text" name="code" required><br><br>
            <button type="submit">Verify</button>
        </form>
    '''

# --- AUTH ROUTES ---
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
            Role:
<select name="role">
    <option value="student">Student</option>
    <option value="verifier">Verifier (College)</option>
    <option value="employer">Employer</option>
    <option value="admin">Admin</option>
</select>
<br><br>
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
            # --- MFA CHECK ---
            if user.role == 'employer' and user.mfa_secret:
                session['pre_2fa_user_id'] = user.id
                return redirect(url_for('verify_2fa'))
            
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

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)