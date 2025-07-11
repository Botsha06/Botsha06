from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_migrate import Migrate
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
import os
SQLAlchemy_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///database.db')
import cloudinary
import cloudinary.uploader

# -------------------- App Setup --------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'bithiah$z5t78@!super#secret_key2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# -------------------- Email Config --------------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'botbithiah@gmail.com'
app.config['MAIL_PASSWORD'] = 'qdyd ubil vofl vhly'
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# -------------------- Cloudinary Config --------------------
cloudinary.config(
    cloud_name='df0w9iplz',
    api_key='239657756234486',
    api_secret='rgM_xepk-D2UDEjTthXlvnm-iRw'
)

# -------------------- Extensions --------------------
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# -------------------- Models --------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50))
    complaints = db.relationship('Complaint', backref='user', lazy=True)

class ResidentProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    phone = db.Column(db.String(20))
    house_number = db.Column(db.String(50))
    emergency_contact = db.Column(db.String(100))
    user = db.relationship('User', backref=db.backref('resident_profile', uselist=False))

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_path = db.Column(db.String(300))
    category = db.Column(db.String(100))
    status = db.Column(db.String(50), default='Pending')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)


# -------------------- Auth Loader --------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- Helper Functions --------------------
def generate_reset_token(email):
    return serializer.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    try:
        return serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except:
        return None

def send_reset_email(user_email, token):
    reset_url = url_for('reset_password', token=token, _external=True)
    msg = Message('Password Reset Request', recipients=[user_email])
    msg.html = f'''
    <html><body>
        <h2>Password Reset Request</h2>
        <p>Click <a href="{reset_url}">here</a> to reset your password. Link expires in 1 hour.</p>
    </body></html>'''
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# -------------------- Routes --------------------
@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email'].strip()
        password = request.form['password']
        role = request.form['role']
        if User.query.filter_by(email=email).first():
            flash("Email already exists.")
            return redirect('/register')
        hashed = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, email=email, password=hashed, role=role)
        db.session.add(new_user)
        db.session.commit()
        if role == 'user':
            db.session.add(ResidentProfile(user_id=new_user.id))
            db.session.commit()
        flash('Registered successfully! You can now login.')
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!')
            return redirect('/admin' if user.role == 'admin' else '/dashboard')
        flash('Invalid email or password.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash('❌ Invalid or expired reset link.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')

        if password != confirm:
            flash('❌ Passwords do not match.', 'danger')
        elif len(password) < 5:
            flash('❌ Password must be at least 7 characters.', 'danger')
        else:
            user = User.query.filter_by(email=email).first()
            if user:
                user.password = generate_password_hash(password, method='pbkdf2:sha256')
                db.session.commit()
                flash('✅ Password reset successful! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('❌ User not found.', 'danger')
    return render_template('reset_password.html', token=token)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role != 'user':
        return redirect('/admin')
    filter_date = request.args.get('filter_date')
    search = request.args.get('search', '').lower()
    page = int(request.args.get('page', 1))
    per_page = 2

    query = Complaint.query.filter_by(user_id=current_user.id)
    if filter_date:
        query = query.filter(Complaint.timestamp.like(f"{filter_date}%"))
    if search:
        query = query.filter(Complaint.title.ilike(f"%{search}%") | Complaint.description.ilike(f"%{search}%"))

    total = query.count()
    complaints = query.order_by(Complaint.timestamp.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return render_template("dashboard.html", complaints=complaints, current_page=page, total_pages=(total + per_page - 1) // per_page, user=current_user)

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect('/dashboard')

    # Filter and search parameters from URL
    filter_date = request.args.get('filter_date', '')
    search = request.args.get('search', '').lower()
    category = request.args.get('category', '')
    page = int(request.args.get('page', 1))
    per_page = 2

    # Base query
    complaints_query = Complaint.query

    if filter_date:
        complaints_query = complaints_query.filter(
            Complaint.timestamp.like(f"{filter_date}%")
        )

    if category:
        complaints_query = complaints_query.filter(
            Complaint.category == category
        )

    if search:
        complaints_query = complaints_query.filter(
            Complaint.title.ilike(f'%{search}%') |
            Complaint.description.ilike(f'%{search}%')
        )

    # Pagination logic
    total = complaints_query.count()
    total_pages = (total + per_page - 1) // per_page

    complaints = complaints_query.order_by(Complaint.timestamp.desc()) \
                                 .offset((page - 1) * per_page) \
                                 .limit(per_page) \
                                 .all()

    # Distinct category list for filter dropdown
    all_categories = db.session.query(Complaint.category).distinct().all()
    all_categories = [c[0] for c in all_categories if c[0]]

    return render_template(
        'admin_dashboard.html',
        complaints=complaints,
        current_page=page,
        total_pages=total_pages,
        filter_date=filter_date,
        current_category=category,
        current_search=search,
        categories=all_categories
    )

@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form.get('category')
        image_file = request.files.get('image')
        image_path = ''
        if image_file and image_file.filename:
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
            image_path = filename
        complaint = Complaint(title=title, description=description, category=category, image_path=image_path, user_id=current_user.id)
        db.session.add(complaint)
        db.session.commit()
        flash("Complaint submitted!")
        return redirect('/dashboard')
    return render_template('submit.html')

@app.route('/admin/delete/<int:complaint_id>', methods=['POST'])
@login_required
def delete_complaint(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    db.session.delete(complaint)
    db.session.commit()
    flash('Complaint deleted.')
    return redirect('/admin')

@app.route('/admin/update/<int:complaint_id>', methods=['POST'])
@login_required
def update_complaint(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    new_status = request.form['status']

    if new_status == 'resolved' and complaint.status != 'resolved':
        complaint.resolved_at = datetime.utcnow()

    complaint.status = new_status
    db.session.commit()
    flash('Complaint status updated!')
    return redirect('/admin')

@app.route('/resident-info', methods=['GET', 'POST'])
@login_required
def resident_info():
    profile = ResidentProfile.query.filter_by(user_id=current_user.id).first()
    if request.method == 'POST':
        current_user.name = request.form['name']
        if profile:
            profile.phone = request.form['phone']
            profile.house_number = request.form['house_number']
            profile.emergency_contact = request.form.get('emergency_contact')
        else:
            profile = ResidentProfile(user_id=current_user.id, phone=request.form['phone'], house_number=request.form['house_number'], emergency_contact=request.form.get('emergency_contact'))
            db.session.add(profile)
        db.session.commit()
        flash("Profile updated.")
        return redirect('/dashboard')
    return render_template('resident_info.html', profile=profile)

@app.route('/search-suggestions')
@login_required
def search_suggestions():
    query = request.args.get('query', '').lower()
    if not query:
        return jsonify([])
    results = Complaint.query.filter(
        Complaint.user_id == current_user.id,
        Complaint.title.ilike(f'%{query}%')
    ).limit(5).all()
    return jsonify([c.title for c in results])


@app.route('/admin/complaint/<int:complaint_id>')
@login_required
def view_complaint(complaint_id):
    if current_user.role != 'admin':
        return redirect('/dashboard')
    
    complaint = Complaint.query.get_or_404(complaint_id)
    return render_template('view_complaint.html', complaint=complaint)


@app.route('/admin/export')
def export_complaints():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Title', 'Description', 'Category', 'Status', 'User', 'Phone', 'Date'])

    for c in Complaint.query.all():
        writer.writerow([
            c.title, c.description, c.category, c.status,
            c.user.name,
            c.user.resident_profile.phone if c.user.resident_profile else 'N/A',
            c.timestamp.strftime('%Y-%m-%d %H:%M')
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=complaints.csv"
    response.headers["Content-type"] = "text/csv"
    return response

# -------------------- Run App --------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
