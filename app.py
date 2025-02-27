from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import secrets
from functools import wraps
from flask_migrate import Migrate

app = Flask(__name__)
# Use environment variables for sensitive configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)  # Session timeout
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile_image = db.Column(db.String(150), default='default.jpg')
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

# Service Request model
class ServiceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_type = db.Column(db.String(50), nullable=False)  # 'passport', 'invitation', 'business'
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'in_progress', 'completed', 'cancelled'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    notes = db.Column(db.Text, nullable=True)  # Admin notes
    price = db.Column(db.Float, nullable=True)  # Optional price field
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='service_requests')

# New Notification model
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='notifications')

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('Access denied!', 'danger')
            return redirect(url_for('index'))
            
        return f(*args, **kwargs)
    return decorated_function

# Home route
@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.filter_by(id=session['user_id']).first()
        # Get user's service requests
        if user:
            requests = ServiceRequest.query.filter_by(user_id=user.id).order_by(ServiceRequest.created_at.desc()).limit(5).all()
            unread_notifications = Notification.query.filter_by(user_id=user.id, is_read=False).count()
            return render_template('home.html', 
                                 user=user, 
                                 requests=requests, 
                                 unread_notifications=unread_notifications,
                                 now=datetime.now())
    return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session.permanent = remember  # Set session to permanent if remember is checked
            
            # Create a login notification
            notification = Notification(
                message=f"You logged in at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}",
                user_id=user.id
            )
            db.session.add(notification)
            db.session.commit()
            
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate input
        if len(username) < 3:
            flash('Username must be at least 3 characters long', 'danger')
            return redirect(url_for('register'))
            
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        # Check if user exists
        user = User.query.filter((User.username == username) | (User.email == email)).first()
        if user:
            flash('Username or email already exists', 'danger')
            return redirect(url_for('register'))
        
        # Check if this is the admin account - consider using environment variables for this
        is_admin = (username == os.environ.get('ADMIN_USERNAME', 'ramanghorpade0') and 
                    email == os.environ.get('ADMIN_EMAIL', 'ramanghorpade2069@gmail.com'))
        
        new_user = User(
            username=username, 
            email=email, 
            password=generate_password_hash(password),
            is_admin=is_admin
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# User profile route
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate email
        if email != user.email:
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash('Email already in use', 'danger')
                return redirect(url_for('profile'))
            user.email = email
        
        # Change password if provided
        if current_password and new_password and confirm_password:
            if not check_password_hash(user.password, current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('profile'))
                
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('profile'))
                
            if len(new_password) < 6:
                flash('Password must be at least 6 characters long', 'danger')
                return redirect(url_for('profile'))
                
            user.password = generate_password_hash(new_password)
            
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))
        
    return render_template('profile.html', user=user)

# Services page
@app.route('/services')
@login_required
def services():
    user = User.query.get(session['user_id'])
    service_types = [
        {'id': 'passport', 'name': 'Passport Size Photo', 'description': 'Professional passport size photos meeting all requirements.'},
        {'id': 'invitation', 'name': 'Invitation Card', 'description': 'Custom designed invitation cards for all occasions.'},
        {'id': 'business', 'name': 'Business Card', 'description': 'Professional business cards with your branding.'},
        {'id': 'portrait', 'name': 'Portrait Photography', 'description': 'Professional portrait photography sessions.'},
        {'id': 'event', 'name': 'Event Photography', 'description': 'Full event photography coverage.'}
    ]
    return render_template('services.html', user=user, service_types=service_types)

# Submit service request
@app.route('/submit_request', methods=['POST'])
@login_required
def submit_request():
    service_type = request.form.get('service_type')
    description = request.form.get('description')
    
    new_request = ServiceRequest(
        service_type=service_type,
        description=description,
        user_id=session['user_id']
    )
    db.session.add(new_request)
    
    # Add notification for the user
    notification = Notification(
        message=f"Your {service_type} request has been submitted and is pending review.",
        user_id=session['user_id']
    )
    db.session.add(notification)
    
    db.session.commit()
    flash('Service request submitted successfully!', 'success')
    return redirect(url_for('my_requests'))

# My requests page
@app.route('/my_requests')
@login_required
def my_requests():
    user = User.query.get(session['user_id'])
    requests = ServiceRequest.query.filter_by(user_id=user.id).order_by(ServiceRequest.created_at.desc()).all()
    return render_template('my_requests.html', user=user, requests=requests)

# View specific request
@app.route('/request/<int:request_id>')
@login_required
def view_request(request_id):
    user = User.query.get(session['user_id'])
    service_request = ServiceRequest.query.get_or_404(request_id)
    
    # Check if the request belongs to the user or if user is admin
    if service_request.user_id != user.id and not user.is_admin:
        flash('Access denied!', 'danger')
        return redirect(url_for('my_requests'))
        
    return render_template('view_request.html', user=user, request=service_request)

# Admin dashboard
@app.route('/admin')
@admin_required
def admin_dashboard():
    requests = ServiceRequest.query.order_by(ServiceRequest.created_at.desc()).all()
    pending_count = ServiceRequest.query.filter_by(status='pending').count()
    in_progress_count = ServiceRequest.query.filter_by(status='in_progress').count()
    completed_count = ServiceRequest.query.filter_by(status='completed').count()
    
    return render_template('admin_dashboard.html', 
                          requests=requests, 
                          pending_count=pending_count,
                          in_progress_count=in_progress_count,
                          completed_count=completed_count)

# Update service status
@app.route('/update_status/<int:request_id>', methods=['POST'])
@admin_required
def update_status(request_id):
    service_request = ServiceRequest.query.get_or_404(request_id)
    old_status = service_request.status
    new_status = request.form.get('status')
    notes = request.form.get('notes')
    price = request.form.get('price')
    
    service_request.status = new_status
    if notes:
        service_request.notes = notes
    if price:
        try:
            service_request.price = float(price)
        except ValueError:
            flash('Invalid price format', 'danger')
            return redirect(url_for('admin_dashboard'))
    
    # Create notification for the user
    if old_status != new_status:
        notification = Notification(
            message=f"Your {service_request.service_type} request status has been updated to {new_status}.",
            user_id=service_request.user_id
        )
        db.session.add(notification)
    
    db.session.commit()
    flash('Status updated successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

# Notifications page
@app.route('/notifications')
@login_required
def notifications():
    user = User.query.get(session['user_id'])
    notifications = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).all()
    
    # Mark all as read
    for notification in notifications:
        notification.is_read = True
    db.session.commit()
    
    return render_template('notifications.html', user=user, notifications=notifications)

# User management (Admin only)
@app.route('/admin/users')
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

# Admin can toggle user status (enable/disable)
@app.route('/admin/toggle_admin/<int:user_id>', methods=['POST'])
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    
    # Don't allow admin to remove their own admin status
    if user.id == session['user_id']:
        flash('You cannot change your own admin status', 'danger')
    else:
        user.is_admin = not user.is_admin
        db.session.commit()
        flash(f"Admin status for {user.username} has been {'granted' if user.is_admin else 'revoked'}", 'success')
        
    return redirect(url_for('manage_users'))

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

@app.context_processor
def utility_processor():
    return dict(now=datetime.now())

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=os.environ.get('DEBUG', 'True') == 'True')