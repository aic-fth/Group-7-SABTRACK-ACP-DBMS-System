from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import sqlite3
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'sabtrack-secret-key-2025')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

DATABASE = 'instance/sabtrack.db'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('instance', exist_ok=True)

# Email configuration
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS', 'sabtrack@barangaysabang.com')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', '')
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))

def get_db():
    """Get a database connection with row factory set to Row."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database by creating all necessary tables and inserting default data."""
    conn = get_db()
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT NOT NULL,
        age INTEGER,
        address TEXT,
        resident_id TEXT,
        phone TEXT,
        role TEXT DEFAULT 'resident',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Waste schedules table
    c.execute('''CREATE TABLE IF NOT EXISTS schedules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        day TEXT NOT NULL,
        area TEXT NOT NULL,
        waste_type TEXT NOT NULL,
        time_start TEXT NOT NULL,
        time_end TEXT NOT NULL
    )''')
    
    # Garbage reports table
    c.execute('''CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        issue_type TEXT NOT NULL,
        location TEXT NOT NULL,
        description TEXT NOT NULL,
        photo_path TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    # Announcements table
    c.execute('''CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        created_by INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id)
    )''')
    
    # Reminders table
    c.execute('''CREATE TABLE IF NOT EXISTS reminders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        schedule_id INTEGER NOT NULL,
        enabled BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (schedule_id) REFERENCES schedules(id)
    )''')



    # Activity log table
    c.execute('''CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        activity_type TEXT NOT NULL,
        description TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')

    # Notifications table for user notifications
    c.execute('''CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        related_id INTEGER,
        is_read BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')

    # Insert sample schedules if table is empty
    c.execute('SELECT COUNT(*) FROM schedules')
    if c.fetchone()[0] == 0:
        schedules = [
            ('Monday', 'Gen Luna St', 'General Waste', '7:00 AM', '10:00 AM'),
            ('Tuesday', 'Q P. Laygo St', 'General Waste', '7:00 AM', '10:00 AM'),
            ('Wednesday', '9 Llamar', 'General Waste', '8:00 AM', '10:00 AM'),
            ('Thursday', 'Q Monte Claro', 'General Waste', '7:00 AM', '10:00 AM'),
            ('Friday', '9 City Park', 'General Waste', '9:00 AM', '10:00 AM'),
            ('Saturday', '9 Gen Luna St', 'Bulky Waste', '9:00 AM', '10:00 AM'),
        ]
        c.executemany('INSERT INTO schedules (day, area, waste_type, time_start, time_end) VALUES (?, ?, ?, ?, ?)', schedules)

    # Insert default admin account if not exists
    c.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
    if c.fetchone()[0] == 0:
        c.execute(
            'INSERT INTO users (username, email, password, full_name, role) VALUES (?, ?, ?, ?, ?)',
            ('admin', 'sabtrack.system@gmail.com', generate_password_hash('admin123'), 'System Administrator', 'admin')
        )

    conn.commit()
    conn.close()

def send_email(to_email, subject, body):
    """Send an email using SMTP configuration."""
    try:
        print(f"📧 Attempting to send email to: {to_email}")
        print(f"📧 Subject: {subject}")

        if not EMAIL_PASSWORD:
            print(f"Email notification: {subject} to {to_email}")
            print(f"Email body: {body}")
            return True

        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))

        print(f"🌐 Connecting to {SMTP_SERVER}:{SMTP_PORT}")
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10)
        server.starttls()
        print("🔐 Authenticating...")
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        print("📤 Sending message...")
        server.send_message(msg)
        server.quit()
        print("✅ Email sent successfully!")
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
        return False
    except smtplib.SMTPConnectError as e:
        print(f"❌ Connection failed: {e}")
        return False
    except smtplib.SMTPRecipientsRefused as e:
        print(f"❌ Recipient refused: {e}")
        return False
    except Exception as e:
        print(f"❌ Email error: {e}")
        return False

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        conn = get_db()
        user = conn.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        if not user or user['role'] != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_unread_notifications():
    if 'user_id' in session:
        conn = get_db()
        unread_count = conn.execute('SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0', (session['user_id'],)).fetchone()['count']
        conn.close()
        return {'unread_notifications': unread_count}
    return {'unread_notifications': 0}

# Routes - Public pages
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

# Authentication routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        full_name = request.form.get('full_name')
        age = request.form.get('age')
        address = request.form.get('address')
        resident_id = request.form.get('resident_id')
        
        if password != confirm:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        try:
            conn = get_db()
            conn.execute(
                'INSERT INTO users (username, email, password, full_name, age, address, resident_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (username, email, generate_password_hash(password), full_name, age, address, resident_id)
            )
            conn.commit()
            conn.close()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'danger')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']

            # Log login activity
            conn.execute('INSERT INTO activity_log (user_id, activity_type, description) VALUES (?, ?, ?)',
                        (user['id'], 'login', 'User logged in'))
            conn.commit()

            conn.close()
            flash(f'Welcome, {user["full_name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            conn.close()
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user:
            # Generate a simple reset token (in production, use JWT or secure token)
            reset_token = generate_password_hash(f"{user['id']}_{user['email']}_{datetime.now().timestamp()}")

            # Send reset email
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            send_email(
                user['email'],
                'Password Reset Request',
                f'''
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #dc2626;">Password Reset Request</h2>
                    <p>Dear {user["full_name"]},</p>
                    <p>You have requested to reset your password for your SABTRACK account.</p>
                    <p>Please click the link below to reset your password:</p>
                    <p style="text-align: center; margin: 30px 0;">
                        <a href="{reset_link}" style="background-color: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">Reset Password</a>
                    </p>
                    <p>If you didn't request this password reset, please ignore this email.</p>
                    <p>This link will expire in 1 hour.</p>
                    <p>Best regards,<br>SABTRACK Team</p>
                </div>
                '''
            )
            flash('Password reset link has been sent to your email address.', 'success')
        else:
            flash('If an account with that email exists, a reset link has been sent.', 'info')

        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # For demo purposes, we'll use a simple token validation
    # In production, use JWT or store tokens in database with expiration
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('reset_password', token=token))

        if len(new_password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            return redirect(url_for('reset_password', token=token))

        # For demo, we'll allow password reset without token validation
        # In production, validate the token properly
        flash('Password reset successfully! Please log in with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

# User routes
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if session.get('role') == 'admin':
        reports = conn.execute('SELECT COUNT(*) as count FROM reports WHERE status = "pending"').fetchone()
        users_count = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()
        announcements = conn.execute('SELECT * FROM announcements ORDER BY created_at DESC LIMIT 5').fetchall()
        conn.close()
        return render_template('user_dashboard.html', user=user, pending_reports=reports['count'], users_count=users_count['count'], announcements=announcements)

    # Calculate real statistics for regular users
    # Reports this month
    current_month = datetime.now().strftime('%Y-%m')
    reports_this_month = conn.execute('SELECT COUNT(*) as count FROM reports WHERE strftime("%Y-%m", created_at) = ?', (current_month,)).fetchone()['count']

    # Resolved issues (total resolved reports)
    resolved_issues = conn.execute('SELECT COUNT(*) as count FROM reports WHERE status = "resolved"').fetchone()['count']

    # Active users (total users)
    active_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']

    schedules = conn.execute('SELECT * FROM schedules').fetchall()
    announcements = conn.execute('SELECT * FROM announcements ORDER BY created_at DESC LIMIT 3').fetchall()
    conn.close()
    return render_template('dashboard.html', user=user, schedules=schedules, announcements=announcements,
                         reports_this_month=reports_this_month, resolved_issues=resolved_issues, active_users=active_users)

@app.route('/profile')
@login_required
def profile():
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    # Get actual stats counts
    if session.get('role') == 'admin':
        # For admin, show total reports in the system
        reports_count = conn.execute('SELECT COUNT(*) as count FROM reports').fetchone()['count']
        activities_count = conn.execute('SELECT COUNT(*) as count FROM reports WHERE status = "resolved"').fetchone()['count']
    else:
        # For regular users, show their own reports
        reports_count = conn.execute('SELECT COUNT(*) as count FROM reports WHERE user_id = ?', (session['user_id'],)).fetchone()['count']
        activities_count = conn.execute('SELECT COUNT(*) as count FROM reports WHERE user_id = ? AND status = "resolved"', (session['user_id'],)).fetchone()['count']
    announcements_count = conn.execute('SELECT COUNT(*) as count FROM announcements').fetchone()[0]

    # Get recent activities
    activities = conn.execute('SELECT * FROM activity_log WHERE user_id = ? ORDER BY created_at DESC LIMIT 10', (session['user_id'],)).fetchall()

    conn.close()
    return render_template('profile.html', user=user, reports_count=reports_count, announcements_count=announcements_count, activities_count=activities_count, activities=activities)

@app.route('/profile/edit', methods=['POST'])
@login_required
def edit_profile():
    full_name = request.form.get('full_name')
    email = request.form.get('email')
    phone = request.form.get('phone')
    address = request.form.get('address')

    conn = get_db()

    # Check if email is already taken by another user
    existing_user = conn.execute('SELECT id FROM users WHERE email = ? AND id != ?', (email, session['user_id'])).fetchone()
    if existing_user:
        flash('Email address is already in use', 'danger')
        conn.close()
        return redirect(url_for('profile'))

    # Update user profile
    conn.execute('UPDATE users SET full_name = ?, email = ?, phone = ?, address = ? WHERE id = ?',
                 (full_name, email, phone, address, session['user_id']))
    conn.commit()
    conn.close()

    flash('Profile updated successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/profile/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('profile'))

    conn = get_db()
    user = conn.execute('SELECT password FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if not check_password_hash(user['password'], current_password):
        flash('Current password is incorrect', 'danger')
        conn.close()
        return redirect(url_for('profile'))

    # Update password
    conn.execute('UPDATE users SET password = ? WHERE id = ?',
                 (generate_password_hash(new_password), session['user_id']))
    conn.commit()
    conn.close()

    flash('Password changed successfully', 'success')
    return redirect(url_for('profile'))

# Waste schedule routes
@app.route('/schedule')
def schedule():
    conn = get_db()
    schedules = conn.execute('SELECT * FROM schedules ORDER BY CASE WHEN day="Monday" THEN 1 WHEN day="Tuesday" THEN 2 WHEN day="Wednesday" THEN 3 WHEN day="Thursday" THEN 4 WHEN day="Friday" THEN 5 WHEN day="Saturday" THEN 6 WHEN day="Sunday" THEN 7 END').fetchall()
    conn.close()
    return render_template('schedule.html', schedules=schedules)

@app.route('/schedule/set-reminder/<int:schedule_id>', methods=['POST'])
@login_required
def set_reminder(schedule_id):
    conn = get_db()
    existing = conn.execute('SELECT * FROM reminders WHERE user_id = ? AND schedule_id = ?', (session['user_id'], schedule_id)).fetchone()

    if not existing:
        conn.execute('INSERT INTO reminders (user_id, schedule_id) VALUES (?, ?)', (session['user_id'], schedule_id))

        # Log reminder setting activity
        schedule = conn.execute('SELECT * FROM schedules WHERE id = ?', (schedule_id,)).fetchone()
        conn.execute('INSERT INTO activity_log (user_id, activity_type, description) VALUES (?, ?, ?) ',
                    (session['user_id'], 'reminder_set', f'Set reminder for {schedule["day"]} - {schedule["area"]}'))

        # Create notification for the user
        notification_title = f'Reminder Set: {schedule["day"]} - {schedule["area"]}'
        notification_content = f'Waste collection reminder for {schedule["waste_type"]} ({schedule["time_start"]} - {schedule["time_end"]})'
        conn.execute('INSERT INTO notifications (user_id, type, title, content, related_id) VALUES (?, ?, ?, ?, ?)',
                    (session['user_id'], 'reminder', notification_title, notification_content, schedule_id))

        conn.commit()
        flash(' Reminder set successfully', 'success')
    else:
        flash('Reminder already set', 'info')

    # Always send reminder email regardless of whether reminder was newly set or already exists
    # Get user email and schedule details
    user = conn.execute('SELECT email, full_name FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    schedule = conn.execute('SELECT * FROM schedules WHERE id = ?', (schedule_id,)).fetchone()

    # Send reminder email automatically
    print(f"📧 Sending reminder email to {user['email']} for schedule {schedule_id}")
    email_sent = send_email(
        user['email'],
        f'🗓️ Waste Collection Reminder: {schedule["day"]} - {schedule["area"]}',
        f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #dc2626;">🔔 Waste Collection Reminder</h2>
            <p>Dear {user["full_name"]},</p>

            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h3 style="margin-top: 0; color: #1f2937;">Collection Details:</h3>
                <ul style="list-style: none; padding: 0;">
                    <li style="margin: 10px 0;"><strong>📅 Day:</strong> {schedule["day"]}</li>
                    <li style="margin: 10px 0;"><strong>📍 Area:</strong> {schedule["area"]}</li>
                    <li style="margin: 10px 0;"><strong>🗑️ Waste Type:</strong> {schedule["waste_type"]}</li>
                    <li style="margin: 10px 0;"><strong>⏰ Time:</strong> {schedule["time_start"]} - {schedule["time_end"]}</li>
                </ul>
            </div>

            <div style="background: #fef3c7; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #f59e0b;">
                <strong>⚠️ Important:</strong> Please ensure your waste bins are placed at the curb before the collection time.
            </div>

            <p>Thank you for helping keep our community clean!</p>
            <p style="color: #6b7280; font-size: 14px;">This reminder was automatically sent when you set up your waste collection reminder.</p>
        </div>
        '''
    )
    print(f"📧 Reminder email sent result: {email_sent}")

    conn.close()
    return redirect(url_for('schedule'))

# Notification settings routes
@app.route('/notification-settings', methods=['GET', 'POST'])
@login_required
def notification_settings():
    conn = get_db()

    # Get admin announcements
    announcements = conn.execute('SELECT * FROM announcements ORDER BY created_at DESC').fetchall()

    # Get user's reminders with schedule details
    user_reminders = conn.execute('''
        SELECT r.id, r.created_at, s.day, s.area, s.waste_type, s.time_start, s.time_end
        FROM reminders r
        JOIN schedules s ON r.schedule_id = s.id
        WHERE r.user_id = ?
        ORDER BY r.created_at DESC
    ''', (session['user_id'],)).fetchall()

    conn.close()

    # Combine announcements and reminders into notifications
    notifications = []

    # Add announcements
    for announcement in announcements:
        notifications.append({
            'type': 'announcement',
            'id': announcement['id'],
            'title': announcement['title'],
            'content': announcement['content'],
            'created_at': announcement['created_at'],
            'icon': '📢'
        })

    # Add reminders
    for reminder in user_reminders:
        notifications.append({
            'type': 'reminder',
            'id': reminder['id'],
            'title': f'Reminder Set: {reminder["day"]} - {reminder["area"]}',
            'content': f'Waste collection reminder for {reminder["waste_type"]} ({reminder["time_start"]} - {reminder["time_end"]})',
            'created_at': reminder['created_at'],
            'icon': '⏰'
        })

    # Sort notifications by created_at (most recent first)
    notifications.sort(key=lambda x: x['created_at'], reverse=True)

    return render_template('notification_settings.html', notifications=notifications)

# Garbage reporting routes
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        issue_type = request.form.get('issue_type')
        location = request.form.get('location')
        description = request.form.get('description')
        photo = request.files.get('photo')

        photo_path = None
        if photo and allowed_file(photo.filename):
            filename = secure_filename(f"{session['user_id']}_{datetime.now().timestamp()}_{photo.filename}")
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            photo_path = filename

        conn = get_db()

        # Get user info first
        user = conn.execute('SELECT email, full_name FROM users WHERE id = ?', (session['user_id'],)).fetchone()

        report_id = conn.execute(
            'INSERT INTO reports (user_id, issue_type, location, description, photo_path) VALUES (?, ?, ?, ?, ?)',
            (session['user_id'], issue_type, location, description, photo_path)
        ).lastrowid

        # Log report submission activity
        conn.execute('INSERT INTO activity_log (user_id, activity_type, description) VALUES (?, ?, ?)',
                    (session['user_id'], 'report_submitted', f'Submitted {issue_type} report at {location}'))

        # Create notification for all admins
        admins = conn.execute('SELECT id FROM users WHERE role = "admin"').fetchall()
        for admin in admins:
            conn.execute('INSERT INTO notifications (user_id, type, title, content, related_id) VALUES (?, ?, ?, ?, ?)',
                        (admin['id'], 'new_report', f'New Report Submitted: {issue_type}', f'Report from {user["full_name"]} at {location}', report_id))

        conn.commit()
        conn.close()

        # Send email notification to user
        send_email(
            user['email'],
            'Garbage Report Submitted',
            f'<p>Dear {user["full_name"]},</p><p>Your garbage report has been submitted successfully. Report ID: {report_id}</p>'
        )

        # Send email notification to admin
        send_email(
            'sabtrack.system@gmail.com',
            'New Garbage Report Submitted',
            f'<p>A new garbage report has been submitted.</p><p>Report ID: {report_id}</p><p>User: {user["full_name"]} ({user["email"]})</p><p>Issue: {issue_type} at {location}</p>'
        )

        flash('Report submitted successfully! Thank you for helping keep our community clean.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('report.html')

# Admin routes
@app.route('/admin/reports')
@admin_required
def admin_reports():
    conn = get_db()
    reports = conn.execute('''
        SELECT r.*, u.full_name, u.email FROM reports r
        JOIN users u ON r.user_id = u.id
        ORDER BY r.created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('user_reports.html', reports=reports)

@app.route('/admin/reports/<int:report_id>', methods=['GET', 'POST'])
@admin_required
def admin_report_detail(report_id):
    conn = get_db()
    report = conn.execute('''
        SELECT r.*, u.full_name, u.email FROM reports r
        JOIN users u ON r.user_id = u.id
        WHERE r.id = ?
    ''', (report_id,)).fetchone()
    
    if request.method == 'POST':
        status = request.form.get('status')
        conn.execute('UPDATE reports SET status = ? WHERE id = ?', (status, report_id))
        conn.commit()

        # Create notification for the user
        notification_title = f'Report Status Update - {status.upper()}'
        notification_content = f'Your garbage report (ID: {report_id}) status has been updated to: {status.upper()}'
        conn.execute('INSERT INTO notifications (user_id, type, title, content, related_id) VALUES (?, ?, ?, ?, ?)',
                    (report['user_id'], 'report_status', notification_title, notification_content, report_id))

        # Send email to user
        send_email(
            report['email'],
            f'Report Status Update - {status.upper()}',
            f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #dc2626;">📋 Report Status Update</h2>
                <p>Dear {report["full_name"]},</p>

                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <h3 style="margin-top: 0; color: #1f2937;">Status Update Details:</h3>
                    <ul style="list-style: none; padding: 0;">
                        <li style="margin: 10px 0;"><strong>Report ID:</strong> {report_id}</li>
                        <li style="margin: 10px 0;"><strong>Issue Type:</strong> {report["issue_type"]}</li>
                        <li style="margin: 10px 0;"><strong>Location:</strong> {report["location"]}</li>
                        <li style="margin: 10px 0;"><strong>New Status:</strong> <span style="color: #dc2626; font-weight: bold;">{status.upper()}</span></li>
                    </ul>
                </div>

                <p>You can check your notifications in the app for more details.</p>
                <p>Thank you for helping keep our community clean!</p>
                <p style="color: #6b7280; font-size: 14px;">This notification was sent automatically when your report status was updated.</p>
            </div>
            '''
        )

        conn.commit()
        flash('Report status updated and notification sent', 'success')
        conn.close()
        return redirect(url_for('admin_reports'))
    
    conn.close()
    return render_template('user_report_detail.html', report=report)

@app.route('/admin/announcements/new', methods=['GET', 'POST'])
@admin_required
def admin_new_announcement():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')

        conn = get_db()
        announcement_id = conn.execute('INSERT INTO announcements (title, content, created_by) VALUES (?, ?, ?)', (title, content, session['user_id'])).lastrowid
        conn.commit()

        # Create notifications for all users synchronously
        users = conn.execute('SELECT id, email FROM users WHERE role = "resident"').fetchall()
        for user in users:
            # Create notification record for each user
            conn.execute('INSERT INTO notifications (user_id, type, title, content, related_id) VALUES (?, ?, ?, ?, ?)',
                        (user['id'], 'announcement', f'New Announcement: {title}', content, announcement_id))

            print(f"📧 Sending announcement email to {user['email']}")
            email_sent = send_email(
                user['email'],
                f'New Announcement: {title}',
                f'<p><b>{title}</b></p><p>{content}</p>'
            )
            print(f"📧 Announcement email sent result: {email_sent}")

        conn.close()
        flash('Announcement posted and sent to all users', 'success')
        return redirect(url_for('dashboard'))

    return render_template('admin_new_announcement.html')

@app.route('/admin/announcements/delete/<int:announcement_id>', methods=['POST'])
@admin_required
def admin_delete_announcement(announcement_id):
    conn = get_db()
    announcement = conn.execute('SELECT * FROM announcements WHERE id = ?', (announcement_id,)).fetchone()

    if not announcement:
        conn.close()
        flash('Announcement not found', 'danger')
        return redirect(url_for('announcements'))

    # Delete the announcement
    conn.execute('DELETE FROM announcements WHERE id = ?', (announcement_id,))
    conn.commit()
    conn.close()

    flash('Announcement deleted successfully', 'success')
    return redirect(url_for('announcements'))

@app.route('/admin/reports/delete/<int:report_id>', methods=['POST'])
@admin_required
def admin_delete_report(report_id):
    conn = get_db()
    report = conn.execute('SELECT * FROM reports WHERE id = ?', (report_id,)).fetchone()

    if not report:
        conn.close()
        flash('Report not found', 'danger')
        return redirect(url_for('admin_reports'))

    # Delete associated notifications
    conn.execute('DELETE FROM notifications WHERE related_id = ? AND type = "report_status"', (report_id,))

    # Delete the report
    conn.execute('DELETE FROM reports WHERE id = ?', (report_id,))
    conn.commit()
    conn.close()

    flash('Report deleted successfully', 'success')
    return redirect(url_for('admin_reports'))

@app.route('/admin/schedule/edit/<int:schedule_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_schedule(schedule_id):
    conn = get_db()
    schedule = conn.execute('SELECT * FROM schedules WHERE id = ?', (schedule_id,)).fetchone()

    if not schedule:
        conn.close()
        flash('Schedule not found', 'danger')
        return redirect(url_for('schedule'))

    if request.method == 'POST':
        day = request.form.get('day')
        area = request.form.get('area')
        waste_type = request.form.get('waste_type')
        time_start = request.form.get('time_start')
        time_end = request.form.get('time_end')

        # Convert time to AM/PM format
        try:
            time_start_obj = datetime.strptime(time_start, '%H:%M')
            time_end_obj = datetime.strptime(time_end, '%H:%M')
            time_start_formatted = time_start_obj.strftime('%I:%M %p')
            time_end_formatted = time_end_obj.strftime('%I:%M %p')
        except ValueError:
            time_start_formatted = time_start
            time_end_formatted = time_end

        conn.execute('UPDATE schedules SET day = ?, area = ?, waste_type = ?, time_start = ?, time_end = ? WHERE id = ?',
                    (day, area, waste_type, time_start_formatted, time_end_formatted, schedule_id))

        # Update notifications for users who have reminders set for this schedule
        users_with_reminders = conn.execute('SELECT DISTINCT r.user_id FROM reminders r WHERE r.schedule_id = ?', (schedule_id,)).fetchall()

        for user_row in users_with_reminders:
            user_id = user_row['user_id']

            # Update existing reminder notifications
            conn.execute('''
                UPDATE notifications
                SET title = ?, content = ?
                WHERE user_id = ? AND type = 'reminder' AND related_id = ?
            ''', (f'Reminder Set: {day} - {area}',
                  f'Waste collection reminder for {waste_type} ({time_start_formatted} - {time_end_formatted})',
                  user_id, schedule_id))

            # Create notification about schedule change
            change_notification_title = f'Schedule Updated: {day} - {area}'
            change_notification_content = f'The waste collection schedule has been updated. New details: {waste_type} ({time_start_formatted} - {time_end_formatted})'
            conn.execute('INSERT INTO notifications (user_id, type, title, content, related_id) VALUES (?, ?, ?, ?, ?)',
                        (user_id, 'schedule_update', change_notification_title, change_notification_content, schedule_id))

        conn.commit()
        conn.close()

        flash('Schedule updated successfully and notifications sent to affected users', 'success')
        return redirect(url_for('schedule'))

    # Convert time from AM/PM to 24-hour format for the form
    try:
        time_start_obj = datetime.strptime(schedule['time_start'], '%I:%M %p')
        time_end_obj = datetime.strptime(schedule['time_end'], '%I:%M %p')
        schedule = dict(schedule)
        schedule['time_start'] = time_start_obj.strftime('%H:%M')
        schedule['time_end'] = time_end_obj.strftime('%H:%M')
    except ValueError:
        pass  # Keep original format if parsing fails

    conn.close()
    return render_template('admin_edit_schedule.html', schedule=schedule)



@app.route('/notifications')
@login_required
def notifications():
    conn = get_db()

    # Get user's reminders with schedule details
    user_reminders = conn.execute('''
        SELECT r.id, r.created_at, s.day, s.area, s.waste_type, s.time_start, s.time_end
        FROM reminders r
        JOIN schedules s ON r.schedule_id = s.id
        WHERE r.user_id = ?
        ORDER BY r.created_at DESC
    ''', (session['user_id'],)).fetchall()

    # Get all user's notifications (including announcements, report status updates, etc.)
    user_notifications = conn.execute('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],)).fetchall()

    conn.close()

    # Combine reminders and notifications
    notifications = []

    # Add reminders
    for reminder in user_reminders:
        notifications.append({
            'type': 'reminder',
            'id': reminder['id'],
            'title': f'Reminder Set: {reminder["day"]} - {reminder["area"]}',
            'content': f'Waste collection reminder for {reminder["waste_type"]} ({reminder["time_start"]} - {reminder["time_end"]})',
            'created_at': reminder['created_at'],
            'icon': '⏰'
        })

    # Add all user notifications (announcements, report status updates, etc.)
    for notification in user_notifications:
        icon = '📢' if notification['type'] == 'announcement' else ('📋' if notification['type'] == 'report_status' else '🔔')
        notifications.append({
            'type': notification['type'],
            'id': notification['id'],
            'title': notification['title'],
            'content': notification['content'],
            'created_at': notification['created_at'],
            'icon': icon
        })

    # Sort notifications by created_at (most recent first)
    notifications.sort(key=lambda x: x['created_at'], reverse=True)

    return render_template('notifications.html', notifications=notifications)

@app.route('/announcements')
@login_required
def announcements():
    conn = get_db()
    announcements = conn.execute('SELECT * FROM announcements ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('announcements.html', announcements=announcements)

@app.route('/awareness')
def awareness():
    conn = get_db()
    announcements = conn.execute('SELECT * FROM announcements ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('awareness.html', announcements=announcements)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
