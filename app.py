from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, time, timedelta
import csv
import io
import qrcode
from io import BytesIO
import base64
from functools import wraps
from jose import jwt
from geopy.distance import geodesic
import json
import hashlib
import shutil
import os
from werkzeug.security import generate_password_hash
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
basedir = os.path.abspath(os.path.dirname(__file__))

# Database configuration
if os.environ.get('DATABASE_URL'):
    # Use PostgreSQL in production
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')
else:
    # Use SQLite for local development
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database', 'attendance.db')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Constants
SECRET_KEY = 'your-secret-key-here'  # Change this in production
TOKEN_EXPIRATION = 24  # hours
ALLOWED_DISTANCE = 100  # meters

# Predefined departments and their HODs
DEPARTMENTS = {
    'GOLD_MAKING': 'Gold Making Department',
    'POLISHING': 'Polishing Department',
    'SETTING': 'Setting Department',
    'SALES': 'Sales Department',
    'ACCOUNTS': 'Accounts Department',
    'ADMIN': 'Administration'
}

# Helper Functions
def generate_token(employee):
    """Generate JWT token for mobile authentication"""
    now = datetime.utcnow()
    payload = {
        'employee_id': employee.id,
        'exp': now + timedelta(hours=TOKEN_EXPIRATION),
        'iat': now,
        'role': employee.role
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token):
    """Verify JWT token and return employee"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        employee = Employee.query.get(payload['employee_id'])
        if not employee:
            return None
        return employee
    except:
        return None

def mobile_auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        try:
            # Verify token and get employee
            employee = verify_token(token)
            if not employee:
                raise ValueError('Invalid token')
            
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'error': str(e)}), 401
    
    return decorated_function

def get_current_employee():
    token = request.headers.get('Authorization')
    return verify_token(token)

def is_valid_location(latitude, longitude):
    """Validate if the given location is within allowed office locations"""
    if not latitude or not longitude:
        return False
    
    # Get all active office locations
    locations = Location.query.filter_by(is_active=True).all()
    
    # Convert string coordinates to float
    try:
        lat = float(latitude)
        lon = float(longitude)
    except ValueError:
        return False
    
    # Check if the location is within the radius of any office location
    for loc in locations:
        distance = geodesic(
            (lat, lon),
            (loc.latitude, loc.longitude)
        ).meters
        
        if distance <= loc.radius:
            return True
    
    return False

def verify_face(face_data, stored_encoding):
    """
    Simplified face verification (placeholder)
    In a production environment, use a proper face recognition library
    """
    if not face_data or not stored_encoding:
        return False
    
    try:
        # For demonstration, we'll just compare hashes
        face_hash = hashlib.sha256(face_data.encode()).hexdigest()
        return face_hash == stored_encoding
    except:
        return False

def verify_fingerprint(fingerprint_data, stored_data):
    """
    Simplified fingerprint verification (placeholder)
    In a production environment, use a proper fingerprint recognition library
    """
    if not fingerprint_data or not stored_data:
        return False
    
    try:
        # For demonstration, we'll just compare hashes
        fp_hash = hashlib.sha256(fingerprint_data.encode()).hexdigest()
        return fp_hash == stored_data
    except:
        return False

def calculate_compliance(employee_id, date):
    """Calculate compliance status for an employee on a given date"""
    attendance = Attendance.query.filter_by(
        employee_id=employee_id,
        date=date
    ).first()
    
    if not attendance:
        return 'absent'
    
    employee = Employee.query.get(employee_id)
    shift = employee.shift
    
    # Calculate total hours worked
    if attendance.check_in and attendance.check_out:
        total_hours = (attendance.check_out - attendance.check_in).total_seconds() / 3600
        
        # Calculate break duration
        breaks = json.loads(attendance.breaks or '[]')
        break_duration = sum(
            (datetime.fromisoformat(b['end']) - datetime.fromisoformat(b['start'])).seconds / 60
            for b in breaks if b.get('end')
        )
        
        # Check compliance
        if total_hours > 12:  # Max work hours per day
            return 'overtime-excess'
        elif break_duration < 30:  # Minimum break time
            return 'break-violation'
        
    return 'compliant'

# Models
class Shift(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    description = db.Column(db.Text)
    employees = db.relationship('Employee', backref='shift', lazy=True)

class Employee(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(50))
    role = db.Column(db.String(20), default='employee')  # admin, employee, team_leader, hod
    is_department_head = db.Column(db.Boolean, default=False)
    is_team_leader = db.Column(db.Boolean, default=False)
    department_head_id = db.Column(db.Integer, db.ForeignKey('employee.id'))
    team_leader_id = db.Column(db.Integer, db.ForeignKey('employee.id'))
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))
    shift_id = db.Column(db.Integer, db.ForeignKey('shift.id'))
    designation = db.Column(db.String(100))
    reporting_to = db.Column(db.Integer, db.ForeignKey('employee.id'))
    base_salary = db.Column(db.Float, default=0.0)
    joining_date = db.Column(db.Date, default=datetime.now().date())
    leave_balance = db.Column(db.Integer, default=20)
    performance_rating = db.Column(db.Float, default=0.0)
    qr_code = db.Column(db.String(500))
    face_encoding = db.Column(db.String(1000))
    fingerprint_data = db.Column(db.String(1000))
    mobile_token = db.Column(db.String(500))
    allowed_ip_addresses = db.Column(db.String(500))
    allowed_locations = db.Column(db.String(1000))
    is_remote_employee = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    device_info = db.Column(db.String(500))
    
    # Relationships with explicit foreign keys and join conditions
    department_employees = db.relationship(
        'Employee',
        backref=db.backref('department_head', remote_side=[id]),
        foreign_keys=[department_head_id],
        primaryjoin="Employee.department_head_id == Employee.id"
    )
    
    team_members = db.relationship(
        'Employee',
        backref=db.backref('team_leader', remote_side=[id]),
        foreign_keys=[team_leader_id],
        primaryjoin="Employee.team_leader_id == Employee.id"
    )
    
    direct_reports = db.relationship(
        'Employee',
        backref=db.backref('reporting_manager', remote_side=[id]),
        foreign_keys=[reporting_to],
        primaryjoin="Employee.reporting_to == Employee.id"
    )
    
    # Team relationship
    assigned_team = db.relationship(
        'Team',
        backref='team_members',
        foreign_keys=[team_id],
        primaryjoin="Employee.team_id == Team.id"
    )

    # Helper methods
    def get_department_name(self):
        """Get full department name"""
        return DEPARTMENTS.get(self.department, self.department)

    def get_hod(self):
        """Get Head of Department"""
        if self.is_department_head:
            return self
        return Employee.query.filter_by(department=self.department, is_department_head=True).first()

    def get_reporting_hierarchy(self):
        """Get reporting hierarchy: Team Leader -> HOD -> Admin"""
        hierarchy = []
        if self.team_leader and self.team_leader.id != self.id:
            hierarchy.append(f"Team Leader: {self.team_leader.name}")
        if self.department_head and self.department_head.id != self.id:
            hierarchy.append(f"HOD: {self.department_head.name}")
        return " -> ".join(hierarchy) if hierarchy else "No direct supervisor"

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    check_in = db.Column(db.DateTime)
    check_out = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='absent')  # present, absent, late
    overtime_hours = db.Column(db.Float, default=0.0)
    location = db.Column(db.String(200))  # Location data for attendance
    # New fields for advanced features
    check_in_location = db.Column(db.String(200))  # Geolocation data for check-in
    check_out_location = db.Column(db.String(200))  # Geolocation data for check-out
    check_in_method = db.Column(db.String(50))  # QR/Biometric/Mobile/Web
    check_out_method = db.Column(db.String(50))  # QR/Biometric/Mobile/Web
    check_in_photo = db.Column(db.String(500))  # Base64 encoded photo at check-in
    check_in_device = db.Column(db.String(200))  # Device info for check-in
    check_out_device = db.Column(db.String(200))  # Device info for check-out
    breaks = db.Column(db.String(1000))  # JSON string of break times
    work_from_home = db.Column(db.Boolean, default=False)
    employee = db.relationship('Employee', backref='attendances')

class Leave(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    leave_type = db.Column(db.String(50), nullable=False)  # casual, sick, annual
    reason = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    team_approval_status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    dept_approval_status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    applied_on = db.Column(db.DateTime, default=datetime.now)
    team_approved_by = db.Column(db.Integer, db.ForeignKey('employee.id'))  # New field
    dept_approved_by = db.Column(db.Integer, db.ForeignKey('employee.id'))
    approved_by = db.Column(db.Integer, db.ForeignKey('employee.id'))
    team_approved_on = db.Column(db.DateTime)  # New field
    dept_approved_on = db.Column(db.DateTime)
    employee = db.relationship('Employee', foreign_keys=[employee_id], backref='leaves')
    team_approver = db.relationship('Employee', foreign_keys=[team_approved_by], backref='team_approved_leaves')
    dept_approver = db.relationship('Employee', foreign_keys=[dept_approved_by], backref='dept_approved_leaves')
    approver = db.relationship('Employee', foreign_keys=[approved_by], backref='approved_leaves')

class Salary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    month = db.Column(db.Integer, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    base_amount = db.Column(db.Float, nullable=False)
    overtime_amount = db.Column(db.Float, default=0.0)
    deductions = db.Column(db.Float, default=0.0)
    bonus = db.Column(db.Float, default=0.0)
    net_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, paid
    payment_date = db.Column(db.DateTime)
    employee = db.relationship('Employee', backref='salaries')

class Performance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    review_period = db.Column(db.String(50))  # e.g., "2023-Q1"
    attendance_score = db.Column(db.Float, default=0.0)
    punctuality_score = db.Column(db.Float, default=0.0)
    productivity_score = db.Column(db.Float, default=0.0)
    overall_rating = db.Column(db.Float, default=0.0)
    review_date = db.Column(db.DateTime, default=datetime.now)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('employee.id'))
    comments = db.Column(db.Text)
    employee = db.relationship('Employee', foreign_keys=[employee_id], backref='performance_reviews')
    reviewer = db.relationship('Employee', foreign_keys=[reviewed_by])

class Break(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attendance_id = db.Column(db.Integer, db.ForeignKey('attendance.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime)
    break_type = db.Column(db.String(50))  # lunch, coffee, personal
    duration = db.Column(db.Integer)  # in minutes

class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200))
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    radius = db.Column(db.Float, default=100)  # Geofence radius in meters
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    device_id = db.Column(db.String(100), nullable=False)
    device_type = db.Column(db.String(50))  # mobile, tablet, desktop
    device_name = db.Column(db.String(100))
    is_approved = db.Column(db.Boolean, default=False)
    last_used = db.Column(db.DateTime)
    ip_address = db.Column(db.String(50))

class WorkSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    shift_id = db.Column(db.Integer, db.ForeignKey('shift.id'))
    is_remote = db.Column(db.Boolean, default=False)
    location_id = db.Column(db.Integer, db.ForeignKey('location.id'))
    status = db.Column(db.String(50), default='scheduled')  # scheduled, completed, absent
    notes = db.Column(db.Text)

class ComplianceLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    total_hours = db.Column(db.Float)
    overtime_hours = db.Column(db.Float)
    break_duration = db.Column(db.Integer)  # in minutes
    compliance_status = db.Column(db.String(50))  # compliant, overtime-excess, break-violation
    notes = db.Column(db.Text)

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)
    leader_id = db.Column(db.Integer, db.ForeignKey('employee.id'))
    
    # Explicitly specify the relationship with the leader
    leader = db.relationship('Employee',
                           foreign_keys=[leader_id],
                           backref=db.backref('led_teams', lazy='dynamic'),
                           primaryjoin="Team.leader_id == Employee.id")

@login_manager.user_loader
def load_user(user_id):
    return Employee.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/health')
def health_check():
    """Health check endpoint that returns immediately"""
    return jsonify({'status': 'ok'})

@app.route('/loading')
def loading():
    """Show loading page while the server is starting up"""
    return render_template('loading.html')

@app.route('/dashboard')
@login_required
def dashboard():
    today = datetime.now().date()
    attendance = Attendance.query.filter_by(
        employee_id=current_user.id,
        date=today
    ).first()
    pending_leaves = Leave.query.filter_by(
        employee_id=current_user.id,
        status='pending'
    ).all()
    return render_template('dashboard.html', 
                         attendance=attendance,
                         pending_leaves=pending_leaves)

# Employee Management Routes
@app.route('/manage-employees')
@login_required
def manage_employees():
    if not current_user.role == 'admin' and not current_user.is_department_head:
        flash('Access denied. Admin or Department Head privileges required.')
        return redirect(url_for('dashboard'))
    
    employees = Employee.query.all()
    shifts = Shift.query.all()
    return render_template('manage_employees.html', 
                         employees=employees, 
                         shifts=shifts,
                         departments=DEPARTMENTS)

@app.route('/check-hod/<department>')
@login_required
def check_hod(department):
    existing_hod = Employee.query.filter_by(
        department=department,
        is_department_head=True
    ).first()
    return jsonify({'has_hod': existing_hod is not None})

@app.route('/employee-details/<int:employee_id>')
@login_required
def employee_details(employee_id):
    employee = Employee.query.get_or_404(employee_id)
    
    # Check if user has permission to view details
    if not current_user.role == 'admin' and not current_user.is_department_head:
        if current_user.id != employee_id:
            return jsonify({'error': 'Access denied'}), 403
    
    return jsonify({
        'id': employee.id,
        'employee_id': employee.employee_id,
        'name': employee.name,
        'email': employee.email,
        'department': employee.department,
        'department_name': employee.get_department_name(),
        'designation': employee.designation or 'Not Set',
        'role': employee.role,
        'role_display': 'HOD' if employee.is_department_head else 
                       'Team Leader' if employee.is_team_leader else 
                       'Admin' if employee.role == 'admin' else 'Employee',
        'reporting_to': employee.reporting_to,
        'shift_id': employee.shift_id,
        'base_salary': employee.base_salary,
        'joining_date': employee.joining_date.strftime('%Y-%m-%d')
    })

@app.route('/add-employee', methods=['POST'])
@login_required
def add_employee():
    if not current_user.role == 'admin' and not current_user.is_department_head:
        flash('Access denied. Admin or Department Head privileges required.')
        return redirect(url_for('dashboard'))
    
    # Get form data
    employee_id = request.form.get('employee_id')
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    department = request.form.get('department')
    role = request.form.get('role')
    designation = request.form.get('designation')
    reporting_to = request.form.get('reporting_to')
    shift_id = request.form.get('shift_id')
    base_salary = request.form.get('base_salary')
    
    # Validate department head
    if role == 'hod':
        existing_hod = Employee.query.filter_by(
            department=department,
            is_department_head=True
        ).first()
        if existing_hod:
            flash('This department already has a Head of Department.')
            return redirect(url_for('manage_employees'))
    
    # Create new employee
    new_employee = Employee(
        employee_id=employee_id,
        name=name,
        email=email,
        password=generate_password_hash(password),
        department=department,
        role=role,
        is_department_head=(role == 'hod'),
        is_team_leader=(role == 'team_leader'),
        designation=designation,
        reporting_to=reporting_to if reporting_to else None,
        shift_id=shift_id if shift_id else None,
        base_salary=base_salary
    )
    
    try:
        db.session.add(new_employee)
        db.session.commit()
        flash('Employee added successfully!')
    except Exception as e:
        db.session.rollback()
        flash('Error adding employee. Please try again.')
        print(f"Error: {str(e)}")
    
    return redirect(url_for('manage_employees'))

@app.route('/delete-employee/<int:employee_id>', methods=['POST'])
@login_required
def delete_employee(employee_id):
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    employee = Employee.query.get_or_404(employee_id)
    
    # Prevent deleting own account
    if employee.id == current_user.id:
        flash('Cannot delete your own account!')
        return redirect(url_for('manage_employees'))

    try:
        db.session.delete(employee)
        db.session.commit()
        flash('Employee deleted successfully!')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting employee. Please try again.')

    return redirect(url_for('manage_employees'))

@app.route('/check-in', methods=['POST'])
@login_required
def check_in():
    now = datetime.now()
    today = now.date()
    attendance = Attendance.query.filter_by(
        employee_id=current_user.id,
        date=today
    ).first()
    
    if attendance:
        flash('Already checked in for today!')
    else:
        attendance = Attendance(
            employee_id=current_user.id,
            date=today,
            check_in=now,
            status='present'
        )
        db.session.add(attendance)
        db.session.commit()
        flash('Successfully checked in!')
    return redirect(url_for('dashboard'))

@app.route('/check-out', methods=['POST'])
@login_required
def check_out():
    now = datetime.now()
    today = now.date()
    attendance = Attendance.query.filter_by(
        employee_id=current_user.id,
        date=today
    ).first()
    
    if attendance and not attendance.check_out:
        attendance.check_out = now
        db.session.commit()
        flash('Successfully checked out!')
    else:
        flash('No active check-in found!')
    return redirect(url_for('dashboard'))

@app.route('/apply-leave', methods=['GET', 'POST'])
@login_required
def apply_leave():
    if request.method == 'POST':
        leave_type = request.form.get('leave_type')
        start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d').date()
        end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d').date()
        reason = request.form.get('reason')

        # Calculate number of days
        days = (end_date - start_date).days + 1

        # Check leave balance
        if days > current_user.leave_balance:
            flash('Insufficient leave balance.', 'danger')
            return redirect(url_for('apply_leave'))

        # Create new leave application
        leave = Leave(
            employee_id=current_user.id,
            leave_type=leave_type,
            start_date=start_date,
            end_date=end_date,
            reason=reason,
            status='pending',
            dept_approval_status='pending',
            applied_on=datetime.now()
        )
        db.session.add(leave)
        db.session.commit()

        flash('Leave application submitted successfully.', 'success')
        return redirect(url_for('dashboard'))

    # Get user's leave applications
    leaves = Leave.query.filter_by(employee_id=current_user.id).order_by(Leave.applied_on.desc()).all()
    return render_template('apply_leave.html', leaves=leaves)

@app.route('/reports')
@login_required
def reports():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    return render_template('reports.html')

@app.route('/generate-report', methods=['POST'])
@login_required
def generate_report():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d').date()
    end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d').date()
    department = request.form.get('department')

    # Query attendance data
    query = db.session.query(
        Attendance, Employee
    ).join(
        Employee, Attendance.employee_id == Employee.id
    ).filter(
        Attendance.date.between(start_date, end_date)
    )

    if department:
        query = query.filter(Employee.department == department)

    records = query.all()

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Employee ID', 'Name', 'Department', 'Check In', 'Check Out', 'Status'])

    for attendance, employee in records:
        writer.writerow([
            attendance.date.strftime('%Y-%m-%d'),
            employee.employee_id,
            employee.name,
            employee.department,
            attendance.check_in.strftime('%H:%M:%S') if attendance.check_in else 'N/A',
            attendance.check_out.strftime('%H:%M:%S') if attendance.check_out else 'N/A',
            attendance.status
        ])

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'attendance_report_{start_date}_to_{end_date}.csv'
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        employee = Employee.query.filter_by(employee_id=request.form['employee_id']).first()
        if employee and employee.password == request.form['password']:
            login_user(employee)
            employee.last_login = datetime.now()
            db.session.commit()
            return redirect(url_for('dashboard'))
        flash('Invalid employee ID or password')
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        employee_id = request.form.get('employee_id')
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate input
        if not all([employee_id, email, new_password, confirm_password]):
            flash('All fields are required')
            return render_template('forgot_password.html')
        
        if new_password != confirm_password:
            flash('Passwords do not match')
            return render_template('forgot_password.html')
        
        # Find employee
        employee = Employee.query.filter_by(
            employee_id=employee_id,
            email=email
        ).first()
        
        if not employee:
            flash('No account found with these credentials')
            return render_template('forgot_password.html')
        
        try:
            # Update password
            employee.password = new_password
            db.session.commit()
            flash('Password updated successfully. Please login with your new password.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating password. Please try again.')
            return render_template('forgot_password.html')
    
    return render_template('forgot_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/update_salary', methods=['POST'])
@login_required
def update_salary():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Access denied. Admin privileges required.'}), 403
    
    data = request.get_json()
    employee_id = data.get('employee_id')
    new_salary = float(data.get('base_salary', 0))
    
    employee = Employee.query.get_or_404(employee_id)
    
    try:
        employee.base_salary = new_salary
        db.session.commit()
        return jsonify({'success': True, 'message': 'Salary updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error updating salary'}), 500

@app.route('/add_shift', methods=['POST'])
@login_required
def add_shift():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    try:
        name = request.form.get('name')
        start_time = datetime.strptime(request.form.get('start_time'), '%H:%M').time()
        end_time = datetime.strptime(request.form.get('end_time'), '%H:%M').time()
        description = request.form.get('description')

        new_shift = Shift(
            name=name,
            start_time=start_time,
            end_time=end_time,
            description=description
        )

        db.session.add(new_shift)
        db.session.commit()
        flash('Shift added successfully!')
    except Exception as e:
        db.session.rollback()
        flash('Error adding shift. Please try again.')

    return redirect(url_for('manage_employees'))

@app.route('/update_shift', methods=['POST'])
@login_required
def update_shift():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': 'Access denied. Admin privileges required.'}), 403
    
    data = request.get_json()
    employee_id = data.get('employee_id')
    shift_id = data.get('shift_id')
    
    try:
        employee = Employee.query.get_or_404(employee_id)
        employee.shift_id = shift_id if shift_id else None
        db.session.commit()
        return jsonify({'success': True, 'message': 'Shift updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error updating shift'}), 500

@app.route('/generate-qr/<int:employee_id>')
@login_required
def generate_qr(employee_id):
    if current_user.role != 'admin' and current_user.id != employee_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    employee = Employee.query.get_or_404(employee_id)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(f"emp_{employee.employee_id}_{datetime.now().strftime('%Y%m%d')}")
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    employee.qr_code = img_str
    db.session.commit()
    
    return jsonify({'qr_code': img_str})

@app.route('/scan-qr', methods=['POST'])
@login_required
def scan_qr():
    data = request.json.get('qr_data')
    if not data:
        return jsonify({'error': 'No QR data provided'}), 400
    
    try:
        prefix, emp_id, date = data.split('_')
        if prefix != 'emp':
            raise ValueError('Invalid QR code')
        
        employee = Employee.query.filter_by(employee_id=emp_id).first()
        if not employee:
            return jsonify({'error': 'Employee not found'}), 404
        
        today = datetime.now().date()
        attendance = Attendance.query.filter_by(
            employee_id=employee.id,
            date=today
        ).first()
        
        if not attendance:
            attendance = Attendance(
                employee_id=employee.id,
                date=today,
                check_in=datetime.now(),
                status='present'
            )
            db.session.add(attendance)
        elif not attendance.check_out:
            attendance.check_out = datetime.now()
            # Calculate overtime
            shift_end = datetime.combine(today, employee.shift.end_time)
            if attendance.check_out > shift_end:
                overtime = (attendance.check_out - shift_end).total_seconds() / 3600
                attendance.overtime_hours = round(overtime, 2)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Attendance recorded successfully'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/salary-management')
@login_required
def salary_management():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    employees = Employee.query.all()
    current_month = datetime.now().month
    current_year = datetime.now().year
    
    salaries = Salary.query.filter_by(
        month=current_month,
        year=current_year
    ).all()
    
    return render_template('salary_management.html', 
                         employees=employees,
                         salaries=salaries,
                         current_month=current_month,
                         current_year=current_year)

@app.route('/calculate-salary', methods=['POST'])
@login_required
def calculate_salary():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    employee_id = data.get('employee_id')
    month = data.get('month', datetime.now().month)
    year = data.get('year', datetime.now().year)
    
    employee = Employee.query.get_or_404(employee_id)
    
    # Calculate overtime amount
    total_overtime = db.session.query(db.func.sum(Attendance.overtime_hours)).filter(
        Attendance.employee_id == employee_id,
        db.extract('month', Attendance.date) == month,
        db.extract('year', Attendance.date) == year
    ).scalar() or 0
    
    overtime_rate = employee.base_salary / 160  # Assuming 160 working hours per month
    overtime_amount = total_overtime * overtime_rate * 1.5  # 1.5x overtime rate
    
    # Calculate deductions based on leaves
    leaves = Leave.query.filter(
        Leave.employee_id == employee_id,
        Leave.status == 'approved',
        db.extract('month', Leave.start_date) == month,
        db.extract('year', Leave.start_date) == year
    ).all()
    
    leave_deduction = 0
    for leave in leaves:
        if leave.leave_type == 'unpaid':
            days = (leave.end_date - leave.start_date).days + 1
            leave_deduction += (employee.base_salary / 30) * days
    
    # Calculate bonus based on performance
    performance = Performance.query.filter(
        Performance.employee_id == employee_id,
        Performance.review_period == f"{year}-Q{(month-1)//3 + 1}"
    ).first()
    
    bonus = 0
    if performance and performance.overall_rating >= 4:
        bonus = employee.base_salary * 0.1  # 10% bonus for high performers
    
    net_amount = employee.base_salary + overtime_amount + bonus - leave_deduction
    
    salary = Salary(
        employee_id=employee_id,
        month=month,
        year=year,
        base_amount=employee.base_salary,
        overtime_amount=overtime_amount,
        deductions=leave_deduction,
        bonus=bonus,
        net_amount=net_amount
    )
    
    db.session.add(salary)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'salary': {
            'base_amount': employee.base_salary,
            'overtime_amount': overtime_amount,
            'deductions': leave_deduction,
            'bonus': bonus,
            'net_amount': net_amount
        }
    })

@app.route('/performance-review', methods=['GET', 'POST'])
@login_required
def performance_review():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        employee_id = request.form.get('employee_id')
        review_period = request.form.get('review_period')
        
        # Calculate attendance score
        total_days = db.session.query(db.func.count(Attendance.id)).filter(
            Attendance.employee_id == employee_id,
            Attendance.status == 'present'
        ).scalar() or 0
        
        attendance_score = min(total_days / 20 * 5, 5)  # Max 5 points, 20 working days
        
        # Calculate punctuality score
        late_days = db.session.query(db.func.count(Attendance.id)).filter(
            Attendance.employee_id == employee_id,
            Attendance.status == 'late'
        ).scalar() or 0
        
        punctuality_score = 5 - (late_days * 0.5)  # Deduct 0.5 points per late day
        
        # Get productivity score from form
        productivity_score = float(request.form.get('productivity_score', 0))
        
        # Calculate overall rating
        overall_rating = (attendance_score + punctuality_score + productivity_score) / 3
        
        performance = Performance(
            employee_id=employee_id,
            review_period=review_period,
            attendance_score=attendance_score,
            punctuality_score=punctuality_score,
            productivity_score=productivity_score,
            overall_rating=overall_rating,
            reviewed_by=current_user.id,
            comments=request.form.get('comments')
        )
        
        db.session.add(performance)
        
        # Update employee's performance rating
        employee = Employee.query.get(employee_id)
        employee.performance_rating = overall_rating
        
        db.session.commit()
        flash('Performance review submitted successfully!')
        return redirect(url_for('performance_review'))
    
    employees = Employee.query.all()
    reviews = Performance.query.order_by(Performance.review_date.desc()).all()
    
    return render_template('performance_review.html',
                         employees=employees,
                         reviews=reviews)

@app.route('/review-details/<int:review_id>')
@login_required
def review_details(review_id):
    review = Performance.query.get_or_404(review_id)
    
    # Check if user has permission to view this review
    if current_user.role != 'admin' and current_user.id != review.employee_id:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    return jsonify({
        'employee_name': review.employee.name,
        'review_period': review.review_period,
        'attendance_score': review.attendance_score,
        'punctuality_score': review.punctuality_score,
        'productivity_score': review.productivity_score,
        'overall_rating': review.overall_rating,
        'comments': review.comments
    })

@app.route('/my-performance')
@login_required
def my_performance():
    reviews = Performance.query.filter_by(
        employee_id=current_user.id
    ).order_by(Performance.review_date.desc()).all()
    
    return render_template('my_performance.html', reviews=reviews)

@app.route('/api/mobile/login', methods=['POST'])
def mobile_login():
    data = request.get_json()
    employee = Employee.query.filter_by(employee_id=data.get('employee_id')).first()
    
    if employee and employee.password == data.get('password'):
        # Generate mobile token
        token = generate_token(employee)
        employee.mobile_token = token
        employee.last_login = datetime.now()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'token': token,
            'employee': {
                'id': employee.id,
                'name': employee.name,
                'role': employee.role
            }
        })
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/mobile/check-in', methods=['POST'])
@mobile_auth_required
def mobile_check_in():
    data = request.get_json()
    employee = get_current_employee()
    
    # Validate location
    if not is_valid_location(data.get('latitude'), data.get('longitude')):
        return jsonify({'error': 'Invalid location'}), 400
    
    # Check for existing attendance
    today = datetime.now().date()
    attendance = Attendance.query.filter_by(
        employee_id=employee.id,
        date=today
    ).first()
    
    if attendance:
        return jsonify({'error': 'Already checked in'}), 400
    
    # Create new attendance record
    attendance = Attendance(
        employee_id=employee.id,
        date=today,
        check_in=datetime.now(),
        status='present',
        check_in_method='mobile',
        check_in_location=f"{data.get('latitude')},{data.get('longitude')}",
        check_in_device=data.get('device_info'),
        work_from_home=data.get('is_remote', False)
    )
    
    db.session.add(attendance)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Check-in successful'})

@app.route('/api/mobile/check-out', methods=['POST'])
@mobile_auth_required
def mobile_check_out():
    data = request.get_json()
    employee = get_current_employee()
    
    # Validate location
    if not is_valid_location(data.get('latitude'), data.get('longitude')):
        return jsonify({'error': 'Invalid location'}), 400
    
    # Get today's attendance
    today = datetime.now().date()
    attendance = Attendance.query.filter_by(
        employee_id=employee.id,
        date=today
    ).first()
    
    if not attendance:
        return jsonify({'error': 'No check-in found'}), 400
    
    if attendance.check_out:
        return jsonify({'error': 'Already checked out'}), 400
    
    # Update attendance record
    attendance.check_out = datetime.now()
    attendance.check_out_method = 'mobile'
    attendance.check_out_location = f"{data.get('latitude')},{data.get('longitude')}"
    attendance.check_out_device = data.get('device_info')
    
    # Calculate overtime
    shift_end = datetime.combine(today, employee.shift.end_time)
    if attendance.check_out > shift_end:
        overtime = (attendance.check_out - shift_end).total_seconds() / 3600
        attendance.overtime_hours = round(overtime, 2)
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Check-out successful'})

@app.route('/api/biometric/register', methods=['POST'])
@login_required
def register_biometric():
    if not current_user.role == 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    employee_id = data.get('employee_id')
    biometric_type = data.get('type')  # face or fingerprint
    biometric_data = data.get('data')
    
    employee = Employee.query.get_or_404(employee_id)
    
    try:
        if biometric_type == 'face':
            employee.face_encoding = biometric_data
        elif biometric_type == 'fingerprint':
            employee.fingerprint_data = biometric_data
        else:
            return jsonify({'error': 'Invalid biometric type'}), 400
        
        db.session.commit()
        return jsonify({'success': True, 'message': f'{biometric_type} registered successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/biometric/verify', methods=['POST'])
def verify_biometric():
    data = request.get_json()
    employee_id = data.get('employee_id')
    biometric_type = data.get('type')
    biometric_data = data.get('data')
    
    employee = Employee.query.filter_by(employee_id=employee_id).first()
    if not employee:
        return jsonify({'error': 'Employee not found'}), 404
    
    try:
        if biometric_type == 'face':
            if verify_face(biometric_data, employee.face_encoding):
                return jsonify({'success': True, 'employee_id': employee.id})
        elif biometric_type == 'fingerprint':
            if verify_fingerprint(biometric_data, employee.fingerprint_data):
                return jsonify({'success': True, 'employee_id': employee.id})
        
        return jsonify({'error': 'Biometric verification failed'}), 401
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/locations', methods=['GET'])
@login_required
def get_locations():
    locations = Location.query.filter_by(is_active=True).all()
    return jsonify({
        'locations': [{
            'id': loc.id,
            'name': loc.name,
            'address': loc.address,
            'latitude': loc.latitude,
            'longitude': loc.longitude,
            'radius': loc.radius
        } for loc in locations]
    })

@app.route('/api/locations', methods=['POST'])
@login_required
def add_location():
    if not current_user.role == 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    location = Location(
        name=data.get('name'),
        address=data.get('address'),
        latitude=data.get('latitude'),
        longitude=data.get('longitude'),
        radius=data.get('radius', 100)
    )
    
    try:
        db.session.add(location)
        db.session.commit()
        return jsonify({'success': True, 'location_id': location.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/attendance', methods=['GET'])
@login_required
def attendance_analytics():
    if not current_user.role == 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    department = request.args.get('department')
    
    query = db.session.query(
        Attendance, Employee
    ).join(
        Employee, Attendance.employee_id == Employee.id
    )
    
    if start_date and end_date:
        query = query.filter(Attendance.date.between(start_date, end_date))
    if department:
        query = query.filter(Employee.department == department)
    
    records = query.all()
    
    analytics = {
        'total_present': len([r for r in records if r[0].status == 'present']),
        'total_absent': len([r for r in records if r[0].status == 'absent']),
        'total_late': len([r for r in records if r[0].status == 'late']),
        'total_overtime_hours': sum(r[0].overtime_hours or 0 for r in records),
        'department_wise': {},
        'daily_attendance': {}
    }
    
    return jsonify(analytics)

@app.route('/manage-leaves', methods=['GET'])
@login_required
def manage_leaves():
    if not current_user.role == 'admin' and not current_user.is_department_head and not current_user.is_team_leader:
        flash('Access denied. Admin, Department Head, or Team Leader privileges required.', 'danger')
        return redirect(url_for('dashboard'))
    
    if current_user.role == 'admin':
        # Admin sees all department-approved leaves
        pending_leaves = Leave.query.filter_by(
            dept_approval_status='approved',
            status='pending'
        ).all()
    elif current_user.is_department_head:
        # Department head sees team-approved leaves from their department
        pending_leaves = Leave.query.join(
            Employee,
            Leave.employee_id == Employee.id  # Explicitly specify join condition
        ).filter(
            Employee.department_head_id == current_user.id,
            Leave.team_approval_status.in_(['approved', 'pending']),  # See both team approved and pending
            Leave.dept_approval_status == 'pending'
        ).all()
    else:
        # Team leader sees leaves from their team members
        pending_leaves = Leave.query.join(
            Employee,
            Leave.employee_id == Employee.id  # Explicitly specify join condition
        ).filter(
            Employee.team_leader_id == current_user.id,
            Leave.team_approval_status == 'pending'
        ).all()
    
    return render_template('manage_leaves.html', leaves=pending_leaves)

@app.route('/approve-leave/<int:leave_id>', methods=['POST'])
@login_required
def approve_leave(leave_id):
    if not current_user.role == 'admin' and not current_user.is_department_head and not current_user.is_team_leader:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    leave = Leave.query.get_or_404(leave_id)
    action = request.form.get('action')
    
    # Get the employee who applied for leave
    employee = Employee.query.get(leave.employee_id)
    
    if current_user.is_team_leader and employee.team_leader_id == current_user.id:
        # Team leader approval
        if action == 'approve':
            leave.team_approval_status = 'approved'
            leave.team_approved_by = current_user.id
            leave.team_approved_on = datetime.now()
            message = 'Leave application approved by team leader.'
        else:
            leave.team_approval_status = 'rejected'
            leave.status = 'rejected'
            message = 'Leave application rejected by team leader.'
    
    elif current_user.is_department_head and not current_user.role == 'admin':
        # Department head approval (only if team leader has approved or no team leader exists)
        if leave.team_approval_status == 'approved' or not employee.team_leader_id:
            if action == 'approve':
                leave.dept_approval_status = 'approved'
                leave.dept_approved_by = current_user.id
                leave.dept_approved_on = datetime.now()
                message = 'Leave application approved by department head.'
            else:
                leave.dept_approval_status = 'rejected'
                leave.status = 'rejected'
                message = 'Leave application rejected by department head.'
        else:
            message = 'Team leader approval required first.'
            flash(message, 'warning')
            return redirect(url_for('manage_leaves'))
    
    elif current_user.role == 'admin':
        # Final admin approval (only if department head has approved)
        if leave.dept_approval_status == 'approved':
            if action == 'approve':
                leave.status = 'approved'
                leave.approved_by = current_user.id
                
                # Update leave balance
                employee = Employee.query.get(leave.employee_id)
                days = (leave.end_date - leave.start_date).days + 1
                employee.leave_balance -= days
                
                message = 'Leave application approved.'
            else:
                leave.status = 'rejected'
                message = 'Leave application rejected.'
        else:
            message = 'Department head approval required first.'
            flash(message, 'warning')
            return redirect(url_for('manage_leaves'))
    
    db.session.commit()
    flash(message, 'success')
    
    return redirect(url_for('manage_leaves'))

@app.route('/backup-database')
@login_required
def trigger_backup():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('dashboard'))
    
    try:
        backup_database()
        flash('Database backup created successfully!')
    except Exception as e:
        flash('Error creating backup: ' + str(e))
    
    return redirect(url_for('dashboard'))

@app.route('/manage-teams', methods=['GET'])
@login_required
def manage_teams():
    if not current_user.role == 'admin' and not current_user.is_department_head:
        flash('Access denied. Admin or Department Head privileges required.')
        return redirect(url_for('dashboard'))
    
    teams = Team.query.all()
    employees = Employee.query.all()
    return render_template('manage_teams.html', teams=teams, employees=employees)

@app.route('/add-team', methods=['POST'])
@login_required
def add_team():
    if not current_user.role == 'admin' and not current_user.is_department_head:
        flash('Access denied. Admin or Department Head privileges required.')
        return redirect(url_for('dashboard'))
    
    name = request.form.get('name')
    department = request.form.get('department')
    description = request.form.get('description')
    leader_id = request.form.get('leader_id')
    
    # Create new team
    team = Team(
        name=name,
        department=department,
        description=description,
        leader_id=leader_id
    )
    
    try:
        db.session.add(team)
        
        # Update team leader status
        leader = Employee.query.get(leader_id)
        if leader:
            leader.is_team_leader = True
            leader.role = 'team_leader'
        
        db.session.commit()
        flash('Team created successfully!')
    except Exception as e:
        db.session.rollback()
        flash('Error creating team. Please try again.')
    
    return redirect(url_for('manage_teams'))

@app.route('/update-team/<int:team_id>', methods=['POST'])
@login_required
def update_team(team_id):
    if not current_user.role == 'admin' and not current_user.is_department_head:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    team = Team.query.get_or_404(team_id)
    data = request.get_json()
    
    try:
        # If leader is being changed
        if data.get('leader_id') and data['leader_id'] != team.leader_id:
            # Remove team leader status from old leader if they don't lead any other teams
            if team.leader and len(team.leader.led_teams) <= 1:
                team.leader.is_team_leader = False
                team.leader.role = 'employee'
            
            # Update new leader
            new_leader = Employee.query.get(data['leader_id'])
            if new_leader:
                new_leader.is_team_leader = True
                new_leader.role = 'team_leader'
        
        # Update team details
        team.name = data.get('name', team.name)
        team.department = data.get('department', team.department)
        team.description = data.get('description', team.description)
        team.leader_id = data.get('leader_id', team.leader_id)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Team updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/delete-team/<int:team_id>', methods=['POST'])
@login_required
def delete_team(team_id):
    if not current_user.role == 'admin' and not current_user.is_department_head:
        flash('Access denied. Admin or Department Head privileges required.')
        return redirect(url_for('dashboard'))
    
    team = Team.query.get_or_404(team_id)
    
    try:
        # Remove team leader status if they don't lead any other teams
        if team.leader and len(team.leader.led_teams) <= 1:
            team.leader.is_team_leader = False
            team.leader.role = 'employee'
        
        db.session.delete(team)
        db.session.commit()
        flash('Team deleted successfully!')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting team. Please try again.')
    
    return redirect(url_for('manage_teams'))

@app.route('/assign-team-members/<int:team_id>', methods=['POST'])
@login_required
def assign_team_members(team_id):
    if not current_user.role == 'admin' and not current_user.is_department_head and not current_user.is_team_leader:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    team = Team.query.get_or_404(team_id)
    data = request.get_json()
    member_ids = data.get('member_ids', [])
    
    try:
        # Update team members
        for employee in Employee.query.filter(Employee.team_id == team_id).all():
            if str(employee.id) not in member_ids:
                employee.team_id = None
                employee.team_leader_id = None
        
        for member_id in member_ids:
            employee = Employee.query.get(member_id)
            if employee:
                employee.team_id = team_id
                employee.team_leader_id = team.leader_id
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Team members updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/update-employee/<int:employee_id>', methods=['POST'])
@login_required
def update_employee(employee_id):
    if not current_user.role == 'admin' and not current_user.is_department_head:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    employee = Employee.query.get_or_404(employee_id)
    
    try:
        # Update employee details
        employee.name = request.form.get('name', employee.name)
        employee.email = request.form.get('email', employee.email)
        employee.department = request.form.get('department', employee.department)
        employee.designation = request.form.get('designation', employee.designation)
        
        # Update role and related flags
        new_role = request.form.get('role', employee.role)
        employee.role = new_role
        employee.is_department_head = (new_role == 'hod')
        employee.is_team_leader = (new_role == 'team_leader')
        
        # Handle reporting relationship
        reporting_to = request.form.get('reporting_to')
        if reporting_to:
            try:
                employee.reporting_to = int(reporting_to)
            except ValueError:
                employee.reporting_to = None
        
        # Handle shift assignment
        shift_id = request.form.get('shift_id')
        if shift_id:
            try:
                employee.shift_id = int(shift_id)
            except ValueError:
                employee.shift_id = None
        
        # Handle base salary
        base_salary = request.form.get('base_salary')
        if base_salary:
            try:
                employee.base_salary = float(base_salary)
            except ValueError:
                pass  # Keep existing salary if invalid value
        
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'Employee updated successfully',
            'employee': {
                'id': employee.id,
                'name': employee.name,
                'email': employee.email,
                'department': employee.department,
                'designation': employee.designation,
                'role': employee.role,
                'reporting_to': employee.reporting_to,
                'shift_id': employee.shift_id,
                'base_salary': employee.base_salary
            }
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error updating employee: {str(e)}")  # Log the error
        return jsonify({'success': False, 'message': f'Error updating employee: {str(e)}'}), 500

@app.route('/reset-employee-password/<int:employee_id>', methods=['POST'])
@login_required
def reset_employee_password(employee_id):
    # Check if user has permission
    if not current_user.role == 'admin' and not current_user.is_department_head:
        return jsonify({
            'success': False,
            'message': 'Access denied. Admin or Department Head privileges required.'
        }), 403
    
    # Get employee
    employee = Employee.query.get_or_404(employee_id)
    
    try:
        data = request.get_json()
        new_password = data.get('new_password')
        
        if not new_password:
            return jsonify({
                'success': False,
                'message': 'New password is required'
            }), 400
        
        # Update password
        employee.password = new_password
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Password reset successfully'
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Error resetting password: {str(e)}'
        }), 500

# Add database backup function
def backup_database():
    """Create a backup of the database"""
    from datetime import datetime
    import shutil
    import os
    
    # Create backups folder if it doesn't exist
    if not os.path.exists('database/backups'):
        os.makedirs('database/backups')
    
    # Create backup with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = f'database/backups/attendance_backup_{timestamp}.db'
    
    # Copy the database file
    shutil.copy2('database/attendance.db', backup_file)
    
    # Keep only last 5 backups
    backups = sorted([f for f in os.listdir('database/backups') if f.endswith('.db')])
    if len(backups) > 5:
        os.remove(os.path.join('database/backups', backups[0]))

if __name__ == '__main__':
    with app.app_context():
        # Create the database and tables
        db.create_all()
        
        # Create an admin user if not exists
        admin = Employee.query.filter_by(employee_id='ADMIN001').first()
        if not admin:
            admin = Employee(
                employee_id='ADMIN001',
                name='Admin User',
                email='admin@example.com',
                password='admin123',  # Change this in production!
                department='Administration',
                role='admin',
                base_salary=50000.0
            )
            db.session.add(admin)
        db.session.commit()
    
    # Development server
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True) 