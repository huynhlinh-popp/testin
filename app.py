import datetime
import uuid
from flask import Flask, render_template, redirect, url_for, request, flash # type: ignore
from flask_sqlalchemy import SQLAlchemy # type: ignore
from flask_bcrypt import Bcrypt # type: ignore
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required # type: ignore

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(60), nullable=False)
    attendances = db.relationship('Attendance', backref='employee', lazy=True)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    checkin_time = db.Column(db.DateTime, nullable=True)
    checkout_time = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main'))
    if request.method == 'POST':
        uid = request.form.get('uid')
        password = request.form.get('password')
        user = User.query.filter_by(uid=uid).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('main'))
        else:
            flash('Login Unsuccessful. Please check UID and password', 'danger')
    return render_template('login.html')

@app.route('/main')
@login_required
def main():
    return render_template('main.html')

@app.route('/checkin')
@login_required
def checkin():
    attendance = Attendance(checkin_time=datetime.utcnow(), employee=current_user)
    db.session.add(attendance)
    db.session.commit()
    flash('Check-in successful', 'success')
    return redirect(url_for('main'))

@app.route('/checkout')
@login_required
def checkout():
    attendance = Attendance.query.filter_by(user_id=current_user.id).order_by(Attendance.id.desc()).first()
    if attendance and attendance.checkin_time and not attendance.checkout_time:
        attendance.checkout_time = datetime.utcnow()
        db.session.commit()
        flash('Check-out successful', 'success')
    else:
        flash('Check-out failed. Please check-in first.', 'danger')
    return redirect(url_for('main'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if request.method == 'POST':
        name = request.form.get('name')
        password = bcrypt.generate_password_hash(request.form.get('password')).decode('utf-8')
        user = User(uid=str(uuid.uuid4()), name=name, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Employee added successfully', 'success')
        return redirect(url_for('admin'))
    return render_template('admin.html')

@app.route('/manage_employees')
@login_required
def manage_employees():
    employees = User.query.all()
    return render_template('manage_employees.html', employees=employees)

@app.route('/manage_attendance')
@login_required
def manage_attendance():
    attendances = Attendance.query.all()
    return render_template('manage_attendance.html', attendances=attendances)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
