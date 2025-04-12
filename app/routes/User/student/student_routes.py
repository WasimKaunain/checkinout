from flask import Blueprint, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import OperationalError, IntegrityError, DataError
from app.utils.id_generator import generate_custom_user_id
from app.models import User, Student, db
import re

#from flask_sqlalchemy import SQLAlchemy

student_bp = Blueprint('student', __name__, url_prefix='/student')

@student_bp.route('/login-register')
def student_login_register():
    return render_template('User/Student/stud_login_reg.html')

@student_bp.route('/login')
def student_login():
    return render_template('User/Student/stud_login.html')

@student_bp.route('/forget-password')
def student_forget_password():
    return render_template('User/Student/stud_forget_password.html')

@student_bp.route('/register', methods=['GET', 'POST'])
def student_register():
    if request.method == 'POST':
        roll_no = request.form['roll']
        name = request.form['name']
        department = request.form['dept']
        gender = request.form['gender']
        email = request.form['email']
        hostel_name = request.form['hostel']
        room_no = request.form['room']
        mess_id = request.form['messid']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Password match check
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('student.student_register'))

        # Password complexity check
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$'
        if not re.match(pattern, password):
            flash('Password must be at least 8 characters long, contain upper and lowercase letters, numbers, and special characters.', 'danger')
            return redirect(url_for('student.student_register'))

        hashed_password = generate_password_hash(password)

        try:
            # Generate custom user ID
            custom_user_id = generate_custom_user_id('Student')

            # Save to User table
            user = User(user_id=custom_user_id, username=email, password_hash=hashed_password, role='Student')
            db.session.add(user)

            # Save to Student table (with foreign key to User)
            student = Student(
                roll_no=roll_no,
                name=name,
                department=department,
                gender=gender,
                email=email,
                hostel_name=hostel_name,
                room_no=room_no,
                mess_id=mess_id
            )
            db.session.add(student)

            db.session.commit()

            flash('Registration successful!', 'success')
            return redirect(url_for('student.student_login'))

        except IntegrityError as e:
            db.session.rollback()
            error_msg = str(e.orig).split(':')[-1].strip()
            flash(error_msg, 'danger')
            return redirect(url_for('student.student_register'))

        except DataError as e:
            db.session.rollback()
            error_msg = str(e.orig).split(':')[-1].strip()
            flash(error_msg, 'danger')
            return redirect(url_for('student.student_register'))

        except OperationalError as e:
            db.session.rollback()
            error_msg = str(e.orig).split(':')[-1].strip()
            flash(error_msg, 'danger')
            return redirect(url_for('student.student_register'))

    return render_template('User/Student/stud_register.html')
