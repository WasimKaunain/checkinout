from flask import Blueprint, render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError, DataError, OperationalError
from app.utils.id_generator import generate_custom_user_id
from app.models import db, User, Visitor, Student, Staff
import re

visitor_bp = Blueprint('visitor', __name__, url_prefix='/visitor')

@visitor_bp.route('/login-register')
def visitor_login_register():
    return render_template('User/Visitor/visitor_login_reg.html')

@visitor_bp.route('/login')
def visitor_login():
    return render_template('User/Visitor/visitor_login.html')

@visitor_bp.route('/forget-password')
def visitor_forget_password():
    return render_template('User/Visitor/visitor_forget_password.html')

@visitor_bp.route('/register', methods=['GET', 'POST'])
def visitor_register():
    if request.method == 'POST':
        visitor_id = request.form['visitor_id']
        name = request.form['visitor_name']
        gender = request.form['gender']
        contact_no = request.form['contact']
        room_no = request.form['room_number']
        guesthouse_name = request.form['guesthouse_name']
        duration = request.form['duration']
        purpose = request.form['purpose']
        reference = request.form['reference']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Password match check
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('visitor.visitor_register'))

        # Password complexity check
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$'
        if not re.match(pattern, password):
            flash('Password must be at least 8 characters, with upper/lowercase, number, and special character.', 'danger')
            return redirect(url_for('visitor.visitor_register'))

        # ✅ Reference check: must match a Student or Staff
        student_ref = Student.query.filter_by(roll_no=reference).first()
        staff_ref = Staff.query.filter_by(staff_id=reference).first()

        if not student_ref and not staff_ref:
            flash('Invalid reference. It must match a registered Student Roll No or Staff ID.', 'danger')
            return redirect(url_for('visitor.visitor_register'))

        hashed_password = generate_password_hash(password)

        try:
            custom_user_id = generate_custom_user_id('Student')
            # Save to User table
            user = User(user_id = custom_user_id, username=email, password_hash=hashed_password, role='Visitor')
            db.session.add(user)
            db.session.flush()

            # Save to Visitor table
            visitor = Visitor(
                visitor_id=visitor_id,
                name=name,
                contact_no=contact_no,
                gender=gender,
                room_no=room_no,
                guesthouse_name=guesthouse_name,
                duration_of_stay=int(duration),
                purpose=purpose,
                reference=reference
            )
            db.session.add(visitor)
            db.session.commit()

            flash('Visitor registered successfully!', 'success')
            return redirect(url_for('visitor.visitor_login'))

        except IntegrityError:
            db.session.rollback()
            error_msg = str(e.orig).split(':')[-1].strip()
            flash(error_msg, 'danger')
            return redirect(url_for('visitor.visitor_register'))

        except DataError as e:
            db.session.rollback()
            error_msg = str(e.orig).split(':')[-1].strip()
            flash(error_msg, 'danger')
            return redirect(url_for('visitor.visitor_register'))

        except OperationalError as e:
            db.session.rollback()
            error_msg = str(e.orig).split(':')[-1].strip()
            flash(error_msg, 'danger')
            return redirect(url_for('visitor.visitor_register'))

    return render_template('User/Visitor/visitor_register.html')