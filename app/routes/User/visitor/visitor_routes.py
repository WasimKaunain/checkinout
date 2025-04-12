from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError, DataError, OperationalError
from app.utils.id_generator import generate_custom_user_id
from app.models import db, User, Visitor, Student, Staff
import re

visitor_bp = Blueprint('visitor', __name__, url_prefix='/visitor')

@visitor_bp.route('/login-register')
def visitor_login_register():
    return render_template('User/Visitor/visitor_login_reg.html')

@visitor_bp.route('/forget-password')
def visitor_forget_password():
    return render_template('User/Visitor/visitor_forget_password.html')

@visitor_bp.route('/login', methods=['GET', 'POST'])
def visitor_login():
    if request.method == 'POST':
        username = request.form.get('email')
        password = request.form.get('password')

        # Fetch user from Users table (assuming you're using User model here)
        user = User.query.filter_by(username=username).first()
        if user:
            # Now check if user is linked to a student
            visitor = Visitor.query.filter_by(email=user.username).first()
            if visitor:
                # Now validate password
                if check_password_hash(user.password_hash, password):
                    session['user_id'] = user.user_id
                    session['user_type'] = 'visitor'

                    flash('Login successful!', 'success')
                    return redirect(url_for('visitor.visitor_dashboard'))
                else:
                    flash('Invalid password', 'danger')
            else:
                flash('Not a valid student account', 'warning')
        else:
            flash('Invalid username', 'danger')

        return redirect(url_for('visitor.visitor_login'))

    # For GET request
    return render_template('User/Visitor/visitor_login.html')

@visitor_bp.route('/dashboard', methods=['GET','POST'])
def visitor_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'visitor':
        flash('Please log in as visitor first.', 'warning')
        return redirect(url_for('visitor.visitor_login'))
    return render_template('User/Visitor/visitor_dashboard.html')

@visitor_bp.route('/logout')
def visitor_logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('visitor.visitor_login'))

@visitor_bp.route('/register', methods=['GET', 'POST'])
def visitor_register():
    print("🛠️ Entered visitor_register route")
    if request.method == 'POST':
        print("📤 Received POST request")
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

        print(f"📋 Data: {name}, {visitor_id}, {email}, {password}, {confirm_password}")

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

        print(f"Student : {student_ref}, Staff : {staff_ref}")

        if not student_ref and not staff_ref:
            flash('Invalid reference. It must match a registered Student Roll No or Staff ID.', 'danger')
            return redirect(url_for('visitor.visitor_register'))

        hashed_password = generate_password_hash(password)
        print(f"Password hashed...")

        try:
            custom_user_id = generate_custom_user_id('Visitor')
            print("Custom id created...")
            # Save to User table
            user = User(user_id = custom_user_id, username=email, password_hash=hashed_password, role='Visitor')
            db.session.add(user)
    

            # Save to Visitor table
            visitor = Visitor(
                visitor_id=visitor_id,
                name=name,
                contact_no=contact_no,
                email=email,
                gender=gender,
                room_no=room_no,
                guesthouse_name=guesthouse_name,
                duration_of_stay=int(duration),
                purpose=purpose,
                reference=reference
            )
            db.session.add(visitor)

            print("before commit...")
            db.session.commit()
            print("after commit...")

            flash('Visitor registered successfully!', 'success')
            return redirect(url_for('visitor.visitor_login'))

        except IntegrityError as e:
            db.session.rollback()
            error_msg = str(e.orig).split(':')[-1].strip()
            print(f"🔥 IntegrityError: {error_msg}")
            flash(error_msg, 'danger')
            return redirect(url_for('visitor.visitor_register'))

        except DataError as e:
            db.session.rollback()
            error_msg = str(e.orig).split(':')[-1].strip()
            print(f"🔥 DataError: {error_msg}")
            flash(error_msg, 'danger')
            return redirect(url_for('visitor.visitor_register'))

        except OperationalError as e:
            db.session.rollback()
            error_msg = str(e.orig).split(':')[-1].strip()
            print(f"🔥 OperationalError: {error_msg}")
            flash(error_msg, 'danger')
            return redirect(url_for('visitor.visitor_register'))

        except Exception as e:
            db.session.rollback()
            print(f"🔥 Exception occurred: {e}")
            flash("Registration failed due to internal error.", "danger")
            return redirect(url_for('visitor.visitor_register'))

    return render_template('User/Visitor/visitor_register.html')