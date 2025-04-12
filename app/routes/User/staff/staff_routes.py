from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError, DataError, OperationalError
from app.utils.id_generator import generate_custom_user_id
from app.models import db, User, Staff
import re

staff_bp = Blueprint('staff', __name__, url_prefix='/staff')

@staff_bp.route('/login-register')
def staff_login_register():
    return render_template('User/staff/staff_login_reg.html')

@staff_bp.route('/login', methods=['GET', 'POST'])
def staff_login():
    if request.method == 'POST':
        username = request.form.get('email')
        password = request.form.get('password')

        # Fetch user from Users table (assuming you're using User model here)
        user = User.query.filter_by(username=username).first()
        if user:

            # Now check if user is linked to a student
            staff = Staff.query.filter_by(email=user.username).first()
            if staff:

                # Now validate password
                if check_password_hash(user.password_hash, password):

                    session['user_id'] = user.user_id
                    session['user_type'] = 'staff'

                    flash('Login successful!', 'success')
                    return redirect(url_for('staff.staff_dashboard'))
                else:
                    flash('Invalid password', 'danger')
            else:
                flash('Not a valid student account', 'warning')
        else:
            flash('Invalid username', 'danger')

        return redirect(url_for('staff.staff_login'))

    # For GET request
    return render_template('User/Staff/staff_login.html')

@staff_bp.route('/dashboard', methods=['GET','POST'])
def staff_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'staff':
        flash('Please log in as staff first.', 'warning')
        return redirect(url_for('staff.staff_login'))
    return render_template('User/Staff/staff_dashboard.html')

@staff_bp.route('/logout')
def staff_logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('staff.staff_login'))

@staff_bp.route('/forget-password')
def staff_forget_password():
    return render_template('User/Staff/staff_forget_password.html')


@staff_bp.route('/register', methods=['GET', 'POST'])
def staff_register():
    if request.method == 'POST':
        staff_id = request.form.get('staff_id')
        name = request.form.get('staff_name')
        department = request.form.get('department')
        gender = request.form.get('gender')
        contact_no = request.form.get('contact')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Password match check
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('staff.staff_register'))

        # Password complexity check
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$'
        if not re.match(pattern, password):
            flash("Password must contain uppercase, lowercase, digit, special character and be at least 8 characters.", "danger")
            return redirect(url_for('staff.staff_register'))

        hashed_password = generate_password_hash(password)

        try:
            custom_user_id = generate_custom_user_id('Staff')
            user = User(user_id=custom_user_id, username=email, password_hash=hashed_password, role='Staff')
            db.session.add(user)
        
            staff = Staff(
                staff_id=staff_id,
                name=name,
                department=department,
                gender=gender,
                email=email,
                contact_no=contact_no
            )
            db.session.add(staff)
            db.session.commit()
        
            flash("Staff registered successfully!", "success")
            return redirect(url_for('staff.staff_login'))
        
        except IntegrityError as e:
            db.session.rollback()
            error_msg = str(e.orig).split(':')[-1].strip()
            flash(error_msg, "danger")

        except DataError as e:
            db.session.rollback()
            error_msg = str(e.orig).split(':')[-1].strip()
            flash(error_msg, "danger")

        except OperationalError as e:
            db.session.rollback()
            error_msg = str(e.orig).split(':')[-1].strip()
            flash(error_msg, "danger")

        except Exception as e:
            db.session.rollback()
            error_msg = str(e.orig).split(':')[-1].strip()
            flash(error_msg, "danger")

    return render_template('User/Staff/staff_register.html')