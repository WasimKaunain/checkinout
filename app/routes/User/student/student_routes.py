from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import OperationalError, IntegrityError, DataError
from app.utils.id_generator import generate_custom_user_id
from app.models import User, Student, Member , MemberGroupMapping, Login, Mess, Hostel, HostelRoom, GuestroomRequest, db
import hashlib, secrets
from datetime import datetime, timedelta
import qrcode, io, base64
import re

#from flask_sqlalchemy import SQLAlchemy

student_bp = Blueprint('student', __name__, url_prefix='/student')

@student_bp.route('/login-register')
def student_login_register():
    return render_template('User/Student/stud_login_reg.html')


@student_bp.route('/login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        username = request.form.get('email')
        password = request.form.get('password')

        # Fetch user from Users table (assuming you're using User model here)
        user = User.query.filter_by(username=username).first()
        if user:

            # Now check if user is linked to a student
            student = Student.query.filter_by(email=user.username).first()
            if student:
                # Now validate password
                if check_password_hash(user.password_hash, password):
                    session['user_id'] = user.user_id
                    session['user_type'] = 'student'

                    flash('Login successful!', 'success')
                    return redirect(url_for('student.student_dashboard'))
                else:
                    flash('Invalid password', 'danger')
            else:
                flash('Not a valid student account', 'warning')
        else:
            flash('Invalid username', 'danger')

        return redirect(url_for('student.student_login'))

    return render_template('User/Student/stud_login.html')

@student_bp.route('/dashboard', methods=['GET','POST'])
def student_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'student':
        flash('Please log in as student first.', 'warning')
        return redirect(url_for('student.student_login'))
    return render_template('User/Student/student_dashboard.html')


@student_bp.route('/logout')
def student_logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('student.student_login'))


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

            # Commit first to ensure data is valid before inserting into the other DB
            db.session.commit()

            # Now insert into Member (cs432cims DB using bind 'eval')
            member = Member(UserName=custom_user_id, emailID=email)
            db.session.add(member)
            db.session.commit()

            # Get the auto-incremented member.id
            member_id = member.ID
            login = Login(MemberID=member_id, Password=hashed_password, Role='Student')
            db.session.add(login)
            db.session.commit()

            # Insert into MemberGroupMapping with group_id = 5
            mapping = MemberGroupMapping(MemberID=member_id, GroupID=5)
            db.session.add(mapping)
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

@student_bp.route('/profile')
def student_profile():
    if 'user_id' not in session or session.get('user_type') != 'student':
        flash('Please log in as a student first.', 'warning')
        return redirect(url_for('student.student_login'))

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('student.student_login'))

    student = Student.query.filter_by(email=user.username).first()
    if not student:
        flash('Student profile not found.', 'danger')
        return redirect(url_for('student.student_dashboard'))
    
    mess = Mess.query.filter_by(mess_id = student.mess_id).first()
    
    # Combine student info for QR content
    qr_data = f"StudentID: {student.roll_no}\nName: {student.name}\nDepartment: {student.department}\nEmail: {student.email}\nMess: {mess.mess_name}\nHostel Name: {student.hostel_name}\nRoom No: {student.room_no}"

    # Generate QR code
    qr_img = qrcode.make(qr_data)
    buffer = io.BytesIO()
    qr_img.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    return render_template('User/Student/student_profile.html', student=student, qr_code=qr_base64)

@student_bp.route('/profile-update', methods=['GET', 'POST'])
def student_profile_update():
    if request.method == 'GET':
        if 'user_id' not in session or session.get('user_type') != 'student':
            flash('Please log in as a student first.', 'warning')
            return redirect(url_for('student.student_login'))

        user_id = session['user_id']
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('student.student_login'))

        student = Student.query.filter_by(email=user.username).first()
        if not student:
            flash('Student profile not found.', 'danger')
            return redirect(url_for('student.student_dashboard'))

        return render_template('User/Student/student_profile_update.html', student=student)

    else:
        # POST method: update the student's editable fields
        if 'user_id' not in session or session.get('user_type') != 'student':
            flash('Unauthorized access.', 'danger')
            return redirect(url_for('student.student_login'))

        user_id = session['user_id']
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('student.student_login'))

        student = Student.query.filter_by(email=user.username).first()
        if not student:
            flash('Student profile not found.', 'danger')
            return redirect(url_for('student.student_dashboard'))

        # Get form data
        student.name = request.form['name']
        student.department = request.form['department']
        student.hostel_name = request.form['hostel_name']
        student.room_no = request.form['room_number']
        student.mess_id = request.form['mess_id']

        try:
            db.session.commit()
            flash('Profile updated successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating profile.', 'danger')
            print("Update Error:", e)

        return redirect(url_for('student.student_profile'))
    

@student_bp.route('/profile-delete')
def student_profile_delete():
    if 'user_id' not in session or session.get('user_type') != 'student':
        flash('Please log in as a student first.', 'warning')
        return redirect(url_for('student.student_login'))

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('student.student_login'))

    student = Student.query.filter_by(email=user.username).first()
    if not student:
        flash('Student profile not found.', 'danger')
        return redirect(url_for('student.student_dashboard'))

    try:
        db.session.delete(student)
        db.session.delete(user)
        db.session.commit()
        session.clear()
        flash('Your profile has been deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting your profile.', 'danger')
        print("Deletion Error:", e)

    return redirect(url_for('student.student_login'))

    

@student_bp.route('/hostels')
def student_hostel():
    if 'user_id' not in session or session.get('user_type') != 'student':
        flash('Please log in as a student first.', 'warning')
        return redirect(url_for('student.student_login'))
    
    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('student.student_login'))

    # Get student using the user's email/username
    student = Student.query.filter_by(email=user.username).first()
    if not student:
        flash('Student profile not found.', 'danger')
        return redirect(url_for('student.student_dashboard'))

    return render_template('User/Student/student_hostels.html', student=student)


@student_bp.route('/hostelroom-availability')
def student_hostelroom_availability():
    if 'user_id' not in session or session.get('user_type') != 'student':
        flash('Please log in as a student first.', 'warning')
        return redirect(url_for('student.student_login'))

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('student.student_login'))

    student = Student.query.filter_by(email=user.username).first()
    if not student:
        flash('Student profile not found.', 'danger')
        return redirect(url_for('student.student_dashboard'))

    return render_template('User/Student/student_hostelroom_availability.html', student=student)

@student_bp.route('/get_hostels')
def get_hostels():
    try:
        hostels = Hostel.query.with_entities(Hostel.hostel_name).all()
        hostel_names = [h.hostel_name for h in hostels]
        return jsonify(hostel_names)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@student_bp.route('/check_room_status', methods=['POST'])
def check_room_status():
    data = request.get_json()
    hostel = data.get('hostel')
    room_no = data.get('room')

    room = HostelRoom.query.filter_by(hostel_name=hostel, room_no=room_no).first()
    
    if not room:
        return jsonify({'error': 'Room not found'}), 404

    return jsonify({
        'status': room.status,
        'room_type': f"{room.capacity}-Sharing",  # Just an assumption!
        'guesthouse': hostel  # you could customize this if needed
    })

@student_bp.route('/hostelroom-vacancy-update')
def student_hostelroom_vacancy_update():
    if 'user_id' not in session or session.get('user_type') != 'student':
        flash('Please log in as a student first.', 'warning')
        return redirect(url_for('student.student_login'))

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('student.student_login'))

    student = Student.query.filter_by(email=user.username).first()
    if not student:
        flash('Student profile not found.', 'danger')
        return redirect(url_for('student.student_dashboard'))

    return render_template('User/Student/student_hostelroom_vacancy_update.html', student=student)

@student_bp.route('/hostelroom-allotment-details')
def student_hostelroom_allotment_details():
    if 'user_id' not in session or session.get('user_type') != 'student':
        flash('Please log in as a student first.', 'warning')
        return redirect(url_for('student.student_login'))

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('student.student_login'))

    student = Student.query.filter_by(email=user.username).first()
    if not student:
        flash('Student profile not found.', 'danger')
        return redirect(url_for('student.student_dashboard'))
    
    roommates = Student.query.filter_by(room_no=student.room_no).all()

    return render_template('User/Student/student_hostelroom_allotment_details.html', student=student, roommates = roommates)

@student_bp.route('/checkin-history')
def student_checkin_history():
    if 'user_id' not in session or session.get('user_type') != 'student':
        flash('Please log in as a student first.', 'warning')
        return redirect(url_for('student.student_login'))

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('student.student_login'))

    student = Student.query.filter_by(email=user.username).first()
    if not student:
        flash('Student profile not found.', 'danger')
        return redirect(url_for('student.student_dashboard'))

    return render_template('User/Student/student_checkin_history.html', student=student)


@student_bp.route('/guesthouses')
def student_guesthouses():
    if 'user_id' not in session or session.get('user_type') != 'student':
        flash('Please log in as a student first.', 'warning')
        return redirect(url_for('student.student_login'))

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('student.student_login'))

    student = Student.query.filter_by(email=user.username).first()
    if not student:
        flash('Student profile not found.', 'danger')
        return redirect(url_for('student.student_dashboard'))

    return render_template('User/Student/student_guesthouses.html', student=student)

@student_bp.route('/guestroom-availability')
def student_guestroom_availability():
    if 'user_id' not in session or session.get('user_type') != 'student':
        flash('Please log in as a student first.', 'warning')
        return redirect(url_for('student.student_login'))

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('student.student_login'))

    student = Student.query.filter_by(email=user.username).first()
    if not student:
        flash('Student profile not found.', 'danger')
        return redirect(url_for('student.student_dashboard'))

    return render_template('User/Student/student_guestroom_availability.html', student=student)


@student_bp.route('/guestroom-allotment-request', methods=['GET', 'POST'])
def student_guestroom_allotment_request():
    if request.method == 'POST':
        if 'user_id' not in session or session.get('user_type') != 'student':
            flash('Please log in as a student first.', 'warning')
            return redirect(url_for('student.student_login'))

        user_id = session['user_id']
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('student.student_login'))

        student = Student.query.filter_by(email=user.username).first()
        if not student:
            flash('Student profile not found.', 'danger')
            return redirect(url_for('student.student_dashboard'))    

        try:
            current_app.logger.info("Form submission received.")

            name = request.form.get('visitor_name')
            email = request.form.get('email')
            contact = request.form.get('contact')
            guesthouse = request.form.get('guesthouse')
            room_type = request.form.get('room_type')
            checkin_date_str = request.form.get('checkin_date')
            checkout_date_str = request.form.get('checkout_date')
            purpose = request.form.get('purpose')
            referenced_by = student.roll_no

            # Debug logs
            current_app.logger.info(f"Received: {name}, {email}, {contact}, {guesthouse}, {room_type}, {checkin_date_str}, {checkout_date_str}, {purpose}")

            checkin_date = datetime.strptime(checkin_date_str, '%Y-%m-%d').date()
            checkout_date = datetime.strptime(checkout_date_str, '%Y-%m-%d').date()

            duration = (checkout_date - checkin_date).days
            current_app.logger.info(f"Calculated duration: {duration} days")

            new_request = GuestroomRequest(
                name=name,
                email=email,
                contact_no=contact,
                guesthouse_name=guesthouse,
                room_type=room_type,
                checkindate=checkin_date,
                checkoutdate=checkout_date,
                duration_of_stay=duration,
                purpose=purpose,
                referenced_by=referenced_by,
                status='pending'
            )

            db.session.add(new_request)
            db.session.commit()

            flash("✅ Guestroom request submitted successfully!", "success")
            current_app.logger.info("Request saved to DB successfully.")
            return redirect(url_for('student.student_guesthouses'))

        except Exception as e:
            current_app.logger.error(f"Exception occurred: {e}", exc_info=True)
            flash(f"⚠️ Error submitting request: {e}", "danger")
            return redirect(url_for('student.student_guestroom_allotment_request'))
        
    else:
        if 'user_id' not in session or session.get('user_type') != 'student':
            flash('Please log in as a student first.', 'warning')
            return redirect(url_for('student.student_login'))

        user_id = session['user_id']
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('student.student_login'))

        student = Student.query.filter_by(email=user.username).first()
        if not student:
            flash('Student profile not found.', 'danger')
            return redirect(url_for('student.student_dashboard'))    

        return render_template("User/Student/student_guestroom_allotment_request.html", student=student)



@student_bp.route('/mess')
def student_mess():
    if 'user_id' not in session or session.get('user_type') != 'student':
        flash('Please log in as a student first.', 'warning')
        return redirect(url_for('student.student_login'))

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('student.student_login'))

    student = Student.query.filter_by(email=user.username).first()
    if not student:
        flash('Student profile not found.', 'danger')
        return redirect(url_for('student.student_dashboard'))

    return render_template('User/Student/student_mess.html', student=student)


@student_bp.route('/mess-checkin-history')
def student_mess_checkin_history():
    if 'user_id' not in session or session.get('user_type') != 'student':
        flash('Please log in as a student first.', 'warning')
        return redirect(url_for('student.student_login'))

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('student.student_login'))

    student = Student.query.filter_by(email=user.username).first()
    if not student:
        flash('Student profile not found.', 'danger')
        return redirect(url_for('student.student_dashboard'))

    return render_template('User/Student/student_mess_checkin_history.html', student=student)

@student_bp.route('/mess-allotment-details')
def student_mess_allotment_details():
    if 'user_id' not in session or session.get('user_type') != 'student':
        flash('Please log in as a student first.', 'warning')
        return redirect(url_for('student.student_login'))

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('student.student_login'))

    student = Student.query.filter_by(email=user.username).first()
    if not student:
        flash('Student profile not found.', 'danger')
        return redirect(url_for('student.student_dashboard'))
    
    mess = Mess.query.filter_by(mess_id=student.mess_id).first()
    
    # Combine student info for QR content
    qr_data = f"StudentID: {student.roll_no}\nName: {student.name}\nEmail: {student.email}\nMess: {mess.mess_name}"

    # Generate QR code
    qr_img = qrcode.make(qr_data)
    buffer = io.BytesIO()
    qr_img.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    return render_template('User/Student/student_mess_allotment_details.html', mess=mess, qr_code=qr_base64)






