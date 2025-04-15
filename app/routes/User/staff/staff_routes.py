from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError, DataError, OperationalError
from app.utils.id_generator import generate_custom_user_id
from app.models import db, User, Staff, Member ,MemberGroupMapping, Login, GuestroomRequest
import qrcode, io, base64
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

            # Commit first to ensure data is valid before inserting into the other DB
            db.session.commit()

            # Now insert into Member (cs432cims DB using bind 'eval')
            member = Member(UserName=custom_user_id, emailID=email)
            db.session.add(member)
            db.session.commit()

            # Get the auto-incremented member.id
            member_id = member.ID
            login = Login(MemberID=member_id, Password=hashed_password, Role='Staff')
            db.session.add(login)
            db.session.commit()

            # Insert into MemberGroupMapping with group_id = 5
            mapping = MemberGroupMapping(MemberID=member_id, GroupID=5)
            db.session.add(mapping)

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

@staff_bp.route('/profile')
def staff_profile():
    if 'user_id' not in session or session.get('user_type') != 'staff':
        flash('Please log in as a staff first.', 'warning')
        return redirect(url_for('staff.staff_login'))

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('staff.staff_login'))

    staff = Staff.query.filter_by(email=user.username).first()
    if not staff:
        flash('Staff profile not found.', 'danger')
        return redirect(url_for('staff.staff_dashboard'))
    
    # Combine student info for QR content
    qr_data = f"StaffID: {staff.staff_id}\nName: {staff.name}\nDepartment: {staff.department}\nEmail: {staff.email}"

    # Generate QR code
    qr_img = qrcode.make(qr_data)
    buffer = io.BytesIO()
    qr_img.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()


    return render_template('User/Staff/staff_profile.html', staff=staff, user=user, qr_code=qr_base64)

@staff_bp.route('/profile-update',methods=['GET','POST'])
def staff_profile_update():
    if request.methos == 'GET':
        if 'user_id' not in session or session.get('user_type') != 'staff':
            flash('Please log in as a staff first.', 'warning')
            return redirect(url_for('staff.staff_login'))

        user_id = session['user_id']
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('staff.staff_login'))

        staff = Staff.query.filter_by(email=user.username).first()
        if not staff:
            flash('Staff profile not found.', 'danger')
            return redirect(url_for('staff.staff_dashboard'))
        return render_template('User/Staff/staff_profile_update.html', staff=staff, user=user)
    
    else:
        if 'user_id' not in session or session.get('user_type') != 'staff':
            flash('Please log in as a staff first.', 'warning')
            return redirect(url_for('staff.staff_login'))

        user_id = session['user_id']
        user = User.query.filter_by(user_id=user_id).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('staff.staff_login'))

        staff = Staff.query.filter_by(email=user.username).first()
        if not staff:
            flash('Staff profile not found.', 'danger')
            return redirect(url_for('staff.staff_dashboard'))
        
        # Get form data
        staff.name = request.form['name']
        staff.department = request.form['department']
        staff.email = request.form['email']
        staff.contact_no = request.form['contact']

        try:
            db.session.commit()
            flash('Profile updated successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating profile.', 'danger')
            print("Update Error:", e)

        return redirect(url_for('staff.staff_profile'))
    

@staff_bp.route('/guestroom-requests')
def staff_view_guestroom_requests():
    if 'user_id' not in session or session.get('user_type') != 'staff':
        flash('Please log in as a staff first.', 'warning')
        return redirect(url_for('staff.staff_login'))
    
    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('staff.staff_login'))

    # Get staff using the user's email/username
    staff = Staff.query.filter_by(email=user.username).first()

    if not staff:
        flash('Staff profile not found.', 'danger')
        return redirect(url_for('staff.staff_dashboard'))

    requests = GuestroomRequest.query.filter_by(referenced_by=staff.staff_id).order_by(GuestroomRequest.created_at.desc()).all()
    return render_template('User/Staff/staff_guestroom_requests.html', requests=requests)


@staff_bp.route('/guesthouses')
def staff_guesthouses():
    if 'user_id' not in session or session.get('user_type') != 'staff':
        flash('Please log in as a staff first.', 'warning')
        return redirect(url_for('staff.staff_login'))

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('staff.staff_login'))

    staff = Staff.query.filter_by(email=user.username).first()
    if not staff:
        flash('Staff profile not found.', 'danger')
        return redirect(url_for('staff.staff_dashboard'))

    return render_template('User/Staff/staff_guesthouses.html', staff=staff)

@staff_bp.route('/guestroom-availability')
def staff_guestroom_availability():
    if 'user_id' not in session or session.get('user_type') != 'staff':
        flash('Please log in as a staff first.', 'warning')
        return redirect(url_for('staff.staff_login'))

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('staff.staff_login'))

    staff = Staff.query.filter_by(email=user.username).first()
    if not staff:
        flash('Staff profile not found.', 'danger')
        return redirect(url_for('staff.staff_dashboard'))

    return render_template('User/Staff/staff_guestroom_availability.html', staff=staff)

# API 1: Get all guesthouse names for staff
@staff_bp.route('/api/guesthouses', methods=['GET'])
def get_guesthouses():
    guesthouses = Guesthouse.query.all()
    names = [gh.guesthouse_name for gh in guesthouses]
    return jsonify({'guesthouses': names})

# API 2: Get unique room types for staff (optional)
@staff_bp.route('/api/room-types', methods=['GET'])
def get_room_types():
    types = db.session.query(GuestRoom.type).distinct().all()
    room_types = [t[0] for t in types]
    return jsonify({'room_types': room_types})

# API 3: Get filtered rooms by guesthouse_name, room_type, and status for staff
@staff_bp.route('/api/guestrooms', methods=['GET'])
def get_guestrooms():
    guesthouse_name = request.args.get('guesthouse_name')
    room_type = request.args.get('room_type')
    status = request.args.get('status')

    query = GuestRoom.query

    if guesthouse_name:
        query = query.filter_by(guesthouse_name=guesthouse_name)
    if room_type:
        query = query.filter_by(type=room_type)
    if status:
        query = query.filter_by(status=status)

    rooms = query.all()
    room_data = [
        {
            'room_no': room.room_no,
            'guesthouse_name': room.guesthouse_name,
            'capacity': room.capacity,
            'type': room.type,
            'status': room.status
        }
        for room in rooms
    ]
    return jsonify({'rooms': room_data})


@staff_bp.route('/guestroom-allotment-request')
def staff_guestroom_allotment_request():
    if 'user_id' not in session or session.get('user_type') != 'staff':
        flash('Please log in as a staff first.', 'warning')
        return redirect(url_for('staff.staff_login'))

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('staff.staff_login'))

    staff = Staff.query.filter_by(email=user.username).first()
    if not staff:
        flash('Staff profile not found.', 'danger')
        return redirect(url_for('staff.staff_dashboard'))

    return render_template('User/Staff/staff_guestroom_allotment_request.html', staff=staff)


