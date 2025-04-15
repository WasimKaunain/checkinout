from flask import Blueprint, render_template, request, session, flash, redirect, url_for,jsonify
from app.models import User, db,Hostel,HostelRoom,Student
from werkzeug.security import check_password_hash

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('email')
        password = request.form.get('password')

        print(f"[DEBUG] Login attempt for username: {username}")

        # Check if user exists with role 'Admin'
        user = User.query.filter_by(username=username, role='Admin').first()
        
        if user:
            print("[DEBUG] Admin user found in DB.")
            if check_password_hash(user.password_hash, password):
                print("[DEBUG] Password verified successfully.")
                session['user_id'] = user.user_id
                session['user_type'] = 'admin'
                flash('Login successful!', 'success')
                return redirect(url_for('admin.admin_dashboard'))
            else:
                print("[DEBUG] Password verification failed.")
                flash('Invalid password', 'danger')
        else:
            print("[DEBUG] No admin user found with given username.")
            flash('Invalid username', 'danger')

        return redirect(url_for('admin.admin_login'))

    # For GET request
    return render_template('Admin/admin_login.html')


@admin_bp.route('/dashboard', methods=['GET','POST'])
def admin_dashboard():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))
    return render_template('Admin/admin_dashboard.html')


@admin_bp.route('/logout')
def admin_logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('admin.admin_login'))


@admin_bp.route('/guesthouses')
def admin_guesthouses():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as an admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))  # Make sure this route exists

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id, role='Admin').first()

    if not user:
        flash('Admin user not found.', 'danger')
        return redirect(url_for('admin.admin_login'))

    return render_template('Admin/admin_manage_guesthouses.html', user=user)

@admin_bp.route('/guestrooms-allot-deallot')
def admin_guestrooms_allot_deallot():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as an admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))  # Make sure this route exists

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id, role='Admin').first()

    if not user:
        flash('Admin user not found.', 'danger')
        return redirect(url_for('admin.admin_login'))

    return render_template('Admin/admin_guestrooms_allot_deallot.html', user=user)

@admin_bp.route('/generate-guesthouse-reports')
def admin_generate_guesthouse_reports():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as an admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))  # Make sure this route exists

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id, role='Admin').first()

    if not user:
        flash('Admin user not found.', 'danger')
        return redirect(url_for('admin.admin_login'))

    return render_template('Admin/admin_generate_guesthouse_reports.html', user=user)

@admin_bp.route('/monitor-guestroom-vacancies')
def admin_monitor_guestroom_vacancies():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as an admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))  # Make sure this route exists

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id, role='Admin').first()

    if not user:
        flash('Admin user not found.', 'danger')
        return redirect(url_for('admin.admin_login'))

    return render_template('Admin/admin_monitor_guestroom_vacancies.html', user=user)

@admin_bp.route('/manage-visitor-details')
def admin_manage_visitor_details():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as an admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))  # Make sure this route exists

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id, role='Admin').first()

    if not user:
        flash('Admin user not found.', 'danger')
        return redirect(url_for('admin.admin_login'))

    return render_template('Admin/admin_manage_visitor_details.html', user=user)










@admin_bp.route('/hostels')
def admin_hostels():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as an admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))  # Make sure this route exists

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id, role='Admin').first()

    if not user:
        flash('Admin user not found.', 'danger')
        return redirect(url_for('admin.admin_login'))

    return render_template('Admin/admin_manage_hostels.html', user=user)


@admin_bp.route('/hostelrooms-allot-deallot')
def admin_hostelrooms_allot_deallot():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as an admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))  # Make sure this route exists

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id, role='Admin').first()

    if not user:
        flash('Admin user not found.', 'danger')
        return redirect(url_for('admin.admin_login'))

    return render_template('Admin/admin_hostelrooms_allot_deallot.html', user=user)

@admin_bp.route('/generate-hostel-reports')
def admin_generate_hostel_reports():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as an admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))  # Make sure this route exists

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id, role='Admin').first()

    if not user:
        flash('Admin user not found.', 'danger')
        return redirect(url_for('admin.admin_login'))

    return render_template('Admin/admin_generate_hostel_reports.html', user=user)

@admin_bp.route('/monitor-hostelroom-vacancies')
def admin_monitor_hostelroom_vacancies():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as an admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))  # Make sure this route exists

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id, role='Admin').first()

    if not user:
        flash('Admin user not found.', 'danger')
        return redirect(url_for('admin.admin_login'))

    return render_template('Admin/admin_monitor_hostelroom_vacancies.html', user=user)

@admin_bp.route('/manage-student-details', methods=['GET', 'POST'])
def admin_manage_student_details():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as an admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))  # Make sure this route exists
    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id, role='Admin').first()
    if not user:
        flash('Admin user not found.', 'danger')
        return redirect(url_for('admin.admin_login'))
    hostels = Hostel.query.all()
    students = []
    if request.method == 'POST':
        hostel_name = request.form.get('hostel')
        room_number = request.form.get('room')
        if hostel_name and room_number:
            students = Student.query.filter_by(hostel_name=hostel_name, room_no=room_number).all()

    return render_template('Admin/admin_manage_student_details.html',
                           hostels=hostels,
                           students=students)

@admin_bp.route('/get-rooms/<hostel_name>', methods=['GET'])
def get_rooms(hostel_name):
    # Fetch rooms for the selected hostel_name from the HostelRoom table
    rooms = HostelRoom.query.filter_by(hostel_name=hostel_name).all()
    # Extract room numbers or room names
    room_list = [room.room_no for room in rooms]
    return jsonify(room_list)



@admin_bp.route('/mess')
def admin_mess():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as an admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))  # Make sure this route exists

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id, role='Admin').first()

    if not user:
        flash('Admin user not found.', 'danger')
        return redirect(url_for('admin.admin_login'))

    return render_template('Admin/admin_manage_mess.html', user=user)

@admin_bp.route('/generate_mess_reports')
def admin_generate_mess_reports():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as an admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))  # Make sure this route exists

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id, role='Admin').first()

    if not user:
        flash('Admin user not found.', 'danger')
        return redirect(url_for('admin.admin_login'))

    return render_template('Admin/admin_generate_mess_report.html', user=user)

@admin_bp.route('/manage-mess-details')
def admin_manage_mess_details():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as an admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))  # Make sure this route exists

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id, role='Admin').first()

    if not user:
        flash('Admin user not found.', 'danger')
        return redirect(url_for('admin.admin_login'))

    return render_template('Admin/admin_manage_mess_details.html', user=user)