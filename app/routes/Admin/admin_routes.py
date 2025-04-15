import re
import io
import pandas as pd
from flask import send_file
from io import BytesIO
from flask import Blueprint, render_template, request, session, flash, redirect, url_for, jsonify,jsonify
from app.models import User, db,  MessCheckInOut, Student, Mess,Hostel,HostelRoom,Student, GuestroomRequest
from werkzeug.security import check_password_hash
import random

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
    
    # Count pending guestroom requests
    pending_count = GuestroomRequest.query.filter_by(status='Pending').count()
    approved_count = GuestroomRequest.query.filter_by(status='Accepted').count()
    rejected_count = GuestroomRequest.query.filter_by(status='Rejected').count()

    return render_template('Admin/admin_guestrooms_allot_deallot.html', user=user, pending_count=pending_count, approved_count=approved_count, rejected_count=rejected_count)

@admin_bp.route('/pending-requests', methods = ['GET','POST'])
def admin_pending_requests():
    if request.method == 'GET':
        if 'user_id' not in session or session.get('user_type') != 'admin':
            flash('Please log in as an admin first.', 'warning')
            return redirect(url_for('admin.admin_login'))  # Make sure this route exists

        user_id = session['user_id']
        user = User.query.filter_by(user_id=user_id, role='Admin').first()

        if not user:
            flash('Admin user not found.', 'danger')
            return redirect(url_for('admin.admin_login'))
        # Fetch all pending requests
        pending_requests = GuestroomRequest.query.filter_by(status='Pending').order_by(GuestroomRequest.created_at.desc()).all()
        return render_template('Admin/admin_pending_requests.html', user=user, requests=pending_requests )
    else:
        request_id = request.form.get('request_id')
        decision = request.form.get('decision')
        reason = request.form.get('rejection_reason', '').strip()

        if not request_id or not decision:
            flash('Missing request ID or decision.', 'danger')
            return redirect(url_for('admin.admin_pending_requests'))

        req = GuestroomRequest.query.get(request_id)
        if not req:
            flash('Guestroom request not found.', 'danger')
            return redirect(url_for('admin.admin_pending_requests'))

        if decision == 'Accepted':
            # Step 1: Find all vacant rooms in the guesthouse
            vacant_rooms = GuestRoom.query.filter_by(guesthouse_name=req.guesthouse_name, status='Vacant').all()

            if not vacant_rooms:
                flash('No vacant rooms available in the selected guesthouse.', 'danger')
                return redirect(url_for('admin.admin_pending_requests'))
        
            selected_room = random.choice(vacant_rooms)

            # Step 3: Assign and update status
            req.status = 'Accepted'
            req.rejection_reason = None
            req.allotted_room = selected_room.room_no

            selected_room.status = 'Occupied'  # Mark the room as occupied


        elif decision == 'Rejected':
            req.status = 'Rejected'
            req.reject_reason = reason

        else:
            flash('Invalid decision value.', 'danger')
            return redirect(url_for('admin.admin_pending_requests'))

        db.session.commit()
        flash(f"Request ID {request_id} has been {req.status.lower()}.", 'success')
        return redirect(url_for('admin.admin_pending_requests'))


@admin_bp.route('/approved-requests')
def admin_approved_requests():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as an admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))  # Make sure this route exists

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id, role='Admin').first()

    if not user:
        flash('Admin user not found.', 'danger')
        return redirect(url_for('admin.admin_login'))
    
    approved_requests = GuestroomRequest.query.filter_by(status='Accepted').order_by(GuestroomRequest.created_at.desc()).all()

    return render_template('Admin/admin_approved_requests.html', user=user, approved_requests=approved_requests)

@admin_bp.route('/rejected-requests')
def admin_rejected_requests():
    if 'user_id' not in session or session.get('user_type') != 'admin':
        flash('Please log in as an admin first.', 'warning')
        return redirect(url_for('admin.admin_login'))  # Make sure this route exists

    user_id = session['user_id']
    user = User.query.filter_by(user_id=user_id, role='Admin').first()

    if not user:
        flash('Admin user not found.', 'danger')
        return redirect(url_for('admin.admin_login'))

    return render_template('Admin/admin_rejected_requests.html', user=user)




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

@admin_bp.route('/manage-student-details')
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


@admin_bp.route('/get_mess_checkin_history', methods=['GET'])
def get_mess_checkin_history():
    try:
        checkin_history = db.session.query(MessCheckInOut).all()

        results = []

        for record in checkin_history:
            checkin_date = record.checkin_time.date().strftime('%Y-%m-%d')  # Format date
            checkin_time = record.checkin_time.time().strftime('%H:%M:%S')  # Format time
            
            # Fetch the mess_name from the Mess model using mess_id
            mess = db.session.query(Mess).filter(Mess.mess_id == record.mess_id).first()
            mess_name = mess.mess_name if mess else "Unknown"  # Default to "Unknown" if no mess found

            results.append({
                'user_id': record.user_id,
                'user_type': record.user_type,
                'mess_name': mess_name,
                'date': checkin_date,
                'time': checkin_time
            })

        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@admin_bp.route('/export_mess_checkins', methods=['POST'])
def export_mess_checkin_history():
    try:
        # Fetch the mess check-in/out history from the database
        checkin_history = db.session.query(MessCheckInOut).all()

        # Prepare data for export (as a list of dictionaries)
        data = []
        for record in checkin_history:
            checkin_date = record.checkin_time.date().strftime('%Y-%m-%d')
            checkin_time = record.checkin_time.time().strftime('%H:%M:%S')
            
            # Fetch mess name
            mess = db.session.query(Mess).filter(Mess.mess_id == record.mess_id).first()
            mess_name = mess.mess_name if mess else "Unknown"
            
            data.append({
                'user_id': record.user_id,
                'user_type': record.user_type,
                'mess_name': mess_name,
                'date': checkin_date,
                'time': checkin_time
            })

        # Create a pandas DataFrame
        df = pd.DataFrame(data)

        # Use XlsxWriter engine to write the DataFrame to an Excel file
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Mess Check In Out History')

        # Save the content to a file and send it as a response
        output.seek(0)
        return send_file(output, as_attachment=True, download_name="mess_checkin_history.xlsx", mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500




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

@admin_bp.route('/get_all_mess')
def get_all_mess():
    try:
        messes = Mess.query.with_entities(Mess.mess_id, Mess.mess_name).all()
        mess_list = [{"mess_id": m.mess_id, "name": m.mess_name} for m in messes]
        return jsonify(mess_list)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@admin_bp.route('/get_mess_details/<int:mess_id>')
def get_mess_details(mess_id):
    try:
        mess = Mess.query.get(mess_id)
        if not mess:
            return jsonify({"error": "Mess not found"}), 404

        students = Student.query.filter_by(mess_id=mess_id).all()
        student_rolls = [s.roll_no for s in students]

        return jsonify({
            "capacity": mess.capacity,
            "student_count": len(student_rolls)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
