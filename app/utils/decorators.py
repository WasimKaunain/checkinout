from functools import wraps
from flask import request, redirect, url_for, flash, g
from app.utils.auth_utils import decode_jwt

def jwt_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.cookies.get('jwt')
            if not token:
                flash('Authentication required. Please log in.', 'warning')
                # Redirect to appropriate login page based on role
                if role == 'Student':
                    return redirect(url_for('student.student_login'))
                elif role == 'Staff':
                    return redirect(url_for('staff.staff_login'))
                elif role == 'Visitor':
                    return redirect(url_for('visitor.visitor_login'))
                else:
                    return redirect(url_for('home'))  # fallback

            payload, error = decode_jwt(token)
            if error:
                flash(error, 'danger')
                if role == 'Student':
                    return redirect(url_for('student.student_login'))
                elif role == 'Staff':
                    return redirect(url_for('staff.staff_login'))
                elif role == 'Visitor':
                    return redirect(url_for('visitor.visitor_login'))
                else:
                    return redirect(url_for('home'))

            if role and payload.get('role') != role:
                flash('Unauthorized access', 'danger')
                return redirect(url_for('home'))

            # Inject user details into global context
            g.member_id = payload.get('member_id')
            g.role = payload.get('role')

            return f(*args, **kwargs)
        return decorated_function
    return decorator
