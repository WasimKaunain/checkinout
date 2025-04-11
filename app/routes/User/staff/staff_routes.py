from flask import Blueprint, render_template

staff_bp = Blueprint('staff', __name__, url_prefix='/staff')

@staff_bp.route('/login-register')
def staff_login_register():
    return render_template('User/staff/staff_login_reg.html')

@staff_bp.route('/login')
def staff_login():
    return render_template('User/Staff/staff_login.html')

@staff_bp.route('/register')
def staff_register():
    return render_template('User/Staff/staff_register.html')

@staff_bp.route('/forget-password')
def staff_forget_password():
    return render_template('User/Staff/staff_forget_password.html')
