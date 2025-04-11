from flask import Blueprint, render_template

visitor_bp = Blueprint('visitor', __name__, url_prefix='/visitor')

@visitor_bp.route('/login-register')
def visitor_login_register():
    return render_template('User/Visitor/visitor_login_reg.html')

@visitor_bp.route('/login')
def visitor_login():
    return render_template('User/Visitor/visitor_login.html')

@visitor_bp.route('/register')
def visitor_register():
    return render_template('User/Visitor/visitor_register.html')

@visitor_bp.route('/forget-password')
def visitor_forget_password():
    return render_template('User/Visitor/visitor_forget_password.html')