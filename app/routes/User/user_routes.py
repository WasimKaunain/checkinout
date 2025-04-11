# app/routes/User/user_routes.py

from flask import Blueprint, render_template

user_bp = Blueprint('user', __name__, url_prefix='/user')

@user_bp.route('/dashboard')
def user_dashboard():
    return render_template('User/user_dashboard.html')
