from flask import Blueprint, render_template

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/login')
def admin_login():
    return render_template('Admin/admin_login.html')
