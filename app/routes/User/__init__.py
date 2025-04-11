from flask import Blueprint
from .user_routes import user_bp
from .student.student_routes import student_bp
from .staff.staff_routes import staff_bp
from .visitor.visitor_routes import visitor_bp

def register_user_routes(app):
    app.register_blueprint(user_bp)         #for /user/dashboard
    app.register_blueprint(student_bp)      # for /student* 
    app.register_blueprint(staff_bp)        # for /staff*
    app.register_blueprint(visitor_bp)      # for /visitor*
