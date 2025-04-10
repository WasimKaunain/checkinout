from app import db
from flask_login import UserMixin

from flask import session

@login_manager.user_loader
def load_user(user_id):
    role = session.get('role')
    if role == 'student':
        return Student.query.get(int(user_id))
    elif role == 'staff':
        return Staff.query.get(int(user_id))
    elif role == 'visitor':
        return Visitor.query.get(int(user_id))
    return None


class Student(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(150), nullable=False)

class Staff(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(150), nullable=False)

class Visitor(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(150), nullable=False)

# For Flask-Login to load user
from app import login_manager

@login_manager.user_loader
def load_user(user_id):
    return Student.query.get(int(user_id))

