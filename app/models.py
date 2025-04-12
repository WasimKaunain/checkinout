from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class UserIDCounter(db.Model):
    __tablename__ = 'user_id_counters'

    user_type = db.Column(db.String(10), primary_key=True, nullable=False)
    current_number = db.Column(db.Integer, nullable=False)

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    user_id = db.Column(db.String(10), primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('Student', 'Visitor', 'Staff'), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

class Student(db.Model):
    __tablename__ = 'students'

    roll_no = db.Column(db.String(20), primary_key=True, unique=True, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    department = db.Column(db.String(30), nullable=False)
    gender = db.Column(db.Enum('Male', 'Female', 'Other'), nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=True)
    hostel_name = db.Column(db.String(30), db.ForeignKey('hostels.hostel_name', ondelete='SET NULL'), nullable=True)
    room_no = db.Column(db.String(10), db.ForeignKey('hostelrooms.room_no', ondelete='SET NULL'), nullable=True)
    mess_id = db.Column(db.Integer, db.ForeignKey('mess.mess_id', ondelete='SET NULL'), nullable=True)

    # Optional: relationships (not strictly necessary unless you want to navigate back-references)
    mess = db.relationship('Mess', backref='students', lazy=True)
    hostel = db.relationship('Hostel', backref='students', lazy=True)
    room = db.relationship('HostelRoom', backref='students', lazy=True)

class Staff(db.Model):
    __tablename__ = 'staffs'
    
    staff_id = db.Column(db.String(20), primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    department = db.Column(db.String(30), nullable=False)
    gender = db.Column(db.Enum('Male', 'Female', 'Other'), nullable=False)
    contact_no = db.Column(db.String(10), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

    
class Visitor(db.Model):
    __tablename__ = 'visitors'

    visitor_id = db.Column(db.String(20), primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    contact_no = db.Column(db.String(10), unique=True, nullable=False)
    gender = db.Column(db.Enum('Male', 'Female', 'Other'), nullable=False)
    room_no = db.Column(db.String(10), db.ForeignKey('guestrooms.room_no', ondelete='SET NULL'))
    guesthouse_name = db.Column(db.String(30), db.ForeignKey('guesthouses.guesthouse_name', ondelete='SET NULL'))
    duration_of_stay = db.Column(db.Integer, nullable=False)
    purpose = db.Column(db.String(1000), nullable=False)
    reference = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(30), nullable=False)

class Hostel(db.Model):
    __tablename__ = 'hostels'

    hostel_name = db.Column(db.String(30), primary_key=True)
    total_rooms = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(100), nullable=False)

class Guesthouse(db.Model):
    __tablename__ = 'guesthouses'

    guesthouse_name = db.Column(db.String(30), primary_key=True)
    total_rooms = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(100), nullable=False)

class Mess(db.Model):
    __tablename__ = 'mess'

    mess_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    mess_name = db.Column(db.String(50), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(100))

class HostelRoom(db.Model):
    __tablename__ = 'hostelrooms'

    room_no = db.Column(db.String(10), primary_key=True)
    hostel_name = db.Column(db.String(30), db.ForeignKey('hostels.hostel_name', ondelete='CASCADE'), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Enum('Vacant', 'Occupied'), nullable=False, default='Vacant')

class GuestRoom(db.Model):
    __tablename__ = 'guestrooms'

    room_no = db.Column(db.String(10), primary_key=True)
    guesthouse_name = db.Column(db.String(30), db.ForeignKey('guesthouses.guesthouse_name', ondelete='CASCADE'), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    type = db.Column(db.String(10), nullable=False)
    status = db.Column(db.Enum('Vacant', 'Occupied'), nullable=False, default='Vacant')

class HostelCheckInOut(db.Model):
    __tablename__ = 'hostelcheckinout'

    record_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String(20), nullable=False)
    user_type = db.Column(db.Enum('Student', 'Staff', 'Visitor'), nullable=False)
    room_no = db.Column(db.String(20), db.ForeignKey('hostelrooms.room_no', ondelete='CASCADE'), nullable=False)
    hostel_name = db.Column(db.String(50), db.ForeignKey('hostels.hostel_name', ondelete='CASCADE'), nullable=False)
    checkin_time = db.Column(db.DateTime, nullable=False)
    checkout_time = db.Column(db.DateTime, nullable=True)

class GuestCheckInOut(db.Model):
    __tablename__ = 'guestcheckinout'

    record_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String(20), db.ForeignKey('visitors.visitor_id', ondelete='CASCADE'), nullable=False)
    room_no = db.Column(db.String(10), db.ForeignKey('guestrooms.room_no', ondelete='CASCADE'), nullable=False)
    guesthouse_name = db.Column(db.String(30), db.ForeignKey('guesthouses.guesthouse_name', ondelete='CASCADE'), nullable=False)
    checkin_time = db.Column(db.DateTime, nullable=False)
    checkout_time = db.Column(db.DateTime, nullable=True)

class MessCheckInOut(db.Model):
    __tablename__ = 'messcheckinout'

    record_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String(10), nullable=False)
    user_type = db.Column(db.Enum('Student', 'Staff', 'Visitor'), nullable=False)
    mess_id = db.Column(db.Integer, db.ForeignKey('mess.mess_id', ondelete='CASCADE'))
    checkin_time = db.Column(db.DateTime, nullable=False)


