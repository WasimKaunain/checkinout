from flask import render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, logout_user
from app import app, db
from app.models import Student, Staff, Visitor  # only Student for now


@app.route('/')
def homepage():
    return render_template('homepage.html')

@app.route('/user_select')
def user_select():
    return render_template('user_select.html')

from flask import session

@app.route('/login/<role>', methods=['GET', 'POST'])
def login(role):
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = None
        if role == 'student':
            user = Student.query.filter_by(username=username).first()
        elif role == 'staff':
            user = Staff.query.filter_by(username=username).first()
        elif role == 'visitor':
            user = Visitor.query.filter_by(username=username).first()

        if user and user.password == password:
            login_user(user)
            session['role'] = role  # Save role for user_loader
            return redirect(url_for('dashboard', role=role))
        else:
            flash("Invalid username or password.")

    return render_template('login.html', role=role)


@app.route('/register/<role>', methods=['GET', 'POST'])
def register(role):
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        name = request.form['name']

        if role == 'student':
            existing_user = Student.query.filter_by(username=username).first()
            if existing_user:
                flash("Username already exists!")
            else:
                new_student = Student(username=username, password=password, name=name)
                db.session.add(new_student)
                db.session.commit()
                flash("Registered successfully! Please log in.")
                return redirect(url_for('login', role=role))

    return render_template('register.html', role=role)
@app.route('/dashboard/<role>')
@login_required
def dashboard(role):
    return render_template(f'dashboard_{role}.html', user=current_user)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('homepage'))