from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'login'

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///checkinout.db'

    db.init_app(app)
    login_manager.init_app(app)

    from .routes import app as routes_blueprint
    app.register_blueprint(routes_blueprint)

    return app
