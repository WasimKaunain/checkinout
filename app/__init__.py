from flask import Flask
from app.routes import register_routes
from app.models import db #import db objects
from config import Config  # import the Config class

def create_app():
    app = Flask(__name__)

    # Load configuration (this should point to config.py where DB URI is defined)
    app.config.from_object(Config)

    # Initialize the SQLAlchemy database
    db.init_app(app)
    register_routes(app)
    return app
