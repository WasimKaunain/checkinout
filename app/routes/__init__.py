from .main_routes import main
from .Admin.admin_routes import admin_bp
from .User import register_user_routes

def register_routes(app):
    app.register_blueprint(main)
    app.register_blueprint(admin_bp)
    register_user_routes(app)
