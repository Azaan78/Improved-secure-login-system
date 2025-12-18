from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy

from config import Config


#Added imports
import os
from flask_wtf import CSRFProtect
import secrets
import logging
from logging.handlers import RotatingFileHandler
import os

db = SQLAlchemy()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    from .routes import main
    app.register_blueprint(main)

    app.config['SECRET_KEY'] = os.environ.get(
        'SECRET_KEY',
        'dev-secret-key-change-me'
    )

    #Initialising logging
    log_dir = app.config.get('LOG_DIR', 'logs')
    os.makedirs(log_dir, exist_ok=True)
    handler = RotatingFileHandler(os.path.join(log_dir, 'security.log'), maxBytes=1_000_000, backupCount=5)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s | %(levelname)s | user=%(user)s ip=%(ip)s | %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)



    #NEEDS COMMENTS
    @app.context_processor
    def inject_csrf():
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_urlsafe(32)
        return dict(csrf_token=session['csrf_token'])



    @app.after_request
    def set_security_headers(response):
        csp = ("default-src 'self'; "
               "script-src 'self'; "
               "style-src 'self'; "
               "img-src 'self' data:;")
        response.headers['Content-Security-Policy'] = csp
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
        if not app.debug and app.config.get('USE_HSTS', True):
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response



    with app.app_context():
        from app.routes import encrypt_bio, sanatize_bio
        from .models import User
        db.drop_all()
        db.create_all()

        users = [
            {"username": "user1@email.com", "password": "Userpass!23", "role": "user", "bio": "I'm a basic user"},
            {"username": "mod1@email.com", "password": "Modpass!23", "role": "moderator", "bio": "I'm a moderator"},
            {"username": "admin1@email.com", "password": "Adminpass!23", "role": "admin", "bio": "I'm an administrator"}
        ]

        if User.query.count() == 0:
            for user in users:
                user_data = user
                db_user = User(username=user_data["username"], password="", role=user_data["role"], bio=encrypt_bio(sanatize_bio(user_data["bio"])))
                db_user.set_password(user_data["password"], app.config.get('PASSWORD_PEPPER'))
                db.session.add(db_user)
            db.session.commit()

    return app
