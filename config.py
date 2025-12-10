from datetime import timedelta
import os


class Config:
    DEBUG = True
    SECRET_KEY = 'supersecretkey'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
    SESSION_COOKKIE_HTTPONLY = True
    SESSION_COOKKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE','False').lower() in ('true', '1')
    PASSWORD_PEPPER = os.environ.get('PASSWORD_PEPPER')
    FERENT_KEY = os.environ.get('FERENT_KEY')
