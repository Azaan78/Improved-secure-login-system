from app import db

from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False)
    bio = db.Column(db.String(500), nullable=False)

    def __init__(self, username, password, role, bio):
        self.username = username
        self.password = password
        self.role = role
        self.bio = bio

    def set_password(self, password: str, pepper: str = None):
        to_hash = password if not pepper else password + pepper
        self.password = generate_password_hash(to_hash)

    def check_password(self, password: str, pepper: str = None) -> bool:
        check = password if not pepper else password + pepper
        return check_password_hash(self.password, check)