from app import db
from werkzeug.security import generate_password_hash
from hashlib import md5

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nickname = db.Column(db.String(64), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True)
    about_me = db.Column(db.String(140))
    posts = db.relationship('Post', backref = 'user', cascade="all, delete-orphan", lazy = 'dynamic')
    password_changes = db.relationship('PasswordChange', backref = 'author', cascade="all, delete-orphan", lazy = 'dynamic')
    last_seen = db.Column(db.DateTime)

    def avatar(self, size):
        return 'http://www.gravatar.com/avatar/%s?d=mm&s=%d' % (md5(self.email.encode('utf-8')).hexdigest(), size)

    def __init__(self, nickname, email=None, encrypted_password=None):
        self.nickname = nickname
        self.email = email
        self.password = encrypted_password

    def __repr__(self):
        return '<User %r>' % (self.nickname)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, body, timestamp, user_id):
        self.body = body
        self.timestamp = timestamp
        self.user_id = user_id

    def __repr__(self):
        return '<Post %r>' % (self.body)


class PasswordChange(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    expiration = db.Column(db.DateTime, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable = False)
    token = db.Column(db.String(255), nullable = False)

    def __init__(self, expiration, user_id, token):
        self.expiration = expiration
        self.user_id = user_id
        self.token = token

    def __repr__(self):
        return '<PasswordChanges %r>' % (self.expiration)