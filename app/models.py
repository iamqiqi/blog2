from app import db
from werkzeug.security import generate_password_hash
from hashlib import md5

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nickname = db.Column(db.String(64), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True)
    about_me = db.Column(db.String(140))
    posts = db.relationship('Post', backref = 'author', cascade="all, delete-orphan", lazy = 'dynamic')
    last_seen = db.Column(db.DateTime)

    def avatar(self, size):
        return 'http://www.gravatar.com/avatar/%s?d=mm&s=%d' % (md5(self.email.encode('utf-8')).hexdigest(), size)

    def __init__(self, nickname, email=None, password=None):
        self.nickname = nickname
        self.email = email
        self.password = password

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
