from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
import os
from flask.ext.login import LoginManager
from flask_debugtoolbar import DebugToolbarExtension

class GuestUser():
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def __init__(self):
        self.nickname = 'guest'


app = Flask(__name__)
app.config.from_object('config')
toolbar = DebugToolbarExtension()
toolbar.init_app(app)
db = SQLAlchemy(app)
lm = LoginManager()
lm.init_app(app)
lm.login_view = 'login'
lm.anonymous_user = GuestUser


from app import views, models