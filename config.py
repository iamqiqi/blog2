import os
import inspect

# db_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile(inspect.currentframe()))[0], "db")))

DEBUG = True
# SERVER_NAME = os.getenv('IP', '0.0.0.0') + ':' + os.getenv('PORT', 8080)
WTF_CSRF_ENABLED = True
SECRET_KEY = 'uih;oGiehrfRpq9c'
SQLALCHEMY_DATABASE_URI = 'mysql://iamqiqi:@localhost/blog'
SQLALCHEMY_MIGRATE_REPO = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile(inspect.currentframe()))[0], "db_repository")))

# mail server settings
MAIL_SERVER = 'localhost'
MAIL_PORT = 25
MAIL_USERNAME = None
MAIL_PASSWORD = None

# administrator list
ADMINS = ['itsqiqi@hotmail.com']

# google api settings
GOOGLE_CLIENT_ID = '915670173616-300ki119bk6pgmqfqojga2bo36i20305.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '3DQd0XLTJ47-nfQAsdT2r4bi'
GOOGLE_REDIRECT_URI = 'https://python-app-2222-iamqiqi.c9users.io/auth/google/callback'