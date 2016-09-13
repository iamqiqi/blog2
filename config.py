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
