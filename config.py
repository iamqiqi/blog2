import os
import inspect

# db_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile(inspect.currentframe()))[0], "db")))

DEBUG = True
# SERVER_NAME = os.getenv('IP', '0.0.0.0') + ':' + os.getenv('PORT', 8080)
WTF_CSRF_ENABLED = True
SECRET_KEY = 'uih;oGiehrfRpq9c'
SQLALCHEMY_DATABASE_URI = 'mysql://iamqiqi:@localhost/blog'
SQLALCHEMY_MIGRATE_REPO = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile(inspect.currentframe()))[0], "db_repository")))

# google api settings
GOOGLE_CLIENT_ID = '915670173616-300ki119bk6pgmqfqojga2bo36i20305.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '3DQd0XLTJ47-nfQAsdT2r4bi'
GOOGLE_REDIRECT_URI = 'https://python-app-2222-iamqiqi.c9users.io/auth/google/callback'

# facebook api settings
FACEBOOK_CLIENT_ID = '1747986245450913'
FACEBOOK_CLIENT_SECRET = '4ef98cdc0c807f307444c65bf9f0d2e7'
FACEBOOK_REDIRECT_URI = 'https://python-app-2222-iamqiqi.c9users.io/auth/facebook/callback'