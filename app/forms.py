from flask.ext.wtf import Form
from wtforms import StringField, BooleanField, PasswordField
from wtforms.fields.html5 import EmailField
from wtforms.fields import TextAreaField

from wtforms.validators import DataRequired, EqualTo, Length, Email
from .validators import Unique, Exist

from .models import User

class LoginForm(Form):
    email = EmailField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Email address must be valid'),
        Exist(User, User.email)
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required')
    ])
    rememberme = BooleanField('Remember me', default=False)

class SignupForm(Form):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Unique(User, User.nickname, message='username already exists')
    ])
    email = EmailField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Email address must be valid'),
        Unique(User, User.email, message='email already exists')
    ])
    password = PasswordField('New password', validators=[
        DataRequired(message='Password is required'),
        Length(min=6, message='Password minimum is 6 characters')
    ])
    password2 = PasswordField('Password Confirm', validators=[
        DataRequired(message='Confirm password is required'),
        EqualTo('password', message='Passwords must match')
    ])

class PostForm(Form):
    post = TextAreaField('Post', validators=[
        DataRequired(message='New post can not be empty'),
        Length(max=140, message="Maximum is 140 characters")
    ])

class BioForm(Form):
    bio = TextAreaField('Bio', validators=[
        Length(max=140, message="Maximum is 140 characters")
    ])

class EditForm(Form):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required')
    ])

    email = EmailField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Email address must be valid')
    ])

    email2 = EmailField('Email2', validators=[
        DataRequired(message='Email is required'),
        Email(message='Email address must be valid')
    ])

    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required')
    ])

    password2 = PasswordField('Password2', validators=[
        DataRequired(message='Password is required'),
        Length(min=6, message='Password minimum is 6 characters')
    ])

    password3 = PasswordField('Password3', validators=[
        DataRequired(message='Password is required'),
        Length(min=6, message='Password minimum is 6 characters'),
        EqualTo('password2', message='Passwords must match')
    ])