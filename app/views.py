from flask import render_template, flash, redirect, request, session, flash, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db
from .forms import LoginForm, SignupForm, PostForm
from .models import User, Post
from wtforms.validators import ValidationError
from datetime import datetime

@app.route('/')
@app.route('/index')
def index():
    login_form = LoginForm()
    post_form = PostForm()
    return render_template('home/index.html', post_form=post_form, login_form=login_form)

@app.route('/users/<username>')
def userPage(username):
    post_form = PostForm()
    login_form = LoginForm()
    user = User.query.filter_by(nickname=username).first()
    posts = user.post.all()
    return render_template('user/userposts.html', post_form=post_form, login_form=login_form, username=user.nickname, about_me=user.about_me, posts=posts)

@app.route('/post', methods=['POST'])
def post():
    content = request.form['content']
    timestamp = datetime.utcnow()
    user_id = session['logged_in_userid']
    post = Post(content, timestamp, user_id)
    db.session.add(post)
    db.session.commit()
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    flash('You were successfully logged out')
    return redirect('/')

@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    post_form = PostForm()
    if request.method == 'GET':
        return render_template('session/signin.html', title='Sign in', post_form=post_form, login_form=login_form)
    else:
        email = request.form['email']
        if login_form.validate_on_submit() == False:
            return render_template('session/signin.html', title='Sign in', post_form=post_form, login_form=login_form, email=email)
        else:
            password = request.form['password']
            user = User.query.filter_by(email=email).first()
            if not check_password_hash(user.password, password):
                login_form.errors['password'] = ['Password is not correct']
                return render_template('session/signin.html', title='Sign in', post_form=post_form, login_form=login_form, email=email)
            else:
                session['logged_in_userid'] = user.id
                session['logged_in_username'] = user.nickname
                flash('Welcome back! You were successfully logged in')
                return redirect('/')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    login_form = LoginForm()
    signup_form = SignupForm()
    post_form = PostForm()
    if request.method == 'GET':
        return render_template('session/signup.html', title='Sign up', post_form=post_form, login_form=login_form, signup_form=signup_form)
    else:
        username = request.form['username']
        email = request.form['email']
        if signup_form.validate_on_submit() == False:
            return render_template('session/signup.html', title='Sign up', post_form=post_form, login_form=login_form, signup_form=signup_form, username=username, email=email)
        else:
            password = signup_form.password.data
            hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
            user = User(username, email, hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Welcome! You were successfully signed up')
            session['logged_in_userid'] = user.id
            session['logged_in_username'] = user.nickname
            return redirect('/')
