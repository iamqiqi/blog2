from flask import render_template, flash, redirect, request, session, flash, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db
from .forms import LoginForm, SignupForm, PostForm, BioForm, EditForm, ResetPwdForm
from .models import User, Post
from wtforms.validators import ValidationError
from datetime import datetime
from hashlib import md5

@app.route('/')
@app.route('/index')
def index():
    login_form = LoginForm()
    post_form = PostForm()
    return render_template('home/index.html', post_form=post_form, login_form=login_form)

@app.route('/listall')
def listall():
    login_form = LoginForm()
    post_form = PostForm()
    posts = Post.query.order_by(Post.timestamp.desc()).all()
    return render_template('home/listall.html', posts=posts, post_form=post_form, login_form=login_form)

@app.route('/users/<username>/')
def userPage(username):
    post_form = PostForm()
    login_form = LoginForm()
    bio_form = BioForm()
    user = User.query.filter_by(nickname=username).first()
    posts = user.post.order_by(Post.timestamp.desc()).all()
    bio_form.bio.data = user.about_me
    return render_template('user/userposts.html', post_form=post_form, login_form=login_form, bio_form=bio_form, user=user, posts=posts)

@app.route('/users/<username>/account/')
def account(username):
    user = User.query.filter_by(nickname=username).first()
    post_form = PostForm()
    login_form = LoginForm()
    bio_form = BioForm()
    edit_form = EditForm()
    bio_form.bio.data = user.about_me
    return render_template('user/account.html', edit_form=edit_form, post_form=post_form, login_form=login_form, bio_form=bio_form, user=user)

@app.route('/users/<username>/account/<option>', methods=['POST'])
def accountedit(username, option):
    user = User.query.filter_by(nickname=username).first()
    if option == 'username':
        username = request.form['new_username']
        check = User.query.filter_by(nickname=username).first()
        if check:
            return "username is taken", 409
        else:
            user.nickname = username
            db.session.commit()
            session['logged_in_username'] = username
            return 'changed username'

    elif option == 'email':
        email = request.form['new_email']
        check = User.query.filter_by(email=email).first()
        if check:
            return "email is registered", 409
        else:
            user.email = email
            db.session.commit()
            return 'changed email'

    elif option == 'password':
        password = request.form['current_password']
        if not check_password_hash(user.password, password):
            return "current password is incorrect", 403
        else:
            new_password = request.form['new_password']
            user.password = generate_password_hash(new_password, method="pbkdf2:sha256")
            db.session.commit()
            return 'changed password'

@app.route('/post', methods=['POST'])
def post():
    content = request.form['content']
    timestamp = datetime.utcnow()
    user_id = session['logged_in_userid']
    post = Post(content, timestamp, user_id)
    db.session.add(post)
    db.session.commit()
    return str(post.id)

@app.route('/bio', methods=['POST'])
def bio():
    content = request.form['content']
    user_id = session['logged_in_userid']
    user = User.query.filter_by(id=user_id).first()
    user.about_me = content
    db.session.commit()
    return 'done'

@app.route('/deletepost', methods=['POST'])
def deletepost():
    post_id = request.form['id']
    post = Post.query.filter_by(id=int(post_id)).delete()
    db.session.commit()
    return 'done'

@app.route('/logout')
def logout():
    user_id = session['logged_in_userid']
    user = User.query.filter_by(id=user_id).first()
    user.last_seen = datetime.utcnow()
    db.session.commit()
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
        email = request.form['email'].lower()
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
        username = request.form['username'].lower()
        email = request.form['email'].lower()
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

@app.route('/resetpwd', methods=['GET', 'POST'])
def resetpwd():
    login_form = LoginForm()
    post_form = PostForm()
    resetpwd_form = ResetPwdForm()
    if request.method == 'GET':
        return render_template('session/resetpwd.html', title='reset password', post_form=post_form, login_form=login_form, resetpwd_form=resetpwd_form)
    else:
        email = request.form['email'].lower()
        if resetpwd_form.validate_on_submit() == False:
            return render_template('session/resetpwd.html', title='reset password', post_form=post_form, login_form=login_form, email=email)
        else:
            credentials = None
            if MAIL_USERNAME or MAIL_PASSWORD:
                credentials = (MAIL_USERNAME, MAIL_PASSWORD)
            mail_handler = SMTPHandler((MAIL_SERVER, MAIL_PORT), 'no-reply@' + MAIL_SERVER, ADMINS, 'microblog failure', credentials)
            mail_handler.setLevel(logging.ERROR)
            app.logger.addHandler(mail_handler)

            flash('A confirmation is sent to your email')
            return redirect('/')
