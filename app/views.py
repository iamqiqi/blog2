from flask import render_template, flash, redirect, request, session, flash, url_for, g
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db, lm
from .forms import LoginForm, SignupForm, PostForm, BioForm, EditForm, ResetPwdEmailForm, ResetPwdForm
from .models import User, Post, PasswordChange
from wtforms.validators import ValidationError
from datetime import datetime, timedelta
import random
import string
import requests
import config
import sendgrid
import os
from sendgrid.helpers.mail import *
from flask.ext.login import login_user, logout_user, current_user, login_required

@app.before_request
def check_session():
    g.user = current_user
    print "====pre-request==="
    print g.user.nickname
    print "=================="
    if 'logged_in_userid' in session:
        username = session['logged_in_username']
        check = User.query.filter_by(nickname=username).first()
        if not check:
            session.clear()

@app.route('/')
@app.route('/index')
@login_required
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
    posts = user.posts.order_by(Post.timestamp.desc()).all()
    bio_form.bio.data = user.about_me
    following = None
    if session.has_key('logged_in_userid'):
        logged_in_user = User.query.filter_by(id=session['logged_in_userid']).first()
        following = logged_in_user.is_following(user)
    return render_template('user/userposts.html', post_form=post_form, login_form=login_form, bio_form=bio_form, user=user, posts=posts, following=following)

@app.route('/users/account/')
def account():
    user = User.query.filter_by(id=session['logged_in_userid']).first()
    post_form = PostForm()
    login_form = LoginForm()
    bio_form = BioForm()
    edit_form = EditForm()
    bio_form.bio.data = user.about_me
    return render_template('user/account.html', edit_form=edit_form, post_form=post_form, login_form=login_form, bio_form=bio_form, user=user)

@app.route('/users/<username>/follow', methods=['POST'])
def follow(username):
    user = User.query.filter_by(id=session['logged_in_userid']).first()
    followed_user = User.query.filter_by(nickname=username).first()
    user.follow(followed_user)
    db.session.commit()
    return redirect('/users/'+ username)

@app.route('/users/<username>/unfollow', methods=['POST'])
def unfollow(username):
    user = User.query.filter_by(id=session['logged_in_userid']).first()
    followed_user = User.query.filter_by(nickname=username).first()
    user.unfollow(followed_user)
    db.session.commit()
    return redirect('/users/'+ username)

@app.route('/users/account/<option>', methods=['POST'])
def accountedit(option):
    user = User.query.filter_by(id=session['logged_in_userid']).first()
    if option == 'username':
        username = request.form['new_username']
        check = User.query.filter_by(nickname=username).first()
        if check:
            return "username is taken", 409

        user.nickname = username
        db.session.commit()
        session['logged_in_username'] = username
        return 'changed username'

    elif option == 'email':
        email = request.form['new_email']
        check = User.query.filter_by(email=email).first()
        if check:
            return "email is registered", 409

        user.email = email
        db.session.commit()
        return 'changed email'

    elif option == 'password':
        password = request.form['current_password']
        if not check_password_hash(user.password, password):
            return "current password is incorrect", 403

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
    Post.query.filter_by(id=post_id, user_id=session['logged_in_userid']).delete()
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

@app.route('/deleteaccount', methods=['POST'])
def deleteaccount():
    email = request.form['email']
    user = User.query.filter_by(email=email).first()
    db.session.delete(user)
    db.session.commit()
    session.clear()
    flash('You were successfully logged out deleteaccount')
    return '/'

@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    post_form = PostForm()
    if request.method == 'GET':
        return render_template('session/signin.html', title='Sign in', post_form=post_form, login_form=login_form)

    email = request.form['email'].lower()
    if login_form.validate_on_submit() == False:
        return render_template('session/signin.html', title='Sign in', post_form=post_form, login_form=login_form, email=email)

    password = request.form['password']
    user = User.query.filter_by(email=email).first()
    if not check_password_hash(user.password, password):
        login_form.errors['password'] = ['Password is not correct']
        return render_template('session/signin.html', title='Sign in', post_form=post_form, login_form=login_form, email=email)

    session['logged_in_userid'] = user.id
    session['logged_in_username'] = user.nickname
    flash('Welcome back! You were successfully logged in')
    print "====pre-request==="
    print g.user.nickname
    print "=================="
    return redirect('/')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    login_form = LoginForm()
    signup_form = SignupForm()
    post_form = PostForm()
    if request.method == 'GET':
        return render_template('session/signup.html', title='Sign up', post_form=post_form, login_form=login_form, signup_form=signup_form)

    username = request.form['username'].lower()
    email = request.form['email'].lower()
    if signup_form.validate_on_submit() == False:
        return render_template('session/signup.html', title='Sign up', post_form=post_form, login_form=login_form, signup_form=signup_form, username=username, email=email)

    password = signup_form.password.data
    hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
    user = User(username, email, hashed_password)
    db.session.add(user)
    db.session.commit()
    flash('Welcome! You were successfully signed up')
    session['logged_in_userid'] = user.id
    session['logged_in_username'] = user.nickname
    return redirect('/')


@app.route('/resetpwd/', methods=['GET', 'POST'])
def resetpwd():
    login_form = LoginForm()
    post_form = PostForm()
    resetpwd_email_form = ResetPwdEmailForm()
    if request.method == 'GET':
        return render_template('session/resetpwdemail.html', title='reset password', post_form=post_form, login_form=login_form, resetpwd_email_form=resetpwd_email_form)

    email = request.form['email'].lower()
    if resetpwd_email_form.validate_on_submit() == False:
        return render_template('session/resetpwdemail.html', title='reset password', post_form=post_form, login_form=login_form, email=email, resetpwd_email_form=resetpwd_email_form)

    #create reset data record
    user = User.query.filter_by(email=email).first()
    if user:
        expiration_time = datetime.now() + timedelta(minutes = 30)
        token = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(60))
        passwordchange = PasswordChange(expiration_time, user.id, token)
        db.session.add(passwordchange)
        db.session.commit()

        #setting up the email
        mykey=os.environ.get('SENDGRID_API_KEY')
        sg = sendgrid.SendGridAPIClient(apikey=mykey)
        from_email = Email("Blogpepper<iamqiqijiang@gmail.com>")
        subject = "Blogpepper - Reset your password"
        to_email = Email(email)
        content_value = render_template('email/resetpwd.html', token=token)
        content = Content("text/html", content_value)
        mail = Mail(from_email, subject, to_email, content)
        response = sg.client.mail.send.post(request_body=mail.get())
        flash('A confirm email has been sent to your email')
    else:
        flash('this email does not exist')
    return redirect('/')

@app.route('/password/<token>', methods=['GET', 'POST'])
def passwordconfirm(token):
    pwdrequest = PasswordChange.query.filter_by(token=token).first()
    if pwdrequest:
        now = datetime.now()
        if now < pwdrequest.expiration:
            login_form = LoginForm()
            post_form = PostForm()
            pwdreset_form = ResetPwdForm()
            if request.method == 'GET':
                return render_template('session/pswdreset.html', username=pwdrequest.user.nickname, token=token, post_form=post_form, login_form=login_form, pwdreset_form=pwdreset_form)

            if pwdreset_form.validate_on_submit() == False:
                return render_template('session/pswdreset.html', username=pwdrequest.user.nickname, token=token, post_form=post_form, login_form=login_form, pwdreset_form=pwdreset_form)

            new_password = request.form['password']
            new_hashed_password = generate_password_hash(new_password, method="pbkdf2:sha256")
            pwdrequest.user.password = new_hashed_password
            db.session.delete(pwdrequest)
            db.session.commit()
            session['logged_in_userid'] = pwdrequest.user.id
            session['logged_in_username'] = pwdrequest.user.nickname
            flash('password changed!')
            return redirect('/')
        else:
            return 'token expired'
    return 'invalid token'


@app.route('/auth/google/', methods=['GET'])
def auth_google():
    scope = 'profile email'
    response_type = 'code'
    state = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(60))

    session['google_auth_state'] = state

    return redirect(
        'https://accounts.google.com/o/oauth2/v2/auth' +
        '?client_id=' + config.GOOGLE_CLIENT_ID +
        '&scope=' + scope +
        '&response_type=' + response_type +
        '&redirect_uri=' + config.GOOGLE_REDIRECT_URI +
        '&state=' + state
    )

@app.route('/auth/google/callback', methods=['GET'])
def auth_google_callback():
    login_form = LoginForm()
    post_form = PostForm()
    state = request.args.get('state')
    code = request.args.get('code')
    grant_type = 'authorization_code'
    saved_state = session.pop('google_auth_state', None)

    if saved_state == None or saved_state != state:
        return 'FAILED (invalide state)'

    post_url = 'https://www.googleapis.com/oauth2/v4/token'

    data = {
        'code': code,
        'client_id': config.GOOGLE_CLIENT_ID,
        'client_secret': config.GOOGLE_CLIENT_SECRET,
        'redirect_uri': config.GOOGLE_REDIRECT_URI,
        'grant_type': grant_type
    }
    r = requests.post(post_url, data=data)
    access_token = r.json()['access_token']

    profile = requests.get('https://www.googleapis.com/plus/v1/people/me?access_token=' + access_token)
    email = profile.json()['emails'][0]['value']
    user = User.query.filter_by(email=email).first()
    if user:
        session['logged_in_userid'] = user.id
        session['logged_in_username'] = user.nickname
        flash('You are blog pepper registered user, redirect to your blog pepper account')
        return redirect('/')

    username = profile.json()['displayName']
    check_username = User.query.filter_by(nickname = username).first()
    if check_username:
        session['email'] = email
        return render_template('user/checkUsername.html', post_form=post_form, login_form=login_form, username=username, email=email)
    user = User(username, email)
    db.session.add(user)
    db.session.commit()
    session['logged_in_userid'] = user.id
    session['logged_in_username'] = user.nickname
    flash('Welcome! You were successfully logged in')
    return redirect('/')

@app.route('/auth/facebook/', methods=['GET'])
def auth_facebook():
    scope = 'public_profile,email'
    response_type = 'code'
    state = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(60))

    session['facebook_auth_state'] = state

    return redirect(
        'https://www.facebook.com/dialog/oauth?' +
        'client_id='+ config.FACEBOOK_CLIENT_ID +
        '&redirect_uri=' + config.FACEBOOK_REDIRECT_URI +
        '&scope=' + scope +
        '&response_type=' + response_type +
        '&state=' + state
    )

@app.route('/auth/facebook/callback', methods=['GET'])
def auth_facebook_callback():
    login_form = LoginForm()
    post_form = PostForm()
    state = request.args.get('state')
    code = request.args.get('code')
    saved_state = session.pop('facebook_auth_state', None)

    if saved_state == None or saved_state != state:
        return 'FAILED (invalide state)'

    r = requests.get('https://graph.facebook.com/v2.3/oauth/access_token?' +
                    'client_id='+ config.FACEBOOK_CLIENT_ID +
                    '&redirect_uri=' + config.FACEBOOK_REDIRECT_URI +
                    '&client_secret=' + config.FACEBOOK_CLIENT_SECRET +
                    '&code=' + code
                    )

    access_token = r.json()['access_token']

    profile = requests.get('https://graph.facebook.com/v2.7/me?access_token=' + access_token + '&fields=email,name')
    username = profile.json()['name']
    email = profile.json()['email']
    user = User.query.filter_by(email=email).first()
    if user:
        session['logged_in_userid'] = user.id
        session['logged_in_username'] = user.nickname
        flash('You are blog pepper registered user, redirect to your blog pepper account')
        return redirect('/')

    check_username = User.query.filter_by(nickname = username).first()
    if check_username:
        session['email'] = email
        return render_template('user/checkUsername.html', post_form=post_form, login_form=login_form, username=username, email=email)
    user = User(username, email)
    db.session.add(user)
    db.session.commit()
    session['logged_in_userid'] = user.id
    session['logged_in_username'] = user.nickname
    flash('Welcome! You were successfully logged in')
    return redirect('/')


@app.route('/createusername', methods=['POST'])
def createusername():
    email = session['email']
    username = request.form['new_username']
    check_username = User.query.filter_by(nickname=username).first()
    if check_username:
        return "username is taken", 409
    user = User(username, email)
    db.session.add(user)
    db.session.commit()
    session['logged_in_userid'] = user.id
    session['logged_in_username'] = user.nickname
    flash('Welcome! You were successfully logged in')
    return '/'
