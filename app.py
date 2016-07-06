#!/usr/bin/env python
import os
import re
import sys
sys.path.insert(0, '../db')
from flask import Flask, render_template, request, json, redirect, Markup, session, Blueprint
from werkzeug.security import generate_password_hash, check_password_hash
from Models import db, User

app = Flask(__name__, static_folder='public')
app.secret_key = "vhainonWBU$J:TS*:$Yn4iaoew"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://iamqiqi:@localhost/blog2'
db.init_app(app)

@app.before_first_request
def createDatabase():
    db.create_all()

@app.route("/")
def main():
    return render_template('home/index.html')


@app.route('/showSignUp')
def showSignUp():
    return render_template('session/signup.html')


@app.route('/showSignIn')
def showSignIn():
    return render_template('session/signin.html')


@app.route('/showUserPage')
def showUserPage():
    return render_template('user/userpage.html')


@app.route('/signIn', methods=['POST'])
def signIn():
    email = request.form['inputEmail']
    password = request.form['inputPassword']
    errors = []
    # pre check fields
    if not (email and password):
        errors.append("One or more fields are missing")
        return render_template("session/signin.html", errors=errors, email=email, password=password)
    elif validation_email == None:
        errors.append("Invalid email address")
        return render_template("signin.html", errors=errors, email=email, password=password)
    else:
        logged_in_user = User.query.filter_by(email=email).first()
        if logged_in_user == None:
            errors.append("User does not exist")
            return render_template("signin.html", errors=errors, email=email, password=password)
        elif not check_password_hash(logged_in_user.password, password):
            errors.append("Password is incorrect")
            return render_template("session/signin.html", errors=errors, email=email, password=password)
        else:
            session['logged_in_userid'] = logged_in_user.id
            session['logged_in_username'] = logged_in_user.username
            return redirect('/')


@app.route('/signOut')
def signOut():
    session.clear()
    return redirect('/')


@app.route('/signUp', methods=['POST'])
def signUp():
    errors = []
    username = request.form['inputName']
    email = request.form['inputEmail']
    password = request.form['inputPassword']
    password2 = request.form['inputPassword2']
    # pre check fields
    if not (username and email and password and password2):
        errors.append("One or more fields are missing")
        return render_template("session/signup.html", errors=errors, username=username, email=email, password=password, password2=password2)
    else:
        validation_email = re.match('^[^@\s]+@[^@\s]+$', email)
        if validation_email == None:
            errors.append("Invalid email address")
        if password2 != password:
            errors.append("Passwords don't match")

        if len(errors) != 0:
            return render_template("session/signup.html", errors=errors, username=username, email=email, password=password, password2=password2)
        else:
            hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
            test_email = User.query.filter_by(email=email).first()
            if test_email != None:
                errors.append("this email is registed, user already exists")
                return render_template("session/signup.html", errors=errors, username=username, email=email, password=password, password2=password2)
            else:
                test_username = User.query.filter_by(username=username).first()
                if test_username != None:
                    errors.append("username already exists, please pick another one")
                    return render_template("session/signup.html", errors=errors, username=username, email=email, password=password, password2=password2)
                else:
                    user = User(username, email, password)
                    db.session.add(user)
                    db.session.commit()
                    return redirect('/')


if __name__ == '__main__':
    host = os.getenv('IP', '0.0.0.0')
    port = int(os.getenv('PORT', 8080))
    app.run(host=host, port=port, debug=True)

