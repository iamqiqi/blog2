#!/usr/bin/env python
from flask import Flask, render_template, request, json, redirect, Markup, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask.ext.mysql import MySQL
import os
import re

app = Flask(__name__, static_folder='public')
app.secret_key = "vhainonWBU$J:TS*:$Yn4iaoew"

mysql = MySQL()
# MySQL configurations
app.config['MYSQL_DATABASE_USER'] = 'iamqiqi'
app.config['MYSQL_DATABASE_PASSWORD'] = ''
app.config['MYSQL_DATABASE_DB'] = 'blog'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)

conn = mysql.connect()
cursor = conn.cursor()

@app.route("/")
def main():
    # if(cookie('loggedin')):
    #     set some variable in the view
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
    # create user code
    email = request.form['inputEmail']
    password = request.form['inputPassword']
    errors = []
    if email and password:
        query = 'select id, username, password from users where email = \'' + email + '\''
        cursor.execute(query)
        data = cursor.fetchone()
        print data
        if data == None:
            errors.append("User does not exist")
            return render_template("signin.html", errors=errors, email=email, password=password)
        else:
            if check_password_hash(data[2], password):
                session['logged_in_userid'] = data[0]
                session['logged_in_username'] = data[1]
                return redirect('/')
            else:
                errors.append("Password is incorrect")
                return render_template("session/signin.html", errors=errors, email=email, password=password)
    else:
        errors.append("One or more fields are missing")
        return render_template("session/signin.html", errors=errors, email=email, password=password)


@app.route('/signOut')
def signOut():
    session.clear()
    return redirect('/')


@app.route('/signUp', methods=['POST'])
def signUp():
    errors = []
    name = request.form['inputName']
    email = request.form['inputEmail']
    password = request.form['inputPassword']
    password2 = request.form['inputPassword2']
    if name and email and password and password2:
        validation_email = re.match('^[^@\s]+@[^@\s]+$', email)
        if validation_email == None:
            errors.append("Invalid email address")
        if password and password2:
            if password2 != password:
                errors.append("Passwords don't match")
    else:
        errors.append("One or more fields are missing")

    if len(errors) == 0:
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        cursor.callproc('createUser', (name, email, hashed_password))
        data = cursor.fetchall()
        if len(data) is 0:
            conn.commit()
            return redirect('/')
        else:
            errors.append(str(data[0]))
            return render_template("session/signup.html", errors=errors, name=name, email=email, password=password, password2=password2)
    else:
        return render_template("session/signup.html", errors=errors, name=name, email=email, password=password, password2=password2)


if __name__ == '__main__':
    host = os.getenv('IP', '0.0.0.0')
    port = int(os.getenv('PORT', 8080))
    app.run(host=host, port=port, debug=True)
else:
    print "app.py was imported, so I'm not running the server"
