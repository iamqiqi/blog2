#!/usr/bin/env python
import os
import re
import sys
import inspect

db_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile(inspect.currentframe()))[0], "db")))
if db_subfolder not in sys.path:
    sys.path.insert(0, db_subfolder)

from flask import Flask, render_template, request, json, redirect, session, Markup#, Blueprint
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Article

app = Flask(__name__, static_folder='public')
app.secret_key = "vhainonWBU$J:TS*:$Yn4iaoew"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://iamqiqi:@localhost/blog'
db.init_app(app)


@app.before_first_request
def createDatabase():
    db.create_all()


@app.route("/")
def main():
    return render_template('home/index.html')


@app.route('/signUp', methods=['GET', 'POST'])
def signUp():
    if request.method == 'GET':
        return render_template('session/signup.html')
    else:
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


@app.route('/signIn', methods=['GET', 'POST'])
def signIn():
    if request.method == 'GET':
        return render_template('session/signin.html')
    else:
        errors = []
        email = request.form['inputEmail']
        password = request.form['inputPassword']
        # pre check fields
        if not (email and password):
            errors.append("One or more fields are missing")
            return render_template("session/signin.html", errors=errors, email=email, password=password)
        else:
            validation_email = re.match('^[^@\s]+@[^@\s]+$', email)
            if validation_email == None:
                errors.append("Invalid email address")
                return render_template("session/signin.html", errors=errors, email=email, password=password)
            else:
                logged_in_user = User.query.filter_by(email=email).first()
                if logged_in_user == None:
                    errors.append("User does not exist")
                    return render_template("session/signin.html", errors=errors, email=email, password=password)
                elif not check_password_hash(logged_in_user.password, password):
                    errors.append("Password is incorrect")
                    return render_template("session/signin.html", errors=errors, email=email, password=password)
                else:
                    session['logged_in_userid'] = logged_in_user.id
                    session['logged_in_username'] = logged_in_user.username
                    return redirect('/')


@app.route('/userPage/<user_id>')
def userPage(user_id):
    user = User.query.filter_by(id = user_id).first()
    articles = Article.query.filter_by(author_id = user_id).all()
    print articles
    return render_template('user/userpage.html', username = user.username, articles=articles)


@app.route('/newArticle', methods=['GET', 'POST'])
def newArticle():
    if request.method == 'GET':
        return render_template('article/new.html')
    else:
        errors = []
        title = request.form['inputArticleTitle']
        content = request.form['inputArticleContent']
        if not 'logged_in_userid' in session:
            errors.append("log in required")
        else:
            author_id = session['logged_in_userid']

        if not (title and content):
            errors.append("all fields are required")

        if len(errors) != 0:
            return render_template('article/new.html', errors=errors, title=title, content=content)
        else:
            article = Article(title, author_id, content)
            db.session.add(article)
            db.session.commit()
            return redirect('/userPage/' + str(author_id))


@app.route('/signOut')
def signOut():
    session.clear()
    return redirect('/')


if __name__ == '__main__':
    host = os.getenv('IP', '0.0.0.0')
    port = int(os.getenv('PORT', 8080))
    app.run(host=host, port=port, debug=True)
