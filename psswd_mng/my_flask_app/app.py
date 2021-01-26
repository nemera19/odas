#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
import math, os, time
import sys

import pyperclip
from datetime import timedelta
from Crypto.Protocol.KDF import PBKDF2
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, flash, session
from flask_login import LoginManager
from flask_login import UserMixin, current_user
from flask_login import login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CsrfProtect
from werkzeug.security import generate_password_hash, check_password_hash
from forms import LoginForm, CreateUserForm, CreateServiceForm, DecodePassword

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///psswds.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SECURITY_TRACKABLE'] = True
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"

csrf = CsrfProtect(app)
csrf.init_app(app)

db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String, nullable=False)
    password = db.Column(db.String(45), nullable=False)
    email = db.Column(db.String(30))
    loggings = db.Column(db.Integer)

    def __repr__(self):
        return '<Username %r>' % self.login


class Service(db.Model):
    login = db.Column(db.String, nullable=False)
    service = db.Column(db.String, nullable=False)
    password = db.Column(db.String(30), primary_key=True, nullable=False)
    salt = db.Column(db.String(30), nullable=False)

    def __repr__(self):
        return '<Login %r>' % self.login


@app.before_request
def set_session_timeout():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=10)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')


@app.route('/')
def hello_world():
    login = "secret"
    password = "2xSjZLm8gBnJ3M25TnTxJMmRz"
    email = "-"
    user = User(login=login, password=password, email=email)
    db.session.add(user)
    db.session.commit()
    return render_template("index.html")


@app.route('/new_user', methods=['POST', 'GET'])
def create_user():
    form = CreateUserForm()
    if form.validate_on_submit():
        if request.method == "POST":
            login = request.form['login']
            password = request.form['password']
            email = request.form['email']
            if not verify_psswd(password):
                flash('Your password is too weak!!')
                return redirect('/new_user')

            u = User.query.filter_by(login=login).first()
            if u:
                flash('Your data is not acceptable')
                return redirect('/new_user')

            user = User(login=login, password=generate_password_hash(password, method='sha256'), email=email, loggings=0)
            try:
                db.session.add(user)
                db.session.commit()
                return redirect('/')
            except:
                return "Your data is bad! Try again"
    return render_template("new_user.html", form=form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if request.method == "POST":
            login = request.form['login']
            password = request.form['password']
            remember = True if request.form.get('remember') else False
            if login == 'secret' and password == '2xSjZLm8gBnJ3M25TnTxJMmRz':
                print(f'Normaline wysłałbym wiadomość na nemera192000@gmail.com o tym, że ktoś się zalogował na secret', file=sys.stderr)
            u = db.session.query(User).filter_by(login=login).first()
            if not u:
                flash('Login or password might not be correct')
                return redirect('/login')
            if u.loggings < 10:
                if not check_password_hash(u.password, password):
                        u.loggings = u.loggings + 1
                        db.session.commit()
                        flash('Login or password might not be correct')
                        return redirect('/login')
                login_user(u, remember=remember)
                time.sleep(2)
                return redirect('/user')
            elif u.loggings >= 10:
                flash('You are banned. Please come back in 10 minutes and try again')
                time.sleep(7)
                return redirect('/login')

    return render_template("login.html", form=form)


@app.route('/user', methods=['POST', 'GET'])
@login_required
def list_services():
    if request.method == "POST":
        service = request.form['service']
        password = request.form['password']
        master_password = request.form['master_password']
        if not verify_psswd(password):
            return "Your password is too weak!!"
        if not verify_psswd(master_password):
            return "Your master_password is not acceptable!!"
        salt = os.urandom(16)
        encrypted = encrypt_password(master_password, password, salt)
        new_service = Service(login=current_user.login, service=service, password=encrypted, salt=salt)
        db.session.add(new_service)
        db.session.commit()
        return redirect('/user')
    return render_template("user.html", login=current_user.login)


@app.route('/show_services')
def show_services():
    services = db.session.query(Service).filter_by(login=current_user.login).all()
    return render_template("show_services.html", services=services)


@app.route('/service_password', methods=['POST', 'GET'])
def your_pass():
    form = DecodePassword()
    if form.validate_on_submit():
        if request.method == "POST":
            service = request.form['service']
            master_password = request.form['master_password']
            s = db.session.query(Service).filter_by(service=service, login=current_user.login).first()
            if s is not None:
                p = s.password
                decrypted = decrypt_password(p, master_password, s.salt)
                print(decrypted, file=sys.stderr)
                # doesn't work for nginx
                # pyperclip.copy(decrypted)
                # pyperclip.paste()
                # flash('Your password is successfully copied')
                return redirect('/show_services')
    return render_template('top_secret.html', form=form)


@app.route('/reset', methods=['POST', 'GET'])
def reset_password():
    if request.method == "POST":
        email = request.form['email']
        u = db.session.query(User).filter_by(email=email).first()
        if not u:
            flash('Something is wrong...')
            return redirect('/login')
        else:
            login_user(u)
            print(
                f'Normaline wysłałbym wiadomość na {u.email}.\n Hurry up you only have 10 min https://localhost:5000/new_password', file=sys.stderr)
    return render_template('reset.html')


@app.route('/new_password', methods=['POST', 'GET'])
def new_password():
    if current_user:
        if request.method == "POST":
            user = db.session.query(User).filter_by(login=current_user.login).first()
            new_password = request.form['password']
            if not verify_psswd(new_password):
                return "Your new password is too weak!!"
            user.password = generate_password_hash(new_password, method='sha256')
            db.session.commit()
            return redirect('/login')
    return render_template('new_password.html')


def verify_psswd(password):
    is_good = False
    if count_ent(password) > 3.9:
        is_good = True
    return is_good


def generate_key(master_password, salt):
    k = PBKDF2(master_password, salt, 32)
    return base64.urlsafe_b64encode(k)


def encrypt_password(master_password, password, salt):
    master_password = master_password.encode()
    password = password.encode()
    key = generate_key(master_password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(password)
    return encrypted


def decrypt_password(encrypted, master_password, salt):
    master_password = master_password.encode()
    key = generate_key(master_password, salt)
    f = Fernet(key)
    decrypted = f.decrypt(encrypted)
    return decrypted.decode()


def count_ent(text):
    stat = {}
    for c in text:
        m = c
        if m in stat:
            stat[m] += 1
        else:
            stat[m] = 1
    h = 0.0
    for i in stat.keys():
        pi = stat[i] / len(text)
        h -= pi * math.log2(pi)
    return h


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')
