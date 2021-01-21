#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
import math

from flask import Flask, render_template, request, redirect, json
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///psswds.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
is_logged = ""


class User(db.Model):
    login = db.Column(db.String, primary_key=True, nullable=False)
    password = db.Column(db.String(45), nullable=False)
    email = db.Column(db.String(30), nullable=False)

    def __repr__(self):
        return '<Username %r>' % self.login


class Service(db.Model):
    login = db.Column(db.String, nullable=False)
    service = db.Column(db.String, primary_key=True, nullable=False)
    password = db.Column(db.String(30), nullable=False)

    def __repr__(self):
        return '<Login %r>' % self.login


@app.route('/')
def hello_world():
    # login = "secret"
    # password = "2xSjZLm8gBnJ3M25TnTxJMmRz"
    # email = "-"
    # u = User(login=login, password=password, email=email)
    return render_template("index.html")


@app.route('/new_user', methods=['POST', 'GET'])
def create_user():
    if request.method == "POST":
        login = request.form['login']
        password = request.form['password']
        email = request.form['email']
        if not verify_psswd(password):
            return "Your password is too weak!!"
        if not verify_data(login):
            return "Your login is not acceptable!!"
        if not verify_data(email):
            return "Your email is not acceptable!!"

        user = User(login=login, password=password, email=email)

        try:
            db.session.add(user)
            db.session.commit()
            return redirect('/')
        except:
            return "Your data is bad! Try again"
    else:
        return render_template("create-user.html")


@app.route('/user', methods=['POST', 'GET'])
def list_services():
    if is_logged != "":
        u = User.query.filter_by(login=is_logged).first()
        if request.method == "POST":
            service = request.form['service']
            password = request.form['password']
            master_password = request.form['master_password']
            if not verify_psswd(password):
                return "Your password is too weak!!"
            if not verify_data(service):
                return "Your data is not acceptable!!"
            if not verify_data(master_password):
                return "Your master_password is not acceptable!!"
            new_service = Service(login=is_logged, service=service, password=password)
            try:
                db.session.add(new_service)
                db.session.commit()
                return redirect('/user')
            except:
                return "Your data is bad! Try again"
    else:
        return redirect('/')
    return render_template("services.html", user=u)


@app.route('/show_services')
def show_services():
    if is_logged != "":
        try:
            services = db.session.query(Service).filter_by(login=is_logged).all()
        except:
            return "Your bad!"
    return render_template("show_services.html", services=services)


@app.route('/auth', methods=['POST', 'GET'])
def auth():
    global is_logged
    is_logged = ""
    n = 0
    if request.method == "POST":
        login = request.form['login']
        password = request.form['password']
        if login == 'secret':
            return redirect('/oops')
        elif not verify_psswd(password):
            return "Your data is not acceptable!!"
        elif not verify_data(login):
            return "Your data is not acceptable!!"
        u = db.session.query(User).filter_by(login=login).first()
        if u is not None:
            if password == u.password:
                is_logged = u.login
                time.sleep(0.5)
                return redirect('/user')
    n += 1
    if n == 10:
        time.sleep(180)
    return render_template("sign_in.html")


@app.route('/oops')
def go_away():
    return render_template('oops.html')


@app.route('/service_password', methods=['POST', 'GET'])
def your_pass():
    global is_logged
    if request.method == "POST":
        service = request.form['service']
        master_password = request.form['master_password']
        if not verify_data(master_password):
            return "Your data is not acceptable!!"
        if not verify_data(service):
            return "Your data is not acceptable!!"
        try:
            s = db.session.query(Service).filter_by(service=service, login=is_logged).first()
            if s is not None:
                p = s.password
                return p
        except:
            return "nope"
    return render_template('top_secret.html')


def verify_psswd(password):
    is_good = False
    banned = ["select", "SELECT", "DROP", "drop", "INSERT", "insert", "update", "UPDATE", "DELETE", "delete", "script"]
    for ban in banned:
        if password.find(ban) == -1:
            if count_ent(password) > 3.9:
                is_good = True
    return is_good


def verify_data(login):
    is_good = True
    banned = ["select", "SELECT", "DROP", "drop", "INSERT", "insert", "update", "UPDATE", "DELETE", "delete", "script"]
    for ban in banned:
        if login.find(ban) != -1:
            is_good = False
    return is_good


def code_password(master_password, password):
    return password


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
    app.run(debug=True, host='0.0.0.0')
