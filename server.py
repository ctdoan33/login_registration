from flask import Flask, render_template, redirect, request, session, flash
from mysqlconnection import MySQLConnector
import re
import os, binascii
import md5
LETTER_REGEX = re.compile(r"^[a-zA-Z]+$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$")
app = Flask(__name__)
app.secret_key = "KeepItSecretKeepItSafe"
mysql = MySQLConnector(app,'login_reg')
@app.route("/")
def form():
    if "id" in session:
        flash("You are already logged in!")
        return redirect("/success")
    else:
        return render_template("index.html")
@app.route("/log", methods=["POST"])
def log():
    valid = True
    if len(request.form["email"]) < 1:
        flash("Email must not be blank!", "log")
        valid = False
    elif not EMAIL_REGEX.match(request.form["email"]):
        flash("Invalid email!", "log")
        valid = False
    if len(request.form["password"]) < 1:
        flash("Password must not be blank!", "log")
        valid = False
    if valid:
        query = "SELECT id, hashed_pw, salt FROM registrations WHERE email = :email"
        data = {"email": request.form["email"]}
        pw_info = mysql.query_db(query, data)
        if pw_info == []:
            flash("Email not registered!", "log")
            return redirect("/")
        elif md5.new(request.form["password"]+pw_info[0]["salt"]).hexdigest() == pw_info[0]["hashed_pw"]:
            session["id"]=pw_info[0]["id"]
            flash("Successfully logged in!")
            return redirect("/success")
        else:
            flash("Email and password do not match!", "log")
    return redirect("/")
@app.route("/reg", methods=["POST"])
def reg():
    valid = True
    if len(request.form["first_name"]) < 1:
        flash("First name must not be blank!", "reg")
        valid = False
    elif len(request.form["first_name"]) < 2:
        flash("First name must be at least 2 letters!", "reg")
        valid = False
    elif not LETTER_REGEX.match(request.form["first_name"]):
        flash("First name must be letters only!", "reg")
        valid = False
    if len(request.form["last_name"]) < 1:
        flash("Last name cannot be blank!", "reg")
        valid = False
    elif len(request.form["last_name"]) < 2:
        flash("Last name must be at least 2 letters!", "reg")
        valid = False
    elif not LETTER_REGEX.match(request.form["last_name"]):
        flash("Last name must be letters only!", "reg")
        valid = False
    if len(request.form["email"]) < 1:
        flash("Email must not be blank!", "reg")
        valid = False
    elif not EMAIL_REGEX.match(request.form["email"]):
        flash("Invalid email!", "reg")
        valid = False
    else:
        query = "SELECT email FROM registrations WHERE email = :email"
        data = {"email":request.form["email"]}
        if mysql.query_db(query, data) != []:
            flash("An account with that email is already registered!", "reg")
            valid = False
    if len(request.form["password"]) < 1:
        flash("Password must not be blank!", "reg")
        valid = False
    elif len(request.form["password"])<8:
        flash("Password must be at least 8 characters!", "reg")
        valid = False
    if len(request.form["confirm_password"]) < 1:
        flash("Password confirmation cannot be blank!", "reg")
        valid = False
    elif request.form["password"] != request.form["confirm_password"]:
        flash("Password confirmation must match password!", "reg")
        valid = False
    if valid:
        salt = binascii.b2a_hex(os.urandom(15))
        hashed_password = md5.new(request.form["password"] + salt).hexdigest()
        query = "INSERT INTO registrations (first_name, last_name, email, hashed_pw, salt, created_at, updated_at) VALUES (:first_name, :last_name, :email, :hashed_pw, :salt, NOW(), NOW())"
        data = {
            "first_name": request.form["first_name"],
            "last_name": request.form["last_name"],
            "email": request.form["email"],
            "hashed_pw": hashed_password,
            "salt": salt
        }
        session["id"] = mysql.query_db(query, data)
        flash("Successfully registered and logged in!")
        return redirect("/success")
    else:
        return redirect("/")
@app.route("/success")
def success():
    query = "SELECT first_name, last_name FROM registrations WHERE id = :id"
    data = {"id": session["id"]}
    namedic = mysql.query_db(query, data)
    name = namedic[0]["first_name"]+" "+namedic[0]["last_name"]
    return render_template("success.html", user=name)
@app.route("/logout", methods=["POST"])
def logout():
    session.pop("id")
    return redirect("/")
app.run(debug=True)