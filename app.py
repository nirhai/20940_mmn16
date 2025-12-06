from flask import Flask, render_template, request, redirect, url_for
import json
from database import create_table, get_user, insert_user
from hash_func import generate_hash, check_hash

app = Flask(__name__)
create_table()

# routs
@app.route("/", methods=["POST","GET"]) #test methods
def index():
    if request.method == "POST":
        return "TEST"
    return render_template("index.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form['username']
    password = request.form['password']
    hashlist = [generate_hash("argon2", password),
                generate_hash("bcrypt", password),
                generate_hash("sha256", password),
                generate_hash("md5", password)]
    if insert_user(username, hashlist):
        return "registered"
    return "user exists"

@app.route("/login", methods=["POST"])
def login():
    username = request.form['username']
    password = request.form['password']
    user = get_user(username)
    if user and check_hash("bcrypt", user[1:], password):
        return "success"
    return "wrong user or password"

@app.route("/login_totp")
def login_totp():
    return "TEST"

@app.route("/config")
def config():
    return render_template("config.html")


if __name__ in "__main__":
    app.run(debug=True)