from flask import Flask, render_template, request, redirect, url_for
import json
from database import create_table, get_user, insert_user
from hash_func import generate_hash, check_hash

app = Flask(__name__)
config_file = 'config.json'
users_file = 'users.json'
create_table()

# routs
@app.route("/", methods=["POST","GET"]) #test methods
def index():
    if request.method == "POST":
        with open(config_file, 'w') as file:
            hashfunc = request.form.get('hashfunc')
            pepper = request.form.get('pepper')
            ratelimit = request.form.get('ratelimit')
            userlock = request.form.get('userlock')
            captcha = request.form.get('captcha')
            totp = request.form.get('totp')
            data = {
                "options" : [
                    {"name":"argon2", "label":"argon2", "status":"selected" if hashfunc=='argon2' else ""},
                    {"name":"bcrypt", "label":"bcrypt", "status":"selected" if hashfunc=='bcrypt' else ""},
                    {"name":"sha256", "label":"SHA256/salt", "status":"selected" if hashfunc=='sha256' else ""},
                    {"name":"md5", "label":"MD5", "status":"selected" if hashfunc=='md5' else ""}
                ],
                "checkboxs" : [
                    {"name":"pepper", "label":"Pepper", "status":"checked" if pepper else ""},
                    {"name":"ratelimit", "label":"Rate-Limiting", "status":"checked" if ratelimit else ""},
                    {"name":"userlock", "label":"User-Locking", "status":"checked" if userlock else ""},
                    {"name":"captcha", "label":"CAPTCHA", "status":"checked" if captcha else ""},
                    {"name":"totp", "label":"Time-based One-Time Password", "status":"checked" if totp else ""}
                ]
            }
            json.dump(data, file, indent=4)
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
    with open(config_file, 'r') as file:
        form_config = json.load(file)
    return render_template("config.html", form_config=form_config)


if __name__ in "__main__":
    app.run(debug=True)