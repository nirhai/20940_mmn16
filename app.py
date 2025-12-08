from flask import Flask, render_template, request
import json
from database import create_table, insert_user, check_user

config_file = 'config.json'
users_file = 'users.json'

def _gen_config_data(hashfunc, pepper, ratelimit, userlock, captcha, totp):
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
    return data

def _get_config_hashfunc():
    with open(config_file, 'r') as file:
        config = json.load(file)
    for option in config['options']:
        if option['status'] == "selected":
            return option['name']

app = Flask(__name__)

#build database
with open(users_file, 'r') as file:
    users = json.load(file)
create_table(users)

# routs
@app.route("/", methods=["POST","GET"])
def index():
    if request.method == "POST":
        hashfunc = request.form.get('hashfunc')
        pepper = request.form.get('pepper')
        ratelimit = request.form.get('ratelimit')
        userlock = request.form.get('userlock')
        captcha = request.form.get('captcha')
        totp = request.form.get('totp')
        config_data = _gen_config_data(hashfunc, pepper, ratelimit, userlock, captcha, totp)
        with open(config_file, 'w') as file:
            json.dump(config_data, file, indent=4)
    return render_template("index.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form['username']
    password = request.form['password']
    if insert_user(username, password):
        return "registered"
    return "user exists"

@app.route("/login", methods=["POST"])
def login():
    username = request.form['username']
    password = request.form['password']
    hashfunc = _get_config_hashfunc()
    if check_user(username, password, hashfunc):
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