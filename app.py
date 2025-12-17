from flask import Flask, render_template, request, redirect, url_for
import json
import csv
import time
import secrets
from database import Database
from config import Config, save_config, load_config

GROUP_SEED = 300225935
CONFIG_FILE = 'config.json'
USERS_FILE = 'users.json'
DB_FILE = 'users.db'
LOG_FILE = 'attempts.log'

def _build_db(db_filename, users_filename):
    db = Database(db_filename, conf.pepper)
    with open(users_filename, 'r') as file:
        users = json.load(file)
    for user in users:
        db.insert_user(user['username'], user['password'])
    return db

def _log_to_csv(filename, data):
    with open(filename, 'a', newline='', encoding='utf-8') as file:
        log = csv.writer(file)
        log.writerow(data)

def _generate_token():
    return secrets.token_urlsafe(10)

def _validate_token(token, max_attempts):
    global captcha_attempts_count
    captcha_required = False
    if captcha_on := max_attempts is not None:
        if captcha_attempts_count > max_attempts - 1:
            captcha_required = token != captcha_token
            if not captcha_required:
                captcha_attempts_count = 0
    return captcha_on, captcha_required


app = Flask(__name__)

# routs
@app.route("/")
def index():
    if captcha_on := conf.captcha is not None:
         captcha_required = captcha_attempts_count > conf.captcha - 1
    return render_template("index.html", captcha_required=captcha_on and captcha_required)

@app.route("/register", methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    token = request.form['captcha']
    captcha_on, captcha_required = _validate_token(token, conf.captcha)
    global captcha_token
    if captcha_required:
        msg = "wrong token"
        captcha_token = _generate_token()
    else:
        msg = "registered" if database.insert_user(username, password) else "user exists"
        captcha_token = None
    return render_template("index.html", response=msg, captcha_required=captcha_on and captcha_required)

@app.route("/login", methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    token = request.form['captcha']
    attempts_per_minute, max_attempts, captcha_max_attempts = conf.ratelimit, conf.userlock, conf.captcha
    start_time_ms = int(time.time() * 1000) #for log
    captcha_on, captcha_required = _validate_token(token, captcha_max_attempts)
    global captcha_attempts_count, captcha_token
    if captcha_required:
        msg = "wrong token"
    else:
        if captcha_on:
            captcha_attempts_count += 1
            captcha_required = captcha_attempts_count > captcha_max_attempts - 1
        match database.check_user(username, password, conf.hashfunc, max_attempts, attempts_per_minute):
            case None:
                msg = "locked"
            case False:
                msg = "wrong user or password"
            case True:
                msg = "logged in"
                captcha_attempts_count = 0
                captcha_required = False
    captcha_token = _generate_token() if captcha_required else None
    end_time_ms = int(time.time() * 1000) #for log
    latency_ms = end_time_ms - start_time_ms #for log
    log_data = [GROUP_SEED, username, conf.hashfunc, conf.pepper, conf.ratelimit, conf.userlock, conf.captcha, conf.totp, msg, latency_ms, end_time_ms]
    _log_to_csv(LOG_FILE, log_data)
    return render_template("index.html", response=msg, captcha_required=captcha_on and captcha_required)
        
@app.route("/admin/get_captcha_token")
def get_captcha_token():
    gs = request.args.get('group_seed')
    if captcha_token is not None and gs is not None and int(gs) == GROUP_SEED:
        return captcha_token
    return "error"

@app.route("/login_totp")
def login_totp():
    return "TEST"

@app.route("/config")
def config():
    with open(CONFIG_FILE, 'r') as file:
        form_config = json.load(file)
    return render_template("config.html", form_config=form_config)

@app.route("/save", methods=['POST'])
def save():
    hashfunc = request.form.get('hashfunc')
    sec_modules = []
    for sec_module in ['pepper', 'ratelimit', 'userlock', 'captcha', 'totp']:
        val = request.form.get(sec_module + '_val') if request.form.get(sec_module) else None
        sec_modules.append(val)
    config_obj = Config(hashfunc, sec_modules)
    save_config(CONFIG_FILE, config_obj)
    global conf, database, captcha_attempts_count, captcha_token
    conf = load_config(CONFIG_FILE)
    database = _build_db(DB_FILE, USERS_FILE)
    captcha_attempts_count = 0
    captcha_token = None
    return redirect(url_for('index'))

@app.route("/attack", methods=['GET', 'POST'])
def attack():
    if request.method == 'GET':
        return render_template("attack.html")
    return "TEST"

if __name__ == "__main__":
    conf = load_config(CONFIG_FILE)
    database = _build_db(DB_FILE, USERS_FILE)
    captcha_attempts_count = 0
    captcha_token = None
    app.run(debug=True)