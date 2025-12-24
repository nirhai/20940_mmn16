from flask import Flask, render_template, request, redirect, url_for, session, flash
import json
import csv
import time
import secrets
from database import Database
from config import Config, save_config, load_config
from attack import bruteforce_attack, dictionary_attack
from totp_auth import get_totp

GROUP_SEED = '496905569'
CONFIG_FILE = 'config.json'
USERS_FILE = 'users.json'
DB_FILE = 'users.db'
LOG_FILE = 'attempts.log'

def _build_db(db_filename, users_filename):
    db = Database(db_filename, conf.hashfunc, conf.pepper if conf.pepper else None)
    with open(users_filename, 'r') as file:
        users = json.load(file)
    for user in users:
        db.insert_user(user['username'], user['password'], user['totp'])
    return db

def _log_to_csv(filename, data):
    with open(filename, 'a', newline='', encoding='utf-8') as file:
        log = csv.writer(file)
        log.writerow(data)

def _generate_token():
    return secrets.token_urlsafe(10)

def _token_invalid(token, max_attempts):
    invalid = False
    if session['captcha_attempts_count'] > max_attempts - 1:
        if not (invalid := token != session['captcha_token']):
            session['captcha_attempts_count'] = 0
    return invalid

app = Flask(__name__)
app.secret_key = GROUP_SEED.encode("utf-8")

# routs
@app.route("/")
def index():
    if captcha_on := conf.captcha is not None:
        if 'captcha_attempts_count' not in session:
            session['captcha_attempts_count'] = 0
        captcha_required = session['captcha_attempts_count'] > conf.captcha - 1
    return render_template("index.html", captcha_required=captcha_on and captcha_required, totp_on=conf.totp is not None)

@app.route("/register_<register_type>", methods=['POST'])
def register(register_type):
    register_totp = (totp_on := conf.totp is not None) and register_type == 'totp'
    username = request.form.get('username')
    password = request.form.get('password')
    token = request.form.get('captcha')
    if (captcha_on := conf.captcha is not None) and ('captcha_attempts_count' not in session):
        session['captcha_attempts_count'] = 0
    if captcha_on and (captcha_required := _token_invalid(token, conf.captcha)):
        flash("wrong token")
        session['captcha_token'] = _generate_token()
    else:
        result = database.insert_user(username, password, register_totp)
        if result == False:
            flash("user exists")
        else:
            flash("registered")
            if register_totp:
                flash(f"secret: {result}")
        session.pop('captcha_token', None)
    return render_template("index.html", captcha_required=captcha_on and captcha_required, totp_on=totp_on)

@app.route("/login_<login_type>", methods=['POST'])
def login(login_type):
    login_totp = (totp_on := conf.totp is not None) and login_type == 'totp'
    username = request.form.get('username')
    password = request.form.get('password')
    token = request.form.get('captcha')
    otp = request.form.get('otp') if login_totp else None
    attempts_per_minute, max_attempts, captcha_max_attempts = conf.ratelimit, conf.userlock, conf.captcha
    start_time = int(time.time()) #for log

    if (captcha_on := captcha_max_attempts is not None) and ('captcha_attempts_count' not in session):
        session['captcha_attempts_count'] = 0
    captcha_required = captcha_on  and _token_invalid(token, captcha_max_attempts)
    if captcha_required:
        flash(msg := "wrong token")
    else:
        if captcha_on:
            session['captcha_attempts_count'] += 1
            captcha_required = session['captcha_attempts_count'] > captcha_max_attempts - 1
        result = database.check_user(username, password, max_attempts, attempts_per_minute, otp)
        if result == None:
            flash(msg := "locked")
        elif type(result) == int:
            flash(msg := f"locked for {result} seconds")
        elif type(result) == str:
            flash(msg := "OTP required")
        elif result == False:
            flash(msg := "wrong user or password")
        elif result == True:
            flash(msg := "logged in")
            session['captcha_attempts_count'] = 0
            captcha_required = False

    if captcha_required:
        session['captcha_token'] = _generate_token()
    else:
        session.pop('captcha_token', None)

    end_time = int(time.time()) #for log
    latency_ms = (end_time - start_time) * 1000 #for log
    log_data = [GROUP_SEED, username, conf.hashfunc, conf.pepper, conf.ratelimit, conf.userlock, conf.captcha, conf.totp, msg, latency_ms, end_time]
    _log_to_csv(LOG_FILE, log_data)
    return render_template("index.html", captcha_required=captcha_on and captcha_required, totp_on=totp_on)
        
@app.route("/admin/get_captcha_token")
def get_captcha_token():
    gs = request.args.get('group_seed')
    if 'captcha_token' in session and gs == GROUP_SEED:
        return session['captcha_token']
    return "error"

@app.route("/admin/config")
def config():
    with open(CONFIG_FILE, 'r') as file:
        form_config = json.load(file)
    return render_template("config.html", form_config=form_config)

@app.route("/save", methods=['POST'])
def save():
    hashfunc = request.form.get('hashfunc')
    sec_modules = []
    for sec_module in ['pepper', 'ratelimit', 'userlock', 'captcha', 'totp']:
        if (val := request.form.get(sec_module)) == 'on':
            if (val := request.form.get(sec_module + '_val')) is None:
                val = True
        sec_modules.append(val)
    config_obj = Config(hashfunc, sec_modules)
    save_config(CONFIG_FILE, config_obj)
    global conf, database
    conf = load_config(CONFIG_FILE)
    database = _build_db(DB_FILE, USERS_FILE)
    session.clear()
    return redirect(url_for('index'))

@app.route("/otp_gen", methods=['GET', 'POST'])
def otp_gen():
    if request.method == 'POST':
        secret = request.form.get('secret')
        otp = get_totp(secret)
        flash(otp) if otp is not None else flash("invalid secret key")
    return render_template("otp_gen.html")

@app.route("/attack", methods=['GET', 'POST'])
def attack():
    if request.method == 'GET':
        return render_template("attack.html")
    
    users = []
    attack_range = request.form.get('attack_range')
    if attack_range == "single_user":
        username = request.form.get('username')
        users.append(username)
    elif attack_range == "pwd_spraying":
        users_path = request.form.get('users_path')
        with open(users_path, 'r') as file:
            users_file = json.load(file)
        for user in users_file:
            users.append(user['username'])

    attack_type = request.form.get('attack_type')
    if attack_type == "bruteforce":
        digit = request.form.get('digit') == 'on'
        lowercase = request.form.get('lowercase') == 'on'
        uppercase = request.form.get('uppercase') == 'on'
        special = request.form.get('special') == 'on'
        pwd_len = int(request.form.get('pwd_len'))
        result = bruteforce_attack(users, digit, lowercase, uppercase, special, pwd_len)
    elif attack_type == "dictionary":
        wordlist_path = request.form.get('wordlist_path')
        result = dictionary_attack(users, wordlist_path)

    return result

if __name__ == "__main__":
    conf = load_config(CONFIG_FILE)
    database = _build_db(DB_FILE, USERS_FILE)
    app.run(debug=True)