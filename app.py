from flask import Flask, render_template, request, redirect, url_for, session, flash
import json
import csv
import secrets
from time import time
from database import Database
from config import Config, save_config, load_config
from attack import bruteforce_attack, dictionary_attack, stop_attack
from totp_auth import get_totp

GROUP_SEED = '496905569'
CONFIG_FILE = 'config.json'
USERS_FILE = 'users.json'
DB_FILE = 'auth.db'
LOG_FILE = 'attempts.log'

def _build_db(db_filename, users_filename):
    db = Database(db_filename, conf)
    with open(users_filename, 'r') as file:
        users = json.load(file)
    for user in users:
        db.insert_user(user['username'], user['password'], user['totp'])
    return db

def _init_csv(filename):
    data = ['group_seed','username','password','hash_mode','pepper','ratelimit','userlock','captcha','totp','result','latency_ms','timestamp']
    with open(filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(data)

def _log_to_csv(filename, data):
    with open(filename, 'a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(data)

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
            if conf.captcha == 0:
                session['captcha_token'] = _generate_token()
        captcha_required = session['captcha_attempts_count'] > conf.captcha - 1
    return render_template("index.html", userlock_on=conf.userlock is not None, captcha_required=captcha_on and captcha_required, totp_on=conf.totp is not None)

@app.route("/register", methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    token = request.form.get('captcha')
    register_totp = (totp_on := conf.totp is not None) and request.form.get('2fa') is not None
    if (captcha_on := conf.captcha is not None) and ('captcha_attempts_count' not in session):
        session['captcha_attempts_count'] = 0
        if conf.captcha == 0:
            session['captcha_token'] = _generate_token()
    if captcha_on and (captcha_required := _token_invalid(token, conf.captcha)):
        flash("wrong token")
        session['captcha_token'] = _generate_token()
    else:
        msgs = database.insert_user(username, password, register_totp)
        for msg in msgs: flash(msg)
        if conf.captcha == 0:
            session['captcha_token'] = _generate_token()
        else:
            session.pop('captcha_token', None)
    return render_template("index.html", userlock_on=conf.userlock is not None, captcha_required=captcha_on and (captcha_required or conf.captcha == 0), totp_on=totp_on)

@app.route("/login", methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    token = request.form.get('captcha')
    login_totp = (totp_on := conf.totp is not None) and request.form.get('2fa') is not None
    otp = request.form.get('otp') if login_totp else None
    captcha_max_attempts = conf.captcha
    start_time = int(time()) #for log

    if (captcha_on := captcha_max_attempts is not None) and ('captcha_attempts_count' not in session):
        session['captcha_attempts_count'] = 0
        if captcha_max_attempts == 0:
            session['captcha_token'] = _generate_token()
    captcha_required = captcha_on  and _token_invalid(token, captcha_max_attempts)
    if captcha_required:
        flash(msg := "wrong token")
    else:
        if captcha_on:
            session['captcha_attempts_count'] += 1
            captcha_required = session['captcha_attempts_count'] > captcha_max_attempts - 1
        msg = database.check_user(username, password, otp)
        if msg == "logged in" and captcha_on:
            session['captcha_attempts_count'] = 0
            captcha_required = session['captcha_attempts_count'] > captcha_max_attempts - 1
        flash(msg)
    if captcha_required:
        session['captcha_token'] = _generate_token()
    else:
        session.pop('captcha_token', None)

    end_time = int(time()) #for log
    latency_ms = (end_time - start_time) * 1000 #for log
    log_data = [GROUP_SEED, username, password, conf.hashfunc, conf.pepper, conf.ratelimit, conf.userlock, conf.captcha, conf.totp, msg, latency_ms, end_time]
    _log_to_csv(LOG_FILE, log_data)
    return render_template("index.html", userlock_on=conf.userlock is not None, captcha_required=captcha_on and captcha_required, totp_on=totp_on)

@app.route("/admin/unlock", methods=['POST'])
def unlock():
    username = request.form.get('username')
    password = request.form.get('password')
    msg = database.unlock_user(username, password)
    flash(msg)
    return render_template("index.html", userlock_on=conf.userlock is not None, captcha_required=False, totp_on=conf.totp is not None)

@app.route("/admin/get_captcha_token")
def get_captcha_token():
    gs = request.args.get('group_seed')
    if 'captcha_token' in session and gs == GROUP_SEED:
        flash("token: " + session['captcha_token'])
    else:
        flash("token: not found")
    return redirect(url_for('index'))

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
    config_obj = Config(hashfunc, *sec_modules)
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
    result = stop_attack()
    if request.method == 'GET':
        action = request.args.get('action')
        if action == 'stop':
            return result
        elif action == 'back':
            return redirect(url_for('index'))
        return render_template("attack.html")
    
    users = []
    max_attempts = int(request.form.get('max_attempts'))
    max_duration = int(request.form.get('max_duration'))
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
        result = bruteforce_attack(users, digit, lowercase, uppercase, special, pwd_len, max_attempts, max_duration)
    elif attack_type == "dictionary":
        wordlist_path = request.form.get('wordlist_path')
        result = dictionary_attack(users, wordlist_path, max_attempts, max_duration)

    return result

if __name__ == "__main__":
    conf = load_config(CONFIG_FILE)
    database = _build_db(DB_FILE, USERS_FILE)
    _init_csv(LOG_FILE)
    app.run(debug=False)