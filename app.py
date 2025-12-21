from flask import Flask, render_template, request, redirect, url_for
import json
import csv
import time
import secrets
from database import Database
from config import Config, save_config, load_config
from attack import bruteforce_attack, dictionary_attack

GROUP_SEED = 300225935
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

def _token_is_valid(token, max_attempts):
    global captcha_attempts_count
    valid = True
    if captcha_attempts_count > max_attempts - 1:
        if valid := token == captcha_token:
            captcha_attempts_count = 0
    return valid

app = Flask(__name__)

# routs
@app.route("/")
def index():
    if captcha_on := conf.captcha is not None:
         captcha_required = captcha_attempts_count > conf.captcha - 1
    return render_template("index.html", captcha_required=captcha_on and captcha_required, totp_on=conf.totp is not None)

@app.route("/register/<type>", methods=['POST'])
def register(type):
    totp_reg = (totp_on := conf.totp is not None) and type == 'totp'
    username = request.form.get('username')
    password = request.form.get('password')
    token = request.form.get('captcha')
    global captcha_token
    if (captcha_on := conf.captcha is not None) and (captcha_required := not _token_is_valid(token, conf.captcha)):
        msg = "wrong token"
        captcha_token = _generate_token()
    else:
        msg = "registered" if database.insert_user(username, password, totp_reg) else "user exists"
        captcha_token = None
    return render_template("index.html", msg=msg, captcha_required=captcha_on and captcha_required, totp_on=totp_on)

@app.route("/login", methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    token = request.form.get('captcha')
    attempts_per_minute, max_attempts, captcha_max_attempts = conf.ratelimit, conf.userlock, conf.captcha
    start_time_ms = int(time.time() * 1000) #for log

    captcha_on = captcha_max_attempts is not None
    captcha_required = captcha_on and not _token_is_valid(token, captcha_max_attempts)
    global captcha_attempts_count, captcha_token
    if captcha_required:
        msg = "wrong token"
    else:
        if captcha_on:
            captcha_attempts_count += 1
            captcha_required = captcha_attempts_count > captcha_max_attempts - 1
        match database.check_user(username, password, max_attempts, attempts_per_minute):
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
    return render_template("index.html", msg=msg, captcha_required=captcha_on and captcha_required, totp_on=conf.totp is not None)
        
@app.route("/admin/get_captcha_token")
def get_captcha_token():
    gs = request.args.get('group_seed')
    if captcha_token is not None and gs is not None and int(gs) == GROUP_SEED:
        return captcha_token
    return "error"

@app.route("/login_totp")
def login_totp():
    return "TEST"

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
    captcha_attempts_count = 0
    captcha_token = None
    app.run(debug=True)