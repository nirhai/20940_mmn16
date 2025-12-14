from flask import Flask, render_template, request
import json
import time
import csv
from database import Database

GROUP_SEED = 300225935
CONFIG_FILE = 'config.json'
USERS_FILE = 'users.json'
DB_FILE = 'users.db'
LOG_FILE = 'attempts.log'

class SecModule:
    def __init__(self, status, value=None):
        self.status = status
        self.value = value

class Config:
    def __init__(self, hashfunc, pepper, ratelimit, userlock, captcha, totp):
        self.hashfunc = hashfunc
        self.pepper = pepper
        self.ratelimit = ratelimit
        self.userlock = userlock
        self.captcha = captcha
        self.totp = totp

def _gen_config_data(config_obj):
    data = {
        "hash_functions" : [
            {"name":"argon2", "label":"argon2", "status":"selected" if config_obj.hashfunc=='argon2' else ""},
            {"name":"bcrypt", "label":"bcrypt", "status":"selected" if config_obj.hashfunc=='bcrypt' else ""},
            {"name":"sha256", "label":"SHA256/salt", "status":"selected" if config_obj.hashfunc=='sha256' else ""},
            {"name":"md5", "label":"MD5", "status":"selected" if config_obj.hashfunc=='md5' else ""}
        ],
        "security_modules" : [
            {"name":"pepper", "label":"Pepper", "status":"checked" if config_obj.pepper.status else "", "value": config_obj.pepper.value},
            {"name":"ratelimit", "label":"Rate-Limiting", "status":"checked" if config_obj.ratelimit.status else "", "value": config_obj.ratelimit.value},
            {"name":"userlock", "label":"User-Locking", "status":"checked" if config_obj.userlock.status else "", "value": config_obj.userlock.value},
            {"name":"captcha", "label":"CAPTCHA", "status":"checked" if config_obj.captcha.status else "", "value": config_obj.captcha.value},
            {"name":"totp", "label":"Time-based One-Time Password", "status":"checked" if config_obj.totp.status else "", "value": ""}
        ]
    }
    return data

def _get_config_hashfunc(config):
    for hf in config['hash_functions']:
        if hf['status'] == "selected":
            return hf['name']
        
def _get_config_secmodule_val(config, secmodule=None):
    val_list = []
    for sm in config['security_modules']:
        val = sm['value'] if sm['status'] == "checked" else None
        if secmodule is None:
            val_list.append(val)
        elif sm['name'] == secmodule:
            return val
    return val_list

def _get_config(param):
    with open(CONFIG_FILE, 'r') as file:
        config = json.load(file)
    match param:
        case 'hashfunc':
            return _get_config_hashfunc(config)
        case 'pepper' | 'ratelimit' | 'userlock' | 'captcha' | 'totp':
            return _get_config_secmodule_val(config, param)
        case 'security_modules':
            return _get_config_secmodule_val(config)
        
def _build_db(db_filename, users_filename):
    db = Database(db_filename, _get_config('pepper'))
    with open(users_filename, 'r') as file:
        users = json.load(file)
    for user in users:
        db.insert_user(user['username'], user['password'])
    return db

def _log_to_csv(filename, data):
    with open(filename, 'a', newline='', encoding='utf-8') as file:
        log = csv.writer(file)
        log.writerow(data)

app = Flask(__name__)

# routs
@app.route("/", methods=["POST","GET"])
def index():
    if request.method == "POST":
        hashfunc = request.form.get('hashfunc')
        pepper = SecModule(request.form.get('pepper'), request.form.get('pepper_val'))
        ratelimit = SecModule(request.form.get('ratelimit'), request.form.get('ratelimit_val'))
        userlock = SecModule(request.form.get('userlock'), request.form.get('userlock_val'))
        captcha = SecModule(request.form.get('captcha'), request.form.get('captcha_val'))
        totp = SecModule(request.form.get('totp'))
        config_obj = Config(hashfunc, pepper, ratelimit, userlock, captcha, totp)
        config_data = _gen_config_data(config_obj)
        with open(CONFIG_FILE, 'w') as file:
            json.dump(config_data, file, indent=4)
        global database
        database = _build_db(DB_FILE, USERS_FILE)
    return render_template("index.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form['username']
    password = request.form['password']
    if database.insert_user(username, password):
        return "registered"
    return "user exists"

@app.route("/login", methods=["POST"])
def login():
    username = request.form['username']
    password = request.form['password']
    hashfunc = _get_config('hashfunc')
    sec_modules = _get_config('security_modules') #for log
    attempts_per_minute = int(sec_modules[1]) if sec_modules[1] is not None else None
    max_attempts = int(sec_modules[2]) if sec_modules[2] is not None else None
    result = None
    start_time_ms = int(time.time() * 1000) #for log
    match database.check_user(username, password, hashfunc, max_attempts, attempts_per_minute):
        case None:
            result = "locked"
        case False:
            result = "wrong user or password"
        case True:
            result = "success"
    end_time_ms = int(time.time() * 1000) #for log
    latency_ms = end_time_ms - start_time_ms #for log
    log_data = [GROUP_SEED, username, hashfunc] + sec_modules + [result, latency_ms, end_time_ms]
    _log_to_csv(LOG_FILE, log_data)
    return result
        
@app.route("/admin/get_captcha_token", methods=["GET"])
def get_captcha_token():
    return "TEST"

@app.route("/login_totp")
def login_totp():
    return "TEST"

@app.route("/config")
def config():
    with open(CONFIG_FILE, 'r') as file:
        form_config = json.load(file)
    return render_template("config.html", form_config=form_config)


if __name__ in "__main__":
    database = _build_db(DB_FILE, USERS_FILE)
    app.run(debug=True)