import json

class Config:
    def __init__(self, hashfunc, sec_modules):
        self.hashfunc = hashfunc
        self.pepper = sec_modules[0]
        self.ratelimit = sec_modules[1]
        self.userlock = sec_modules[2]
        self.captcha = sec_modules[3]
        self.totp = sec_modules[4]

def _gen_config_data(config_obj):
    data = {
        "hash_functions" : [
            {"name":"argon2", "label":"argon2", "status":"selected" if config_obj.hashfunc=='argon2' else ""},
            {"name":"bcrypt", "label":"bcrypt", "status":"selected" if config_obj.hashfunc=='bcrypt' else ""},
            {"name":"sha256", "label":"SHA256/salt", "status":"selected" if config_obj.hashfunc=='sha256' else ""},
            {"name":"md5", "label":"MD5", "status":"selected" if config_obj.hashfunc=='md5' else ""}
        ],
        "security_modules" : [
            {"name":"pepper", "label":"Pepper", "type":"text", "info":"",
             "status":"" if config_obj.pepper is None else "checked",
             "value": "" if config_obj.pepper is None else config_obj.pepper},

            {"name":"ratelimit", "label":"Rate-Limiting", "type":"number", "info":"failed login attempts in one minute",
             "status":"" if config_obj.ratelimit is None else "checked",
             "value": "" if config_obj.ratelimit is None else config_obj.ratelimit},

            {"name":"userlock", "label":"User-Locking", "type":"number", "info":"failed login attempts",
             "status":"" if config_obj.userlock is None else "checked",
             "value": "" if config_obj.userlock is None else config_obj.userlock},

            {"name":"captcha", "label":"CAPTCHA", "type":"number", "info":"failed login attempts",
             "status":"" if config_obj.captcha is None else "checked",
             "value": "" if config_obj.captcha is None else config_obj.captcha},

            {"name":"totp", "label":"Time-based One-Time Password", "type":"text", "info":"",
             "status":"" if config_obj.totp is None else "checked"}
        ]
    }
    return data

def _get_config_hashfunc(config_json):
    for hf in config_json['hash_functions']:
        if hf['status'] == "selected":
            return hf['name']
        
def _get_config_secmodules(config_json):
    val_list = []
    for sm in config_json['security_modules']:
        if sm['status'] == "checked":
            val = int(sm['value']) if sm['type'] == "number" else sm['value']
        else:
            val = None
        val_list.append(val)
    return val_list
        
def save_config(filename, config_obj):
    config_data = _gen_config_data(config_obj)
    with open(filename, 'w') as file:
        json.dump(config_data, file, indent=4)

def load_config(filename):
    with open(filename, 'r') as file:
        config_json = json.load(file)
    hashfunc = _get_config_hashfunc(config_json)
    sec_modules = _get_config_secmodules(config_json)
    return Config(hashfunc, sec_modules)
