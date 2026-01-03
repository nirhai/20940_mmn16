import json

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
            {"name":"argon2", "label":"argon2", "status":config_obj.hashfunc=='argon2'},
            {"name":"bcrypt", "label":"bcrypt", "status":config_obj.hashfunc=='bcrypt'},
            {"name":"sha256", "label":"SHA256/salt", "status":config_obj.hashfunc=='sha256'},
            {"name":"md5", "label":"MD5", "status":config_obj.hashfunc=='md5'}
        ],
        "security_modules" : [
            {"name":"pepper", "label":"Pepper", "type":"text",
             "status":config_obj.pepper is not None,
             "value": config_obj.pepper if config_obj.pepper is not None else None},

            {"name":"ratelimit", "label":"Rate-Limiting", "type":"number", "info":"failed login attempts in one minute",
             "status":config_obj.ratelimit is not None,
             "value": config_obj.ratelimit if config_obj.ratelimit is not None else None},

            {"name":"userlock", "label":"User-Locking", "type":"number", "info":"failed login attempts",
             "status":config_obj.userlock is not None,
             "value": config_obj.userlock if config_obj.userlock is not None else None},

            {"name":"captcha", "label":"CAPTCHA", "type":"number", "info":"failed login attempts",
             "status":config_obj.captcha is not None,
             "value": config_obj.captcha if config_obj.captcha is not None else None},

            {"name":"totp", "label":"Time-based One-Time Password",
             "status":config_obj.totp is not None}
        ]
    }
    return data

def _get_config_hashfunc(config_json):
    for hf in config_json['hash_functions']:
        if hf['status']:
            return hf['name']
        
def _get_config_secmodules(config_json):
    sec_modules = {}
    for sm in config_json['security_modules']:
        if sm['status']:
            if 'value' in sm:
                val = int(sm['value']) if sm['type'] == "number" else sm['value']
            else:
                val = True
        else:
            val = None
        sec_modules[sm['name']] = val
    return sec_modules
        
def save_config(filename, config_obj):
    config_data = _gen_config_data(config_obj)
    with open(filename, 'w') as file:
        json.dump(config_data, file, indent=4)

def load_config(filename):
    with open(filename, 'r') as file:
        config_json = json.load(file)
    hashfunc = _get_config_hashfunc(config_json)
    sec_modules = _get_config_secmodules(config_json)
    return Config(hashfunc, **sec_modules)
