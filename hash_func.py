from argon2 import PasswordHasher
import bcrypt
import hashlib

def _gen_argon2(password):
    ph = PasswordHasher()
    hash_pwd = ph.hash(password)
    return hash_pwd

def _chk_argon2(hash, password):
    ph = PasswordHasher()
    try:
        ph.verify(hash, password)
        return True
    except:
        return False

def _gen_bcrypt(password, rounds):
    salt = bcrypt.gensalt(rounds)
    hash_pwd = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hash_pwd.decode('utf-8')

def _chk_bcrypt(hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), hash.encode('utf-8'))

def _gen_sha256(password):
    sha256_hash_obj = hashlib.sha256()
    sha256_hash_obj.update(password.encode('utf-8'))
    hash_pwd = sha256_hash_obj.hexdigest()
    return hash_pwd

def _chk_sha256(hash, password):
    return hash == _gen_sha256(password)

def _gen_md5(password):
    md5_hash_obj = hashlib.md5(password.encode('utf-8'))
    hash_pwd = md5_hash_obj.hexdigest()
    return hash_pwd

def _chk_md5(hash, password):
    return  hash == _gen_md5(password)

def generate_hash(func, password):
    match func:
        case "argon2":
            return _gen_argon2(password)
        case "bcrypt":
            return _gen_bcrypt(password, 12)
        case "sha256":
            return _gen_sha256(password)
        case "md5":
            return _gen_md5(password)
        
def check_hash(func, hash, password):
    match func:
        case "argon2":
            return _chk_argon2(hash, password)
        case "bcrypt":
            return _chk_bcrypt(hash, password)
        case "sha256":
            return _chk_sha256(hash, password)
        case "md5":
            return _chk_md5(hash, password)