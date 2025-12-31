from argon2 import PasswordHasher
import bcrypt
import hashlib
import secrets

class HashFunction:
    def generate_hash():
        pass
    def check_hash():
        pass

class ARGON2(HashFunction):
    PH = PasswordHasher(
        time_cost = 1,
        memory_cost = 65536,
        parallelism = 1
    )

    def generate_hash(self, password):
        hash_pwd = self.PH.hash(password)
        return hash_pwd
    
    def check_hash(self, hash, password):
        try:
            self.PH.verify(hash, password)
            return True
        except:
            return False

class BCRYPT(HashFunction):
    BCRYPT_ROUNDS = 12

    def generate_hash(self, password):
        salt = bcrypt.gensalt(self.BCRYPT_ROUNDS)
        hash_pwd = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hash_pwd.decode('utf-8')
    
    def check_hash(self, hash, password):
        return bcrypt.checkpw(password.encode('utf-8'), hash.encode('utf-8'))

class SHA256(HashFunction):
    SHA256_SALT_BYTES = 16

    def generate_hash(self, password):
        salt = secrets.token_bytes(self.SHA256_SALT_BYTES)
        sha256_hash_obj = hashlib.sha256()
        sha256_hash_obj.update(salt + password.encode('utf-8'))
        hash_pwd = sha256_hash_obj.hexdigest()
        return salt.hex() + hash_pwd
    
    def check_hash(self, hash_salt, password):
        hash = hash_salt[self.SHA256_SALT_BYTES * 2 :]
        salt = hash_salt[: self.SHA256_SALT_BYTES * 2]
        sha256_hash_obj = hashlib.sha256()
        sha256_hash_obj.update(bytes.fromhex(salt) + password.encode('utf-8'))
        return hash == sha256_hash_obj.hexdigest()

class MD5(HashFunction):
    def generate_hash(self, password):
        md5_hash_obj = hashlib.md5(password.encode('utf-8'))
        hash_pwd = md5_hash_obj.hexdigest()
        return hash_pwd
    
    def check_hash(self, hash, password):
        return  hash == self.generate_hash(password)

def HashFunctionFactory(hashfunc):
    hash_funcs = {
        "argon2" : ARGON2,
        "bcrypt" : BCRYPT,
        "sha256" : SHA256,
        "md5" : MD5
    }
    return hash_funcs[hashfunc]()