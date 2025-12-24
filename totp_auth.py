import pyotp
import ntplib

OTP_LENGTH = 6
OTP_INTERVAL = 60

def _get_network_time(server='pool.ntp.org'):
    client = ntplib.NTPClient()
    response = client.request(server, version=3)
    return response.tx_time

def get_totp(secret):
    try:
        network_time = _get_network_time()
        totp = pyotp.TOTP(secret, digits=OTP_LENGTH, interval=OTP_INTERVAL)
        return totp.at(network_time)
    except:
        return None

def generate_secret():
    return pyotp.random_base32()

def validate_totp(otp, secret):
    try:
        network_time = _get_network_time()
        totp = pyotp.TOTP(secret, digits=OTP_LENGTH, interval=OTP_INTERVAL)
        return totp.verify(otp, for_time=network_time)
    except:
        return None
