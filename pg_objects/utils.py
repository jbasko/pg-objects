import hashlib
import random
import string


def generate_password(length=24) -> str:
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def get_password_md5(username, password) -> str:
    return "md5" + hashlib.md5(f"{password}{username}".encode()).hexdigest()
