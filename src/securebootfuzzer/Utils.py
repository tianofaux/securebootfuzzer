import string
import random
import socket

def random_str(N: int) -> str:
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(N))

def find_available_port(start: int = 8000, end: int = 9999) -> int | None:
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('localhost', port))
                return port
            except socket.error:
                continue

    return None
