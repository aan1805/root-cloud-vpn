from cryptography.fernet import Fernet
import base64
import hashlib
from flask import current_app

def get_fernet():
    secret_key = current_app.config['SECRET_KEY'].encode()
    key = base64.urlsafe_b64encode(hashlib.sha256(secret_key).digest())
    return Fernet(key)

def encrypt_data(data: str) -> str:
    """Принимает строку, возвращает зашифрованную строку (utf-8)"""
    if data is None:
        return None
    f = get_fernet()
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    """Принимает зашифрованную строку, возвращает расшифрованную"""
    if encrypted_data is None:
        return None
    f = get_fernet()
    return f.decrypt(encrypted_data.encode()).decode()