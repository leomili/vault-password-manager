from cryptography.fernet import Fernet
from argon2.low_level import hash_secret_raw, Type
import base64
import hashlib
from django.conf import settings


# Derives a Fernet instance from Django's SECRET_KEY
# used to encrypt/decrypt the master password in the session
def get_session_fernet():
    digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


# Derives a secure vault key from the master password using Argon2id
# the salt is unique per user and stored in the database
def derive_key(master_password, salt):
    raw = hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )
    return base64.urlsafe_b64encode(raw)


# Encrypts a vault password using the derived vault key
def encrypt(text, key):
    f = Fernet(key)
    return f.encrypt(text.encode())


# Decrypts a vault password using the derived vault key
# bytes() converts the memoryview returned by Django's BinaryField
def decrypt(token, key):
    f = Fernet(key)
    return f.decrypt(bytes(token)).decode()


# Encrypts the master password for safe storage in the session
def encrypt_for_session(text):
    f = get_session_fernet()
    return f.encrypt(text.encode()).decode()


# Decrypts the master password retrieved from the session
def decrypt_from_session(token):
    f = get_session_fernet()
    return f.decrypt(token.encode()).decode()