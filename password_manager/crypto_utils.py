"""Cryptographic helpers for the password manager."""
import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from .exceptions import DecryptionError

SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32                 # 256-bit AES key
TAG_BYTES = 16
PBKDF2_ITERATIONS = 600_000
VERIFIER_TEXT = b"cli-password-manager-v1-master-password-check"


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError, AttributeError) as exc:
        raise DecryptionError("Invalid base64 data in vault.") from exc


def derive_key(master_password: str, salt: bytes) -> bytes:
    if not master_password:
        raise ValueError("Master password cannot be empty.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(master_password.encode("utf-8"))


def encrypt_bytes(key: bytes, plaintext: bytes) -> dict:
    nonce = os.urandom(NONCE_BYTES)
    combined = AESGCM(key).encrypt(nonce, plaintext, None)
    ciphertext, tag = combined[:-TAG_BYTES], combined[-TAG_BYTES:]
    return {
        "nonce": b64encode(nonce),
        "ciphertext": b64encode(ciphertext),
        "tag": b64encode(tag),
    }


def decrypt_bytes(key: bytes, record: dict) -> bytes:
    try:
        nonce = b64decode(record["nonce"])
        ciphertext = b64decode(record["ciphertext"])
        tag = b64decode(record["tag"])
        if len(nonce) != NONCE_BYTES or len(tag) != TAG_BYTES:
            raise DecryptionError("Invalid nonce or authentication-tag length.")
        return AESGCM(key).decrypt(nonce, ciphertext + tag, None)
    except (InvalidTag, KeyError, TypeError, ValueError) as exc:
        raise DecryptionError(
            "Vault authentication failed. The master password may be wrong, "
            "or the encrypted data may have been modified."
        ) from exc


def make_verifier(key: bytes) -> dict:
    return encrypt_bytes(key, VERIFIER_TEXT)


def verify_key(key: bytes, verifier: dict) -> bool:
    try:
        return decrypt_bytes(key, verifier) == VERIFIER_TEXT
    except DecryptionError:
        return False
