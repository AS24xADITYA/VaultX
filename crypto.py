"""
crypto.py — Key Derivation + Symmetric Encryption

Key Derivation: PBKDF2-HMAC-SHA256
  - Converts a human password into a 256-bit AES key
  - 200,000 iterations makes brute-force extremely slow
  - A random 16-byte salt ensures same password → different key each setup

Encryption: AES-256-GCM (Advanced Encryption Standard, Galois/Counter Mode)
  - 256-bit key → impossible to brute-force (2^256 possible keys)
  - GCM mode provides BOTH confidentiality AND integrity (authentication)
  - If vault.json is tampered with → decryption raises an error (tamper-evident)
  - Nonce: 12 random bytes generated fresh for EVERY encryption call
    (same password encrypted twice → completely different ciphertext)
"""

import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SALT_FILE        = 'kdf_salt.bin'
PBKDF2_ITERS     = 200_000
KEY_BYTES        = 32          # 32 bytes = 256 bits


def _get_or_create_salt() -> bytes:
    """Load KDF salt from disk, or generate and save a new one."""
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, 'rb') as f:
            return f.read()
    salt = os.urandom(16)      # Cryptographically secure random bytes
    with open(SALT_FILE, 'wb') as f:
        f.write(salt)
    return salt


def derive_key(password: str) -> bytes:
    """
    Convert a human password to a 256-bit AES key using PBKDF2.
    
    Even a short/weak password becomes a strong 256-bit key after
    200,000 rounds of SHA-256 hashing with a random salt.
    """
    salt = _get_or_create_salt()
    kdf  = PBKDF2HMAC(
        algorithm  = hashes.SHA256(),
        length     = KEY_BYTES,
        salt       = salt,
        iterations = PBKDF2_ITERS,
        backend    = default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt(key: bytes, plaintext: str) -> dict:
    """
    Encrypt a string using AES-256-GCM.
    Returns a dict with nonce and ciphertext (both base64-encoded for JSON storage).
    """
    nonce      = os.urandom(12)         # 96-bit fresh nonce (MUST be unique per encryption)
    aesgcm     = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

    return {
        'nonce'      : base64.b64encode(nonce).decode('utf-8'),
        'ciphertext' : base64.b64encode(ciphertext).decode('utf-8')
    }


def decrypt(key: bytes, nonce_b64: str, ciphertext_b64: str) -> str:
    """
    Decrypt AES-256-GCM ciphertext back to plaintext.
    Raises InvalidTag exception if data has been tampered with.
    """
    nonce      = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    aesgcm     = AESGCM(key)
    plaintext  = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')
