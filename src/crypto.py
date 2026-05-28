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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

SALT_FILE        = 'kdf_salt.bin'
KEY_BYTES        = 32          # 32 bytes = 256 bits

# OWASP recommended parameters for Argon2id (2024):
ARGON2_TIME_COST   = 3          # Number of iterations
ARGON2_MEM_COST    = 65536      # 64 MB of RAM per attempt
ARGON2_PARALLELISM = 4          # 4 parallel threads


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
    Convert a human password to a 256-bit AES key using Argon2id.
    
    Argon2id is memory-hard and time-hard, making GPU-based brute-force
    attacks significantly more expensive than PBKDF2.
    """
    salt = _get_or_create_salt()
    return hash_secret_raw(
        secret      = password.encode('utf-8'),
        salt        = salt,
        time_cost   = ARGON2_TIME_COST,
        memory_cost = ARGON2_MEM_COST,
        parallelism = ARGON2_PARALLELISM,
        hash_len    = KEY_BYTES,
        type        = Type.ID
    )


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
