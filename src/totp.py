"""
totp.py — Time-based One-Time Password (2FA) logic.
"""

import pyotp
import qrcode
import io
import base64
import json
import os
from crypto import encrypt, decrypt

TOTP_FILE = "totp_config.json"

def generate_totp_secret() -> str:
    """Generate a new 160-bit base32 TOTP secret."""
    return pyotp.random_base32()

def save_totp_secret(key: bytes, secret: str):
    """Encrypt the TOTP secret before saving to disk."""
    enc = encrypt(key, secret)
    with open(TOTP_FILE, "w") as f:
        json.dump(enc, f)

def load_totp_secret(key: bytes) -> str | None:
    """Load and decrypt the TOTP secret."""
    if not os.path.exists(TOTP_FILE):
        return None
    with open(TOTP_FILE) as f:
        enc = json.load(f)
    return decrypt(key, enc["nonce"], enc["ciphertext"])

def verify_totp(key: bytes, code: str) -> bool:
    """Verify a 6-digit TOTP code. valid_window=1 allows 30s clock drift."""
    secret = load_totp_secret(key)
    if not secret:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

def get_qr_base64(secret: str, account_name: str = "VaultX") -> str:
    """Generate QR code as a base64 image for display."""
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=account_name, issuer_name="VaultX")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

def totp_enabled() -> bool:
    return os.path.exists(TOTP_FILE)
