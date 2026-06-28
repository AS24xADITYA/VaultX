import hmac
import hashlib
import json
import os
from src.crypto import encrypt, decrypt

CANARY_FILE = 'canary.json'

def compute_canary(vault_key: bytes, db_path: str = 'vault.db') -> str:
    """Compute HMAC-SHA256 of entire db file. Key = derived AES key."""
    if not os.path.exists(db_path):
        return hmac.new(vault_key, b'', hashlib.sha256).hexdigest()
    with open(db_path, 'rb') as f:
        data = f.read()
    return hmac.new(vault_key, data, hashlib.sha256).hexdigest()

def save_canary(vault_key: bytes, db_path: str = 'vault.db') -> None:
    """Encrypt and save the current canary hash to canary.json."""
    canary_hex = compute_canary(vault_key, db_path)
    enc = encrypt(vault_key, canary_hex)
    with open(CANARY_FILE, 'w') as f:
        json.dump(enc, f)

def verify_canary(vault_key: bytes, db_path: str = 'vault.db') -> dict:
    """
    Returns:
        {'status': 'ok'}                          — no tampering
        {'status': 'no_canary'}                   — first login, canary not yet set
        {'status': 'tampered', 'details': str}    — mismatch detected
    """
    if not os.path.exists(CANARY_FILE):
        return {'status': 'no_canary'}
    try:
        with open(CANARY_FILE) as f:
            enc = json.load(f)
        stored_canary = decrypt(vault_key, enc['nonce'], enc['ciphertext'])
    except Exception:
        return {'status': 'tampered', 'details': 'Canary file decryption failed or corrupted.'}
        
    current_canary = compute_canary(vault_key, db_path)
    if hmac.compare_digest(stored_canary, current_canary):
        return {'status': 'ok'}
    return {
        'status': 'tampered',
        'details': f'Stored: {stored_canary[:16]}... | Current: {current_canary[:16]}...'
    }
