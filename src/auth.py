"""
auth.py — Master Password Authentication

Uses bcrypt with cost factor 12 (intentionally slow).
bcrypt hashes take ~100ms each → attacker can only try ~10 guesses/sec.
SHA-256 would allow ~10 BILLION guesses/sec — completely insecure for passwords.

The stored hash looks like: $2b$12$<22-char salt><31-char hash>
The raw password is NEVER stored anywhere.
"""

import bcrypt
import json
import os

AUTH_FILE = 'master.json'


def master_password_exists() -> bool:
    """Check if a master password has been set up."""
    return os.path.exists(AUTH_FILE)


def set_master_password(password: str) -> None:
    """
    Hash the master password using bcrypt and save it.
    
    bcrypt.gensalt(rounds=12) creates a random 128-bit salt.
    rounds=12 means 2^12 = 4096 internal iterations (computationally expensive).
    The salt is embedded inside the hash string automatically.
    """
    salt   = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

    with open(AUTH_FILE, 'w') as f:
        json.dump({'hash': hashed.decode('utf-8')}, f)


def verify_master_password(password: str) -> bool:
    """
    Verify a password attempt against the stored bcrypt hash.
    
    bcrypt.checkpw() re-hashes the attempt using the salt embedded in the stored hash
    and compares. It uses constant-time comparison to prevent timing attacks.
    """
    if not master_password_exists():
        return False

    with open(AUTH_FILE, 'r') as f:
        data = json.load(f)

    stored_hash = data['hash'].encode('utf-8')
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)


def change_master_password(old_password: str, new_password: str) -> bool:
    """Verify old password, then set new one."""
    if not verify_master_password(old_password):
        return False
    set_master_password(new_password)
    return True
