"""
utils.py — Password Generator, Strength Checker, Breach Checker

Password Generator:
  Uses Python's `secrets` module (NOT `random`).
  `random` uses a Mersenne Twister — seeded by time, predictable.
  `secrets` reads from the OS's hardware entropy source (/dev/urandom on Linux,
  CryptGenRandom on Windows) — truly unpredictable.

Breach Checker:
  Uses the HaveIBeenPwned (HIBP) k-Anonymity API.
  k-Anonymity: Only the first 5 characters of the password's SHA-1 hash are sent.
  The full password or full hash NEVER leaves your machine.
  This is the same API used by Firefox Monitor and 1Password.
"""

import secrets
import string
import hashlib
import urllib.request


# ─────────────────────────────────────────
#  Password Generator
# ─────────────────────────────────────────

_SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?'


def generate_password(
    length: int = 16,
    use_symbols: bool = True,
    use_numbers: bool = True,
    use_upper: bool = True
) -> str:
    """
    Generate a cryptographically secure random password.
    Guarantees at least one character from each enabled character class.
    """
    pool = string.ascii_lowercase

    # Build character pool
    guaranteed = [secrets.choice(string.ascii_lowercase)]
    if use_upper:
        pool += string.ascii_uppercase
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if use_numbers:
        pool += string.digits
        guaranteed.append(secrets.choice(string.digits))
    if use_symbols:
        pool += _SYMBOLS
        guaranteed.append(secrets.choice(_SYMBOLS))

    # Fill remaining length
    remaining = length - len(guaranteed)
    password  = guaranteed + [secrets.choice(pool) for _ in range(max(0, remaining))]

    # Shuffle to avoid predictable position patterns
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)


# ─────────────────────────────────────────
#  Strength Checker
# ─────────────────────────────────────────

def check_strength(password: str) -> dict:
    """
    Score a password on 7 criteria and return a strength rating.
    Returns: score (0-7), percent (0-100), label, color, feedback list.
    """
    score    = 0
    feedback = []
    n        = len(password)

    # Length scoring
    if n >= 8:
        score += 1
    else:
        feedback.append('Use at least 8 characters')
    if n >= 12:
        score += 1
    if n >= 16:
        score += 1

    # Character variety
    has_upper  = any(c.isupper() for c in password)
    has_lower  = any(c.islower() for c in password)
    has_digit  = any(c.isdigit() for c in password)
    has_symbol = any(c in _SYMBOLS for c in password)

    if has_upper:
        score += 1
    else:
        feedback.append('Add uppercase letters')
    if has_lower:
        score += 1
    else:
        feedback.append('Add lowercase letters')
    if has_digit:
        score += 1
    else:
        feedback.append('Add numbers (0-9)')
    if has_symbol:
        score += 1
    else:
        feedback.append('Add special characters (!@#$...)')

    percent = round((score / 7) * 100)

    if percent < 30:
        label, color = 'Very Weak',    '#ff4757'
    elif percent < 50:
        label, color = 'Weak',         '#ff6b35'
    elif percent < 65:
        label, color = 'Fair',         '#ffd32a'
    elif percent < 85:
        label, color = 'Strong',       '#4f9eff'
    else:
        label, color = 'Very Strong',  '#00e676'

    return {
        'score'   : score,
        'percent' : percent,
        'label'   : label,
        'color'   : color,
        'feedback': feedback
    }


# ─────────────────────────────────────────
#  HaveIBeenPwned Breach Check
# ─────────────────────────────────────────

def check_breach(password: str) -> int:
    """
    Check if a password appears in known data breach databases.

    Uses k-Anonymity: only first 5 hex chars of SHA-1 are sent to the API.
    The API returns all ~500 matching suffixes; we check locally.
    The plaintext password NEVER leaves this machine.

    Returns:
        -1  → could not connect to HIBP API
         0  → password not found in any breach (safe)
        >0  → number of times this password appeared in breaches
    """
    try:
        sha1   = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'VaultX-Password-Manager-v1.0'}
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            lines = resp.read().decode('utf-8').splitlines()

        for line in lines:
            h, count = line.split(':')
            if h == suffix:
                return int(count)
        return 0

    except Exception:
        return -1   # Network unavailable or API down
