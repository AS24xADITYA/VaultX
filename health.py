"""
health.py — Password Health Audit Engine

Analyses the entire vault and surfaces three categories of risk:

  1. Weak passwords      — strength score < 4/7 (Very Weak / Weak / Fair)
  2. Reused passwords    — identical plaintext shared across multiple sites
  3. Old passwords       — not updated in > 90 days

This module operates entirely in-memory; it decrypts passwords just long
enough to compute hashes for duplicate detection and strength scores.
Plaintexts are cleared from local variables before the function returns.
"""

import hashlib
from datetime import datetime, timezone
from crypto import decrypt
from utils import check_strength
import sqlite3

MAX_AGE_DAYS   = 90     # Flag passwords older than this many days
WEAK_THRESHOLD = 50     # Flag passwords with strength percent below this


def _days_since(date_str: str) -> int:
    """Return number of days since an ISO-format datetime string."""
    try:
        dt = datetime.fromisoformat(date_str)
        # Make both datetimes timezone-naive for comparison
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return (datetime.now() - dt).days
    except Exception:
        return 0


def audit_vault(db_path: str, key: bytes) -> dict:
    """
    Decrypt all vault entries and compute health metrics.

    Returns a dict with:
        total          — total entries
        weak           — list of {id, site, username, strength_label, strength_percent}
        reused         — list of groups: [{hash_prefix, sites: [{id, site, username}]}]
        old            — list of {id, site, username, days_old}
        score          — overall health score 0–100
        weak_count     — int
        reused_count   — int (number of entries that share a password)
        old_count      — int
    """
    weak_entries   = []
    old_entries    = []
    hash_map: dict = {}   # sha256_prefix → list of {id, site, username}

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            'SELECT id, site, username, password_ciphertext, password_nonce, updated_at '
            'FROM passwords'
        ).fetchall()

    total = len(rows)

    for row in rows:
        try:
            plaintext = decrypt(key, row['password_nonce'], row['password_ciphertext'])
        except Exception:
            continue  # Skip tampered / unreadable entries

        # ── Strength check ─────────────────────────────────────────────
        strength = check_strength(plaintext)
        if strength['percent'] < WEAK_THRESHOLD:
            weak_entries.append({
                'id'              : row['id'],
                'site'            : row['site'],
                'username'        : row['username'] or '',
                'strength_label'  : strength['label'],
                'strength_percent': strength['percent'],
                'strength_color'  : strength['color'],
            })

        # ── Reuse check (hash fingerprint, never store plaintext) ───────
        # Use first 16 hex chars of SHA-256 as a bucket key
        # (collision probability negligible for < 10 000 entries)
        pw_hash = hashlib.sha256(plaintext.encode('utf-8')).hexdigest()
        prefix  = pw_hash[:16]   # Not the full hash — avoids rainbow-table creation
        if prefix not in hash_map:
            hash_map[prefix] = []
        hash_map[prefix].append({
            'id'      : row['id'],
            'site'    : row['site'],
            'username': row['username'] or '',
        })

        # ── Age check ──────────────────────────────────────────────────
        days = _days_since(row['updated_at'])
        if days >= MAX_AGE_DAYS:
            old_entries.append({
                'id'      : row['id'],
                'site'    : row['site'],
                'username': row['username'] or '',
                'days_old': days,
            })

        # Clear plaintext from memory
        plaintext = None

    # Build reuse groups (only groups with > 1 entry)
    reused_groups = [
        {'sites': entries}
        for entries in hash_map.values()
        if len(entries) > 1
    ]
    reused_count = sum(len(g['sites']) for g in reused_groups)

    # ── Health score ────────────────────────────────────────────────────
    # Perfect vault = 100; deduct proportionally for each issue
    if total == 0:
        score = 100
    else:
        penalty = (
            (len(weak_entries) / total) * 40 +
            (reused_count      / total) * 35 +
            (len(old_entries)  / total) * 25
        )
        score = max(0, round(100 - penalty))

    if score >= 85:
        score_label, score_color = 'Excellent', '#00e676'
    elif score >= 65:
        score_label, score_color = 'Good',      '#4f9eff'
    elif score >= 45:
        score_label, score_color = 'Fair',      '#ffd32a'
    else:
        score_label, score_color = 'Poor',      '#ff4757'

    return {
        'total'        : total,
        'weak'         : weak_entries,
        'reused'       : reused_groups,
        'old'          : old_entries,
        'score'        : score,
        'score_label'  : score_label,
        'score_color'  : score_color,
        'weak_count'   : len(weak_entries),
        'reused_count' : reused_count,
        'old_count'    : len(old_entries),
    }
