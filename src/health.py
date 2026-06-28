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
            'SELECT id, site, username, password_ciphertext, password_nonce, updated_at, expiry_days '
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
        expiry = row['expiry_days'] if row['expiry_days'] is not None else MAX_AGE_DAYS
        if days >= expiry:
            old_entries.append({
                'id'      : row['id'],
                'site'    : row['site'],
                'username': row['username'] or '',
                'days_old': days,
                'expiry'  : expiry
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

def generate_entropy_heatmap_data(db_path: str, vault_key: bytes) -> dict:
    """
    Decrypt all passwords and compute per-character frequency.
    Returns a dict of {character: frequency_count} for heatmap rendering.
    Also detects keyboard walk patterns.
    """
    all_chars = {}
    keyboard_walks = []
    WALK_PATTERNS = ['qwerty', 'asdfgh', 'zxcvbn', '123456', 'qazwsx', 'poiuyt']

    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("SELECT password_ciphertext, password_nonce FROM passwords").fetchall()

    for row in rows:
        pw = decrypt(vault_key, row[1], row[0]).lower()
        for ch in pw:
            if ch.isprintable():
                all_chars[ch] = all_chars.get(ch, 0) + 1
        for pattern in WALK_PATTERNS:
            if pattern in pw:
                keyboard_walks.append(pattern)

    return {
        'char_freq'      : all_chars,
        'keyboard_walks' : keyboard_walks,
        'total_passwords': len(rows)
    }

def record_health_snapshot(vault_instance, score: int, total: int, weak: int, reused: int):
    with sqlite3.connect(vault_instance.db_path) as conn:
        conn.execute(
            "INSERT INTO health_timeline (score, total, weak_count, reused_count) VALUES (?,?,?,?)",
            (score, total, weak, reused)
        )

def get_health_timeline(vault_instance) -> list[dict]:
    with sqlite3.connect(vault_instance.db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT score, total, weak_count, reused_count, recorded_at "
            "FROM health_timeline ORDER BY recorded_at ASC LIMIT 90"
        ).fetchall()
    return [dict(r) for r in rows]

# Matplotlib keyboard heatmap
def render_heatmap_png(char_freq: dict) -> bytes:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import io

    KEYBOARD_ROWS = [
        list('1234567890'),
        list('qwertyuiop'),
        list('asdfghjkl'),
        list('zxcvbnm')
    ]

    fig, ax = plt.subplots(figsize=(8, 3))
    ax.set_xlim(0, 10); ax.set_ylim(0, 4); ax.axis('off')
    fig.patch.set_facecolor('#0D1422')
    max_freq = max(char_freq.values()) if char_freq else 1
    
    for row_i, row in enumerate(KEYBOARD_ROWS):
        for col_i, key in enumerate(row):
            freq = char_freq.get(key, 0)
            heat = freq / max_freq  # 0.0 → 1.0
            color = plt.cm.RdYlGn_r(heat)  # green=low, red=high
            rect = mpatches.FancyBboxPatch(
                (col_i * 0.95 + row_i * 0.2, 3 - row_i * 0.85),
                0.88, 0.75, boxstyle="round,pad=0.05",
                ec='#2A3A5A', fc=color, lw=0.5
            )
            ax.add_patch(rect)
            ax.text(col_i * 0.95 + row_i * 0.2 + 0.44,
                    3 - row_i * 0.85 + 0.37,
                    key.upper(), ha='center', va='center',
                    fontsize=7, color='white', fontweight='bold')
    
    buf = io.BytesIO()
    plt.savefig(buf, format='PNG', dpi=150, bbox_inches='tight', facecolor='#0D1422')
    plt.close()
    return buf.getvalue()
