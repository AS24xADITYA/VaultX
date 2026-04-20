"""
vault.py — Encrypted Password Storage (SQLite)

Why SQLite over a plain JSON file?
- Real database: supports queries, indexing, sorting
- Atomic writes: no data corruption if app crashes mid-save
- Scalable: handles thousands of entries efficiently
- Industry standard: SQLite is used in Firefox, Chrome, iOS, Android

All passwords and notes are encrypted BEFORE being stored.
The database only contains ciphertext — even if stolen, it's unreadable.
"""

import sqlite3
from datetime import datetime
from crypto import encrypt, decrypt


class Vault:
    def __init__(self, db_path: str, key: bytes):
        self.db_path = db_path
        self.key = key
        self._init_db()

    def _init_db(self):
        """Create the passwords table if it doesn't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                    site                 TEXT    NOT NULL,
                    username             TEXT,
                    password_ciphertext  TEXT    NOT NULL,
                    password_nonce       TEXT    NOT NULL,
                    category             TEXT    DEFAULT "Other",
                    notes_ciphertext     TEXT,
                    notes_nonce          TEXT,
                    created_at  TEXT  DEFAULT CURRENT_TIMESTAMP,
                    updated_at  TEXT  DEFAULT CURRENT_TIMESTAMP
                )
            ''')

    # ──────────────────────────────────────
    #  CRUD Operations
    # ──────────────────────────────────────

    def add_password(self, site, username, password, category='Other', notes='') -> int:
        enc_pw = encrypt(self.key, password)
        enc_notes = encrypt(self.key, notes) if notes else None

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                INSERT INTO passwords
                (site, username, password_ciphertext, password_nonce,
                 category, notes_ciphertext, notes_nonce)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                site, username,
                enc_pw['ciphertext'], enc_pw['nonce'],
                category,
                enc_notes['ciphertext'] if enc_notes else None,
                enc_notes['nonce'] if enc_notes else None
            ))
            return cursor.lastrowid

    def update_password(self, entry_id, site, username, password, category='Other', notes=''):
        enc_pw = encrypt(self.key, password)
        enc_notes = encrypt(self.key, notes) if notes else None

        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                UPDATE passwords SET
                    site                = ?,
                    username            = ?,
                    password_ciphertext = ?,
                    password_nonce      = ?,
                    category            = ?,
                    notes_ciphertext    = ?,
                    notes_nonce         = ?,
                    updated_at          = datetime("now")
                WHERE id = ?
            ''', (
                site, username,
                enc_pw['ciphertext'], enc_pw['nonce'],
                category,
                enc_notes['ciphertext'] if enc_notes else None,
                enc_notes['nonce'] if enc_notes else None,
                entry_id
            ))

    def delete_password(self, entry_id):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('DELETE FROM passwords WHERE id = ?', (entry_id,))

    def get_full_entry(self, entry_id) -> dict | None:
        """Return decrypted entry (used when user clicks Edit or Show)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                'SELECT * FROM passwords WHERE id = ?', (entry_id,)
            ).fetchone()

        if not row:
            return None

        row = dict(row)
        row['password'] = decrypt(
            self.key, row['password_nonce'], row['password_ciphertext'])
        row['notes'] = (
            decrypt(self.key, row['notes_nonce'], row['notes_ciphertext'])
            if row.get('notes_ciphertext') else ''
        )
        # Remove raw ciphertext from response
        for k in ['password_ciphertext', 'password_nonce', 'notes_ciphertext', 'notes_nonce']:
            row.pop(k, None)
        return row

    def list_all(self) -> list[dict]:
        """Return all entries (metadata only — no passwords)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                'SELECT id, site, username, category, created_at, updated_at '
                'FROM passwords ORDER BY site COLLATE NOCASE'
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute(
                'SELECT COUNT(*) FROM passwords').fetchone()[0]
            cats = dict(conn.execute(
                'SELECT category, COUNT(*) FROM passwords GROUP BY category'
            ).fetchall())
        return {'total': total, 'categories': cats}

    def export_encrypted(self) -> dict:
        """Export the raw (still-encrypted) vault rows for backup."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute('SELECT * FROM passwords').fetchall()
        return {
            'app': 'VaultX',
            'exported_at': str(datetime.now()),
            'note': 'Entries are AES-256-GCM encrypted. KDF salt required to decrypt.',
            'entries': [dict(r) for r in rows]
        }
