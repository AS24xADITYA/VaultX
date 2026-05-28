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
        """Create the necessary tables and handle migrations."""
        with sqlite3.connect(self.db_path) as conn:
            # Main passwords table
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
                    expiry_days          INTEGER DEFAULT 90,
                    created_at           TEXT    DEFAULT CURRENT_TIMESTAMP,
                    updated_at           TEXT    DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Feature 3: Password History table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS password_history (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_id            INTEGER NOT NULL,
                    password_ciphertext TEXT    NOT NULL,
                    password_nonce      TEXT    NOT NULL,
                    changed_at          TEXT    DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(entry_id) REFERENCES passwords(id) ON DELETE CASCADE
                )
            ''')

            # Feature 7: Secure Notes table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS secure_notes (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    title              TEXT    NOT NULL,
                    content_ciphertext TEXT    NOT NULL,
                    content_nonce      TEXT    NOT NULL,
                    category           TEXT    DEFAULT "General",
                    created_at         TEXT    DEFAULT CURRENT_TIMESTAMP,
                    updated_at         TEXT    DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Handle migration for existing DBs missing expiry_days
            try:
                conn.execute('ALTER TABLE passwords ADD COLUMN expiry_days INTEGER DEFAULT 90')
            except sqlite3.OperationalError:
                pass # Column already exists

    # ──────────────────────────────────────
    #  CRUD Operations
    # ──────────────────────────────────────

    def add_password(self, site, username, password, category='Other', notes='', expiry_days=90) -> int:
        enc_pw = encrypt(self.key, password)
        enc_notes = encrypt(self.key, notes) if notes else None

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                INSERT INTO passwords
                (site, username, password_ciphertext, password_nonce,
                 category, notes_ciphertext, notes_nonce, expiry_days)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                site, username,
                enc_pw['ciphertext'], enc_pw['nonce'],
                category,
                enc_notes['ciphertext'] if enc_notes else None,
                enc_notes['nonce'] if enc_notes else None,
                expiry_days
            ))
            return cursor.lastrowid

    def update_password(self, entry_id, site, username, password, category='Other', notes='', expiry_days=90):
        # Feature 3: Save current password to history before updating
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            old = conn.execute(
                'SELECT password_ciphertext, password_nonce FROM passwords WHERE id=?',
                (entry_id,)
            ).fetchone()
            
            if old:
                conn.execute('''
                    INSERT INTO password_history (entry_id, password_ciphertext, password_nonce)
                    VALUES (?, ?, ?)
                ''', (entry_id, old['password_ciphertext'], old['password_nonce']))
                
                # Keep only last 5 versions
                conn.execute('''
                    DELETE FROM password_history WHERE entry_id=? AND id NOT IN (
                        SELECT id FROM password_history WHERE entry_id=?
                        ORDER BY changed_at DESC LIMIT 5
                    )
                ''', (entry_id, entry_id))

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
                    expiry_days         = ?,
                    updated_at          = datetime("now")
                WHERE id = ?
            ''', (
                site, username,
                enc_pw['ciphertext'], enc_pw['nonce'],
                category,
                enc_notes['ciphertext'] if enc_notes else None,
                enc_notes['nonce'] if enc_notes else None,
                expiry_days,
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

    # Feature 3: Password History
    def get_password_history(self, entry_id) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                'SELECT password_ciphertext, password_nonce, changed_at '
                'FROM password_history WHERE entry_id=? ORDER BY changed_at DESC',
                (entry_id,)
            ).fetchall()
        
        history = []
        for r in rows:
            history.append({
                'password': decrypt(self.key, r['password_nonce'], r['password_ciphertext']),
                'changed_at': r['changed_at']
            })
        return history

    # Feature 7: Secure Notes
    def add_note(self, title, content, category='General') -> int:
        enc = encrypt(self.key, content)
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute('''
                INSERT INTO secure_notes (title, content_ciphertext, content_nonce, category)
                VALUES (?, ?, ?, ?)
            ''', (title, enc['ciphertext'], enc['nonce'], category))
            return cur.lastrowid

    def list_notes(self) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                'SELECT id, title, category, created_at, updated_at FROM secure_notes ORDER BY title'
            ).fetchall()
        return [dict(r) for r in rows]

    def get_note(self, note_id) -> dict | None:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute('SELECT * FROM secure_notes WHERE id=?', (note_id,)).fetchone()
        
        if not row: return None
        row = dict(row)
        row['content'] = decrypt(self.key, row['content_nonce'], row['content_ciphertext'])
        for k in ['content_ciphertext', 'content_nonce']: row.pop(k)
        return row

    def delete_note(self, note_id):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('DELETE FROM secure_notes WHERE id=?', (note_id,))

    # Feature 8: CSV Import
    def import_from_csv(self, csv_text: str) -> dict:
        import csv, io
        from urllib.parse import urlparse
        reader = csv.DictReader(io.StringIO(csv_text))
        imported = skipped = 0
        errors = []
        for i, row in enumerate(reader):
            try:
                site = (row.get("name") or row.get("url") or "").strip()
                user = (row.get("username") or "").strip()
                pw   = (row.get("password") or "").strip()
                if not site or not pw:
                    skipped += 1; continue
                if site.startswith("http"):
                    site = urlparse(site).netloc.replace("www.", "")
                self.add_password(site, user, pw, "Imported")
                imported += 1
            except Exception as e:
                errors.append(f"Row {i}: {e}")
        return {"imported": imported, "skipped": skipped, "errors": errors}
