# VaultX Desktop 🔐

**Native password manager — no browser, no server, no internet required.**

Built with PyQt6. Same AES-256-GCM + bcrypt + PBKDF2 cryptographic core as
the web version. Packages into a single executable with PyInstaller.

---

## Run from source

```bash
pip install -r requirements.txt
python main.py
```

Data is stored in `~/.vaultx/` (your home directory):
- `vault.db`        — AES-256-GCM encrypted SQLite database
- `kdf_salt.bin`    — PBKDF2 salt
- `master.json`     — bcrypt hash of master password

---

## Build standalone executable

### Windows → VaultX.exe
```bash
pip install pyinstaller
pyinstaller vaultx.spec
# Output: dist/VaultX.exe   (~35 MB, no install needed)
```

### macOS → VaultX.app
```bash
pip install pyinstaller
pyinstaller vaultx.spec
# Output: dist/VaultX.app   (drag to Applications)
```

### Linux → VaultX binary
```bash
pip install pyinstaller
pyinstaller vaultx.spec
# Output: dist/VaultX
```

---

## Features

| Feature | Status |
|---------|--------|
| AES-256-GCM encryption | ✅ |
| bcrypt master password (cost 12) | ✅ |
| PBKDF2 key derivation (200K iter) | ✅ |
| IP rate limiting (5 attempts → 5 min lockout) | ✅ |
| Health audit (weak / reused / old) | ✅ |
| Password generator (cryptographically secure) | ✅ |
| Real-time strength meter | ✅ |
| HaveIBeenPwned breach check (k-anonymity) | ✅ |
| Clipboard auto-clear after 30s | ✅ |
| Dark theme native UI | ✅ |
| **No browser required** | ✅ |
| **No Flask / web server** | ✅ |
| **No internet connection needed** | ✅ |

---

## Architecture

```
main.py  (PyQt6 GUI — replaces Flask + HTML templates)
├── SetupWindow      — first-run master password
├── LoginWindow      — bcrypt authentication
└── VaultWindow      — main vault
      ├── PasswordTable   — CRUD entries
      ├── HealthPanel     — audit engine
      ├── EntryDialog     — add/edit with strength meter
      └── GeneratorDialog — password generator

Backend (unchanged from web version):
  crypto.py   — AES-256-GCM + PBKDF2
  vault.py    — SQLite CRUD
  auth.py     — bcrypt
  utils.py    — generator + strength + HIBP
  health.py   — audit engine
```

The UI is a clean adapter layer. The entire cryptographic backend is
reused unchanged — proving that separation of concerns allows the same
secure core to power both a web app and a native desktop app.

---

## Author
Aditya Sunil Shinde | VIT Pune | AIML-A | 2025-26
