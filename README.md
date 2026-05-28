# 🔐 VaultX — Secure Desktop Password Manager

VaultX is a premium, offline-first password manager built with **PyQt6** and **Argon2id** encryption. It provides a robust, visually stunning interface to manage your digital life with zero compromise on security.

## ✨ Premium Features

1.  **🛡️ Military-Grade Encryption:** Uses AES-256-GCM with Argon2id key derivation (OWASP 2024 recommended).
2.  **📱 Two-Factor Authentication (TOTP):** Built-in support for Google Authenticator / Authy.
3.  **🌓 Dynamic Themes:** Toggle between beautifully crafted **Dark Mode** and **Light Mode** interfaces.
4.  **🕵️ Fuzzy Search:** Advanced search that handles typos using Levenshtein distance.
5.  **⏳ Auto-Lock:** Automatically locks the vault after 5 minutes of inactivity.
6.  **📋 Password History:** Keeps track of previous passwords so you never lose access.
7.  **📊 Health Audit:** Analyzes your vault for weak, reused, or old passwords with a visual security score.
8.  **🌐 Browser Extension:** Auto-fill support for Chrome via local secure API.
9.  **📝 Secure Notes:** Modern card-based encrypted section for recovery codes and private text.
10. **📁 CSV Import:** Bulk import from Chrome, Firefox, or other managers.
11. **📅 Expiry Reminders:** Proactive rotation alerts for aging credentials.

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- `pip install -r requirements.txt`

### Running the App
```bash
python src/main.py
```

### Building the Windows App
```bash
pyinstaller --windowed --onefile --name VaultX_Secure --icon assets/logo.ico src/main.py
```

## 📂 Project Structure
- `src/`: Core Python source code.
- `extension/`: Chrome Browser Extension for Auto-fill.
- `website/`: Product landing page.
- `assets/`: Icons and static images.

## 🔒 Security Architecture
- **Zero-Knowledge:** Your master password and vault data never leave your computer.
- **Argon2id:** Hardened against GPU brute-force attacks.
- **AES-256-GCM:** Ensures both data privacy and integrity (tamper-evident).
- **k-Anonymity:** Breach checks use the HIBP API without ever sending your actual password or full hash.

---
Created by Aditya Sunil Shinde | VIT Pune
