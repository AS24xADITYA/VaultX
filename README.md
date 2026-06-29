# VaultX — Secure Offline Password Manager

VaultX is a highly secure, offline-first password manager built with Python, PyQt6, and cryptography. It prioritizes extreme data privacy, robust local encryption, and an intuitive user interface, ensuring your most sensitive credentials never leave your local machine without your explicit consent.

## 🚀 Key Features

### Advanced Security
*   **AES-256-GCM Encryption**: All passwords and secure notes are encrypted at rest using military-grade AES-256-GCM.
*   **Zero-Knowledge Architecture**: Your master password is never stored. Keys are derived using Argon2.
*   **Vault Canary (Tamper Protection)**: Uses HMAC-SHA256 to cryptographically verify the integrity of the SQLite vault, alerting you if the database file was tampered with externally.
*   **Secure Memory Wiping**: Uses low-level `ctypes` to actively scrub decrypted sensitive data (like the AES key) from RAM when the vault is locked.
*   **Steganographic Backups**: Hide your encrypted SQLite database inside the pixels of a standard PNG image using LSB (Least Significant Bit) steganography to securely backup your vault in plain sight.
*   **Panic Lock (`Ctrl+Shift+L`)**: A global shortcut that instantly wipes the clipboard, clears the AES key from memory, and locks the application.

### Intelligent & Visual UX
*   **Password DNA Fingerprints**: Generates deterministic, colorful 8x8 Identicon pixel-art based on the SHA-256 hash of your passwords, allowing visual verification of passwords without revealing them.
*   **Smart Auto-Categorization**: Automatically sorts imported or newly added credentials into logical categories (e.g., *Banking*, *Social*, *Work*) based on a domain matching engine.
*   **Entropy Heatmap & Health Audit**: Features a beautiful Matplotlib-rendered heatmap of your password character distribution to identify keyboard-walk vulnerabilities, alongside a comprehensive password health timeline.
*   **Animated Splash & Transitions**: Smooth UI fading transitions using `QPropertyAnimation` for a premium, native feel.

## 📦 Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/VaultX.git
    cd VaultX/vaultx_desktop
    ```

2.  **Set up a virtual environment (Recommended):**
    ```bash
    python -m venv venv
    
    # On Windows:
    venv\Scripts\activate
    # On macOS/Linux:
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the application:**
    ```bash
    python src/main.py
    ```

## 🛠 Tech Stack

*   **GUI Framework**: PyQt6
*   **Database**: SQLite3
*   **Cryptography**: `cryptography` (AES-GCM, HMAC), `argon2-cffi`
*   **Data Visualization**: `matplotlib`, `Pillow` (for Password DNA and Steganography)
*   **API Server**: `Flask`, `Flask-CORS` (for optional browser extension integrations)

## ⚠️ Important Note

VaultX is designed to be **offline**. If you lose your master password, your vault cannot be recovered. Keep your master password safe, and consider utilizing the Steganographic Backup feature to securely store an encrypted copy of your vault.

---
*Built with security and privacy in mind.*
