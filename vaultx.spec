# vaultx.spec — PyInstaller build configuration
# Usage:  pyinstaller vaultx.spec
#
# Produces:
#   Windows : dist/VaultX.exe   (single file, no installer needed)
#   macOS   : dist/VaultX.app   (drag-to-Applications bundle)
#   Linux   : dist/VaultX       (single ELF binary)

import sys
from PyInstaller.building.build_main import Analysis, PYZ, EXE, BUNDLE, COLLECT

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.QtWidgets',
        'cryptography.hazmat.primitives.kdf.pbkdf2',
        'cryptography.hazmat.primitives.ciphers.aead',
        'cryptography.hazmat.backends.openssl',
        'bcrypt',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=['flask', 'jinja2', 'werkzeug', 'requests'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='VaultX',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # No terminal window on Windows
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# macOS .app bundle
if sys.platform == 'darwin':
    app = BUNDLE(
        exe,
        name='VaultX.app',
        icon=None,
        bundle_identifier='com.vaultx.desktop',
        info_plist={
            'NSHighResolutionCapable': True,
            'CFBundleShortVersionString': '2.0.0',
        }
    )
