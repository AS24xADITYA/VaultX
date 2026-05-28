"""
VaultX Desktop — Native Password Manager
PyQt6 GUI — No browser, no Flask, no server required.

Architecture:
  main.py  ←  QApplication entry point
    ├── SetupWindow     — first-run master password creation
    ├── LoginWindow     — authentication screen
    └── VaultWindow     — main vault (passwords + health audit)
          ├── SideBar         — category filter + stats
          ├── PasswordTable   — searchable entry list
          ├── HealthPanel     — weak/reused/old analysis
          ├── EntryDialog     — add/edit credential
          └── GeneratorDialog — password generator

All crypto: crypto.py / vault.py / auth.py / utils.py / health.py
(identical to web version — UI is the only thing that changed)

Author : Aditya Sunil Shinde | VIT Pune | AIML-A | 2025-26
"""

import sys
import os
import time
import threading
import base64
from pathlib import Path
from datetime import datetime

# ── locate data directory ─────────────────────────────────────────────────────
# On macOS/Windows packaged builds, store data in user home; dev = cwd
DATA_DIR = Path(os.environ.get("VAULTX_DATA", Path.home() / ".vaultx"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE  = str(DATA_DIR / "vault.db")
SALT_FILE = str(DATA_DIR / "kdf_salt.bin")
AUTH_FILE = str(DATA_DIR / "master.json")

# Patch module-level paths so backend modules use DATA_DIR
import crypto as _crypto
import auth   as _auth
_crypto.SALT_FILE = SALT_FILE
_auth.AUTH_FILE   = AUTH_FILE

from auth   import set_master_password, verify_master_password, master_password_exists
from crypto import derive_key
from vault  import Vault
from utils  import generate_password, check_strength, check_breach
from health import audit_vault
from totp   import (
    generate_totp_secret, save_totp_secret, load_totp_secret, 
    verify_totp, get_qr_base64, totp_enabled
)
from api_server import start_api, stop_api
from rapidfuzz import fuzz

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QStackedWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QDialog, QDialogButtonBox, QMessageBox, QSlider,
    QCheckBox, QFrame, QSplitter, QScrollArea,
    QProgressBar, QSizePolicy, QAbstractItemView, QFileDialog, QInputDialog
)
from PyQt6.QtCore  import Qt, QThread, pyqtSignal, QTimer, QSize, QSettings, QObject, QEvent, QRect, QRectF, pyqtProperty, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui   import QFont, QColor, QPalette, QIcon, QPixmap, QClipboard, QPainter, QBrush, QPen
from cryptography.exceptions import InvalidTag

# ── Feature 2: Auto-Lock ─────────────────────────────────────────────────────
class InactivityFilter(QObject):
    timeout = pyqtSignal()
    def __init__(self, interval_ms):
        super().__init__()
        self.timer = QTimer()
        self.timer.setInterval(interval_ms)
        self.timer.timeout.connect(self.timeout.emit)
        self.timer.start()

    def eventFilter(self, obj, event):
        if event.type() in (QEvent.Type.MouseMove, QEvent.Type.MouseButtonPress, 
                           QEvent.Type.KeyPress, QEvent.Type.Wheel):
            self.timer.start()
        return super().eventFilter(obj, event)

# ── Feature: Animated Switch ──────────────────────────────────────────────────
class AnimatedSwitch(QWidget):
    toggled = pyqtSignal(bool)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(50, 26)
        self._checked = False
        self._thumb_pos = 3
        self.animation = QPropertyAnimation(self, b"thumb_pos")
        self.animation.setDuration(200)
        self.animation.setEasingCurve(QEasingCurve.Type.InOutQuad)

    @pyqtProperty(float)
    def thumb_pos(self): return self._thumb_pos
    @thumb_pos.setter
    def thumb_pos(self, pos):
        self._thumb_pos = pos
        self.update()

    def setChecked(self, checked):
        if self._checked == checked: return
        self._checked = checked
        self.animation.stop()
        self.animation.setEndValue(27 if checked else 3)
        self.animation.start()
        self.update()

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.setChecked(not self._checked)
            self.toggled.emit(self._checked)

    def paintEvent(self, e):
        p = QPainter(self); p.setRenderHint(QPainter.RenderHint.Antialiasing)
        # Track
        bg = QColor("#3b82f6" if self._checked else "#374151")
        p.setBrush(QBrush(bg)); p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(0, 0, self.width(), self.height(), 13, 13)
        # Thumb
        p.setBrush(QBrush(QColor("#ffffff")))
        p.drawEllipse(QRectF(self._thumb_pos, 3, 20, 20))

# ─────────────────────────────────────────────────────────────────────────────
#  THEMES
# ─────────────────────────────────────────────────────────────────────────────
COMMON_CSS = """
QWidget {
    font-family: 'Segoe UI', 'SF Pro Display', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
}
#sidebarBrand {
    font-size: 24px; font-weight: 800;
    padding: 36px 24px 24px;
    letter-spacing: -0.05em;
    color: #3b82f6;
}
#catBtn {
    background: transparent; border: none;
    text-align: left; padding: 8px 24px;
    border-radius: 12px; font-weight: 600;
    margin: 2px 14px;
    min-height: 56px;
}
#sidebarAction {
    background: transparent; border: none;
    text-align: left; padding: 8px 24px;
    font-size: 12px; font-weight: 600;
    margin: 1px 12px;
    min-height: 48px;
}
#btnPrimary {
    background: #2563eb; color: #ffffff;
    border: none; border-radius: 12px;
    padding: 0 24px; font-weight: 700;
    min-height: 46px;
}
#btnSecondary {
    border-radius: 12px; padding: 0 24px; font-weight: 600;
    min-height: 46px;
}
#btnIcon {
    border-radius: 10px; padding: 0;
    font-size: 18px; min-width: 42px; min-height: 42px;
}
#searchBar {
    border-radius: 14px; padding: 0 20px;
    font-size: 14px; min-height: 46px;
}
QTableWidget { border: none; gridline-color: transparent; outline: 0; }
QTableWidget::item { padding: 4px 16px; border-bottom: 1px solid transparent; }
QHeaderView::section {
    border: none; padding: 16px; font-size: 11px;
    font-weight: 800; text-transform: uppercase; letter-spacing: 0.12em;
}
#sidebarScroll { background: transparent; }
#sidebarContent { background: transparent; }
QLineEdit, QTextEdit, QComboBox {
    border-radius: 10px; padding: 8px 16px;
    min-height: 36px;
}
QProgressBar { border: none; border-radius: 5px; height: 10px; }
QProgressBar::chunk { border-radius: 5px; }
QSlider::groove:horizontal { height: 6px; border-radius: 3px; }
QSlider::handle:horizontal {
    width: 20px; height: 20px; border-radius: 10px; margin: -7px 0;
}
#authCard { border-radius: 24px; padding: 56px; }
#authTitle { font-size: 28px; font-weight: 800; letter-spacing: -0.04em; }
#card { border-radius: 14px; padding: 22px; }
#scoreNum { font-size: 48px; font-weight: 900; }
"""

DARK = COMMON_CSS + """
QWidget { background-color: #040508; color: #e5e7eb; }
QMainWindow, QDialog { background-color: #040508; }

#sidebar { background-color: #0a0c14; border-right: 1px solid #1a1d2e; }
#sidebarBrand { color: #3b82f6; }
#catBtn { color: #9ca3af; }
#catBtn:hover { background: #1a1d2e; color: #ffffff; }
#catBtn[active="true"] { background: #1a1d2e; color: #3b82f6; }
#sidebarAction { color: #6b7280; }
#sidebarAction:hover { background: #1a1d2e; color: #9ca3af; }
#sidebarDanger { color: #ef4444 !important; }

#mainPanel { background: #040508; }
#toolbar { background: #0a0c14; border-bottom: 1px solid #1a1d2e; }
#searchBar { background: #0f1222; border: 1px solid #1a1d2e; color: #ffffff; }
#searchBar:focus { border-color: #3b82f6; background: #14182c; }

#btnPrimary { background: #2563eb; color: #ffffff; }
#btnPrimary:hover { background: #3b82f6; }
#btnSecondary { background: #14182c; color: #9ca3af; border: 1px solid #1a1d2e; }
#btnSecondary:hover { background: #1a223e; color: #ffffff; border-color: #3b82f6; }
#btnIcon { background: #0f1222; border: 1px solid #1a1d2e; color: #9ca3af; }
#btnIcon:hover { background: #1a1e2e; border-color: #3b82f6; color: #ffffff; }

QTableWidget { background: #040508; selection-background-color: #14182c; selection-color: #ffffff; }
QTableWidget::item { border-bottom: 1px solid #0f1222; }
QHeaderView::section { background: #0a0c14; color: #4b5563; border-bottom: 1px solid #1a1d2e; }

QLineEdit, QTextEdit, QComboBox { background: #0f1222; border: 1px solid #1a1d2e; color: #ffffff; }
QLineEdit:focus, QTextEdit:focus, QComboBox:focus { border-color: #3b82f6; background: #14182c; }

QProgressBar { background: #1a1d2e; }
QSlider::groove:horizontal { background: #1a1e2e; }
QSlider::handle:horizontal { background: #3b82f6; }

#labelMuted { color: #6b7280; }
#labelAccent { color: #3b82f6; }
#card { background: #0a0c14; border: 1px solid #1a1d2e; }
#authCard { background: #0a0c14; border: 1px solid #1a1d2e; }
#revealBar { background: #0a0c14; border-top: 1px solid #1a1d2e; }
#statusBar { background: #0a0c14; border-top: 1px solid #1a1d2e; color: #6b7280; }
"""

LIGHT = COMMON_CSS + """
QWidget { background-color: #f9fafb; color: #111827; }
QMainWindow, QDialog { background-color: #f9fafb; }

#sidebar { background-color: #ffffff; border-right: 1px solid #e5e7eb; }
#sidebarBrand { color: #2563eb; }
#catBtn { color: #6b7280; }
#catBtn:hover { background: #eff6ff; color: #111827; }
#catBtn[active="true"] { background: #eff6ff; color: #2563eb; }
#sidebarAction { color: #9ca3af; }
#sidebarAction:hover { background: #eff6ff; color: #4b5563; }
#sidebarDanger { color: #ef4444 !important; }

#mainPanel { background: #f9fafb; }
#toolbar { background: #ffffff; border-bottom: 1px solid #e5e7eb; }
#searchBar { background: #ffffff; border: 1px solid #d1d5db; color: #111827; }
#searchBar:focus { border-color: #2563eb; background: #ffffff; }

#btnPrimary { background: #2563eb; color: #ffffff; }
#btnPrimary:hover { background: #3b82f6; }
#btnSecondary { background: #ffffff; color: #4b5563; border: 1px solid #d1d5db; }
#btnSecondary:hover { background: #f8fafc; color: #111827; border-color: #2563eb; }
#btnIcon { background: #ffffff; border: 1px solid #d1d5db; color: #4b5563; }
#btnIcon:hover { background: #eff6ff; border-color: #2563eb; color: #111827; }

QTableWidget { background: #f9fafb; selection-background-color: #eff6ff; selection-color: #111827; }
QTableWidget::item { border-bottom: 1px solid #f3f4f6; }
QHeaderView::section { background: #ffffff; color: #9ca3af; border-bottom: 1px solid #e5e7eb; }

QLineEdit, QTextEdit, QComboBox { background: #ffffff; border: 1px solid #d1d5db; color: #111827; }
QLineEdit:focus, QTextEdit:focus, QComboBox:focus { border-color: #2563eb; }

QProgressBar { background: #f3f4f6; }
QSlider::groove:horizontal { background: #f3f4f6; }
QSlider::handle:horizontal { background: #2563eb; }

#labelMuted { color: #9ca3af; }
#labelAccent { color: #2563eb; }
#card { background: #ffffff; border: 1px solid #e5e7eb; }
#authCard { background: #ffffff; border: 1px solid #e5e7eb; }
#revealBar { background: #ffffff; border-top: 1px solid #e5e7eb; }
#statusBar { background: #ffffff; border-top: 1px solid #e5e7eb; color: #9ca3af; }
"""


# ─────────────────────────────────────────────────────────────────────────────
#  WORKER THREADS  (keep GUI responsive for slow ops)
# ─────────────────────────────────────────────────────────────────────────────
class BreachWorker(QThread):
    done = pyqtSignal(int)
    def __init__(self, password):
        super().__init__()
        self.password = password
    def run(self):
        self.done.emit(check_breach(self.password))


class HealthWorker(QThread):
    done = pyqtSignal(dict)
    def __init__(self, db, key):
        super().__init__()
        self.db  = db
        self.key = key
    def run(self):
        self.done.emit(audit_vault(self.db, self.key))


# ─────────────────────────────────────────────────────────────────────────────
#  PASSWORD GENERATOR DIALOG
# ─────────────────────────────────────────────────────────────────────────────
class GeneratorDialog(QDialog):
    password_selected = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("⚡ Password Generator")
        self.setMinimumWidth(440)
        self._selected = ""
        self._build()
        self._generate()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setSpacing(14)

        # Output
        out_row = QHBoxLayout()
        self.output = QLineEdit()
        self.output.setReadOnly(True)
        self.output.setObjectName("searchBar")
        self.output.setFont(QFont("Consolas, Courier New", 13))
        btn_copy = QPushButton("📋")
        btn_copy.setObjectName("btnIcon")
        btn_copy.clicked.connect(self._copy)
        out_row.addWidget(self.output)
        out_row.addWidget(btn_copy)
        lay.addLayout(out_row)

        # Strength bar
        self.strength_bar   = QProgressBar()
        self.strength_label = QLabel()
        self.strength_label.setObjectName("labelMuted")
        lay.addWidget(self.strength_bar)
        lay.addWidget(self.strength_label)

        # Length
        len_row = QHBoxLayout()
        len_row.addWidget(QLabel("Length:"))
        self.len_val = QLabel("16")
        self.len_val.setObjectName("labelAccent")
        len_row.addWidget(self.len_val)
        len_row.addStretch()
        lay.addLayout(len_row)
        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setRange(8, 64)
        self.slider.setValue(16)
        self.slider.valueChanged.connect(lambda v: (self.len_val.setText(str(v)), self._generate()))
        lay.addWidget(self.slider)

        # Checkboxes
        self.chk_upper   = QCheckBox("Uppercase (A-Z)")
        self.chk_numbers = QCheckBox("Numbers (0-9)")
        self.chk_symbols = QCheckBox("Symbols (!@#$...)")
        for c in (self.chk_upper, self.chk_numbers, self.chk_symbols):
            c.setChecked(True)
            c.stateChanged.connect(lambda _: self._generate())
            lay.addWidget(c)

        # Buttons
        btn_row = QHBoxLayout()
        btn_regen = QPushButton("🔄 Regenerate")
        btn_regen.setObjectName("btnSecondary")
        btn_regen.clicked.connect(self._generate)
        self.btn_use = QPushButton("✓ Use This Password")
        self.btn_use.setObjectName("btnPrimary")
        self.btn_use.clicked.connect(self._use)
        btn_row.addWidget(btn_regen)
        btn_row.addWidget(self.btn_use)
        lay.addLayout(btn_row)

    def _generate(self):
        pw = generate_password(
            self.slider.value(),
            self.chk_symbols.isChecked(),
            self.chk_numbers.isChecked(),
            self.chk_upper.isChecked()
        )
        self._selected = pw
        self.output.setText(pw)
        s = check_strength(pw)
        self.strength_bar.setValue(s['percent'])
        self.strength_bar.setStyleSheet(
            f"QProgressBar::chunk {{ background: {s['color']}; border-radius: 4px; }}")
        self.strength_label.setText(f"{s['label']}  ({s['percent']}%)")

    def _copy(self):
        QApplication.clipboard().setText(self._selected)

    def _use(self):
        self.password_selected.emit(self._selected)
        self.accept()


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY DIALOG  (Add / Edit)
# ─────────────────────────────────────────────────────────────────────────────
class EntryDialog(QDialog):
    def __init__(self, parent=None, entry=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Password" if entry else "Add Password")
        self.setMinimumWidth(480)
        self.entry = entry
        self._build()
        if entry:
            self._populate(entry)

    def _build(self):
        lay = QFormLayout(self)
        lay.setSpacing(10)
        lay.setContentsMargins(24, 24, 24, 24)

        self.site     = QLineEdit(); self.site.setPlaceholderText("e.g. github.com")
        self.username = QLineEdit(); self.username.setPlaceholderText("your@email.com")

        pw_row = QHBoxLayout()
        self.password = QLineEdit(); self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Enter or generate")
        self.password.textChanged.connect(self._update_strength)
        btn_eye = QPushButton("👁"); btn_eye.setObjectName("btnIcon")
        btn_eye.setCheckable(True)
        btn_eye.toggled.connect(lambda on: self.password.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
        btn_gen = QPushButton("⚡"); btn_gen.setObjectName("btnIcon")
        btn_gen.clicked.connect(self._open_gen)
        pw_row.addWidget(self.password); pw_row.addWidget(btn_eye); pw_row.addWidget(btn_gen)

        self.strength_bar   = QProgressBar(); self.strength_bar.setMaximumHeight(6)
        self.strength_label = QLabel(); self.strength_label.setObjectName("labelMuted")

        self.category = QComboBox()
        for cat in ("Other", "Social", "Banking", "Work", "Shopping", "Entertainment"):
            self.category.addItem(cat)

        self.expiry = QLineEdit(); self.expiry.setText("90")
        self.expiry.setPlaceholderText("Days before rotation reminder")

        self.notes = QTextEdit(); self.notes.setPlaceholderText("Recovery email, 2FA backup…")
        self.notes.setMaximumHeight(70)
        
        # Feature 3: History button
        self.btn_history = QPushButton("📜 View Password History")
        self.btn_history.setObjectName("btnSecondary")
        self.btn_history.setVisible(False) # only for edit
        if self.entry:
            self.btn_history.setVisible(True)

        self.breach_label = QLabel()
        self.breach_label.setObjectName("labelMuted")
        btn_breach = QPushButton("🔎 Check Breaches")
        btn_breach.setObjectName("btnSecondary")
        btn_breach.clicked.connect(self._check_breach)

        lay.addRow("Website / App *", self.site)
        lay.addRow("Username / Email", self.username)
        lay.addRow("Password *", pw_row)
        lay.addRow("",           self.strength_bar)
        lay.addRow("",           self.strength_label)
        lay.addRow("Category",   self.category)
        lay.addRow("Expiry (Days)", self.expiry)
        lay.addRow("Notes",      self.notes)
        lay.addRow("",           self.btn_history)
        lay.addRow("",           btn_breach)
        lay.addRow("",           self.breach_label)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save |
            QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self._validate)
        btns.rejected.connect(self.reject)
        btns.button(QDialogButtonBox.StandardButton.Save).setObjectName("btnPrimary")
        btns.button(QDialogButtonBox.StandardButton.Cancel).setObjectName("btnSecondary")
        lay.addRow(btns)

    def _populate(self, e):
        self.site.setText(e.get('site',''))
        self.username.setText(e.get('username',''))
        self.password.setText(e.get('password',''))
        idx = self.category.findText(e.get('category','Other'))
        if idx >= 0: self.category.setCurrentIndex(idx)
        self.expiry.setText(str(e.get('expiry_days', 90)))
        self.notes.setPlainText(e.get('notes',''))

    def _update_strength(self, pw):
        if not pw:
            self.strength_bar.setValue(0)
            self.strength_label.setText("")
            return
        s = check_strength(pw)
        self.strength_bar.setValue(s['percent'])
        self.strength_bar.setStyleSheet(
            f"QProgressBar::chunk {{ background: {s['color']}; border-radius: 4px; }}")
        self.strength_label.setText(f"{s['label']}  ({s['percent']}%)")

    def _open_gen(self):
        dlg = GeneratorDialog(self)
        dlg.password_selected.connect(lambda pw: self.password.setText(pw))
        dlg.exec()

    def _check_breach(self):
        pw = self.password.text()
        if not pw: return
        self.breach_label.setText("⏳ Checking…")
        self._bw = BreachWorker(pw)
        self._bw.done.connect(self._breach_result)
        self._bw.start()

    def _breach_result(self, count):
        if count == -1:
            self.breach_label.setText("⚠️ Could not connect")
            self.breach_label.setObjectName("labelWarn")
        elif count == 0:
            self.breach_label.setText("✅ Not found in any breach")
            self.breach_label.setObjectName("labelGood")
        else:
            self.breach_label.setText(f"🚨 Found in {count:,} breaches!")
            self.breach_label.setObjectName("labelBad")
        self.breach_label.setStyleSheet("")  # force re-eval

    def _validate(self):
        if not self.site.text().strip():
            QMessageBox.warning(self, "Required", "Site / App name is required.")
            return
        if not self.password.text():
            QMessageBox.warning(self, "Required", "Password is required.")
            return
        self.accept()

    def get_data(self):
        try:
            exp = int(self.expiry.text() or 90)
        except:
            exp = 90
        return {
            'site'    : self.site.text().strip(),
            'username': self.username.text().strip(),
            'password': self.password.text(),
            'category': self.category.currentText(),
            'expiry'  : exp,
            'notes'   : self.notes.toPlainText().strip(),
        }


# ─────────────────────────────────────────────────────────────────────────────
#  HEALTH PANEL
# ─────────────────────────────────────────────────────────────────────────────
class HealthPanel(QWidget):
    edit_requested = pyqtSignal(int)   # entry id

    def __init__(self, db, key, parent=None):
        super().__init__(parent)
        self.db  = db
        self.key = key
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 16, 24, 16)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("🛡  Password Health Audit")
        title.setStyleSheet("font-size: 15px; font-weight: bold;")
        btn_refresh = QPushButton("🔄 Refresh")
        btn_refresh.setObjectName("btnPrimary")
        btn_refresh.clicked.connect(self.run_audit)
        hdr.addWidget(title); hdr.addStretch(); hdr.addWidget(btn_refresh)
        lay.addLayout(hdr)

        # Score card
        score_card = QFrame(); score_card.setObjectName("card")
        sc_lay = QHBoxLayout(score_card)

        self.score_label = QLabel("—")
        self.score_label.setObjectName("scoreNum")
        self.score_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.score_label.setMinimumWidth(90)

        self.score_text  = QLabel("Run audit to see your vault health.")
        self.score_text.setWordWrap(True)
        self.score_badges = QLabel("")
        self.score_badges.setWordWrap(True)
        self.score_badges.setObjectName("labelMuted")

        score_right = QVBoxLayout()
        score_right.addWidget(QLabel("Vault Health Score"))
        score_right.addWidget(self.score_text)
        score_right.addWidget(self.score_badges)

        sc_lay.addWidget(self.score_label)
        sc_lay.addLayout(score_right)
        lay.addWidget(score_card)

        # Scroll area for issues
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        inner = QWidget(); self.issues_lay = QVBoxLayout(inner)
        self.issues_lay.setSpacing(8)
        self.issues_lay.addStretch()
        scroll.setWidget(inner)
        lay.addWidget(scroll)

        # Loading label
        self.loading_label = QLabel("Click Refresh to analyse your vault.")
        self.loading_label.setObjectName("labelMuted")
        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self.loading_label)

    def run_audit(self):
        self.loading_label.setText("⏳ Analysing vault…")
        self._clear_issues()
        self._worker = HealthWorker(self.db, self.key)
        self._worker.done.connect(self._show_results)
        self._worker.start()

    def _clear_issues(self):
        while self.issues_lay.count() > 1:
            item = self.issues_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _show_results(self, data):
        self.loading_label.setText("")

        # Score
        s = data['score']
        c = data['score_color']
        self.score_label.setText(str(s))
        self.score_label.setStyleSheet(f"font-size: 48px; font-weight: 900; color: {c};")
        self.score_text.setText(f"<b style='font-size:16px'>{data['score_label']}</b><br>Overall vault security health")
        self.score_text.setTextFormat(Qt.TextFormat.RichText)
        
        self.score_badges.setText(
            f"<span style='color:#ff5c6c'>●</span> {data['weak_count']} Weak   "
            f"<span style='color:#ffd32a'>●</span> {data['reused_count']} Reused   "
            f"<span style='color:#8e8eaf'>●</span> {data['old_count']} Old")
        self.score_badges.setTextFormat(Qt.TextFormat.RichText)

        # Sections
        self._add_section("🔴  Weak Passwords", data['weak'],
            lambda e: f"{e['site']}  —  {e['strength_label']} ({e['strength_percent']}%)",
            data['weak_count'])
        self._add_section("🟡  Reused Passwords",
            [s for g in data['reused'] for s in g['sites']],
            lambda e: f"{e['site']}  —  same password reused elsewhere",
            data['reused_count'])
        self._add_section("⚪️  Old Passwords", data['old'],
            lambda e: f"{e['site']}  —  last changed {e['days_old']} days ago",
            data['old_count'])

    def _add_section(self, title, entries, label_fn, count):
        hdr = QLabel(f"{title}  ({count})")
        hdr.setStyleSheet("font-weight: bold; color: #6b6b88; font-size: 11px; "
                          "text-transform: uppercase; letter-spacing: 0.05em;")
        self.issues_lay.insertWidget(self.issues_lay.count() - 1, hdr)

        if not entries:
            ok = QLabel("✅ All good here!")
            ok.setObjectName("labelGood")
            ok.setContentsMargins(0, 0, 0, 8)
            self.issues_lay.insertWidget(self.issues_lay.count() - 1, ok)
            return

        for e in entries:
            row = QFrame(); row.setObjectName("card")
            row_lay = QHBoxLayout(row)
            row_lay.setContentsMargins(16, 12, 16, 12)
            info = QLabel(f"<b style='font-size:14px'>{e['site']}</b><br>"
                          f"<span style='color:#6e6e8a;font-size:12px'>{label_fn(e)}</span>")
            info.setTextFormat(Qt.TextFormat.RichText)
            btn = QPushButton("Fix ✏️")
            btn.setObjectName("btnSecondary")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _, eid=e['id']: self.edit_requested.emit(eid))
            row_lay.addWidget(info, 1)
            row_lay.addWidget(btn)
            self.issues_lay.insertWidget(self.issues_lay.count() - 1, row)


# ─────────────────────────────────────────────────────────────────────────────
#  VAULT WINDOW  (main screen)
# ─────────────────────────────────────────────────────────────────────────────
class VaultWindow(QMainWindow):
    def __init__(self, key: bytes):
        super().__init__()
        self.key   = key
        self.vault = Vault(DATABASE, key)
        self._clipboard_timer = None
        self._current_cat = "all"

        # Load theme setting
        self.settings = QSettings("VaultX", "VaultX")
        self.current_theme = self.settings.value("theme", "dark")

        self.setWindowTitle("🔐 VaultX — Password Manager")
        self.setMinimumSize(1024, 700)
        self.setWindowState(Qt.WindowState.WindowMaximized)
        self._build_ui()
        self._load_entries()
        self._load_notes()
        self._update_stats()
        
        # Feature 5: Start extension API
        start_api(self.vault)

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QHBoxLayout(central); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)

        # ── SIDEBAR ──────────────────────────────────────────────────────────
        self._sidebar = QWidget(); self._sidebar.setObjectName("sidebar")
        sb_root = QVBoxLayout(self._sidebar); sb_root.setContentsMargins(0, 0, 0, 0); sb_root.setSpacing(0)

        brand = QLabel("🔐  VaultX"); brand.setObjectName("sidebarBrand")
        sb_root.addWidget(brand)

        # Scrollable area for categories and stats
        sb_scroll = QScrollArea(); sb_scroll.setWidgetResizable(True)
        sb_scroll.setFrameShape(QFrame.Shape.NoFrame); sb_scroll.setObjectName("sidebarScroll")
        sb_content = QWidget(); sb_content.setObjectName("sidebarContent")
        sb_lay = QVBoxLayout(sb_content); sb_lay.setContentsMargins(0, 0, 0, 0); sb_lay.setSpacing(0)
        
        # Nav
        nav_label = QLabel("  VIEW"); nav_label.setObjectName("labelMuted")
        nav_label.setContentsMargins(16, 12, 0, 4)
        nav_label.setStyleSheet("font-size:10px;letter-spacing:.08em;color:#4a4a60;")
        sb_lay.addWidget(nav_label)

        self.nav_passwords = QPushButton("🗝   Passwords")
        self.nav_notes     = QPushButton("📝   Secure Notes")
        self.nav_health    = QPushButton("🛡   Health Audit")
        for btn, active in ((self.nav_passwords, True), (self.nav_notes, False), (self.nav_health, False)):
            btn.setObjectName("catBtn")
            btn.setProperty("active", "true" if active else "false")
            btn.setFlat(True); btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            sb_lay.addWidget(btn)
        self.nav_passwords.clicked.connect(lambda: self._switch_tab(0))
        self.nav_notes.clicked.connect(lambda: self._switch_tab(1))
        self.nav_health.clicked.connect(lambda: self._switch_tab(2))

        # Categories
        cat_label = QLabel("  CATEGORIES"); cat_label.setObjectName("labelMuted")
        cat_label.setContentsMargins(16, 14, 0, 4)
        cat_label.setStyleSheet("font-size:10px;letter-spacing:.08em;color:#4a4a60;")
        sb_lay.addWidget(cat_label)

        self._cat_buttons = {}
        icons = {'all':'🗂','Social':'💬','Banking':'🏦','Work':'💼',
                 'Shopping':'🛒','Entertainment':'🎮','Other':'📦'}
        for cat in ['all','Social','Banking','Work','Shopping','Entertainment','Other']:
            label = 'All Passwords' if cat == 'all' else cat
            btn = QPushButton(f"{icons[cat]}  {label}")
            btn.setObjectName("catBtn")
            btn.setProperty("active", "true" if cat == 'all' else "false")
            btn.setFlat(True)
            btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            btn.clicked.connect(lambda _, c=cat: self._filter_cat(c))
            sb_lay.addWidget(btn)
            self._cat_buttons[cat] = btn

        sb_lay.addStretch()

        # Stats
        stats_label = QLabel("  VAULT STATS")
        stats_label.setStyleSheet("font-size:10px;letter-spacing:.08em;color:#4a4a60;")
        stats_label.setContentsMargins(16, 10, 0, 4)
        sb_lay.addWidget(stats_label)
        self.stat_total = QLabel("Total: 0")
        self.stat_total.setContentsMargins(16, 2, 0, 2)
        self.stat_total.setObjectName("labelMuted")
        sb_lay.addWidget(self.stat_total)

        # Bottom actions (always visible or in scroll?)
        # Let's keep them in the scroll for safety but could also put them in sb_root
        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("border-top: 1px solid #2a2a3d;"); sb_lay.addWidget(sep)

        btn_gen  = QPushButton("⚡  Generate Password"); btn_gen.setObjectName("sidebarAction")
        btn_note = QPushButton("📝  Add Secure Note");     btn_note.setObjectName("sidebarAction")
        btn_ext  = QPushButton("🌐 Browser Extension"); btn_ext.setObjectName("btnPrimary")
        btn_ext.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_ext.setStyleSheet("margin: 8px 14px;")

        # Custom Theme Toggle row
        theme_row = QWidget()
        theme_row.setStyleSheet("margin: 8px 14px;")
        th_lay = QHBoxLayout(theme_row); th_lay.setContentsMargins(10, 0, 10, 0)
        th_lbl = QLabel("🌓 Light Mode")
        th_lbl.setStyleSheet("font-size: 12px; font-weight: 600; color: #6b7280;")
        self.theme_switch = AnimatedSwitch()
        self.theme_switch.setChecked(self.current_theme == "light")
        self.theme_switch.toggled.connect(self._toggle_theme)
        th_lay.addWidget(th_lbl); th_lay.addStretch(); th_lay.addWidget(self.theme_switch)

        btn_lock = QPushButton("🔒  Lock Vault");       btn_lock.setObjectName("sidebarAction")
        btn_lock.setProperty("class", "danger")
        
        btn_gen.clicked.connect(self._open_generator)
        btn_note.clicked.connect(self._add_note)
        btn_ext.clicked.connect(self._show_extension_dialog)
        btn_lock.clicked.connect(self._lock)
        
        sb_lay.addWidget(btn_gen)
        sb_lay.addWidget(btn_note)
        sb_lay.addWidget(btn_ext)
        sb_lay.addWidget(theme_row)
        sb_lay.addWidget(btn_lock)

        sb_scroll.setWidget(sb_content)
        sb_root.addWidget(sb_scroll)
        root.addWidget(self._sidebar)

        # ── RIGHT PANEL ───────────────────────────────────────────────────────
        right = QWidget(); right.setObjectName("mainPanel")
        right_lay = QVBoxLayout(right); right_lay.setContentsMargins(0, 0, 0, 0); right_lay.setSpacing(0)

        # Toolbar
        toolbar = QWidget()
        toolbar.setObjectName("toolbar")
        tb_lay = QHBoxLayout(toolbar); tb_lay.setContentsMargins(20, 12, 20, 12); tb_lay.setSpacing(12)
        self.search = QLineEdit(); self.search.setObjectName("searchBar")
        self.search.setPlaceholderText("🔍  Search sites, usernames…")
        self.search.textChanged.connect(self._filter_search)
        self.search.setMinimumWidth(300)
        btn_import = QPushButton("📁 Import"); btn_import.setObjectName("btnSecondary")
        btn_import.clicked.connect(self._import_csv)
        btn_add = QPushButton("+ Add Password"); btn_add.setObjectName("btnPrimary")
        btn_add.clicked.connect(self._add_entry)
        tb_lay.addWidget(self.search, 1); tb_lay.addWidget(btn_import); tb_lay.addWidget(btn_add)
        right_lay.addWidget(toolbar)

        # Stacked: passwords / health
        self.stack = QStackedWidget()

        # Page 0 — Password table
        pw_page = QWidget()
        pw_lay = QVBoxLayout(pw_page); pw_lay.setContentsMargins(0, 0, 0, 0); pw_lay.setSpacing(0)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Site", "Username", "Category", "Added", "Actions"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.setColumnWidth(0, 200)
        self.table.setColumnWidth(1, 200)
        self.table.setColumnWidth(2, 140)
        self.table.setColumnWidth(3, 120)
        self.table.setColumnWidth(4, 260)  # Room for 4 large action buttons
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(False)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        pw_lay.addWidget(self.table)

        # Reveal bar
        self._reveal_bar = QWidget()
        self._reveal_bar.setObjectName("revealBar")
        rev_lay = QHBoxLayout(self._reveal_bar); rev_lay.setContentsMargins(20, 10, 20, 10)
        self._reveal_site = QLabel(); self._reveal_site.setStyleSheet("font-weight:bold;")
        self._reveal_pw   = QLabel(); self._reveal_pw.setFont(QFont("Consolas, Courier New", 12))
        self._reveal_pw.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        btn_rev_copy  = QPushButton("📋 Copy");    btn_rev_copy.setObjectName("btnIcon")
        btn_rev_breach= QPushButton("🔎 Breach");  btn_rev_breach.setObjectName("btnIcon")
        btn_rev_close = QPushButton("✕");          btn_rev_close.setObjectName("btnIcon")
        self._reveal_breach = QLabel()
        btn_rev_copy.clicked.connect(self._copy_revealed)
        btn_rev_breach.clicked.connect(self._breach_revealed)
        btn_rev_close.clicked.connect(self._close_reveal)
        for w in (self._reveal_site, self._reveal_pw, btn_rev_copy, btn_rev_breach,
                  self._reveal_breach, btn_rev_close):
            rev_lay.addWidget(w)
        rev_lay.addStretch()
        self._reveal_bar.setVisible(False)
        pw_lay.addWidget(self._reveal_bar)

        self.stack.addWidget(pw_page)

        # Page 1 — Secure Notes
        notes_page = QWidget()
        n_lay = QVBoxLayout(notes_page); n_lay.setContentsMargins(24, 24, 24, 24)
        
        n_hdr = QHBoxLayout()
        n_title = QLabel("📝  Secure Notes")
        n_title.setStyleSheet("font-size: 18px; font-weight: 800;")
        btn_add_note = QPushButton("+ Add Note")
        btn_add_note.setObjectName("btnPrimary")
        btn_add_note.clicked.connect(self._add_note)
        n_hdr.addWidget(n_title); n_hdr.addStretch(); n_hdr.addWidget(btn_add_note)
        n_lay.addLayout(n_hdr)

        scroll_notes = QScrollArea(); scroll_notes.setWidgetResizable(True)
        scroll_notes.setFrameShape(QFrame.Shape.NoFrame)
        self.notes_container = QWidget(); self.notes_lay = QVBoxLayout(self.notes_container)
        self.notes_lay.setSpacing(12); self.notes_lay.addStretch()
        scroll_notes.setWidget(self.notes_container)
        n_lay.addWidget(scroll_notes)
        self.stack.addWidget(notes_page)

        # Page 2 — Health
        self.health_panel = HealthPanel(DATABASE, self.key)
        self.health_panel.edit_requested.connect(self._edit_by_id)
        self.stack.addWidget(self.health_panel)

        right_lay.addWidget(self.stack, 1)

        # Status bar
        self.status = QLabel("Ready")
        self.status.setObjectName("statusBar")
        right_lay.addWidget(self.status)

        root.addWidget(right, 1)

        # Clipboard auto-clear timer
        self._clip_timer = QTimer()
        self._clip_timer.setSingleShot(True)
        self._clip_timer.timeout.connect(self._clear_clipboard)

    # ── Navigation ────────────────────────────────────────────────────────────
    def _switch_tab(self, idx):
        self.stack.setCurrentIndex(idx)
        self.nav_passwords.setProperty("active", "true" if idx == 0 else "false")
        self.nav_notes.setProperty("active",     "true" if idx == 1 else "false")
        self.nav_health.setProperty("active",    "true" if idx == 2 else "false")
        self.nav_passwords.setStyle(self.nav_passwords.style())
        self.nav_notes.setStyle(self.nav_notes.style())
        self.nav_health.setStyle(self.nav_health.style())
        # Hide category sidebar when on other tabs
        for cat_btn in self._cat_buttons.values():
            cat_btn.setVisible(idx == 0)
        
        if idx == 1:
            self._load_notes()
        if idx == 2:
            self.health_panel.run_audit()

    # ── Data loading ──────────────────────────────────────────────────────────
    def _load_entries(self):
        self._entries = self.vault.list_all()
        self._render_table(self._entries)

    def _render_table(self, entries):
        self.table.setRowCount(0)
        self.table.setRowCount(len(entries))
        for row, e in enumerate(entries):
            site_item = QTableWidgetItem(e['site'])
            site_item.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
            
            # Feature 10: Expiry Warning
            try:
                days = (datetime.now() - datetime.fromisoformat(e['updated_at'])).days
                if days >= e.get('expiry_days', 90):
                    site_item.setText(f"⚠ {e['site']}")
                    site_item.setForeground(QColor("#ff5c6c"))
                    site_item.setToolTip(f"Security Risk: Password is {days} days old.")
            except: pass

            user_item = QTableWidgetItem(e['username'] or '—')
            user_item.setForeground(QColor("#9a9ab0") if self.current_theme == "dark" else QColor("#6e6e8a"))
            
            cat_item = QTableWidgetItem(e['category'])
            cat_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            self.table.setItem(row, 0, site_item)
            self.table.setItem(row, 1, user_item)
            self.table.setItem(row, 2, cat_item)
            self.table.setItem(row, 3, QTableWidgetItem(e['created_at'][:10]))
            self.table.setRowHeight(row, 72)

            # Action buttons widget
            actions = QWidget()
            a_lay = QHBoxLayout(actions); a_lay.setContentsMargins(4, 8, 4, 8); a_lay.setSpacing(8)
            eid = e['id']
            buttons = [
                ("📋", lambda _, i=eid: self._copy_pw(i), "Copy Password"),
                ("👁",  lambda _, i=eid: self._show_pw(i), "View Password"),
                ("✏️", lambda _, i=eid: self._edit_by_id(i), "Edit Entry"),
                ("🗑",  lambda _, i=eid: self._delete_entry(i), "Delete Entry")
            ]
            for icon, fn, tooltip in buttons:
                b = QPushButton(icon)
                b.setObjectName("btnIcon")
                b.setCursor(Qt.CursorShape.PointingHandCursor)
                b.setToolTip(tooltip)
                b.clicked.connect(fn)
                a_lay.addWidget(b)
            self.table.setCellWidget(row, 4, actions)

    def _load_notes(self):
        # Clear existing
        while self.notes_lay.count() > 1:
            item = self.notes_lay.takeAt(0)
            if item.widget(): item.widget().deleteLater()
            
        notes = self.vault.list_notes()
        for n in notes:
            card = QFrame(); card.setObjectName("card")
            card_lay = QHBoxLayout(card)
            card_lay.setContentsMargins(20, 20, 20, 20)
            card.setMinimumHeight(80)
            
            info = QLabel(f"<b style='font-size:16px;line-height:1.2'>{n['title']}</b><br>"
                          f"<span style='color:#6e6e8a;font-size:12px'>{n['category']} • Added {n['created_at'][:10]}</span>")
            info.setTextFormat(Qt.TextFormat.RichText)
            
            btn_view = QPushButton("👁 View")
            btn_view.setObjectName("btnSecondary")
            btn_view.setCursor(Qt.CursorShape.PointingHandCursor)
            btn_view.clicked.connect(lambda _, nid=n['id']: self._show_note(nid))
            
            btn_del = QPushButton("🗑")
            btn_del.setObjectName("btnIcon")
            btn_del.setFixedSize(36, 36)
            btn_del.setCursor(Qt.CursorShape.PointingHandCursor)
            btn_del.clicked.connect(lambda _, nid=n['id']: self._delete_note(nid))
            
            card_lay.addWidget(info, 1)
            card_lay.addWidget(btn_view)
            card_lay.addWidget(btn_del)
            self.notes_lay.insertWidget(self.notes_lay.count() - 1, card)

    def _show_note(self, nid):
        note = self.vault.get_note(nid)
        if not note: return
        QMessageBox.information(self, note['title'], note['content'])

    def _delete_note(self, nid):
        if QMessageBox.question(self, "Delete Note", "Delete this secure note?") == QMessageBox.StandardButton.Yes:
            self.vault.delete_note(nid)
            self._load_notes()

    def _add_note(self):
        title, ok1 = QInputDialog.getText(self, "New Secure Note", "Note Title:")
        if not ok1 or not title: return
        content, ok2 = QInputDialog.getMultiLineText(self, "New Secure Note", "Note Content (Encrypted):")
        if not ok2 or not content: return
        
        self.vault.add_note(title, content)
        self._load_notes()
        self._set_status("✅  Secure note saved.")

    def _show_history(self, eid):
        history = self.vault.get_password_history(eid)
        if not history:
            QMessageBox.information(self, "History", "No history for this entry.")
            return
        
        msg = "Last 5 passwords:\n\n"
        for h in history:
            msg += f"📅 {h['changed_at']}\n🔑 {h['password']}\n\n"
        QMessageBox.information(self, "Password History", msg)

    def _update_stats(self):
        stats = self.vault.get_stats()
        self.stat_total.setText(f"  Total: {stats['total']} passwords")

    # ── Filtering ─────────────────────────────────────────────────────────────
    def _filter_cat(self, cat):
        self._current_cat = cat
        for c, b in self._cat_buttons.items():
            b.setProperty("active", "true" if c == cat else "false")
            b.setStyle(b.style())
        self._apply_filter()

    def _filter_search(self, text):
        self._apply_filter()

    def _apply_filter(self):
        term = self.search.text().lower()
        if not term:
            filtered = [
                e for e in self._entries
                if (self._current_cat == 'all' or e['category'] == self._current_cat)
            ]
        else:
            # Feature 11: Fuzzy Search
            results = []
            for e in self._entries:
                if self._current_cat != 'all' and e['category'] != self._current_cat:
                    continue
                score = fuzz.partial_ratio(term, e['site'].lower())
                # Exact match or high fuzzy score
                if term in e['site'].lower() or score >= 65:
                    e['_score'] = score
                    results.append(e)
            filtered = sorted(results, key=lambda x: x.get('_score', 0), reverse=True)
            
        self._render_table(filtered)

    # ── CRUD ──────────────────────────────────────────────────────────────────
    def _add_entry(self):
        dlg = EntryDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            d = dlg.get_data()
            self.vault.add_password(d['site'], d['username'], d['password'], d['category'], d['notes'], d['expiry'])
            self._load_entries(); self._update_stats()
            self._set_status("✅  Password saved.")

    def _edit_by_id(self, eid):
        try:
            entry = self.vault.get_full_entry(eid)
            if not entry: return
            dlg = EntryDialog(self, entry)
            dlg.btn_history.clicked.connect(lambda: self._show_history(eid))
            if dlg.exec() == QDialog.DialogCode.Accepted:
                d = dlg.get_data()
                self.vault.update_password(eid, d['site'], d['username'], d['password'], d['category'], d['notes'], d['expiry'])
                self._load_entries(); self._update_stats()
                self._set_status("✅  Entry updated.")
        except InvalidTag:
            QMessageBox.critical(self, "Decryption Error", 
                "Failed to decrypt this entry. This usually happens if the encryption algorithm was upgraded "
                "or the vault files are incompatible. Please try creating a fresh vault.")

    def _import_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import CSV", "", "CSV Files (*.csv)")
        if path:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    csv_text = f.read()
                res = self.vault.import_from_csv(csv_text)
                self._load_entries(); self._update_stats()
                msg = f"Imported {res['imported']} entries."
                if res['skipped']: msg += f" Skipped {res['skipped']} invalid rows."
                QMessageBox.information(self, "Import Complete", msg)
                self._set_status("✅  Import successful.")
            except Exception as e:
                QMessageBox.critical(self, "Import Error", f"Failed to import: {e}")

    def _delete_entry(self, eid):
        reply = QMessageBox.question(self, "Delete", "Delete this password? Cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        if reply == QMessageBox.StandardButton.Yes:
            self.vault.delete_password(eid)
            self._load_entries(); self._update_stats()
            self._set_status("🗑  Entry deleted.")

    # ── Password reveal / copy ─────────────────────────────────────────────────
    def _copy_pw(self, eid):
        try:
            entry = self.vault.get_full_entry(eid)
            if not entry: return
            QApplication.clipboard().setText(entry['password'])
            self._clip_timer.start(30_000)
            self._set_status("📋  Password copied — clears in 30 seconds.")
        except InvalidTag:
            self._decryption_error()

    def _show_pw(self, eid):
        try:
            entry = self.vault.get_full_entry(eid)
            if not entry: return
            self._reveal_site.setText(entry['site'] + "  ")
            self._reveal_pw.setText(entry['password'])
            self._reveal_breach.setText("")
            self._reveal_bar.setVisible(True)
            self._current_reveal_entry = entry
        except InvalidTag:
            self._decryption_error()

    def _decryption_error(self):
        QMessageBox.critical(self, "Decryption Error", 
            "Critical: Failed to decrypt this entry. Your vault may be using an older encryption format. "
            "Please back up your data and restart with a fresh vault if this persists.")

    def _show_extension_dialog(self):
        ExtensionInstallDialog(self).exec()

    def _close_reveal(self):
        self._reveal_bar.setVisible(False)
        self._reveal_pw.setText("")

    def _copy_revealed(self):
        pw = self._reveal_pw.text()
        QApplication.clipboard().setText(pw)
        self._clip_timer.start(30_000)
        self._set_status("📋  Copied — clears in 30 seconds.")

    def _breach_revealed(self):
        pw = self._reveal_pw.text()
        if not pw: return
        self._reveal_breach.setText("⏳")
        self._bw = BreachWorker(pw)
        self._bw.done.connect(lambda c: self._reveal_breach.setText(
            "✅ Safe" if c == 0 else ("⚠️ No connection" if c == -1 else f"🚨 {c:,} breaches!")))
        self._bw.start()

    def _clear_clipboard(self):
        QApplication.clipboard().setText("")
        self._set_status("🧹  Clipboard cleared.")

    # ── Generator ─────────────────────────────────────────────────────────────
    def _open_generator(self):
        GeneratorDialog(self).exec()

    # ── Lock / logout ─────────────────────────────────────────────────────────
    def _lock(self):
        self.key = None
        self.vault = None
        self.close()
        _show_login()

    def _toggle_theme(self, checked=None):
        if checked is not None:
            self.current_theme = "light" if checked else "dark"
        else:
            self.current_theme = "light" if self.current_theme == "dark" else "dark"
            
        self.settings.setValue("theme", self.current_theme)
        app = QApplication.instance()
        app.setStyleSheet(DARK if self.current_theme == "dark" else LIGHT)
        self._set_status(f"✨ Switched to {self.current_theme} mode.")

    # ── Status bar ────────────────────────────────────────────────────────────
    def _set_status(self, msg):
        self.status.setText(msg)
        QTimer.singleShot(4000, lambda: self.status.setText("Ready"))


# ─────────────────────────────────────────────────────────────────────────────
#  LOGIN WINDOW
# ─────────────────────────────────────────────────────────────────────────────
class LoginWindow(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VaultX — Unlock")
        self.setModal(True)
        self.key = None
        self._attempts = 0
        self._locked_until = 0
        self._build()

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame(); card.setObjectName("authCard")
        lay  = QVBoxLayout(card); lay.setSpacing(10)

        title    = QLabel("🔐  VaultX"); title.setObjectName("authTitle")
        subtitle = QLabel("Enter your master password to unlock the vault.")
        subtitle.setObjectName("authSubtitle"); subtitle.setWordWrap(True)

        self.pw_input = QLineEdit()
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_input.setPlaceholderText("Master password")
        self.pw_input.returnPressed.connect(self._try_login)

        btn_eye = QPushButton("👁  Show"); btn_eye.setObjectName("btnSecondary")
        btn_eye.setCheckable(True)
        btn_eye.setAutoDefault(False) # Prevent Enter from triggering this
        btn_eye.toggled.connect(lambda on: self.pw_input.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))

        # Feature 1: TOTP Input
        self.totp_input = QLineEdit()
        self.totp_input.setPlaceholderText("6-digit 2FA code")
        self.totp_input.setVisible(totp_enabled())
        self.totp_input.returnPressed.connect(self._try_login)

        self.btn_unlock = QPushButton("🔓  Unlock"); self.btn_unlock.setObjectName("btnPrimary")
        self.btn_unlock.setDefault(True) # Make this the 'Enter' key action
        self.btn_unlock.clicked.connect(self._try_login)

        self.error_label = QLabel()
        self.error_label.setObjectName("labelBad")
        self.error_label.setWordWrap(True)
        self.error_label.setVisible(False)

        for w in (title, subtitle, self.pw_input, btn_eye, self.totp_input, self.btn_unlock, self.error_label):
            lay.addWidget(w)

        outer.addWidget(card)

    def _try_login(self):
        now = time.time()
        if now < self._locked_until:
            remain = int(self._locked_until - now)
            self._show_error(f"Too many attempts. Wait {remain}s.")
            return

        pw = self.pw_input.text()
        if verify_master_password(pw):
            key = derive_key(pw)
            if totp_enabled():
                if not verify_totp(key, self.totp_input.text()):
                    self._show_error("Invalid 2FA code.")
                    return
            self.key = key
            pw = None
            self.accept()
        else:
            self._attempts += 1
            if self._attempts >= 5:
                self._locked_until = now + 300
                self._attempts = 0
                self._show_error("5 failed attempts — locked for 5 minutes.")
            else:
                left = 5 - self._attempts
                self._show_error(f"Incorrect password. {left} attempt(s) left.")

    def _show_error(self, msg):
        self.error_label.setText(msg)
        self.error_label.setVisible(True)
        self.pw_input.clear()


# ─────────────────────────────────────────────────────────────────────────────
#  SETUP WINDOW
# ─────────────────────────────────────────────────────────────────────────────
class SetupWindow(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VaultX — Create Vault")
        self.setModal(True)
        self._build()

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame(); card.setObjectName("authCard")
        lay  = QVBoxLayout(card); lay.setSpacing(10)

        title = QLabel("🔐  Create Your Vault"); title.setObjectName("authTitle")
        sub   = QLabel("Choose a strong master password. This cannot be recovered if lost.")
        sub.setObjectName("authSubtitle"); sub.setWordWrap(True)

        self.pw1 = QLineEdit(); self.pw1.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw1.setPlaceholderText("Master password (min. 8 characters)")
        self.pw1.textChanged.connect(self._update_strength)

        self.strength_bar   = QProgressBar(); self.strength_bar.setMaximumHeight(6)
        self.strength_label = QLabel(); self.strength_label.setObjectName("labelMuted")

        self.pw2 = QLineEdit(); self.pw2.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw2.setPlaceholderText("Confirm master password")

        # Feature 1: TOTP Setup
        self.totp_secret = generate_totp_secret()
        self.qr_label = QLabel(); self.qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        qr_b64 = get_qr_base64(self.totp_secret)
        pix = QPixmap(); pix.loadFromData(base64.b64decode(qr_b64))
        self.qr_label.setPixmap(pix.scaled(160, 160, Qt.AspectRatioMode.KeepAspectRatio))
        
        totp_instr = QLabel("Scan this QR with Google Authenticator")
        totp_instr.setObjectName("labelMuted"); totp_instr.setAlignment(Qt.AlignmentFlag.AlignCenter)

        btn_create = QPushButton("✓  Create Vault"); btn_create.setObjectName("btnPrimary")
        btn_create.clicked.connect(self._create)

        self.err = QLabel(); self.err.setObjectName("labelBad"); self.err.setVisible(False)

        for w in (title, sub, self.pw1, self.strength_bar, self.strength_label,
                  self.pw2, self.qr_label, totp_instr, btn_create, self.err):
            lay.addWidget(w)

        outer.addWidget(card)

    def _update_strength(self, pw):
        if not pw: return
        s = check_strength(pw)
        self.strength_bar.setValue(s['percent'])
        self.strength_bar.setStyleSheet(
            f"QProgressBar::chunk {{ background: {s['color']}; border-radius: 4px; }}")
        self.strength_label.setText(f"{s['label']}  ({s['percent']}%)")

    def _create(self):
        pw1 = self.pw1.text(); pw2 = self.pw2.text()
        if len(pw1) < 8:
            self._show_err("Password must be at least 8 characters."); return
        if pw1 != pw2:
            self._show_err("Passwords do not match."); return
        
        set_master_password(pw1)
        key = derive_key(pw1)
        save_totp_secret(key, self.totp_secret)
        self.accept()

    def _show_err(self, msg):
        self.err.setText(msg); self.err.setVisible(True)


# ─────────────────────────────────────────────────────────────────────────────
#  EXTENSION INSTALL DIALOG
# ─────────────────────────────────────────────────────────────────────────────
class ExtensionInstallDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🌐 Browser Extension Setup")
        self.setFixedWidth(500)
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 32, 32, 32)
        lay.setSpacing(20)

        title = QLabel("Install VaultX Auto-Fill")
        title.setStyleSheet("font-size: 24px; font-weight: 800; color: #3b82f6;")
        lay.addWidget(title)

        subtitle = QLabel("Follow these simple steps to enable auto-fill in your browser:")
        subtitle.setObjectName("labelMuted")
        lay.addWidget(subtitle)

        steps = [
            "1. Open <b>Google Chrome</b>",
            "2. Go to <b>chrome://extensions/</b>",
            "3. Turn <b>ON</b> 'Developer mode' (top-right)",
            "4. Click <b>'Load unpacked'</b>",
            "5. Select the folder opened by the button below"
        ]

        for s in steps:
            lbl = QLabel(s)
            lbl.setStyleSheet("font-size: 14px; padding: 4px 0;")
            lbl.setTextFormat(Qt.TextFormat.RichText)
            lay.addWidget(lbl)

        lay.addStretch()

        btn_open = QPushButton("📂 Open Extension Folder")
        btn_open.setObjectName("btnPrimary")
        btn_open.clicked.connect(self._open_folder)
        lay.addWidget(btn_open)

        btn_close = QPushButton("Done")
        btn_close.setObjectName("btnSecondary")
        btn_close.clicked.connect(self.accept)
        lay.addWidget(btn_close)

    def _open_folder(self):
        # Handle path regardless of execution environment
        if getattr(sys, 'frozen', False):
            base_dir = Path(sys.executable).parent
        else:
            base_dir = Path(__file__).parent.parent
            
        ext_path = base_dir / "extension"
        
        if ext_path.exists():
            from PyQt6.QtGui import QDesktopServices
            from PyQt6.QtCore import QUrl
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(ext_path.absolute())))
        else:
            QMessageBox.warning(self, "Not Found", f"Extension folder not found at:\n{ext_path}")


# ─────────────────────────────────────────────────────────────────────────────
#  APP FLOW
# ─────────────────────────────────────────────────────────────────────────────
_vault_window = None

def _show_login():
    global _vault_window
    win = LoginWindow()
    if win.exec() == QDialog.DialogCode.Accepted:
        _vault_window = VaultWindow(win.key)
        _vault_window.showMaximized()
    else:
        QApplication.instance().quit()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("VaultX")
    
    # Load saved theme
    settings = QSettings("VaultX", "VaultX")
    theme = settings.value("theme", "dark")
    app.setStyleSheet(DARK if theme == "dark" else LIGHT)

    # Feature 2: Auto-Lock (5 mins)
    lock_filter = InactivityFilter(5 * 60 * 1000)
    app.installEventFilter(lock_filter)

    def on_timeout():
        global _vault_window
        if _vault_window and _vault_window.isVisible():
            _vault_window.close()
            stop_api()
            _show_login()

    lock_filter.timeout.connect(on_timeout)

    if not master_password_exists():
        setup = SetupWindow()
        if setup.exec() != QDialog.DialogCode.Accepted:
            sys.exit(0)

    _show_login()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
