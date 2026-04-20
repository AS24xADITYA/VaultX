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
from pathlib import Path

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

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QStackedWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QDialog, QDialogButtonBox, QMessageBox, QSlider,
    QCheckBox, QFrame, QSplitter, QScrollArea,
    QProgressBar, QSizePolicy, QAbstractItemView
)
from PyQt6.QtCore  import Qt, QThread, pyqtSignal, QTimer, QSize, QSettings
from PyQt6.QtGui   import QFont, QColor, QPalette, QIcon, QPixmap, QClipboard

# ─────────────────────────────────────────────────────────────────────────────
#  THEME
# ─────────────────────────────────────────────────────────────────────────────
DARK = """
QWidget {
    background-color: #0f0f17;
    color: #e8e8f0;
    font-family: 'Segoe UI', 'SF Pro Display', Arial, sans-serif;
    font-size: 13px;
}
QMainWindow, QDialog { background-color: #0f0f17; }

/* Sidebar */
#sidebar {
    background-color: #151521;
    border-right: 1px solid #2a2a3d;
    min-width: 200px; max-width: 220px;
}
#sidebarBrand {
    font-size: 18px; font-weight: bold;
    color: #7c6af7; padding: 20px 16px 14px;
    border-bottom: 1px solid #2a2a3d;
}
#catBtn {
    background: transparent; border: none;
    text-align: left; padding: 10px 16px;
    border-radius: 0; color: #a0a0b8;
    font-size: 13px;
}
#catBtn:hover  { background: #1e1e2e; color: #e8e8f0; }
#catBtn[active="true"] { background: #1e1e2e; color: #7c6af7; border-left: 3px solid #7c6af7; }
#sidebarAction {
    background: transparent; border: none;
    text-align: left; padding: 8px 16px;
    color: #6b6b88; font-size: 12px;
}
#sidebarAction:hover { color: #a0a0b8; }
#sidebarDanger { color: #ff4757 !important; }
#sidebarDanger:hover { color: #ff6b7a !important; }

/* Main panels */
#mainPanel { background: #0f0f17; }
#searchBar {
    background: #1a1a28; border: 1px solid #2a2a3d;
    border-radius: 8px; padding: 8px 14px;
    color: #e8e8f0; font-size: 13px;
}
#searchBar:focus { border-color: #7c6af7; }

/* Buttons */
QPushButton#btnPrimary {
    background: #7c6af7; color: white;
    border: none; border-radius: 7px;
    padding: 9px 18px; font-weight: 600;
}
QPushButton#btnPrimary:hover   { background: #9580ff; }
QPushButton#btnPrimary:pressed { background: #6458d4; }
QPushButton#btnSecondary {
    background: #1e1e2e; color: #a0a0b8;
    border: 1px solid #2a2a3d; border-radius: 7px;
    padding: 9px 18px;
}
QPushButton#btnSecondary:hover { background: #252538; color: #e8e8f0; }
QPushButton#btnDanger {
    background: transparent; color: #ff4757;
    border: 1px solid #ff475733; border-radius: 7px;
    padding: 9px 18px;
}
QPushButton#btnDanger:hover { background: #ff475711; }
QPushButton#btnIcon {
    background: #1a1a28; border: 1px solid #2a2a3d;
    border-radius: 6px; padding: 5px 8px;
    font-size: 14px; min-width: 30px;
}
QPushButton#btnIcon:hover { background: #252538; border-color: #7c6af7; }

/* Table */
QTableWidget {
    background: #0f0f17; border: none;
    gridline-color: #1e1e2e;
    selection-background-color: #1e1e2e;
}
QTableWidget::item { padding: 10px 12px; border-bottom: 1px solid #1a1a28; }
QTableWidget::item:selected { background: #1e1e2e; color: #e8e8f0; }
QHeaderView::section {
    background: #151521; color: #6b6b88;
    border: none; border-bottom: 1px solid #2a2a3d;
    padding: 10px 12px; font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.05em;
}

/* Inputs */
QLineEdit, QTextEdit, QComboBox {
    background: #1a1a28; border: 1px solid #2a2a3d;
    border-radius: 7px; padding: 9px 12px; color: #e8e8f0;
}
QLineEdit:focus, QTextEdit:focus, QComboBox:focus { border-color: #7c6af7; }
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView { background: #1a1a28; border: 1px solid #2a2a3d; }

/* Progress / slider */
QProgressBar {
    background: #1a1a28; border: none; border-radius: 4px; height: 6px;
}
QProgressBar::chunk { border-radius: 4px; }
QSlider::groove:horizontal {
    background: #1a1a28; height: 4px; border-radius: 2px;
}
QSlider::handle:horizontal {
    background: #7c6af7; width: 16px; height: 16px;
    border-radius: 8px; margin: -6px 0;
}
QSlider::sub-page:horizontal { background: #7c6af7; border-radius: 2px; }

/* Scroll */
QScrollBar:vertical { background: #0f0f17; width: 6px; }
QScrollBar::handle:vertical { background: #2a2a3d; border-radius: 3px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }

/* Labels */
#labelMuted  { color: #6b6b88; }
#labelAccent { color: #7c6af7; font-weight: bold; }
#labelGood   { color: #00e676; }
#labelWarn   { color: #ffd32a; }
#labelBad    { color: #ff4757; }

/* Card */
#card {
    background: #151521; border: 1px solid #2a2a3d;
    border-radius: 10px; padding: 16px;
}

/* Score ring label */
#scoreNum { font-size: 36px; font-weight: bold; }

/* Auth screens */
#authCard {
    background: #151521; border: 1px solid #2a2a3d;
    border-radius: 14px; padding: 40px 48px;
    min-width: 380px; max-width: 420px;
}
#authTitle {
    font-size: 22px; font-weight: bold; color: #7c6af7;
    margin-bottom: 6px;
}
#authSubtitle { color: #6b6b88; font-size: 13px; margin-bottom: 24px; }

/* Toast-like status bar */
#statusBar {
    background: #151521; border-top: 1px solid #2a2a3d;
    padding: 6px 16px; color: #6b6b88; font-size: 11px;
}
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
        for cat in ("Other","Social","Banking","Work","Shopping","Entertainment"):
            self.category.addItem(cat)

        self.notes = QTextEdit(); self.notes.setPlaceholderText("Recovery email, 2FA backup…")
        self.notes.setMaximumHeight(70)

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
        lay.addRow("Notes",      self.notes)
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
        return {
            'site'    : self.site.text().strip(),
            'username': self.username.text().strip(),
            'password': self.password.text(),
            'category': self.category.currentText(),
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
        self.score_label.setStyleSheet(f"font-size: 36px; font-weight: bold; color: {c};")
        self.score_text.setText(f"Health: {data['score_label']}")
        self.score_badges.setText(
            f"⚠️ {data['weak_count']} Weak   "
            f"🔁 {data['reused_count']} Reused   "
            f"📅 {data['old_count']} Old")

        # Sections
        self._add_section("⚠️ Weak Passwords", data['weak'],
            lambda e: f"{e['site']}  —  {e['strength_label']} ({e['strength_percent']}%)",
            data['weak_count'])
        self._add_section("🔁 Reused Passwords",
            [s for g in data['reused'] for s in g['sites']],
            lambda e: f"{e['site']}  —  same password reused",
            data['reused_count'])
        self._add_section("📅 Old Passwords", data['old'],
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
            row_lay.setContentsMargins(12, 8, 12, 8)
            info = QLabel(f"<b>{e['site']}</b><br>"
                          f"<span style='color:#6b6b88;font-size:11px'>{label_fn(e)}</span>")
            info.setTextFormat(Qt.TextFormat.RichText)
            btn = QPushButton("Fix ✏️")
            btn.setObjectName("btnSecondary")
            btn.setFixedWidth(70)
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

        self.setWindowTitle("🔐 VaultX — Password Manager")
        self.setMinimumSize(960, 620)
        self._build_ui()
        self._load_entries()
        self._update_stats()

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QHBoxLayout(central); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)

        # ── SIDEBAR ──────────────────────────────────────────────────────────
        self._sidebar = QWidget(); self._sidebar.setObjectName("sidebar")
        sb_lay = QVBoxLayout(self._sidebar); sb_lay.setContentsMargins(0, 0, 0, 0); sb_lay.setSpacing(0)

        brand = QLabel("🔐  VaultX"); brand.setObjectName("sidebarBrand")
        sb_lay.addWidget(brand)

        # Nav
        nav_label = QLabel("  VIEW"); nav_label.setObjectName("labelMuted")
        nav_label.setContentsMargins(16, 12, 0, 4)
        nav_label.setStyleSheet("font-size:10px;letter-spacing:.08em;color:#4a4a60;")
        sb_lay.addWidget(nav_label)

        self.nav_passwords = QPushButton("🗝   Passwords")
        self.nav_health    = QPushButton("🛡   Health Audit")
        for btn, active in ((self.nav_passwords, True), (self.nav_health, False)):
            btn.setObjectName("catBtn")
            btn.setProperty("active", "true" if active else "false")
            btn.setFlat(True); btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            sb_lay.addWidget(btn)
        self.nav_passwords.clicked.connect(lambda: self._switch_tab(0))
        self.nav_health.clicked.connect(lambda: self._switch_tab(1))

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

        # Bottom actions
        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("border-top: 1px solid #2a2a3d;"); sb_lay.addWidget(sep)

        btn_gen  = QPushButton("⚡  Generate Password"); btn_gen.setObjectName("sidebarAction")
        btn_lock = QPushButton("🔒  Lock Vault");       btn_lock.setObjectName("sidebarAction")
        btn_lock.setProperty("class", "danger")
        btn_gen.clicked.connect(self._open_generator)
        btn_lock.clicked.connect(self._lock)
        for b in (btn_gen, btn_lock):
            b.setFlat(True)
            b.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            sb_lay.addWidget(b)

        root.addWidget(self._sidebar)

        # ── RIGHT PANEL ───────────────────────────────────────────────────────
        right = QWidget(); right.setObjectName("mainPanel")
        right_lay = QVBoxLayout(right); right_lay.setContentsMargins(0, 0, 0, 0); right_lay.setSpacing(0)

        # Toolbar
        toolbar = QWidget()
        toolbar.setStyleSheet("background:#151521;border-bottom:1px solid #2a2a3d;padding:10px;")
        tb_lay = QHBoxLayout(toolbar); tb_lay.setContentsMargins(16, 8, 16, 8)
        self.search = QLineEdit(); self.search.setObjectName("searchBar")
        self.search.setPlaceholderText("🔍  Search sites, usernames…")
        self.search.textChanged.connect(self._filter_search)
        self.search.setMinimumWidth(260)
        btn_add = QPushButton("+ Add Password"); btn_add.setObjectName("btnPrimary")
        btn_add.clicked.connect(self._add_entry)
        tb_lay.addWidget(self.search, 1); tb_lay.addWidget(btn_add)
        right_lay.addWidget(toolbar)

        # Stacked: passwords / health
        self.stack = QStackedWidget()

        # Page 0 — Password table
        pw_page = QWidget()
        pw_lay = QVBoxLayout(pw_page); pw_lay.setContentsMargins(0, 0, 0, 0); pw_lay.setSpacing(0)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Site", "Username", "Category", "Added", "Actions"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(2, 120); self.table.setColumnWidth(3, 100)
        self.table.setColumnWidth(4, 140)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(False)
        pw_lay.addWidget(self.table)

        # Reveal bar
        self._reveal_bar = QWidget()
        self._reveal_bar.setStyleSheet("background:#151521;border-top:1px solid #2a2a3d;padding:6px 16px;")
        rev_lay = QHBoxLayout(self._reveal_bar); rev_lay.setContentsMargins(0, 0, 0, 0)
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

        # Page 1 — Health
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
        self.nav_health.setProperty("active",    "true" if idx == 1 else "false")
        self.nav_passwords.setStyle(self.nav_passwords.style())
        self.nav_health.setStyle(self.nav_health.style())
        # Hide category sidebar when on health tab
        for cat_btn in self._cat_buttons.values():
            cat_btn.setVisible(idx == 0)
        if idx == 1:
            self.health_panel.run_audit()

    # ── Data loading ──────────────────────────────────────────────────────────
    def _load_entries(self):
        self._entries = self.vault.list_all()
        self._render_table(self._entries)

    def _render_table(self, entries):
        self.table.setRowCount(0)
        self.table.setRowCount(len(entries))
        for row, e in enumerate(entries):
            self.table.setItem(row, 0, QTableWidgetItem(e['site']))
            self.table.setItem(row, 1, QTableWidgetItem(e['username'] or '—'))
            self.table.setItem(row, 2, QTableWidgetItem(e['category']))
            self.table.setItem(row, 3, QTableWidgetItem(e['created_at'][:10]))
            self.table.setRowHeight(row, 44)

            # Action buttons widget
            actions = QWidget()
            a_lay = QHBoxLayout(actions); a_lay.setContentsMargins(4, 2, 4, 2); a_lay.setSpacing(4)
            eid = e['id']
            for icon, fn in [("📋", lambda _, i=eid: self._copy_pw(i)),
                             ("👁",  lambda _, i=eid: self._show_pw(i)),
                             ("✏️", lambda _, i=eid: self._edit_by_id(i)),
                             ("🗑",  lambda _, i=eid, r=row: self._delete_entry(i))]:
                b = QPushButton(icon); b.setObjectName("btnIcon")
                b.setFixedSize(QSize(30, 30)); b.clicked.connect(fn)
                a_lay.addWidget(b)
            self.table.setCellWidget(row, 4, actions)

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
        filtered = [
            e for e in self._entries
            if (self._current_cat == 'all' or e['category'] == self._current_cat)
            and (not term or term in e['site'].lower() or term in (e['username'] or '').lower())
        ]
        self._render_table(filtered)

    # ── CRUD ──────────────────────────────────────────────────────────────────
    def _add_entry(self):
        dlg = EntryDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            d = dlg.get_data()
            self.vault.add_password(d['site'], d['username'], d['password'], d['category'], d['notes'])
            self._load_entries(); self._update_stats()
            self._set_status("✅  Password saved.")

    def _edit_by_id(self, eid):
        entry = self.vault.get_full_entry(eid)
        if not entry: return
        dlg = EntryDialog(self, entry)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            d = dlg.get_data()
            self.vault.update_password(eid, d['site'], d['username'], d['password'], d['category'], d['notes'])
            self._load_entries(); self._update_stats()
            self._set_status("✅  Entry updated.")

    def _delete_entry(self, eid):
        reply = QMessageBox.question(self, "Delete", "Delete this password? Cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        if reply == QMessageBox.StandardButton.Yes:
            self.vault.delete_password(eid)
            self._load_entries(); self._update_stats()
            self._set_status("🗑  Entry deleted.")

    # ── Password reveal / copy ─────────────────────────────────────────────────
    def _copy_pw(self, eid):
        entry = self.vault.get_full_entry(eid)
        if not entry: return
        QApplication.clipboard().setText(entry['password'])
        self._clip_timer.start(30_000)
        self._set_status("📋  Password copied — clears in 30 seconds.")

    def _show_pw(self, eid):
        entry = self.vault.get_full_entry(eid)
        if not entry: return
        self._reveal_site.setText(entry['site'] + "  ")
        self._reveal_pw.setText(entry['password'])
        self._reveal_breach.setText("")
        self._reveal_bar.setVisible(True)
        self._current_reveal_entry = entry

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
        btn_eye.toggled.connect(lambda on: self.pw_input.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))

        self.btn_unlock = QPushButton("🔓  Unlock"); self.btn_unlock.setObjectName("btnPrimary")
        self.btn_unlock.clicked.connect(self._try_login)

        self.error_label = QLabel()
        self.error_label.setObjectName("labelBad")
        self.error_label.setWordWrap(True)
        self.error_label.setVisible(False)

        for w in (title, subtitle, self.pw_input, btn_eye, self.btn_unlock, self.error_label):
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
            self.key = derive_key(pw)
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

        btn_create = QPushButton("✓  Create Vault"); btn_create.setObjectName("btnPrimary")
        btn_create.clicked.connect(self._create)

        self.err = QLabel(); self.err.setObjectName("labelBad"); self.err.setVisible(False)

        for w in (title, sub, self.pw1, self.strength_bar, self.strength_label,
                  self.pw2, btn_create, self.err):
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
        self.accept()

    def _show_err(self, msg):
        self.err.setText(msg); self.err.setVisible(True)


# ─────────────────────────────────────────────────────────────────────────────
#  APP FLOW
# ─────────────────────────────────────────────────────────────────────────────
_vault_window = None

def _show_login():
    global _vault_window
    win = LoginWindow()
    if win.exec() == QDialog.DialogCode.Accepted:
        _vault_window = VaultWindow(win.key)
        _vault_window.show()
    else:
        QApplication.instance().quit()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("VaultX")
    app.setStyleSheet(DARK)

    if not master_password_exists():
        setup = SetupWindow()
        if setup.exec() != QDialog.DialogCode.Accepted:
            sys.exit(0)

    _show_login()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
