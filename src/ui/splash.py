from PyQt6.QtWidgets import QSplashScreen, QLabel, QVBoxLayout, QWidget, QProgressBar
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QPixmap, QColor, QFont

class VaultXSplash(QSplashScreen):
    def __init__(self):
        super().__init__()
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint)
        self.setFixedSize(480, 320)
        self._setup_ui()
        self._start_animations()
    
    def _setup_ui(self):
        self.setStyleSheet("""
            QSplashScreen {
                background-color: #070B14;
                border: 1px solid rgba(79,158,255,0.3);
                border-radius: 12px;
            }
        """)
    
    def _start_animations(self):
        self.fade_anim = QPropertyAnimation(self, b'windowOpacity')
        self.fade_anim.setDuration(600)
        self.fade_anim.setStartValue(0.0)
        self.fade_anim.setEndValue(1.0)
        self.fade_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.fade_anim.start()
