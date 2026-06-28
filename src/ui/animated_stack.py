from PyQt6.QtWidgets import QStackedWidget
from PyQt6.QtCore import QPropertyAnimation, QEasingCurve

class AnimatedStack(QStackedWidget):
    """
    Drop-in replacement for QStackedWidget with fade transitions.
    Usage: self.stack.slide_to(index)
    """
    def slide_to(self, index: int, duration: int = 350):
        current = self.currentWidget()
        next_w  = self.widget(index)
        
        # Fade out current
        out_anim = QPropertyAnimation(current, b'windowOpacity')
        out_anim.setDuration(duration // 2)
        out_anim.setStartValue(1.0)
        out_anim.setEndValue(0.0)
        out_anim.setEasingCurve(QEasingCurve.Type.InCubic)
        
        # Fade in next
        in_anim = QPropertyAnimation(next_w, b'windowOpacity')
        in_anim.setDuration(duration // 2)
        in_anim.setStartValue(0.0)
        in_anim.setEndValue(1.0)
        in_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        
        out_anim.finished.connect(lambda: (self.setCurrentIndex(index), in_anim.start()))
        out_anim.start()
