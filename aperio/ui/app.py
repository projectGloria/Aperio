"""QApplication bootstrap."""
from __future__ import annotations

import sys


def run_gui() -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("PySide6 is not installed. Install it with:  pip install PySide6\n"
              "(or use the headless CLI: python aperio.py <file-or-dir>)", file=sys.stderr)
        return 2
    from ..config import consume_first_run_notice
    from ..core import procutil
    from .main_window import MainWindow

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("Aperio")
    app.setStyle("Fusion")
    window = MainWindow(notice=consume_first_run_notice())
    window.show()
    app.aboutToQuit.connect(procutil.kill_all)
    return app.exec()
