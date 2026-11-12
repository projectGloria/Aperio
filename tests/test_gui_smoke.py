"""Offscreen GUI smoke test: drives the real MainWindow through a full batch
and the doctor dialog, and measures GUI event-loop stalls while they run."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from PySide6.QtWidgets import QApplication
except ImportError:  # pragma: no cover
    QApplication = None

import samplegen as sg  # noqa: E402


@unittest.skipIf(QApplication is None, "PySide6 not installed")
class GuiSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        from aperio.ui.main_window import MainWindow
        self.tmp = Path(tempfile.mkdtemp(prefix="aperio_gui_"))
        self.src = self.tmp / "src"
        (self.src / "jars").mkdir(parents=True)
        for i in range(40):
            sg.make_zip(self.src / f"jars/lib{i}.jar", ["META-INF/MANIFEST.MF", "a/B.class"])
        (self.src / "bin").mkdir()
        (self.src / "bin" / "x.exe").write_bytes(sg.make_pe())
        (self.src / "bin" / "lib.dll").write_bytes(sg.make_pe(clr=True))
        (self.src / "readme.txt").write_text("hi")
        sg.make_asar(self.src / "app" / "resources" / "app.asar", {"main.js": b"1"})
        self.win = MainWindow(notice="test notice")
        self.win.targets.out.setText(str(self.tmp / "out"))
        self.win.show()

    def tearDown(self):
        self.win.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _pump_until(self, cond, timeout=120.0) -> float:
        """Process events until cond(); returns the worst event-loop gap (ms)."""
        worst, last = 0.0, time.perf_counter()
        deadline = time.monotonic() + timeout
        while not cond() and time.monotonic() < deadline:
            self.app.processEvents()
            now = time.perf_counter()
            worst = max(worst, (now - last) * 1000)
            last = now
            time.sleep(0.002)
        self.assertTrue(cond(), "timed out waiting for GUI condition")
        return worst

    def test_full_batch(self):
        self.win.targets.set_target(self.src)
        self.win._start()
        worst = self._pump_until(lambda: self.win.report_btn.isEnabled())
        model = self.win.model
        self.assertEqual(model.rowCount(), 44)
        self.assertEqual(self.win.progress.value(), 44)
        self.assertEqual(self.win.progress.maximum(), 44)
        counts = model.counts()
        self.assertEqual(counts["Queued"] + counts["Running"], 0)
        self.assertTrue((self.tmp / "out" / "REPORT.md").is_file())
        print(f"\n  worst GUI event-loop gap during batch: {worst:.1f} ms")
        self.assertLess(worst, 250, "GUI thread was blocked")
        # inspector shows metadata for a selected row
        self.win.table.selectRow(0)
        self.app.processEvents()
        self.assertIsNotNone(self.win.inspector.current_id)
        self.assertGreater(self.win.inspector.meta.rowCount(), 2)
        # filter bar
        self.win.status_filter.setCurrentText("Success")
        self.app.processEvents()
        self.assertEqual(self.win.proxy.rowCount(), counts["Success"])
        self.win.status_filter.setCurrentText("All")
        self.win.format_filter.setText("Java Archive")
        self.app.processEvents()
        self.assertEqual(self.win.proxy.rowCount(), 40)
        from aperio.plugins import all_plugins
        batch_log = self.win.inspector.batch.toPlainText()
        if all(p.is_available()[0] for p in all_plugins()):
            self.assertNotIn("[missing tool]", batch_log)  # full ./tools_bin install
        else:
            self.assertIn("[missing tool]", batch_log)

    def test_doctor_dialog_populates_off_thread(self):
        self.win._open_doctor()
        dlg = self.win._doctor
        self._pump_until(lambda: dlg.table.rowCount() > 0, timeout=120)
        names = {dlg.table.item(r, 0).text() for r in range(dlg.table.rowCount())}
        self.assertTrue({"CFR", "Ghidra", "jadx", "ILSpy"} <= names)
        dlg.close()


if __name__ == "__main__":
    unittest.main()
