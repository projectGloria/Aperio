"""Dispatcher tests: two-pool concurrency, missing-tool dedup, cancel,
Electron runtime-stub rule, output mirroring and REPORT.md."""
from __future__ import annotations

import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import samplegen as sg  # noqa: E402
from aperio.core import procutil  # noqa: E402
from aperio.core.dispatcher import Dispatcher  # noqa: E402
from aperio.core.events import TaskCompleted, TaskLog  # noqa: E402
from aperio.core.models import DispatchOptions  # noqa: E402
from aperio.plugins import all_plugins  # noqa: E402
from aperio.plugins.base import DecompilerPlugin, PluginResult  # noqa: E402


class SleepPlugin(DecompilerPlugin):
    """Runs a real child process (python sleep) and records peak concurrency."""

    def __init__(self, name, magic, pool, seconds=0.6, available=True):
        self.name, self.magic, self.pool = name, magic, pool
        self.priority = 1 if pool == "fast" else 2
        self.seconds, self.available = seconds, available
        self.active = self.peak = 0
        self.lock = threading.Lock()

    def detect(self, file_path, header_bytes):
        return header_bytes.startswith(self.magic)

    def is_available(self):
        return (True, "ok") if self.available else (False, "not installed")

    def install_hint(self):
        return f"install {self.name}"

    def run(self, file_path, out_dir, timeout, cancel_event, log=None):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            res = self.exec([sys.executable, "-c", f"import time; time.sleep({self.seconds})"],
                            timeout, cancel_event, log)
        finally:
            with self.lock:
                self.active -= 1
        if not res.ok:
            return self.failure(res, timeout)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "out.txt").write_text("done")
        return PluginResult(True, output_path=out_dir, commands=[res.command])


class DispatcherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="aperio_disp_"))
        self.src = self.tmp / "src"
        self.out = self.tmp / "out"
        self.src.mkdir()

    def tearDown(self):
        procutil.kill_all()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make(self, rel, data):
        p = self.src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def _run(self, plugins, **opts):
        events = []
        d = Dispatcher(self.src, DispatchOptions(out_dir=self.out, **opts), plugins=plugins)
        d.subscribe(events.append)
        return d, d.run(), events

    def test_two_pools_and_mirroring(self):
        fast = SleepPlugin("FAST", b"FAST", "fast")
        heavy = SleepPlugin("HEAVY", b"HEAVY", "heavy")
        for i in range(6):
            self._make(f"a/f{i}.bin", b"FAST" + bytes([i]))
        for i in range(3):
            self._make(f"b/h{i}.bin", b"HEAVY" + bytes([i]))
        self._make("readme.txt", b"just text")
        _d, res, _ev = self._run([fast, heavy], jobs=3, heavy_jobs=1)
        self.assertEqual((res.total, res.succeeded, res.skipped), (10, 9, 1))
        self.assertEqual(heavy.peak, 1, "heavy pool must be serialized")
        self.assertGreaterEqual(fast.peak, 2)
        self.assertLessEqual(fast.peak, 3)
        self.assertTrue((self.out / "a" / "f0.bin_unpacked" / "out.txt").is_file())
        report = (self.out / "REPORT.md").read_text(encoding="utf-8")
        self.assertIn("| Succeeded | 9 |", report)
        self.assertIn("Skipped — Non-executable/Asset", report)

    def test_missing_tool_logged_once(self):
        missing = SleepPlugin("CFRX", b"CAFE", "fast", available=False)
        for i in range(25):
            self._make(f"c{i}.class", b"CAFE" + bytes([i]))
        _d, res, events = self._run([missing])
        hints = [e for e in events if isinstance(e, TaskLog) and "[missing tool]" in e.line]
        self.assertEqual(len(hints), 1)
        reasons = {e.status_text for e in events if isinstance(e, TaskCompleted)}
        self.assertEqual(reasons, {"Skipped (Missing Tool: CFRX)"})
        self.assertEqual(res.skipped, 25)

    def test_cancel_mid_batch(self):
        slow = SleepPlugin("SLOW", b"SLOW", "fast", seconds=30)
        for i in range(8):
            self._make(f"s{i}", b"SLOW" + bytes([i]))
        d = Dispatcher(self.src, DispatchOptions(out_dir=self.out, jobs=2), plugins=[slow])
        result = []
        t = threading.Thread(target=lambda: result.append(d.run()))
        started = time.monotonic()
        t.start()
        while slow.active < 2 and time.monotonic() - started < 15:
            time.sleep(0.05)
        d.cancel()
        t.join(timeout=30)
        self.assertFalse(t.is_alive())
        self.assertLess(time.monotonic() - started, 20)
        self.assertTrue(result[0].cancelled)
        statuses = [x.status_text for x in d.tasks]
        self.assertEqual(statuses.count("Failed (Cancelled)"), 2)
        self.assertEqual(statuses.count("Skipped (Cancelled)"), 6)

    def test_electron_runtime_stub_rule(self):
        app = "MyApp"
        self._make(f"{app}/MyApp.exe", sg.make_pe())
        self._make(f"{app}/ffmpeg.dll", sg.make_pe())
        self._make(f"{app}/swiftshader/libEGL.dll", sg.make_pe())
        self._make(f"{app}/helper/tool.dll", sg.make_pe())
        sg.make_asar(self.src / app / "resources" / "app.asar", {"main.js": b"x"})
        self._make("Unrelated/other.exe", sg.make_pe())
        d, _res, _ev = self._run(all_plugins(), skip_native=False)
        by_name = {t.rel_path.as_posix(): t.status_text for t in d.tasks}
        stub = "Skipped (Electron Runtime Stub)"
        self.assertEqual(by_name[f"{app}/MyApp.exe"], stub)
        self.assertEqual(by_name[f"{app}/ffmpeg.dll"], stub)
        self.assertEqual(by_name[f"{app}/swiftshader/libEGL.dll"], stub)
        self.assertNotEqual(by_name[f"{app}/helper/tool.dll"], stub)
        self.assertNotEqual(by_name["Unrelated/other.exe"], stub)
        asar_task = next(t for t in d.tasks if t.rel_path.name == "app.asar")
        self.assertEqual(asar_task.plugin_name, "asar")

    def test_single_file_target_not_stub(self):
        self._make("MyApp/MyApp.exe", sg.make_pe())
        sg.make_asar(self.src / "MyApp" / "resources" / "app.asar", {"main.js": b"x"})
        d = Dispatcher(self.src / "MyApp" / "MyApp.exe",
                       DispatchOptions(out_dir=self.out, skip_native=True))
        d.run()
        self.assertEqual(d.tasks[0].status_text, "Skipped (Native Disabled)")
        self.assertEqual(d.tasks[0].detected_format, "Native (PE32+, x64)")


if __name__ == "__main__":
    unittest.main()
