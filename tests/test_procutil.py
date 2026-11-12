"""Process-tree termination tests: a launcher spawns a grandchild; cancel and
timeout must kill BOTH (no orphaned child processes)."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aperio.core import procutil  # noqa: E402

CHILD = textwrap.dedent("""
    import os, subprocess, sys, time
    pidfile = sys.argv[1]
    if len(sys.argv) > 2:          # grandchild
        open(pidfile, "w").write(str(os.getpid())); time.sleep(120)
    else:
        subprocess.Popen([sys.executable, __file__, pidfile, "gc"])
        print("parent ready", flush=True); time.sleep(120)
""")


def pid_alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        code = ctypes.c_ulong()
        k32.GetExitCodeProcess(h, ctypes.byref(code))
        k32.CloseHandle(h)
        return code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:  # zombie (reaped by init later) counts as dead
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split()[2] != "Z"
    except OSError:
        return True


class ProcUtilTests(unittest.TestCase):
    def setUp(self):
        # deliberately hostile directory name: spaces and cmd metacharacters
        self.tmp = Path(tempfile.mkdtemp(prefix="aperio proc & test "))
        self.script = self.tmp / "child.py"
        self.script.write_text(CHILD)
        self.pidfile = self.tmp / "gc.pid"

    def tearDown(self):
        procutil.kill_all()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _cmd(self):
        if os.name == "nt":  # go through a .bat launcher like jadx.bat / analyzeHeadless.bat
            bat = self.tmp / "launch.bat"
            bat.write_text(f'@echo off\r\n"{sys.executable}" %*\r\n')
            return [str(bat), str(self.script), str(self.pidfile)]
        return [sys.executable, str(self.script), str(self.pidfile)]

    def _wait_pid(self) -> int:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.pidfile.exists() and self.pidfile.read_text().strip():
                return int(self.pidfile.read_text())
            time.sleep(0.05)
        self.fail("grandchild never started")

    def test_cancel_kills_whole_tree(self):
        cancel = threading.Event()
        lines: list[tuple[str, str]] = []
        out: list = []
        t = threading.Thread(target=lambda: out.append(procutil.run(
            self._cmd(), timeout=60, cancel_event=cancel,
            on_line=lambda s, l: lines.append((s, l)))))
        t.start()
        gc_pid = self._wait_pid()
        self.assertTrue(pid_alive(gc_pid))
        cancel.set()
        t.join(timeout=20)
        self.assertFalse(t.is_alive())
        self.assertTrue(out[0].cancelled)
        time.sleep(0.5)
        self.assertFalse(pid_alive(gc_pid), "grandchild was orphaned")
        self.assertIn(("stdout", "parent ready"), lines)
        self.assertEqual(lines[0][0], "cmd")

    def test_timeout_kills_whole_tree(self):
        res_holder: list = []
        t = threading.Thread(target=lambda: res_holder.append(procutil.run(
            self._cmd(), timeout=4, cancel_event=threading.Event())))
        t.start()
        gc_pid = self._wait_pid()
        t.join(timeout=30)
        self.assertTrue(res_holder[0].timed_out)
        time.sleep(0.5)
        self.assertFalse(pid_alive(gc_pid), "grandchild survived timeout")

    def test_kill_all(self):
        t = threading.Thread(target=lambda: procutil.run(
            self._cmd(), timeout=60, cancel_event=threading.Event()))
        t.start()
        gc_pid = self._wait_pid()
        self.assertGreaterEqual(procutil.kill_all(), 1)
        t.join(timeout=20)
        time.sleep(0.5)
        self.assertFalse(pid_alive(gc_pid))

    def test_normal_exit_and_quoting(self):
        # NB: cmd.exe expands %VAR% even inside quotes; that is documented, not tested
        weird = self.tmp / "out & file (1) ^x.txt"
        code = "import sys; open(sys.argv[1], 'w').write('ok'); print(sys.argv[1])"
        cmd = [sys.executable, "-c", code, str(weird)]
        if os.name == "nt":
            bat = self.tmp / "py.bat"
            bat.write_text(f'@echo off\r\n"{sys.executable}" %*\r\n')
            cmd[0] = str(bat)
        res = procutil.run(cmd, timeout=30, cancel_event=threading.Event())
        self.assertTrue(res.ok, res.stderr)
        self.assertTrue(weird.exists())
        self.assertEqual(res.stdout.strip(), str(weird))


if __name__ == "__main__":
    unittest.main()
