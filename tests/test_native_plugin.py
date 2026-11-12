"""Ghidra launcher path staging: paths with cmd.exe metacharacters such as
"C:\\Program Files (x86)\\..." break Ghidra's launch.bat and must be staged."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aperio.plugins import native_plugin as np  # noqa: E402


@unittest.skipUnless(os.name == "nt", "launcher quirk is Windows-only")
class LauncherSafeTests(unittest.TestCase):
    def test_detects_unsafe(self):
        self.assertFalse(np._is_launcher_safe(Path(r"C:\Program Files (x86)\a.exe")))
        self.assertFalse(np._is_launcher_safe(Path(r"C:\x\bang!.exe")))
        self.assertTrue(np._is_launcher_safe(Path(r"C:\Program Files\a b.exe")))

    def test_stages_unsafe_path(self):
        with tempfile.TemporaryDirectory() as d:
            src_dir = Path(d) / "Prog (x86)"
            src_dir.mkdir()
            src = src_dir / "my app(1).exe"
            src.write_bytes(b"MZ" + b"\0" * 64)
            staged = np._launcher_safe(src, Path(d) / "in", None)
            self.assertNotEqual(staged, src)
            self.assertTrue(np._is_launcher_safe(staged))
            self.assertEqual(staged.read_bytes(), src.read_bytes())

    def test_safe_path_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "plain.exe"
            src.write_bytes(b"MZ")
            self.assertEqual(np._launcher_safe(src, Path(d) / "in", None), src)


if __name__ == "__main__":
    unittest.main()
