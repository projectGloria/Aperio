"""Detector tests against synthetic headers and (when present) real host files."""
from __future__ import annotations

import os
import py_compile
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import samplegen as sg  # noqa: E402
from aperio.core import detector  # noqa: E402
from aperio.plugins import all_plugins  # noqa: E402


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="aperio_det_"))
        self.plugins = all_plugins()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name: str, data: bytes) -> Path:
        p = self.tmp / name
        p.write_bytes(data)
        return p

    def plugin_for(self, path: Path) -> str | None:
        plugin, _ = detector.classify(path, self.plugins)
        return plugin.name if plugin else None

    # ---- native family -------------------------------------------------
    def test_native_pe(self):
        p = self.write("a.bin", sg.make_pe())
        info = detector.analyze(p)
        self.assertEqual(info.container, "PE")
        self.assertEqual(info.native["arch"], "x64")
        self.assertIn(".rdata", info.section_names)
        self.assertEqual(self.plugin_for(p), "Ghidra")

    def test_dotnet_requires_clr_directory(self):
        p = self.write("lib.dat", sg.make_pe(clr=True, pe32plus=False))
        self.assertTrue(detector.is_dotnet(detector.analyze(p)))
        self.assertEqual(self.plugin_for(p), "ILSpy")

    def test_extension_is_ignored(self):
        # a ".exe" that is really a .pyc must be routed to pycdc
        p = self.write("program.exe", sg.make_pyc_bytes())
        self.assertEqual(self.plugin_for(p), "pycdc")
        q = self.write("notes.txt", sg.make_pe(clr=True))
        self.assertEqual(self.plugin_for(q), "ILSpy")

    def test_pyinstaller_cookie_beats_dotnet_and_native(self):
        cookie = b"MEI\x0c\x0b\x0a\x0b\x0e" + b"\0" * 80
        p = self.write("pyi", sg.make_pe(payload=cookie))
        self.assertTrue(detector.analyze(p).pyinstaller_cookie)
        self.assertEqual(self.plugin_for(p), "PyInstaller")
        q = self.write("pyi_elf", sg.make_elf64(sections=(".text", "pydata")))
        self.assertEqual(self.plugin_for(q), "PyInstaller")

    def test_go_marker_and_sections(self):
        p = self.write("gobin", sg.make_pe(payload=b"\xff Go buildinf:\x08\x02"))
        self.assertEqual(self.plugin_for(p), "Ghidra (Go)")
        q = self.write("goelf", sg.make_elf64(sections=(".text", ".gopclntab")))
        self.assertEqual(self.plugin_for(q), "Ghidra (Go)")
        r = self.write("gomacho", sg.make_macho64(sections=(("__text", "__TEXT"),
                                                           ("__gopclntab", "__DATA_CONST"))))
        self.assertEqual(self.plugin_for(r), "Ghidra (Go)")

    def test_elf_and_macho(self):
        p = self.write("elf", sg.make_elf64())
        info = detector.analyze(p)
        self.assertEqual((info.container, info.native["arch"]), ("ELF", "x64"))
        self.assertEqual(info.section_names, {"", ".text", ".data", ".shstrtab"})
        m = self.write("macho", sg.make_macho64())
        self.assertEqual(detector.analyze(m).native["format"], "Mach-O 64")
        self.assertEqual(self.plugin_for(m), "Ghidra")

    def test_cafebabe_disambiguation(self):
        fat = self.write("fat", sg.make_fat_macho())
        cls = self.write("Foo", sg.make_class(61))
        self.assertEqual(detector.analyze(fat).container, "Mach-O")
        self.assertEqual(self.plugin_for(fat), "Ghidra")
        self.assertEqual(detector.analyze(cls).java_version, 61)
        self.assertEqual(self.plugin_for(cls), "CFR")

    # ---- archives & bytecode -------------------------------------------
    def test_asar(self):
        p = self.tmp / "app.bin"
        sg.make_asar(p, {"package.json": b'{"name":"x"}', "main.js": b"1"})
        info = detector.analyze(p)
        self.assertEqual((info.container, info.asar_files), ("ASAR", 2))
        self.assertEqual(self.plugin_for(p), "asar")

    def test_apk_vs_jar_vs_plain_zip(self):
        apk, jar, war, plain = (self.tmp / n for n in ("a.zip", "b.zip", "c.zip", "d.jar"))
        sg.make_zip(apk, ["AndroidManifest.xml", "classes.dex", "META-INF/MANIFEST.MF"])
        sg.make_zip(jar, ["META-INF/MANIFEST.MF", "com/x/A.class"])
        sg.make_zip(war, ["WEB-INF/classes/com/x/S.class"])
        sg.make_zip(plain, ["readme.txt"])
        self.assertEqual(self.plugin_for(apk), "jadx")
        self.assertEqual(self.plugin_for(jar), "CFR")
        self.assertEqual(self.plugin_for(war), "CFR")
        self.assertIsNone(self.plugin_for(plain))

    def test_dex(self):
        self.assertEqual(self.plugin_for(self.write("x", sg.make_dex())), "jadx")

    def test_pyc_validation(self):
        self.assertEqual(detector.pyc_info(sg.make_pyc_bytes(3571)), "3.13")
        self.assertEqual(detector.pyc_info(sg.make_pyc_bytes(3495)), "3.11")
        self.assertIsNone(detector.pyc_info(sg.make_pyc_bytes(3571, flags=7)))
        bad = bytearray(sg.make_pyc_bytes()); bad[16] = 0x41
        self.assertIsNone(detector.pyc_info(bytes(bad)))
        self.assertIsNone(detector.pyc_info(b"\x0d\x0a\x0d\x0a" + b"\0" * 20))

    def test_real_pyc_from_this_interpreter(self):
        src = self.tmp / "m.py"
        src.write_text("print('hi')\n")
        out = Path(py_compile.compile(str(src), cfile=str(self.tmp / "m.bin")))
        info = detector.analyze(out)
        self.assertEqual(info.pyc_version, f"{sys.version_info[0]}.{sys.version_info[1]}")

    def test_assets_and_garbage(self):
        for name, data in [("e", b""), ("t", b"hello world"), ("mz", b"MZ" + b"\0" * 10),
                           ("trunc", sg.make_pe()[:150]), ("png", b"\x89PNG\r\n\x1a\n" + b"\0" * 9)]:
            with self.subTest(name=name):
                self.assertIsNone(self.plugin_for(self.write(name, data)))

    # ---- real files on the host (skipped when absent) --------------------
    def test_real_host_python_exe(self):
        info = detector.analyze(Path(sys.executable).resolve())
        self.assertIn(info.container, ("PE", "ELF", "Mach-O"))
        self.assertFalse(detector.is_dotnet(info))

    @unittest.skipUnless(os.name == "nt", "Windows only")
    def test_real_dotnet_assembly(self):
        root = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "dotnet" / "shared"
        dlls = sorted(root.glob("Microsoft.NETCore.App/*/System.Private.CoreLib.dll"))
        if not dlls:
            self.skipTest(".NET runtime not installed")
        self.assertEqual(self.plugin_for(dlls[-1]), "ILSpy")

    def test_real_go_binary_if_present(self):
        gh = shutil.which("gh")
        if not gh:
            self.skipTest("gh (a Go binary) not on PATH")
        self.assertEqual(self.plugin_for(Path(gh)), "Ghidra (Go)")


if __name__ == "__main__":
    unittest.main()
