"""End-to-end harness: build real sample binaries, run Aperio, verify results.

    python tests/create_samples.py                  # build into %TEMP%/aperio_e2e, run CLI + core, verify
    python tests/create_samples.py --dir D --no-run # only build samples

Real artefacts are compiled when the compilers exist (javac/jar -> .class/.jar,
dotnet -> C# .dll, py_compile -> .pyc); everything else uses structurally valid
synthetic headers from samplegen.py. Expectations adapt to which external tools
are installed: a file must either be processed by its tool or be reported as
"Skipped (Missing Tool: <name>)".
"""
from __future__ import annotations

import argparse
import os
import py_compile
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import samplegen as sg  # noqa: E402
from aperio.core.dispatcher import Dispatcher  # noqa: E402
from aperio.core.models import DispatchOptions  # noqa: E402
from aperio.plugins import all_plugins  # noqa: E402

JAVA_SRC = """package demo;
public class Hello {
    private final String who;
    public Hello(String who) { this.who = who; }
    public String greet() { return "Hello, " + who + "!"; }
    public static void main(String[] args) { System.out.println(new Hello("Aperio").greet()); }
}
"""
CS_SRC = 'namespace Demo { public static class Greeter { public static string Hi(string n) => "Hi " + n; } }\n'
PY_SRC = "def fib(n):\n    return n if n < 2 else fib(n - 1) + fib(n - 2)\n\nprint(fib(10))\n"


def _run(cmd, cwd=None) -> bool:
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=300).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def build(root: Path, pyinstaller: str | None = None) -> dict[str, str]:
    """Create samples; returns {relative path: expected plugin name or None}."""
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    exp: dict[str, str | None] = {}
    tmp = Path(tempfile.mkdtemp(prefix="aperio_build_"))

    # ---- Java (real javac / jar) --------------------------------------
    if shutil.which("javac"):
        (tmp / "demo").mkdir()
        (tmp / "demo" / "Hello.java").write_text(JAVA_SRC)
        if _run(["javac", "-d", str(tmp / "cls"), str(tmp / "demo" / "Hello.java")]):
            (root / "java").mkdir()
            shutil.copy(tmp / "cls" / "demo" / "Hello.class", root / "java" / "Hello.class")
            exp["java/Hello.class"] = "CFR"
            if shutil.which("jar") and _run(["jar", "cfe", str(root / "java" / "hello.jar"),
                                             "demo.Hello", "-C", str(tmp / "cls"), "."]):
                exp["java/hello.jar"] = "CFR"
            # extension lies: a class file disguised as an image
            shutil.copy(root / "java" / "Hello.class", root / "java" / "logo.png")
            exp["java/logo.png"] = "CFR"
    # ---- C# (real, only with a .NET SDK) ------------------------------
    if shutil.which("dotnet") and _run(["dotnet", "--list-sdks"]) and \
            subprocess.run(["dotnet", "--list-sdks"], capture_output=True).stdout.strip():
        proj = tmp / "cs"
        if _run(["dotnet", "new", "classlib", "-o", str(proj), "-n", "Greeter"]):
            (proj / "Class1.cs").write_text(CS_SRC)
            if _run(["dotnet", "build", "-c", "Release", "-o", str(proj / "bin_out")], cwd=proj):
                (root / "dotnet").mkdir(exist_ok=True)
                shutil.copy(proj / "bin_out" / "Greeter.dll", root / "dotnet" / "Greeter.dll")
                exp["dotnet/Greeter.dll"] = "ILSpy"
    # real managed assembly from the installed .NET runtime (no SDK needed)
    shared = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "dotnet" / "shared"
    real = sorted(shared.glob("Microsoft.NETCore.App/*/System.Runtime.dll"))
    if real:
        (root / "dotnet").mkdir(exist_ok=True)
        shutil.copy(real[-1], root / "dotnet" / "System.Runtime.dll")
        exp["dotnet/System.Runtime.dll"] = "ILSpy"
    (root / "dotnet").mkdir(exist_ok=True)
    (root / "dotnet" / "synthetic_clr.bin").write_bytes(sg.make_pe(clr=True))
    exp["dotnet/synthetic_clr.bin"] = "ILSpy"

    # ---- Python bytecode (real) ---------------------------------------
    (root / "python").mkdir()
    (tmp / "fib.py").write_text(PY_SRC)
    py_compile.compile(str(tmp / "fib.py"), cfile=str(root / "python" / "fib.pyc"))
    shutil.copy(root / "python" / "fib.pyc", root / "python" / "renamed.exe")
    exp["python/fib.pyc"] = exp["python/renamed.exe"] = "pycdc"
    # real PyInstaller one-file executable (only when a pyinstaller binary is supplied)
    if pyinstaller and _run([pyinstaller, "--onefile", "--noconfirm", "--log-level", "ERROR",
                             "--distpath", str(tmp / "dist"), "--workpath", str(tmp / "work"),
                             "--specpath", str(tmp), str(tmp / "fib.py")]):
        exe = next((tmp / "dist").glob("fib*"))
        (root / "native").mkdir(exist_ok=True)
        shutil.copy(exe, root / "native" / "real_pyinstaller.exe")
        exp["native/real_pyinstaller.exe"] = "PyInstaller"

    # ---- Native family (synthetic + real host python.exe) --------------
    (root / "native").mkdir(exist_ok=True)
    shutil.copy(Path(sys.executable).resolve(), root / "native" / "host_python.exe")
    exp["native/host_python.exe"] = "Ghidra"
    for name, data, plug in [
            ("plain_pe.exe", sg.make_pe(), "Ghidra"),
            ("tool.elf", sg.make_elf64(), "Ghidra"),
            ("tool.macho", sg.make_macho64(), "Ghidra"),
            ("universal", sg.make_fat_macho(), "Ghidra"),
            ("go_server.exe", sg.make_pe(payload=b"\xff Go buildinf:\x08\x02" + b"\0" * 32), "Ghidra (Go)"),
            ("go_cli", sg.make_elf64(sections=(".text", ".gopclntab", ".go.buildinfo")), "Ghidra (Go)"),
            ("frozen_app.exe", sg.make_pe(payload=b"\0" * 64 + b"MEI\x0c\x0b\x0a\x0b\x0e" + b"\0" * 80),
             "PyInstaller")]:
        (root / "native" / name).write_bytes(data)
        exp[f"native/{name}"] = plug

    # ---- Android -------------------------------------------------------
    (root / "android").mkdir()
    sg.make_zip(root / "android" / "app-release.apk", ["AndroidManifest.xml", "classes.dex",
                                                      "META-INF/MANIFEST.MF"])
    (root / "android" / "classes.dex").write_bytes(sg.make_dex())
    exp["android/app-release.apk"] = exp["android/classes.dex"] = "jadx"

    # ---- Electron app layout (asar is a REAL extractable archive) -------
    eroot = root / "electron" / "MyApp"
    sg.make_asar(eroot / "resources" / "app.asar",
                 {"package.json": b'{"name":"myapp","main":"main.js"}',
                  "main.js": b"console.log('hello from asar');\n"})
    (eroot / "MyApp.exe").write_bytes(sg.make_pe())
    (eroot / "ffmpeg.dll").write_bytes(sg.make_pe())
    (eroot / "d3dcompiler_47.dll").write_bytes(sg.make_pe())
    (eroot / "resources" / "native_addon.node").write_bytes(sg.make_pe())
    exp["electron/MyApp/resources/app.asar"] = "asar"
    exp["electron/MyApp/resources/native_addon.node"] = "Ghidra"
    for stub in ("MyApp.exe", "ffmpeg.dll", "d3dcompiler_47.dll"):
        exp[f"electron/MyApp/{stub}"] = "STUB"

    # ---- Assets ----------------------------------------------------------
    (root / "assets").mkdir()
    (root / "assets" / "readme.txt").write_text("not a binary")
    (root / "assets" / "fake.exe").write_bytes(b"MZ but truncated")
    (root / "assets" / "icon.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 32)
    sg.make_zip(root / "assets" / "docs.zip", ["a.txt", "b/c.md"])
    for n in ("readme.txt", "fake.exe", "icon.png", "docs.zip"):
        exp[f"assets/{n}"] = None
    shutil.rmtree(tmp, ignore_errors=True)
    return exp


def verify(tasks, exp: dict, label: str) -> list[str]:
    avail = {p.name: p.is_available()[0] for p in all_plugins()}
    errors = []
    by_rel = {t.rel_path.as_posix(): t for t in tasks}
    for rel, plug in exp.items():
        t = by_rel.get(rel)
        if t is None:
            errors.append(f"{rel}: not discovered")
            continue
        got = t.status_text
        if plug == "STUB":
            ok = got == "Skipped (Electron Runtime Stub)"
        elif plug is None:
            ok = got == "Skipped (Non-executable/Asset)"
        elif t.plugin_name != plug:
            ok = False
        elif t.pool == "heavy" and got == "Skipped (Native Disabled)":
            ok = True
        elif not avail.get(plug):
            ok = got.startswith("Skipped (Missing Tool:")
        else:
            ok = t.status.value in ("Success", "Failed")  # tool ran; failures are tool verdicts
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {rel:<45} {t.detected_format:<34} {t.plugin_name:<12} {got}")
        if not ok:
            errors.append(f"{label}: {rel}: expected {plug}, got plugin={t.plugin_name} status={got}")
    asar = by_rel.get("electron/MyApp/resources/app.asar")
    if asar and asar.status.value == "Success":
        main_js = asar.out_dir / "main.js"
        if "hello from asar" not in main_js.read_text(errors="replace"):
            errors.append("asar extraction output missing main.js")
        else:
            print("  [PASS] asar extraction produced main.js with expected content")
    for rel in ("java/Hello.class", "java/hello.jar", "java/logo.png"):
        t = by_rel.get(rel)
        if t and t.status.value == "Success":
            src = next(t.out_dir.rglob("Hello.java"), None)
            if not src or "greet()" not in src.read_text(errors="replace"):
                errors.append(f"{rel}: CFR output lacks Hello.greet()")
            else:
                print(f"  [PASS] CFR reconstructed Hello.greet() from {rel}")
    pyi = by_rel.get("native/real_pyinstaller.exe")
    if pyi and pyi.status.value == "Success":
        if not any(pyi.out_dir.rglob("fib.pyc")):
            errors.append("real PyInstaller exe: entry point fib.pyc not extracted")
        else:
            print("  [PASS] pyinstxtractor extracted entry point fib.pyc from a real PyInstaller exe")
    return errors


def live_plugin_checks(samples: Path, out: Path) -> list[str]:
    """Run plugins directly where routing alone cannot exercise them live."""
    import threading
    from aperio.plugins.android_plugin import AndroidPlugin
    errors = []
    cls = samples / "java" / "Hello.class"
    plugin = AndroidPlugin()
    if cls.is_file() and plugin.is_available()[0]:
        res = plugin.run(cls, out / "jadx_direct", 300, threading.Event())
        src = next((out / "jadx_direct").rglob("Hello.java"), None)
        if res.success and src and "greet" in src.read_text(errors="replace"):
            print("  [PASS] jadx (direct) decompiled Hello.class -> Hello.java")
        else:
            errors.append(f"jadx direct run failed: {res.error}")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    # default outside the repo: editors/IDEs built on Electron lock *.asar files they index
    tmp_root = Path(tempfile.gettempdir()) / "aperio_e2e"
    ap.add_argument("--dir", type=Path, default=tmp_root / "samples")
    ap.add_argument("--out", type=Path, default=tmp_root / "samples_out")
    ap.add_argument("--no-run", action="store_true")
    ap.add_argument("--skip-native", action="store_true", default=False)
    ap.add_argument("--pyinstaller", default=shutil.which("pyinstaller"),
                    help="pyinstaller executable used to build a real one-file sample")
    args = ap.parse_args()
    exp = build(args.dir, args.pyinstaller)
    print(f"Built {len(exp)} samples in {args.dir}")
    if args.no_run:
        return 0
    errors: list[str] = []

    print("\n== Core pipeline (in-process Dispatcher) ==")
    core_out = args.out / "core"
    shutil.rmtree(core_out, ignore_errors=True)
    d = Dispatcher(args.dir, DispatchOptions(out_dir=core_out, jobs=4, timeout=300,
                                             skip_native=args.skip_native))
    d.run()
    errors += verify(d.tasks, exp, "core")
    if not (core_out / "REPORT.md").is_file():
        errors.append("core: REPORT.md missing")
    errors += live_plugin_checks(args.dir, args.out)

    print("\n== CLI (subprocess: python aperio.py <dir> --out ...) ==")
    cli_out = args.out / "cli"
    shutil.rmtree(cli_out, ignore_errors=True)
    cmd = [sys.executable, str(ROOT / "aperio.py"), str(args.dir), "--out", str(cli_out),
           "--jobs", "4", "--timeout", "300"] + (["--skip-native"] if args.skip_native else [])
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800,
                          encoding="utf-8", errors="replace")
    print("\n".join("  | " + ln for ln in proc.stdout.splitlines()[-12:]))
    report = cli_out / "REPORT.md"
    if not report.is_file():
        errors.append("cli: REPORT.md missing")
    else:
        text = report.read_text(encoding="utf-8")
        if f"| Total | {len(exp)} |" not in text:
            errors.append(f"cli: REPORT.md total mismatch (expected {len(exp)})")
        print(f"  [PASS] CLI REPORT.md written: {report}")

    print("\n== Result ==")
    for e in errors:
        print("  FAIL:", e)
    print("ALL CHECKS PASSED" if not errors else f"{len(errors)} CHECK(S) FAILED")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
