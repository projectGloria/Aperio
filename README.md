# Aperio

Aperio is a modular binary inspection and decompiler dispatcher. You give it a
file or a folder. It identifies every file **by content** (magic bytes, PE data
directories, ELF/Mach-O section tables, ZIP central directories, never the file
extension), sends each one to the right external unpacker or decompiler, and
writes a mirrored output tree plus a `REPORT.md`.

It comes with a PySide6 desktop GUI and a headless CLI, which share the same
core (`aperio/core` has no UI imports). See [DESIGN.md](DESIGN.md) for the
architecture.

> **Notice:** Only unpack or decompile software you own, open-source software,
> or binaries where you have explicit authorization/license permission.

## Usage

```text
python aperio.py                                            # Desktop GUI
python aperio.py --ui                                       # Desktop GUI (explicit)
python aperio.py <file-or-dir> [--out ./output] [--jobs 4]  # headless CLI
python aperio.py --doctor                                   # toolchain health table
python aperio.py --setup                                    # download portable tools + print install commands
```

Extra CLI options: `--timeout SECONDS` (per task, default 900), `--heavy-jobs {1,2}`
(concurrent Ghidra instances), `--skip-native`, `--copy-assets`, `-v` (stream tool output).
Pressing Ctrl+C cancels the batch and kills every running process tree.

Output layout: `<out>/<relative path>/<filename>_unpacked/` for each processed
file, plus `<out>/REPORT.md` (summary by status and reason, plus a per-file table).

## Supported formats (in detection order)

| # | Format | Tool |
|---|--------|------|
| 1 | Electron `app.asar` (Pickle header) | `asar extract` / `npx --yes @electron/asar extract` |
| 2 | PyInstaller (PE/ELF + `MEI` cookie or `pydata`) | `pyinstxtractor-ng` / `pyinstxtractor.py`, then `pycdc` on entry points |
| 3 | .NET assembly (CLR data directory #14) | `ilspycmd -p -o` |
| 4 | Android APK / DEX | `jadx -d` |
| 5 | Java `.class` / JAR / WAR | `java -jar cfr.jar --outputdir` |
| 6 | Python `.pyc` | `pycdc` |
| 7 | Go binary (`\xff Go buildinf:` / `.gopclntab`) | Ghidra `analyzeHeadless` + `scripts/ExportDecompiled.java` |
| 8 | Native PE / ELF / Mach-O | Ghidra `analyzeHeadless` + `scripts/ExportDecompiled.java` |
| 9 | Anything else | `SKIPPED (Non-executable/Asset)` (or copied with `--copy-assets`) |

When a folder contains `resources/app.asar`, the Electron stub `.exe` and the
Chromium runtime DLLs next to it are marked `SKIPPED (Electron Runtime Stub)`.

## Windows setup (exact steps)

Run these in PowerShell. Each tool is optional; files whose tool is missing are
reported as `SKIPPED (Missing Tool: <name>)`, and the install hint is printed once.

```powershell
# 1. Python 3.11+ and the GUI toolkit
winget install Python.Python.3.12
pip install PySide6

# 2. Java (CFR, jadx, Ghidra). Ghidra 11.2+ needs JDK 21.
winget install EclipseAdoptium.Temurin.21.JDK

# 3. Portable tools -> .\tools_bin (CFR jar, jadx, pyinstxtractor.py)
python aperio.py --setup

# 4. .NET decompiler
winget install Microsoft.DotNet.SDK.8
dotnet tool install -g ilspycmd          # adds %USERPROFILE%\.dotnet\tools to PATH (restart the shell)

# 5. Electron archives (npx fetches @electron/asar on first use)
winget install OpenJS.NodeJS.LTS
npm install -g @electron/asar            # optional; npx works without it

# 6. PyInstaller extraction (alternative to the bundled-download pyinstxtractor.py)
pip install pyinstxtractor-ng

# 7. pycdc (no official binaries; build it once, then copy pycdc.exe into .\tools_bin)
winget install Kitware.CMake
winget install Microsoft.VisualStudio.2022.BuildTools   # "Desktop development with C++" workload
git clone https://github.com/zrax/pycdc
cmake -S pycdc -B pycdc\build
cmake --build pycdc\build --config Release
copy pycdc\build\Release\pycdc.exe tools_bin\

# 8. Ghidra: download a release zip from
#    https://github.com/NationalSecurityAgency/ghidra/releases and unzip it, then:
setx GHIDRA_INSTALL_DIR "C:\Tools\ghidra_11.4_PUBLIC"
# open a NEW terminal so the variable is visible, then verify:
python aperio.py --doctor
```

Tool lookup order: `./tools_bin` (including `tools_bin/*/bin` and
`tools_bin/ghidra*/support`), then `PATH`. Overrides: `GHIDRA_INSTALL_DIR`,
`CFR_JAR`, `JAVA_HOME`, `APERIO_TOOLS_BIN`, `APERIO_CONFIG_DIR`.

## Tests

```powershell
python -m unittest discover -s tests -v     # detector, process-tree kill, dispatcher
python tests\create_samples.py              # build real/synthetic samples, run core + CLI end-to-end
```

## Verification summary

Host: Windows 11, Python 3.14.7, PySide6 6.12.0, OpenJDK 17 (`java`, `javac`, `jar`),
Node 26 / npx 11, .NET 10 runtime (**no SDK**). Not installed: Ghidra, CFR, jadx,
ilspycmd, pycdc, pyinstxtractor(-ng), Go, C compiler.

**Tested live (all passing, 27 unit tests + 26-sample end-to-end harness):**

| Area | Evidence |
|---|---|
| Content detection, all 9 tiers | `tests/test_detector.py`: synthetic PE32/PE32+ (with and without a CLR directory), ELF64, Mach-O 64, fat Mach-O, `.class`, JAR, WAR, APK, DEX, ASAR, and PyInstaller cookie / `pydata` section. Go is detected by the buildinfo marker and by the `.gopclntab` / `__gopclntab` sections. |
| Detection on real files | the real `System.Private.CoreLib.dll` is classified as .NET (CLR directory), the real `gh.exe` as a Go binary, the host `python.exe` as native PE, and a `.pyc` compiled by Python 3.14 as Python Bytecode (3.14). Real `javac`-built `.class` and `jar`-built `.jar` files are detected as Java. |
| Extensions ignored | a `.pyc` renamed to `.exe` goes to pycdc, a `.class` renamed to `.png` goes to CFR, and a truncated `MZ` file named `.exe` is classified as an asset. |
| Process-tree kill | `tests/test_procutil.py`: a `.bat` launcher in a folder whose name contains spaces and `&` spawns a grandchild python. Cancel, timeout and `kill_all()` each kill the whole tree, and the test checks through the Win32 API that the grandchild PID is dead. |
| Two-pool scheduler | the heavy pool's measured peak concurrency is exactly 1, and the fast pool's peak stays within `--jobs`. |
| Missing-tool dedup | for 25 files that need the same missing tool, the install hint is logged once and all 25 are marked `Skipped (Missing Tool: …)`. |
| Cancel All | 2 in-flight tasks become `Failed (Cancelled)` and 6 queued ones become `Skipped (Cancelled)`, all within seconds. |
| Electron stub rule | the stub exe, `ffmpeg.dll`, `d3dcompiler_47.dll` and `libEGL.dll` are skipped. Unrelated natives are not, and neither is an explicitly targeted single file. |
| ASAR pipeline | **real extraction** with `npx --yes @electron/asar` (v4.3.1). The extracted `main.js` content is verified. |
| CLI | `--doctor`, the one-time first-run notice, scanning a directory or a single file, `REPORT.md` contents, and the exit code for a missing target. |
| GUI | offscreen test of the real `MainWindow`: a 44-file batch, progress reaching 44/44, the status and format filters, inspector metadata, and the doctor dialog filled in from a worker thread. **The worst GUI event-loop stall was about 18 ms.** |

**Needs external tools not installed on the host (code paths written, not run live):**

* CFR, jadx, ilspycmd, pycdc and pyinstxtractor runs. On this host they are detected correctly and reported as `Skipped (Missing Tool: …)`. `python aperio.py --setup` downloads CFR, jadx and pyinstxtractor.py; the download code itself has not been run here.
* Ghidra `analyzeHeadless` and `scripts/ExportDecompiled.java`. The script has not been compiled against a Ghidra install. Recent Ghidra releases also need JDK 21, and this host has JDK 17.
* Compiling C# samples: `create_samples.py` builds `Greeter.dll` only when a .NET SDK is present. Without one it uses a real runtime assembly copied from the installed .NET runtime.
* POSIX `os.killpg` path: written, but only the Windows `taskkill /T` path was run.

Known limitation: arguments passed through `.bat` launchers (jadx, Ghidra) go through
cmd.exe, which expands `%NAME%` inside a path even when it is quoted. Other cmd
metacharacters (`& | ^ ( )`) are handled.
