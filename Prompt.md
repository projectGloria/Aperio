You are a senior systems and reverse-engineering tools engineer. Build **Aperio**, a modular binary inspection and decompiler-dispatcher application in Python 3.11+ with both a **Desktop GUI (PySide6)** and a **headless CLI**. Aperio takes any file or directory, identifies binary and archive formats strictly via content inspection (magic bytes, PE data directories, and section markers—never file extensions alone), and orchestrates external unpackers and decompilers.

## 1. Entry Points & Modes
```text
python aperio.py                                               # Launches the Aperio Desktop GUI
python aperio.py --ui                                          # Explicitly launches the GUI
python aperio.py <file-or-dir> [--out ./output] [--jobs 4]     # Runs headless CLI mode
python aperio.py --doctor                                      # Prints toolchain health table in CLI
python aperio.py --setup                                       # Downloads portable tools & prints install commands
```

On the first run (tracked via a `.first_run` marker in the local config directory), display a one-time notice (as a non-blocking banner in GUI or text in CLI):
"Notice: Only unpack or decompile software you own, open-source software, or binaries where you have explicit authorization/license permission."

## 2. Strictly Decoupled Architecture (`aperio/core` vs `aperio/ui`)
`aperio/core/` must have **zero** UI imports so it runs identically in GUI and CLI modes.

### Core Engine & Event Bus (`aperio/core/`)
- The dispatcher runs in a background worker thread and emits structured events (`TaskDiscovered`, `TaskStarted`, `TaskLog`, `TaskCompleted`, `BatchFinished`) via a thread-safe callback/queue interface.
- **Two-Pool Concurrency**:
  - Fast pool (`--jobs`, default 4) for `CFR`, `ilspycmd`, `pycdc`, `asar`, and `jadx`.
  - Heavy Native pool (semaphore locked to `1`, configurable to `2`) exclusively for Ghidra `analyzeHeadless` so concurrent JVM instances never exhaust system RAM.
- **Process Tree Termination (Critical for Cancel / Window Close)**:
  - Because `analyzeHeadless.bat` and `jadx.bat` on Windows spawn child `java.exe` processes, cancelling a job, hitting a timeout, or closing the Aperio window MUST kill the entire process tree (`taskkill /F /T /PID <pid>` on Windows; `os.killpg` with `start_new_session=True` on POSIX). Never leave orphaned `java.exe` or `decompile` processes running in the background.

### Desktop GUI (`aperio/ui/` - PySide6)
1. **Drop Zone & Target Bar**:
   - Drag-and-drop support for a single binary or an entire folder, plus file/folder picker buttons, output directory selector, per-task timeout spinner, and a "Skip Native (Ghidra)" toggle.
2. **Live File Queue Table (`QTableView` / `QTableWidget`)**:
   - Columns: `File Path (Relative)`, `Detected Format`, `Tool / Plugin`, `Status` (`Queued`, `Running`, `Success`, `Failed`, `Skipped`), `Duration`, and `Quick Action` ("Open Output Folder" button).
   - Filter bar to filter rows by status or format.
3. **Inspector & Live Log Drawer**:
   - Clicking any row in the table opens its live/captured `stdout`/`stderr` stream, detected header metadata (magic bytes, architecture, PE sections), and exact command line executed.
4. **Toolchain Doctor & Setup Dialog**:
   - Accessible from the top toolbar: displays a live table of all supported plugins, whether the binary is detected on `PATH` or `./tools_bin`, version string, a "Download Portable Tool" button (for standalone jars like `CFR`), and a "Copy Install Command" button for system tools (`winget`, `dotnet tool`, `npm`).
5. **Batch Controls**:
   - `Start`, `Cancel All` (triggers full process-tree kill), progress bar (`X / Y completed`), and an `Open REPORT.md` button upon completion.

## 3. Detection & Priority Rules (Strict Precedence)
Because many formats share outer headers (e.g., `.apk` and `.jar` are both ZIPs; .NET, PyInstaller, and Go binaries are all PE/ELF), detectors MUST run in a strict priority order from **most specific to most generic**:

1. **Electron Archive (`asar`)**:
   - Detect via the ASAR Pickle uint32 header structure (or `app.asar` header validation).
   - Tool: `npx --yes @electron/asar extract` (or global `asar`).
   - *Smart Directory Rule*: If scanning a directory that contains `resources/app.asar`, mark the root Electron stub executable and standard Chromium DLLs (`libcef.dll`, `ffmpeg.dll`, `d3dcompiler_47.dll`, etc.) as `SKIPPED (Electron Runtime Stub)` unless explicitly targeted as a single file.

2. **PyInstaller Executable (PE / ELF + CArchive)**:
   - Detect PE (`MZ`) or ELF (`\x7fELF`) containing the PyInstaller `MEI\x0c\x0b\x0a\x0b\x0e` magic cookie or a `.pydata` / `pydata` section.
   - Tool: Two-stage pipeline:
     1. Extract archive using `pyinstxtractor-ng` (or bundled `pyinstxtractor.py` with automatic 16-byte Python 3.7+ `.pyc` magic header repair).
     2. Automatically route the extracted entry-point `.pyc` files (skipping standard library modules) into `pycdc`.

3. **.NET Managed Assembly (PE + CLR Header)**:
   - Detect PE (`MZ` -> `PE\0\0`) and parse the Optional Header Data Directories using `struct`. If `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` (Data Directory index 14) has a non-zero RVA and Size, classify as `.NET Assembly`.
   - Tool: `ilspycmd -p -o <target_out_dir> <file>` (outputs a reconstructable `.csproj` + `.cs` files).

4. **Android Package / Dalvik Bytecode (`.apk` / `.dex`)**:
   - `.dex`: Detect `dex\n` (`64 65 78 0A`) magic bytes.
   - `.apk`: Detect ZIP (`PK\x03\x04`) containing `classes.dex` or `AndroidManifest.xml`.
   - Tool: `jadx -d <target_out_dir> <file>`.

5. **Java Bytecode & Archives (`.class` / `.jar` / `.war`)**:
   - `.class`: Detect `0xCAFEBABE` magic bytes (disambiguating from Mach-O Universal binaries by checking bytes 4-7).
   - `.jar` / `.war`: Detect ZIP (`PK\x03\x04`) containing `.class` files or `META-INF/MANIFEST.MF` (and not matching `.apk`).
   - Tool: `java -jar cfr.jar <file> --outputdir <target_out_dir>`.

6. **Python Bytecode (`.pyc`)**:
   - Detect valid Python magic numbers in the first 4 bytes (`\x0d\x0a` in bytes 2-3) and validate header structure.
   - Tool: `pycdc <file>` (write captured stdout to `<filename>.py`).

7. **Go Binary (PE / ELF / Mach-O + Go Buildinfo)**:
   - Detect PE/ELF/Mach-O containing the `\xff Go buildinf:` magic marker or `.go.buildinfo` / `.gopclntab` section.
   - Action: Flag as `Native (Go Binary)` in UI and report, and pass to the Native Ghidra pipeline (unless `--skip-native` is enabled).

8. **Native Binary (PE / ELF / Mach-O without .NET or PyInstaller)**:
   - Detect `MZ` (PE), `\x7fELF` (ELF), or `0xFEEDFACE` / `0xFEEDFACF` / `0xCAFEBABE` (Mach-O).
   - Tool: Ghidra `analyzeHeadless`.
   - *Critical Ghidra Implementation Detail*: `analyzeHeadless` does NOT export C code via a CLI flag. You MUST create a bundled Ghidra post-script (`scripts/ExportDecompiled.java` using `DecompInterface` or `CppExporter`) and invoke:
     `analyzeHeadless <isolated_temp_dir> <temp_proj_name> -import <file> -scriptPath <scripts_dir> -postScript ExportDecompiled.java <output_c_file> -deleteProject`
     Always use a unique `tempfile.TemporaryDirectory()` per binary so concurrent or cancelled runs never leave locked `.gpr` projects behind.

9. **Unrecognized / Static Assets**:
   - Skip or copy (configurable), record as `SKIPPED (Non-executable/Asset)` in UI and `REPORT.md`.

## 4. Plugin Architecture & Reporting
- **Plugin Contract**: Every handler in `aperio/plugins/` inherits from `DecompilerPlugin` ABC with:
  - `priority: int` (controls detection order)
  - `name: str`
  - `detect(file_path: Path, header_bytes: bytes) -> bool`
  - `is_available() -> tuple[bool, str]` (returns availability + path/version)
  - `install_hint() -> str` (exact Windows/cross-platform install command)
  - `run(file_path: Path, out_dir: Path, timeout: int, cancel_event: threading.Event) -> PluginResult`
- **Deduplicated Missing-Tool Handling**:
  - Missing tool = mark file as `SKIPPED (Missing Tool: <name>)`, log the `install_hint()` once per missing tool (never spam the log 500 times for 500 `.class` files), and continue.
- **Output Mirroring & Reporting**:
  - Mirror the input directory hierarchy inside `--out`. Each unpacked/decompiled binary gets its own folder `<relative_path>/<filename>_unpacked/`.
  - Generate `<out>/REPORT.md` containing a summary table (Total, Succeeded, Failed, Skipped by reason) and a detailed per-file table (File, Detected Format, Plugin Used, Duration, Status, Output Path / Error Excerpt).

## 5. Execution Plan (Follow Strictly in Order)
1. Write `DESIGN.md` covering the directory layout (`aperio/core`, `aperio/plugins`, `aperio/ui`, `scripts/`), detection precedence table, process-tree termination design, and event flow between worker threads and PySide6 signals.
2. Implement `aperio/core/detector.py` with real header/PE/ZIP parsing (using standard library `struct` and `zipfile`) and unit tests against synthetic/real headers.
3. Implement `aperio/plugins/base.py`, all format plugins, the bundled Ghidra `scripts/ExportDecompiled.java` post-script, and the `--doctor` / `--setup` logic.
4. Implement the core dispatcher (`aperio/core/dispatcher.py`) with two-pool concurrency, timeout enforcement, process-tree killing, and `REPORT.md` generation.
5. Implement the PySide6 Desktop UI (`aperio/ui/main_window.py`) wired to the dispatcher via `QThread` / `Signal` so the UI remains 60 FPS responsive during heavy scans.
6. Create a test harness (`tests/create_samples.py`) that generates test binaries/archives (compiles `.java` -> `.class`/`.jar`, C# if `dotnet` is available, `.py` -> `.pyc`) and verifies both CLI and core pipeline execution end-to-end.
7. Write `README.md` with exact Windows setup steps (`pip install PySide6`, `winget`, `dotnet tool install -g ilspycmd`, `GHIDRA_INSTALL_DIR` setup) and conclude with a verification summary detailing what was tested live vs. what requires external tools not currently installed on the host.

## 6. Hard Constraints
- Zero stubbed or fake detection logic (never use `file.suffix == ".exe"` to distinguish between .NET, Go, PyInstaller, and Native PE).
- Never block the PySide6 main GUI thread with file I/O or `subprocess.run`.
- Keep individual files modular and under ~300 lines.
- Do not write custom decompilers; strictly orchestrate real external tools and capture their `stdout`/`stderr`.