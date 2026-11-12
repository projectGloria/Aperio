# Aperio — Design

Aperio is a binary inspection and decompiler *dispatcher*. It never decompiles
anything itself: it identifies files strictly by content (magic bytes, PE data
directories, ELF/Mach-O section tables, ZIP central directories) and routes
each one to a real external tool, capturing that tool's `stdout`/`stderr`.

## 1. Directory layout

```text
aperio.py                     entry point (GUI by default, CLI when a target is given)
aperio/
  config.py                   app root, ./tools_bin, config dir, first-run notice
  cli.py                      argparse front-end: scan, --doctor, --setup
  core/                       ZERO UI imports - identical in GUI and CLI
    binfmt.py                 struct-based PE / ELF / Mach-O / fat parsers
    detector.py               FileInfo analysis + format predicates + classify()
    models.py                 Task, TaskStatus, PluginResult, DispatchOptions
    events.py                 TaskDiscovered/Started/Log/Completed, BatchFinished, EventBus
    procutil.py               subprocess runner with timeout/cancel + process-tree kill
    toolchain.py              locate tools on PATH / ./tools_bin / env vars, version probes
    scanner.py                walk targets, mirror paths, Electron runtime-stub rule
    dispatcher.py             two-pool scheduler (fast + heavy native), missing-tool dedup
    report.py                 REPORT.md generation
    doctor.py                 --doctor table + --setup downloader / install commands
  plugins/
    base.py                   DecompilerPlugin ABC (+ re-export of PluginResult)
    __init__.py               registry, sorted by priority
    asar_plugin.py            1  Electron ASAR            -> asar / npx @electron/asar
    pyinstaller_plugin.py     2  PyInstaller CArchive     -> pyinstxtractor(-ng) -> pycdc
    dotnet_plugin.py          3  .NET (CLR header)        -> ilspycmd -p
    android_plugin.py         4  APK / DEX                -> jadx
    java_plugin.py            5  .class / JAR / WAR       -> CFR
    pyc_plugin.py             6  Python bytecode          -> pycdc
    native_plugin.py          7  Go binary, 8 native      -> Ghidra analyzeHeadless
  ui/                         PySide6 only
    app.py                    QApplication bootstrap
    main_window.py            target bar, batch controls, layout
    widgets.py                drop zone, target bar
    queue_model.py            QAbstractTableModel + status/format filter proxy
    inspector.py              inspector + live log drawer
    bridge.py                 QThread worker + event queue -> batched Qt signals
    doctor_dialog.py          toolchain doctor & setup dialog
scripts/ExportDecompiled.java Ghidra post-script (DecompInterface -> .c file)
tests/                        unittest suites + create_samples.py end-to-end harness
tools_bin/                    portable tools downloaded by --setup (git-ignored)
```

## 2. Detection precedence

`detector.analyze(path)` parses a file once (cached by path+mtime+size) into a
`FileInfo` (container kind, architecture, section names, CLR directory, ZIP
names, markers). Plugins are then asked **in priority order**; the first whose
`detect()` returns True wins. Order is most specific -> most generic:

| # | Format | Content evidence | Tool | Pool |
|---|--------|------------------|------|------|
| 1 | Electron ASAR | Pickle header: `u32 4`, `u32 hdr`, `u32 hdr-4`, `u32 jsonlen`, JSON starts `{"files"` | `asar extract` / `npx --yes @electron/asar extract` | fast |
| 2 | PyInstaller | PE/ELF/Mach-O + `MEI\x0c\x0b\x0a\x0b\x0e` cookie, or `pydata` section | `pyinstxtractor-ng` / `pyinstxtractor.py` then `pycdc` | fast |
| 3 | .NET assembly | PE optional header data directory 14 (COM descriptor) RVA != 0 and Size != 0 | `ilspycmd -p -o` | fast |
| 4 | DEX / APK | `dex\n` magic, or `PK\x03\x04` + `classes*.dex` / `AndroidManifest.xml` | `jadx -d` | fast |
| 5 | Java class / JAR / WAR | `CAFEBABE` + bytes 4-7 >= 45 (fat Mach-O has nfat_arch < 45), or ZIP with `*.class` / `META-INF/MANIFEST.MF` | `java -jar cfr.jar` | fast |
| 6 | Python bytecode | magic `xx xx 0D 0A` in a known version range, valid flags field, marshal code-object byte at header end | `pycdc` | fast |
| 7 | Go binary | native container + `\xff Go buildinf:` marker or `.go.buildinfo` / `.gopclntab` / `__go_buildinfo` section | Ghidra | heavy |
| 8 | Native | `MZ`+`PE\0\0`, `\x7fELF`, `FEEDFACE`/`FEEDFACF` (either endianness), fat `CAFEBABE` | Ghidra | heavy |
| 9 | Asset | none of the above | skipped (or copied with `--copy-assets`) | - |

File extensions are never consulted for classification. The only name-based
rule is the Electron *directory* heuristic (below), and even there a file is
only marked as a stub after content detection already classified it native.

**Electron smart-directory rule.** When a scanned directory contains
`resources/app.asar`, the directory holding `resources/` is an Electron root.
Native files directly in that root (the stub `.exe` + Chromium DLLs) and the
well-known Chromium runtime libraries anywhere under it (outside `resources/`)
are recorded as `SKIPPED (Electron Runtime Stub)`. A single explicitly targeted
file is never subject to this rule.

## 3. Process-tree termination

`analyzeHeadless.bat`, `jadx.bat` and `npx.cmd` are launchers whose real work
happens in a child `java.exe`/`node.exe`. Killing the launcher alone would
orphan the JVM. `core/procutil.py` therefore:

* starts every tool with `CREATE_NEW_PROCESS_GROUP` (Windows) or
  `start_new_session=True` (POSIX), and runs `.bat`/`.cmd` through `cmd.exe /c`;
* registers each live `Popen` in a module-level registry;
* polls every 100 ms for: exit, deadline (timeout) or `cancel_event`;
* on timeout/cancel calls `kill_tree(pid)`:
  * Windows: `taskkill /F /T /PID <pid>` (walks and kills the whole tree);
  * POSIX: `os.killpg(pgid, SIGTERM)`, 2 s grace, then `SIGKILL`;
* `kill_all()` kills every registered tree; it is called by `Cancel All`, by the
  GUI `closeEvent`, by `SIGINT` in the CLI, and from an `atexit` hook.

Ghidra additionally gets a fresh `tempfile.TemporaryDirectory()` per binary and
`-deleteProject`, so a killed run never leaves a locked `.gpr` behind.

## 4. Concurrency model

```text
                 +-------------------- Dispatcher thread --------------------+
 targets ---->   | scan + detect (I/O) -> TaskDiscovered ...                 |
                 | for task:                                                 |
                 |   fast plugin  -> ThreadPoolExecutor(--jobs, default 4)   |
                 |   heavy plugin -> ThreadPoolExecutor(heavy) + Semaphore(1|2)
                 | wait all -> REPORT.md -> BatchFinished                    |
                 +-----------------------------------------------------------+
```

Only Ghidra (`pool = "heavy"`) uses the heavy pool, so at most one (or two, if
configured) JVM-hungry `analyzeHeadless` runs at a time, while CFR / jadx /
ilspycmd / pycdc / asar share the fast pool.

Tool availability is resolved once per batch per tool key. A missing tool marks
every affected file `SKIPPED (Missing Tool: <name>)` and the install hint is
logged exactly once.

## 5. Event flow (core -> CLI / GUI)

Core emits plain dataclasses through `EventBus.emit()` from whichever thread
produced them (the bus is lock-protected and never touches UI objects):

`TaskDiscovered -> TaskStarted -> TaskLog* -> TaskCompleted` per file, then one
`BatchFinished`.

* **CLI** subscribes a printer callback (lock-protected stdout writes).
* **GUI** (`ui/bridge.py`): a `QThread` hosts a `DispatchWorker` QObject whose
  `run()` slot calls `Dispatcher.run()`. The bus callback only appends events to
  a `collections.deque` (O(1), lock-free for append/popleft). A GUI-thread
  `QTimer` (16 ms) drains up to N events per tick and emits a single
  `eventsReady(list)` Signal, so thousands of log lines never flood the event
  loop and the UI stays at ~60 FPS. The model applies batched row updates via
  `dataChanged`. All file I/O, `subprocess` and doctor probes happen off the GUI
  thread (`QThreadPool` / `QThread`).
* `Cancel All` -> `Dispatcher.cancel()` -> sets `cancel_event` + `kill_all()`.
  Window close -> cancel, then wait briefly for the worker thread.
