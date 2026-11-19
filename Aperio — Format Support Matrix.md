# Aperio — Format Support Matrix

Nov 12, 2026 · @Lambda

## Summary

Aperio detects 9 format families by content. On this machine, 4 run end to end today (Electron ASAR, Java, PyInstaller extraction, jadx), 3 need a tool installed first (.NET, `.pyc`, native/Go via Ghidra), and several common app types (Tauri, .NET single-file, Nuitka, installers) are not recognised at all and fall through to "Native" or "Asset".

Support levels used below:

- **Verified** — the real tool ran on a real sample and the output was checked.
- **Needs tool** — detection and plugin code exist; the external tool is not installed here, so files show `Skipped (Missing Tool)`.
- **Not supported** — no detector or plugin; the file is misrouted or skipped.

## Verified on this machine

These ran with the real tool on real samples; outputs were checked by the test harness.

| Format | Detected by | Tool | Result |
| --- | --- | --- | --- |
| Electron `app.asar` | Pickle header | `npx @electron/asar` 4.3.1 | Full extraction of the app's JS/HTML |
| Java `.class` / JAR / WAR | `CAFEBABE` + major version ≥ 45; ZIP with `.class` or manifest | CFR 0.152 | `.java` source, incl. a `.class` renamed to `.png` |
| PyInstaller exe (PE/ELF/Mach-O) | `MEI` CArchive cookie or `pydata` section | pyinstxtractor.py | Archive unpacked to `.pyc` files; not yet to `.py` (needs pycdc) |
| Android APK / DEX | `dex\n` magic; ZIP with `classes.dex` + manifest | jadx 1.5.1 | Ran live on JVM bytecode only; no real APK tested yet |
| Anything else | none of the above match | — | `Skipped (Non-executable/Asset)`, or copied with `--copy-assets` |

Also verified: content-only detection (extensions ignored), Electron runtime-stub skipping, two-pool scheduling, Cancel All with process-tree kill, `REPORT.md`, and a responsive GUI (worst stall about 26 ms).

## Supported, but needs a tool installed

Detection works and is tested; the plugin code has not run live because the tool is missing here.

| Format | Detected by | Tool needed | Install |
| --- | --- | --- | --- |
| .NET assembly (`.dll`/`.exe` with CLR header) | PE data directory #14 | ilspycmd | .NET SDK, then `dotnet tool install -g ilspycmd` |
| Python `.pyc` (and stage 2 of PyInstaller) | magic + flags + code-object byte | pycdc | Build from source with CMake + VS Build Tools |
| Go binaries | `\xff Go buildinf:` or `.gopclntab` section | Ghidra | Ghidra zip + JDK 21, set `GHIDRA_INSTALL_DIR` |
| Native PE / ELF / Mach-O (C, C++, Rust, Delphi, …) | valid PE / ELF / Mach-O headers | Ghidra | Same as above |

The Ghidra export script `scripts/ExportDecompiled.java` has never been compiled against a real Ghidra install, so native and Go are the riskiest paths.

## Not supported

These have no detector or plugin. "Falls to" is what Aperio does with them today.

| App / format | Falls to | What's lost |
| --- | --- | --- |
| Tauri apps (e.g. `faber.exe`) | Native → Ghidra | Embedded Brotli-compressed frontend (HTML/JS/CSS) is never extracted; only Rust pseudocode |
| .NET single-file / self-contained bundles | Native → Ghidra | The bundled managed `.dll`s inside the apphost are never extracted for ILSpy |
| .NET NativeAOT | Native → Ghidra | No IL exists; Ghidra is the only option (expected) |
| Nuitka, py2exe, cx\_Freeze | Native or Asset | Python is compiled to C or zipped; no unpacking step |
| Installers (NSIS, Inno Setup, MSI, MSIX) | Native or Asset | Payload files inside are not unpacked or recursed into |
| Generic archives (ZIP, 7z, tar, CAB) | Asset | Contents are not unpacked and scanned |
| Packed executables (UPX, Themida, etc.) | Native → Ghidra | No unpacking; Ghidra sees only the stub |
| Flutter / Dart AOT, Unity IL2CPP | Native → Ghidra | No metadata recovery (Dart snapshot, `global-metadata.dat`) |
| WebAssembly, Lua/LuaJIT bytecode | Asset | No decompiler wired in |
| Unpacked JS / web sources, Android AAB/AAR | Asset or misrouted | Not treated as inputs; AAB/AAR untested |

Unity Mono games still work: their `Assembly-CSharp.dll` is a normal .NET assembly.

## Known limitations and untested paths

- **`%NAME%` in paths:** arguments to `.bat` launchers (jadx, Ghidra) pass through cmd.exe, which expands `%NAME%` even inside quotes. `& | ^ ( )` are handled.
- **No recursion:** files produced by one tool (e.g. `.pyc` inside an extracted ASAR, or a JAR inside an APK) are not fed back into the dispatcher.
- **jadx on a real APK/DEX:** not tested; no Android build tools were available.
- **pyinstxtractor-ng:** only the downloaded `pyinstxtractor.py` path was tested.
- **POSIX process-group kill (`killpg`):** written, only the Windows `taskkill /T` path ran.
- **Ghidra:** heavy (minutes per binary, 1–2 concurrent); output for stripped Rust/Go is hard to read.

## Next steps

Tauri support comes first, because it's the app that exposed the gap. The rest are ordered by how common the app type is.

- [ ] **Tauri plugin:** detect `tauri-runtime-wry` and `tauri://` markers ahead of Native, then extract the embedded Brotli frontend assets
- [ ] **.NET single-file bundles:** detect the bundle signature, extract the managed `.dll`s, and send them to ILSpy
- [ ] **Recursion:** feed newly extracted files back into the dispatcher, with a depth limit
- [ ] **Install and verify** ilspycmd, pycdc, and Ghidra + JDK 21 here
- [ ] **Installers and archives:** NSIS, Inno Setup, MSI and ZIP, via 7-Zip or innoextract
- [ ] **Nuitka:** detect it and report it clearly (true decompilation isn't possible)
