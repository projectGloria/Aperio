"""Priority 5: Java .class / JAR / WAR -> CFR."""
from __future__ import annotations

import threading
from pathlib import Path

from ..core import detector, toolchain
from .base import DecompilerPlugin, LogFn, PluginResult

CFR_VERSION = "0.152"
CFR_URL = (f"https://github.com/leibnitz27/cfr/releases/download/{CFR_VERSION}/"
           f"cfr-{CFR_VERSION}.jar")


def _cfr_cmd() -> list[str] | None:
    jar = toolchain.find_file("cfr*.jar", env_var="CFR_JAR")
    java = toolchain.java()
    if jar and java:
        return [str(java), "-jar", str(jar)]
    wrapper = toolchain.which("cfr")  # e.g. scoop / brew wrapper script
    return [str(wrapper)] if wrapper else None


class JavaPlugin(DecompilerPlugin):
    priority = 50
    name = "CFR"
    portable = True

    def detect(self, file_path: Path, header_bytes: bytes) -> bool:
        if detector.java_class_version(header_bytes):
            return True
        if header_bytes[:4] != b"PK\x03\x04":
            return False
        return detector.is_java_archive(self.info(file_path))

    def is_available(self) -> tuple[bool, str]:
        cmd = _cfr_cmd()
        if cmd:
            return True, " ".join(cmd)
        if not toolchain.java():
            return False, "java not found (and no cfr.jar)"
        return False, "cfr.jar not found in ./tools_bin (or $CFR_JAR)"

    def install_hint(self) -> str:
        return (f"python aperio.py --setup  (downloads cfr-{CFR_VERSION}.jar into ./tools_bin; "
                f"needs Java: winget install EclipseAdoptium.Temurin.21.JDK)")

    def version(self) -> str:
        jar = toolchain.find_file("cfr*.jar", env_var="CFR_JAR")
        return jar.stem if jar else ""

    def describe(self, info) -> str:
        if info.container == "CLASS":
            return f"Java Class (major {info.java_version} / Java {info.java_version - 44})"
        if any(n.startswith("WEB-INF/") for n in info.zip_names):
            return "Java Web Archive (WAR)"
        return "Java Archive (JAR)"

    def run(self, file_path: Path, out_dir: Path, timeout: int,
            cancel_event: threading.Event, log: LogFn | None = None) -> PluginResult:
        cmd = _cfr_cmd()
        if not cmd:
            return PluginResult(False, error="CFR not available")
        out_dir.mkdir(parents=True, exist_ok=True)
        res = self.exec(cmd + [str(file_path), "--outputdir", str(out_dir)],
                        timeout, cancel_event, log)
        if not res.ok:
            return self.failure(res, timeout)
        if not any(out_dir.rglob("*.java")):
            return PluginResult(False, error="CFR produced no .java files",
                                commands=[res.command], stdout=res.stdout, stderr=res.stderr)
        return PluginResult(True, output_path=out_dir, commands=[res.command],
                            stdout=res.stdout, stderr=res.stderr)
