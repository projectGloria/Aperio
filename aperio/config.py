"""Application paths and first-run handling."""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "Aperio"
APP_ROOT = Path(__file__).resolve().parent.parent
TOOLS_BIN = Path(os.environ.get("APERIO_TOOLS_BIN", APP_ROOT / "tools_bin"))
SCRIPTS_DIR = APP_ROOT / "scripts"

NOTICE = ("Notice: Only unpack or decompile software you own, open-source software, "
          "or binaries where you have explicit authorization/license permission.")


def config_dir() -> Path:
    override = os.environ.get("APERIO_CONFIG_DIR")
    if override:
        base = Path(override)
    elif sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / APP_NAME
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / APP_NAME
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "aperio"
    base.mkdir(parents=True, exist_ok=True)
    return base


def consume_first_run_notice() -> str | None:
    """Return the legal notice exactly once per installation (.first_run marker)."""
    marker = config_dir() / ".first_run"
    if marker.exists():
        return None
    try:
        marker.write_text("notice shown\n", encoding="utf-8")
    except OSError:
        pass
    return NOTICE
