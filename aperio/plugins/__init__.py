"""Plugin registry. Order of detection is defined solely by `priority`."""
from __future__ import annotations

from .android_plugin import AndroidPlugin
from .asar_plugin import AsarPlugin
from .base import DecompilerPlugin, PluginResult
from .dotnet_plugin import DotNetPlugin
from .java_plugin import JavaPlugin
from .native_plugin import GhidraPlugin, GoPlugin
from .pyc_plugin import PycPlugin
from .pyinstaller_plugin import PyInstallerPlugin

PLUGIN_CLASSES: list[type[DecompilerPlugin]] = [
    AsarPlugin,         # 1  (10)
    PyInstallerPlugin,  # 2  (20)
    DotNetPlugin,       # 3  (30)
    AndroidPlugin,      # 4  (40)
    JavaPlugin,         # 5  (50)
    PycPlugin,          # 6  (60)
    GoPlugin,           # 7  (70)
    GhidraPlugin,       # 8  (80)
]


def all_plugins() -> list[DecompilerPlugin]:
    return sorted((cls() for cls in PLUGIN_CLASSES), key=lambda p: p.priority)


__all__ = ["DecompilerPlugin", "PluginResult", "all_plugins", "PLUGIN_CLASSES"]
