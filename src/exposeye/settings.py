"""Small persistent settings file (~/.exposeye/settings.json).

Shared by the app and the background task, so writes are locked.
"""

from __future__ import annotations

import os
from pathlib import Path

from exposeye.storage import FileLock, read_json, write_json

LEGACY_DIR_NAME = ".domainscope"  # the project's previous name


def data_dir() -> Path:
    env = os.environ.get("EXPOSEYE_HOME") or os.environ.get("DOMAINSCOPE_HOME")
    if env:
        return Path(env)
    current = Path.home() / ".exposeye"
    legacy = Path.home() / LEGACY_DIR_NAME
    if not current.exists() and legacy.is_dir():
        try:
            legacy.rename(current)  # one-time move of scan history and settings
        except OSError:
            return legacy  # e.g. an old copy of the app still has it open
    return current


class Settings:
    def __init__(self, root: Path | None = None):
        root = Path(root or data_dir())
        self.path = root / "settings.json"
        self.lock = root / ".settings.lock"

    def _read(self) -> dict:
        data = read_json(self.path, {})
        return data if isinstance(data, dict) else {}

    def get(self, key: str, default=None):
        return self._read().get(key, default)

    def set(self, key: str, value) -> None:
        with FileLock(self.lock):
            data = self._read()
            if value is None or value == "":
                data.pop(key, None)
            else:
                data[key] = value
            write_json(self.path, data, indent=2)

    @property
    def hibp_key(self) -> str | None:
        """Environment variable wins over the saved setting."""
        return os.environ.get("HIBP_API_KEY") or self.get("hibp_api_key") or None

    @property
    def hibp_key_source(self) -> str | None:
        if os.environ.get("HIBP_API_KEY"):
            return "environment"
        return "settings" if self.get("hibp_api_key") else None

    def set_hibp_key(self, key: str | None) -> None:
        self.set("hibp_api_key", key.strip() if key else None)


def mask(key: str | None) -> str | None:
    if not key:
        return None
    return key[:4] + "…" + key[-4:] if len(key) > 10 else "…"
