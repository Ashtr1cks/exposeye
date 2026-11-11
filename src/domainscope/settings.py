"""Small persistent settings file (~/.domainscope/settings.json)."""

from __future__ import annotations

import json
import os
from pathlib import Path


def data_dir() -> Path:
    env = os.environ.get("DOMAINSCOPE_HOME")
    return Path(env) if env else Path.home() / ".domainscope"


class Settings:
    def __init__(self, root: Path | None = None):
        self.path = Path(root or data_dir()) / "settings.json"

    def _read(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    @property
    def hibp_key(self) -> str | None:
        """Environment variable wins over the saved setting."""
        return os.environ.get("HIBP_API_KEY") or self._read().get("hibp_api_key") or None

    @property
    def hibp_key_source(self) -> str | None:
        if os.environ.get("HIBP_API_KEY"):
            return "environment"
        return "settings" if self._read().get("hibp_api_key") else None

    def set_hibp_key(self, key: str | None) -> None:
        data = self._read()
        if key:
            data["hibp_api_key"] = key.strip()
        else:
            data.pop("hibp_api_key", None)
        self._write(data)


def mask(key: str | None) -> str | None:
    if not key:
        return None
    return key[:4] + "…" + key[-4:] if len(key) > 10 else "…"
