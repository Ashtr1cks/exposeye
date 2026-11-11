"""Persistent scan history (one JSON file per scan) and a tiny cross-process file lock."""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from datetime import datetime
from pathlib import Path

ID_RE = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")


def new_scan_id() -> str:
    return f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}"


class FileLock:
    """Exclusive lock via an O_EXCL lock file. Works across processes (app + scheduled task).

    Locks older than `stale` seconds are assumed abandoned (crashed process) and broken.
    """

    def __init__(self, path: Path, timeout: float = 15, stale: float = 60):
        self.path = Path(path)
        self.timeout = timeout
        self.stale = stale

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                return self
            except FileExistsError:
                try:
                    if time.time() - self.path.stat().st_mtime > self.stale:
                        self.path.unlink()
                        continue
                except FileNotFoundError:
                    continue
                if time.monotonic() > deadline:
                    raise TimeoutError(f"could not acquire {self.path}") from None
                time.sleep(0.05)

    def __exit__(self, *exc):
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def read_json(path: Path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_json(path: Path, data, indent: int | None = None) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, default=str, indent=indent), encoding="utf-8")
    tmp.replace(path)


def result_target(result: dict) -> tuple[str, str | None]:
    meta = result.get("meta", {})
    kind = meta.get("kind", "domain")
    return kind, meta.get("email") if kind == "email" else meta.get("domain")


class Store:
    """Finished scan results, one JSON file each."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.dir = self.root / "scans"
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, scan_id: str) -> Path:
        if not ID_RE.match(scan_id):  # also blocks path traversal
            raise KeyError(scan_id)
        return self.dir / f"{scan_id}.json"

    def exists(self, scan_id: str) -> bool:
        try:
            return self._path(scan_id).exists()
        except KeyError:
            return False

    def save(self, scan_id: str, result: dict) -> None:
        write_json(self._path(scan_id), result)

    def load(self, scan_id: str) -> dict:
        try:
            return json.loads(self._path(scan_id).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise KeyError(scan_id) from exc

    def delete(self, scan_id: str) -> None:
        try:
            self._path(scan_id).unlink()
        except FileNotFoundError as exc:
            raise KeyError(scan_id) from exc

    def list(self) -> list[dict]:
        out = []
        for path in sorted(self.dir.glob("*.json"), reverse=True):
            result = read_json(path, None)
            if not isinstance(result, dict):
                continue
            meta = result.get("meta", {})
            kind, target = result_target(result)
            summary = result.get("summary") or {}
            out.append(
                {
                    "id": path.stem,
                    "kind": kind,
                    "target": target,
                    "started": meta.get("started"),
                    "duration_s": meta.get("duration_s"),
                    "passive": (meta.get("options") or {}).get("passive"),
                    "findings": summary.get("findings", {}),
                    "breaches": summary.get("breaches"),
                }
            )
        return out

    def previous(self, kind: str, target: str, before_id: str) -> tuple[str, dict] | None:
        """Most recent stored scan of the same target that is older than `before_id`."""
        for path in sorted(self.dir.glob("*.json"), reverse=True):
            if path.stem >= before_id:
                continue
            result = read_json(path, None)
            if isinstance(result, dict) and result_target(result) == (kind, target):
                return path.stem, result
        return None
