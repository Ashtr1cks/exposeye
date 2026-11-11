"""Watchlist (what to re-check, how often) and change log (what changed), stored as JSON.

Both files are shared between the app and the background task, so every
read-modify-write happens under a FileLock.
"""

from __future__ import annotations

import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from domainscope.storage import FileLock, read_json, write_json

INTERVALS = {"daily": 24 * 3600, "weekly": 7 * 24 * 3600}
MODES = ("passive", "full")
SLACK = 15 * 60  # run up to 15 min early so hourly checks don't drift a day
RUNNING_STALE = 3 * 3600  # a "running" marker older than this is from a crashed run
RETRY_AFTER = 3600  # wait an hour after a failed run
UPDATABLE = {
    "enabled",
    "interval",
    "mode",
    "last_run",
    "last_scan_id",
    "last_error",
    "last_change_count",
    "running_since",
    "retry_at",
}


def now_ts() -> float:
    return time.time()


def iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else None


class Watchlist:
    def __init__(self, root: Path):
        self.path = Path(root) / "watchlist.json"
        self.lock = Path(root) / ".watchlist.lock"

    def _load(self) -> list[dict]:
        data = read_json(self.path, [])
        return data if isinstance(data, list) else []

    def _save(self, items: list[dict]) -> None:
        write_json(self.path, items, indent=2)

    @staticmethod
    def next_due(item: dict) -> float:
        if item.get("retry_at"):
            return item["retry_at"]
        if not item.get("last_run"):
            return 0.0
        return item["last_run"] + INTERVALS[item["interval"]] - SLACK

    def _view(self, item: dict, now: float) -> dict:
        running = bool(item.get("running_since")) and now - item["running_since"] < RUNNING_STALE
        return {
            **item,
            "running": running,
            "next_due": iso(max(self.next_due(item), now)) if item.get("enabled") else None,
            "last_run_iso": iso(item.get("last_run")),
        }

    def all(self) -> list[dict]:
        now = now_ts()
        return [self._view(i, now) for i in self._load()]

    def get(self, wid: str) -> dict:
        for item in self._load():
            if item["id"] == wid:
                return self._view(item, now_ts())
        raise KeyError(wid)

    def find(self, kind: str, target: str) -> dict | None:
        return next((i for i in self.all() if i["kind"] == kind and i["target"] == target), None)

    def add(self, kind: str, target: str, interval: str = "daily", mode: str = "passive") -> dict:
        if kind not in ("domain", "email"):
            raise ValueError("kind must be domain or email")
        if interval not in INTERVALS:
            raise ValueError("interval must be daily or weekly")
        if mode not in MODES:
            raise ValueError("mode must be passive or full")
        with FileLock(self.lock):
            items = self._load()
            if any(i["kind"] == kind and i["target"] == target for i in items):
                raise ValueError(f"{target} is already on the watchlist")
            item = {
                "id": secrets.token_hex(4),
                "kind": kind,
                "target": target,
                "interval": interval,
                "mode": mode if kind == "domain" else "passive",
                "enabled": True,
                "created": now_ts(),
                "last_run": None,
                "last_scan_id": None,
                "last_error": None,
                "last_change_count": None,
                "running_since": None,
                "retry_at": None,
            }
            items.append(item)
            self._save(items)
        return self._view(item, now_ts())

    def update(self, wid: str, **fields) -> dict:
        bad = set(fields) - UPDATABLE
        if bad:
            raise ValueError(f"cannot update {', '.join(sorted(bad))}")
        if "interval" in fields and fields["interval"] not in INTERVALS:
            raise ValueError("interval must be daily or weekly")
        if "mode" in fields and fields["mode"] not in MODES:
            raise ValueError("mode must be passive or full")
        with FileLock(self.lock):
            items = self._load()
            for item in items:
                if item["id"] == wid:
                    item.update(fields)
                    self._save(items)
                    return self._view(item, now_ts())
        raise KeyError(wid)

    def remove(self, wid: str) -> None:
        with FileLock(self.lock):
            items = self._load()
            kept = [i for i in items if i["id"] != wid]
            if len(kept) == len(items):
                raise KeyError(wid)
            self._save(kept)

    def due(self, now: float | None = None) -> list[dict]:
        now = now or now_ts()
        return [
            self._view(i, now)
            for i in self._load()
            if i.get("enabled")
            and not (i.get("running_since") and now - i["running_since"] < RUNNING_STALE)
            and self.next_due(i) <= now
        ]

    def claim(self, wid: str) -> bool:
        """Mark an item as running. False if another process is already running it."""
        now = now_ts()
        with FileLock(self.lock):
            items = self._load()
            for item in items:
                if item["id"] == wid:
                    if item.get("running_since") and now - item["running_since"] < RUNNING_STALE:
                        return False
                    item["running_since"] = now
                    self._save(items)
                    return True
        return False

    def finish(
        self,
        wid: str,
        scan_id: str | None = None,
        error: str | None = None,
        change_count: int | None = None,
    ) -> None:
        now = now_ts()
        try:
            if error:
                self.update(wid, running_since=None, last_error=error, retry_at=now + RETRY_AFTER)
            else:
                self.update(
                    wid,
                    running_since=None,
                    last_error=None,
                    retry_at=None,
                    last_run=now,
                    last_scan_id=scan_id,
                    last_change_count=change_count,
                )
        except KeyError:
            pass  # removed from the watchlist while it was running


class ChangeLog:
    MAX_EVENTS = 2000

    def __init__(self, root: Path):
        self.path = Path(root) / "changes.json"
        self.lock = Path(root) / ".changes.lock"

    def _load(self) -> list[dict]:
        data = read_json(self.path, [])
        return data if isinstance(data, list) else []

    def add(self, event: dict) -> dict:
        event = {
            "id": secrets.token_hex(5),
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "read": False,
            **event,
        }
        with FileLock(self.lock):
            events = self._load()
            events.append(event)
            write_json(self.path, events[-self.MAX_EVENTS :])
        return event

    def list(self, limit: int = 100, watch_id: str | None = None) -> list[dict]:
        events = [e for e in self._load() if not watch_id or e.get("watch_id") == watch_id]
        return list(reversed(events))[:limit]

    def unread(self) -> int:
        return sum(1 for e in self._load() if not e.get("read"))

    def mark_read(self) -> None:
        with FileLock(self.lock):
            events = self._load()
            for e in events:
                e["read"] = True
            write_json(self.path, events)

    def remove_watch(self, watch_id: str) -> None:
        with FileLock(self.lock):
            write_json(self.path, [e for e in self._load() if e.get("watch_id") != watch_id])
