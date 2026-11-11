"""Runs watchlist items, compares with the previous scan, records changes and alerts."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from domainscope.emailcheck import check_email
from domainscope.monitor.diff import SEV_ORDER, diff, is_alert
from domainscope.monitor.notify import Notifier
from domainscope.monitor.watchlist import ChangeLog, Watchlist
from domainscope.scanner import ScanOptions, scan
from domainscope.settings import Settings
from domainscope.storage import Store, new_scan_id
from domainscope.utils import short_error

Progress = Callable[[str, str, bool], None]
log = logging.getLogger("domainscope.monitor")


def _noop(step: str, message: str, ok: bool = True) -> None:
    pass


def summarise(target: str, changes: list[dict]) -> tuple[str, str, str]:
    """Notification title, body and severity for a set of changes."""
    alerts = [c for c in changes if is_alert(c)]
    worst = min((c["severity"] for c in alerts), key=SEV_ORDER.__getitem__, default="info")
    title = f"{target}: {len(alerts)} change(s) need attention"
    lines = [f"• {c['title']}" for c in alerts[:5]]
    if len(alerts) > 5:
        lines.append(f"…and {len(alerts) - 5} more. Open domainscope → Monitoring.")
    return title, "\n".join(lines), worst


class Monitor:
    def __init__(
        self,
        root: Path,
        store: Store | None = None,
        settings: Settings | None = None,
        scan_fn: Callable = scan,
        email_fn: Callable = check_email,
        notifier: Notifier | None = None,
    ):
        self.root = Path(root)
        self.store = store or Store(self.root)
        self.settings = settings or Settings(self.root)
        self.watchlist = Watchlist(self.root)
        self.changes = ChangeLog(self.root)
        self.scan_fn = scan_fn
        self.email_fn = email_fn
        self.notifier = notifier or Notifier(self.settings)

    # -- pieces used both by the app (inside a background job) and the headless runner --

    def execute(self, item: dict, progress: Progress = _noop) -> dict:
        if item["kind"] == "email":
            return self.email_fn(item["target"], self.settings.hibp_key, progress)
        opts = ScanOptions(passive=item.get("mode", "passive") == "passive")
        return self.scan_fn(item["target"], opts, progress)

    def record(self, item: dict, scan_id: str, result: dict) -> dict | None:
        """Diff a freshly saved scan against the previous one and log/alert the changes."""
        prev = self.store.previous(item["kind"], item["target"], scan_id)
        event = None
        if prev is None:
            changes: list[dict] = []
            event = self.changes.add(
                {
                    "watch_id": item["id"],
                    "kind": item["kind"],
                    "target": item["target"],
                    "scan_id": scan_id,
                    "previous_id": None,
                    "baseline": True,
                    "changes": [],
                }
            )
        else:
            changes = diff(prev[1], result)
            if changes:
                event = self.changes.add(
                    {
                        "watch_id": item["id"],
                        "kind": item["kind"],
                        "target": item["target"],
                        "scan_id": scan_id,
                        "previous_id": prev[0],
                        "baseline": False,
                        "changes": changes,
                    }
                )
        self.watchlist.finish(item["id"], scan_id=scan_id, change_count=len(changes))
        if any(is_alert(c) for c in changes):
            title, body, severity = summarise(item["target"], changes)
            try:
                sent = self.notifier.send(title, body, severity)
                log.info("notified %s: %s", item["target"], sent)
            except Exception as exc:  # noqa: BLE001 - never let alerting break monitoring
                log.warning("notification failed: %s", exc)
        return event

    def fail(self, item: dict, exc: BaseException) -> None:
        log.warning("watch %s failed: %s", item["target"], exc)
        self.watchlist.finish(item["id"], error=short_error(exc))

    # -- headless --

    def run_item(self, item: dict, progress: Progress = _noop) -> dict:
        """Run one item synchronously. Returns {"item", "status", "event"|"error"}."""
        if not self.watchlist.claim(item["id"]):
            return {"item": item, "status": "skipped", "error": "already running elsewhere"}
        try:
            result = self.execute(item, progress)
            scan_id = new_scan_id()
            result.setdefault("meta", {})["id"] = scan_id
            self.store.save(scan_id, result)
        except Exception as exc:  # noqa: BLE001
            self.fail(item, exc)
            return {"item": item, "status": "error", "error": short_error(exc)}
        try:
            event = self.record(item, scan_id, result)
        except Exception as exc:  # noqa: BLE001
            self.fail(item, exc)
            return {"item": item, "status": "error", "error": short_error(exc)}
        return {"item": item, "status": "ok", "event": event, "scan_id": scan_id}

    def run_due(self, everything: bool = False, progress: Progress = _noop) -> list[dict]:
        items = (
            [i for i in self.watchlist.all() if i["enabled"]]
            if everything
            else self.watchlist.due()
        )
        results = []
        for item in items:
            log.info("%s checking %s", datetime.now().isoformat(timespec="seconds"), item["target"])
            results.append(self.run_item(item, progress))
        return results
