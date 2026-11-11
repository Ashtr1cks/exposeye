"""domainscope-watch: manage the watchlist and run scheduled checks (used by Task Scheduler)."""

from __future__ import annotations

import argparse
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from domainscope import __version__
from domainscope.monitor import task
from domainscope.monitor.runner import Monitor
from domainscope.settings import data_dir
from domainscope.utils import normalize_domain, normalize_email

EPILOG = """\
examples:
  domainscope-watch add example.com              # daily passive scan
  domainscope-watch add example.com --weekly --full
  domainscope-watch add me@example.com           # daily breach check
  domainscope-watch list
  domainscope-watch run                          # scan everything that's due
  domainscope-watch changes
  domainscope-watch install-task                 # check hourly in the background (Windows)
"""


def parse_target(raw: str) -> tuple[str, str]:
    if "@" in raw:
        return "email", normalize_email(raw)
    return "domain", normalize_domain(raw)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="domainscope-watch",
        description="domainscope monitoring",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--data-dir", type=Path, help="data folder (default ~/.domainscope)")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="watch a domain or email")
    a.add_argument("target")
    a.add_argument("--weekly", action="store_true", help="check weekly instead of daily")
    a.add_argument("--full", action="store_true", help="full scan (visits websites) for domains")
    r = sub.add_parser("remove", help="stop watching")
    r.add_argument("target")
    sub.add_parser("list", help="show the watchlist")
    run = sub.add_parser("run", help="scan due items (or --all)")
    run.add_argument("--all", action="store_true", help="scan every enabled item now")
    run.add_argument("--quiet", action="store_true", help="log to file only (for scheduled runs)")
    c = sub.add_parser("changes", help="show recent changes")
    c.add_argument("-n", type=int, default=15)
    sub.add_parser("install-task", help="run checks hourly in the background (Windows)")
    sub.add_parser("uninstall-task", help="remove the background task")
    sub.add_parser("task-status", help="show background task status")

    args = p.parse_args(argv)
    root = args.data_dir or data_dir()
    root.mkdir(parents=True, exist_ok=True)
    quiet = getattr(args, "quiet", False)
    _setup_logging(root, quiet)
    out = (lambda *_a, **_k: None) if quiet else print
    mon = Monitor(root)

    try:
        if args.cmd == "add":
            kind, target = parse_target(args.target)
            item = mon.watchlist.add(
                kind,
                target,
                "weekly" if args.weekly else "daily",
                "full" if args.full else "passive",
            )
            out(
                f"Watching {item['target']} ({item['interval']}, {item['mode']}). "
                "Run 'domainscope-watch run' to take the first snapshot."
            )
        elif args.cmd == "remove":
            kind, target = parse_target(args.target)
            item = mon.watchlist.find(kind, target)
            if not item:
                out(f"{target} is not on the watchlist.")
                return 1
            mon.watchlist.remove(item["id"])
            out(f"Stopped watching {target}.")
        elif args.cmd == "list":
            items = mon.watchlist.all()
            if not items:
                out("Watchlist is empty. Add something with 'domainscope-watch add example.com'.")
            for i in items:
                state = (
                    "paused"
                    if not i["enabled"]
                    else "running"
                    if i["running"]
                    else (f"error: {i['last_error']}" if i["last_error"] else "ok")
                )
                out(
                    f"{i['target']:<34} {i['kind']:<6} {i['interval']:<7} {i['mode']:<8} "
                    f"last: {i['last_run_iso'] or 'never':<26} "
                    f"next: {i['next_due'] or '-':<26} {state}"
                )
        elif args.cmd == "run":
            results = mon.run_due(everything=args.all)
            if not results:
                out("Nothing is due.")
            for res in results:
                target = res["item"]["target"]
                if res["status"] != "ok":
                    out(f"[!] {target}: {res['status']} ({res.get('error')})")
                    continue
                ev = res["event"]
                if ev and ev.get("baseline"):
                    out(f"[+] {target}: baseline snapshot saved")
                elif ev:
                    out(f"[+] {target}: {len(ev['changes'])} change(s)")
                    for ch in ev["changes"]:
                        out(f"    {ch['severity'].upper():<6} {ch['title']}")
                else:
                    out(f"[+] {target}: no changes")
        elif args.cmd == "changes":
            events = mon.changes.list(limit=args.n)
            if not events:
                out("No changes recorded yet.")
            for ev in events:
                head = "baseline" if ev.get("baseline") else f"{len(ev['changes'])} change(s)"
                out(f"{ev['at']}  {ev['target']}: {head}")
                for ch in ev["changes"]:
                    out(f"    {ch['severity'].upper():<6} {ch['title']}")
        elif args.cmd == "install-task":
            st = task.install(args.data_dir)
            out(f"Background checks enabled (hourly). Next run: {st.get('next_run')}")
        elif args.cmd == "uninstall-task":
            task.uninstall()
            out("Background checks disabled.")
        elif args.cmd == "task-status":
            st = task.status()
            out("installed" if st["installed"] else "not installed", st)
    except (ValueError, KeyError, RuntimeError) as exc:
        if quiet:
            logging.getLogger("domainscope.monitor").error("%s", exc)
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _setup_logging(root: Path, quiet: bool) -> None:
    handlers: list[logging.Handler] = [
        RotatingFileHandler(root / "monitor.log", maxBytes=512_000, backupCount=2, encoding="utf-8")
    ]
    if not quiet:
        handlers.append(logging.StreamHandler())
        handlers[-1].setLevel(logging.WARNING)
    logging.basicConfig(
        level=logging.INFO, handlers=handlers, format="%(asctime)s %(levelname)s %(message)s"
    )


if __name__ == "__main__":
    sys.exit(main())
