"""FastAPI backend for the local UI.

Scans run in background threads; the browser follows progress over Server-Sent Events.
Finished scans are stored as JSON files so history survives restarts.
The server is meant to listen on 127.0.0.1 only and rejects other Host headers
(protects against DNS-rebinding attacks from websites you visit).

Password checks are deliberately NOT handled here: the UI hashes passwords in the
browser and queries the k-anonymity API directly, so passwords never reach this server.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from domainscope import __version__
from domainscope.emailcheck import check_email as default_email_check
from domainscope.monitor import task as bg_task
from domainscope.monitor.diff import diff
from domainscope.monitor.notify import Notifier, valid_discord_webhook
from domainscope.monitor.runner import Monitor
from domainscope.report import FORMATS, RENDERERS, report_name
from domainscope.scanner import ScanOptions
from domainscope.scanner import scan as default_scan
from domainscope.settings import Settings, data_dir, mask
from domainscope.storage import ID_RE, Store, new_scan_id, result_target
from domainscope.utils import normalize_domain, normalize_email, short_error

__all__ = ["create_app", "Store", "ID_RE", "new_scan_id"]

STATIC_DIR = Path(__file__).parent / "static"
MAX_CONCURRENT = 3
SCHEDULER_INTERVAL = 60
MEDIA_TYPES = {
    "html": "text/html; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
    "json": "application/json",
}
LOCAL_HOSTS = ("127.0.0.1", "localhost")

ScanFn = Callable[..., dict]
Progress = Callable[[str, str, bool], None]
log = logging.getLogger("domainscope.web")


def default_data_dir() -> Path:
    return data_dir()


@dataclass
class Job:
    id: str
    kind: str
    target: str
    options: dict
    started: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "running"
    events: list[dict] = field(default_factory=list)


class JobManager:
    def __init__(self, store: Store, max_concurrent: int = MAX_CONCURRENT):
        self.store = store
        self.jobs: dict[str, Job] = {}
        self._slots = threading.BoundedSemaphore(max_concurrent)

    def start(
        self,
        kind: str,
        target: str,
        options: dict,
        runner: Callable[[Progress], dict],
        after_save: Callable[[str, dict], None] | None = None,
        on_error: Callable[[BaseException], None] | None = None,
    ) -> Job:
        if not self._slots.acquire(blocking=False):
            raise RuntimeError("too many scans running")
        job = Job(id=new_scan_id(), kind=kind, target=target, options=options)
        self.jobs[job.id] = job
        threading.Thread(
            target=self._run, args=(job, runner, after_save, on_error), daemon=True
        ).start()
        return job

    def _run(self, job: Job, runner, after_save, on_error) -> None:
        def progress(step: str, message: str, ok: bool = True) -> None:
            job.events.append({"type": "progress", "step": step, "message": message, "ok": ok})

        try:
            result = runner(progress)
            result.setdefault("meta", {})["id"] = job.id
            self.store.save(job.id, result)
            if after_save:
                try:
                    after_save(job.id, result)
                except Exception as exc:  # noqa: BLE001 - the scan itself succeeded
                    log.warning("post-scan hook failed: %s", exc)
            job.status = "done"
            job.events.append({"type": "done", "id": job.id})
        except Exception as exc:  # noqa: BLE001 - report any failure to the UI
            job.status = "error"
            job.events.append({"type": "error", "message": short_error(exc)})
            if on_error:
                on_error(exc)
        finally:
            self._slots.release()

    def running(self) -> list[Job]:
        return [j for j in self.jobs.values() if j.status == "running"]


class ScanRequest(BaseModel):
    domain: str = Field(..., max_length=500)
    passive: bool = False
    whois: bool = True
    email: bool = True
    subdomains: bool = True
    probe_limit: int = Field(25, ge=0, le=200)


class EmailCheckRequest(BaseModel):
    email: str = Field(..., max_length=320)


class SettingsUpdate(BaseModel):
    hibp_api_key: str | None = Field(None, max_length=200)
    discord_webhook: str | None = Field(None, max_length=300)
    desktop_notify: bool | None = None


class WatchAdd(BaseModel):
    target: str = Field(..., max_length=500)
    interval: str = "daily"
    mode: str = "passive"
    baseline_scan_id: str | None = None  # an existing scan to treat as the first snapshot


class WatchUpdate(BaseModel):
    enabled: bool | None = None
    interval: str | None = None
    mode: str | None = None


class BackgroundUpdate(BaseModel):
    enabled: bool


def parse_target(raw: str) -> tuple[str, str]:
    if "@" in raw:
        return "email", normalize_email(raw)
    return "domain", normalize_domain(raw)


def create_app(
    data_dir: Path | None = None,
    scan_fn: ScanFn = default_scan,
    email_fn: ScanFn = default_email_check,
    allowed_hosts: Iterable[str] = LOCAL_HOSTS,
    notifier: Notifier | None = None,
    scheduler: bool = False,
) -> FastAPI:
    app = FastAPI(title="domainscope", version=__version__, docs_url=None, redoc_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(allowed_hosts))

    root = Path(data_dir or default_data_dir())
    is_default_root = data_dir is None
    store = Store(root)
    settings = Settings(root)
    jobs = JobManager(store)
    monitor = Monitor(root, store, settings, scan_fn, email_fn, notifier)
    app.state.store, app.state.jobs = store, jobs
    app.state.settings, app.state.monitor = settings, monitor

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    def start_job(kind: str, target: str, options: dict, runner, **hooks) -> dict:
        try:
            job = jobs.start(kind, target, options, runner, **hooks)
        except RuntimeError as exc:
            raise HTTPException(
                429, f"{MAX_CONCURRENT} scans are already running - wait for one to finish."
            ) from exc
        return {"id": job.id, "kind": kind, "target": target}

    def start_watch(item: dict) -> dict:
        """Run a watchlist item as a normal job, then diff + log + alert when it's saved."""
        if not monitor.watchlist.claim(item["id"]):
            raise HTTPException(409, f"{item['target']} is already being checked.")
        try:
            options = {"passive": item["mode"] == "passive"} if item["kind"] == "domain" else {}
            return start_job(
                item["kind"],
                item["target"],
                options,
                lambda progress: monitor.execute(item, progress),
                after_save=lambda sid, res: monitor.record(item, sid, res),
                on_error=lambda exc: monitor.fail(item, exc),
            )
        except HTTPException:
            monitor.watchlist.update(item["id"], running_since=None)  # retry on the next tick
            raise

    # ------------------------------------------------------------------ pages & info

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-store"})

    @app.get("/api/info")
    def info():
        return {"version": __version__, "data_dir": str(store.root)}

    # ------------------------------------------------------------------ settings

    @app.get("/api/settings")
    def get_settings():
        key = settings.hibp_key
        hook = settings.get("discord_webhook")
        return {
            "hibp_key_set": bool(key),
            "hibp_key_masked": mask(key),
            "hibp_key_source": settings.hibp_key_source,
            "discord_webhook_set": bool(hook),
            "discord_webhook_masked": mask(hook.rsplit("/", 1)[-1]) if hook else None,
            "desktop_notify": bool(settings.get("desktop_notify", True)),
            "data_dir": str(store.root),
        }

    @app.put("/api/settings")
    def put_settings(update: SettingsUpdate):
        given = update.model_fields_set
        if "hibp_api_key" in given:
            settings.set_hibp_key(update.hibp_api_key)
        if "discord_webhook" in given:
            hook = (update.discord_webhook or "").strip()
            if hook and not valid_discord_webhook(hook):
                raise HTTPException(
                    400,
                    "That doesn't look like a Discord webhook URL "
                    "(https://discord.com/api/webhooks/...).",
                )
            settings.set("discord_webhook", hook or None)
        if "desktop_notify" in given and update.desktop_notify is not None:
            settings.set("desktop_notify", update.desktop_notify)
        return get_settings()

    @app.post("/api/notify/test")
    def notify_test():
        results = monitor.notifier.send(
            "domainscope test alert",
            "Notifications are working. You'll be alerted here "
            "when a watched domain or email changes.",
            "info",
        )
        if not results:
            raise HTTPException(400, "No alert channels are enabled.")
        return results

    # ------------------------------------------------------------------ scans

    @app.get("/api/scans")
    def list_scans():
        return {
            "running": [
                {
                    "id": j.id,
                    "kind": j.kind,
                    "target": j.target,
                    "started": j.started,
                    "options": j.options,
                }
                for j in jobs.running()
            ],
            "scans": store.list(),
        }

    @app.post("/api/scans", status_code=202)
    def start_scan(req: ScanRequest):
        try:
            domain = normalize_domain(req.domain)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        opts = ScanOptions(
            passive=req.passive,
            whois=req.whois,
            email=req.email,
            subdomains=req.subdomains,
            probe_limit=req.probe_limit,
        )
        return start_job(
            "domain", domain, vars(opts).copy(), lambda progress: scan_fn(domain, opts, progress)
        )

    @app.post("/api/email-checks", status_code=202)
    def start_email_check(req: EmailCheckRequest):
        try:
            email = normalize_email(req.email)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        key = settings.hibp_key
        return start_job(
            "email", email, {"hibp": bool(key)}, lambda progress: email_fn(email, key, progress)
        )

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str):
        try:
            return store.load(scan_id)
        except KeyError as exc:
            raise HTTPException(404, "scan not found") from exc

    @app.delete("/api/scans/{scan_id}", status_code=204)
    def delete_scan(scan_id: str):
        try:
            store.delete(scan_id)
        except KeyError as exc:
            raise HTTPException(404, "scan not found") from exc
        return Response(status_code=204)

    @app.get("/api/scans/{scan_id}/diff")
    def scan_diff(scan_id: str):
        try:
            result = store.load(scan_id)
        except KeyError as exc:
            raise HTTPException(404, "scan not found") from exc
        kind, target = result_target(result)
        prev = store.previous(kind, target, scan_id)
        if prev is None:
            return {"kind": kind, "target": target, "previous": None, "changes": []}
        return {
            "kind": kind,
            "target": target,
            "previous": {"id": prev[0], "started": prev[1]["meta"].get("started")},
            "current": {"id": scan_id, "started": result["meta"].get("started")},
            "changes": diff(prev[1], result),
        }

    @app.get("/api/scans/{scan_id}/report/{fmt}")
    def report(scan_id: str, fmt: str, download: bool = False):
        if fmt not in FORMATS:
            raise HTTPException(404, "unknown format")
        try:
            result = store.load(scan_id)
        except KeyError as exc:
            raise HTTPException(404, "scan not found") from exc
        headers = {}
        if download:
            name = f"{report_name(result)}_{scan_id}.{fmt}"
            headers["Content-Disposition"] = f'attachment; filename="{name}"'
        return Response(RENDERERS[fmt](result), media_type=MEDIA_TYPES[fmt], headers=headers)

    @app.get("/api/scans/{scan_id}/events")
    async def events(scan_id: str, request: Request):
        job = jobs.jobs.get(scan_id)
        if job is None:
            if not store.exists(scan_id):
                raise HTTPException(404, "scan not found")
            done = json.dumps({"type": "done", "id": scan_id})
            return StreamingResponse(iter([f"data: {done}\n\n"]), media_type="text/event-stream")

        # Resume after a reconnect instead of replaying everything.
        last = request.headers.get("last-event-id", "")
        start = int(last) + 1 if last.isdigit() else 0

        async def stream():
            i = start
            while True:
                while i < len(job.events):
                    event = job.events[i]
                    yield f"id: {i}\ndata: {json.dumps(event)}\n\n"
                    i += 1
                    if event["type"] in ("done", "error"):
                        return
                if await request.is_disconnected():
                    return
                await asyncio.sleep(0.25)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ------------------------------------------------------------------ monitoring

    @app.get("/api/monitor/summary")
    def monitor_summary():
        items = monitor.watchlist.all()
        return {
            "unread": monitor.changes.unread(),
            "watching": sum(1 for i in items if i["enabled"]),
        }

    @app.get("/api/watchlist")
    def get_watchlist():
        return {"items": monitor.watchlist.all()}

    @app.post("/api/watchlist", status_code=201)
    def add_watch(req: WatchAdd):
        try:
            kind, target = parse_target(req.target)
            item = monitor.watchlist.add(kind, target, req.interval, req.mode)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        base = req.baseline_scan_id
        if base and store.exists(base) and result_target(store.load(base)) == (kind, target):
            # The scan being viewed becomes the baseline; next check is a full interval away.
            item = monitor.watchlist.update(item["id"], last_run=time.time(), last_scan_id=base)
        return item

    @app.patch("/api/watchlist/{wid}")
    def update_watch(wid: str, req: WatchUpdate):
        fields = {k: v for k, v in req.model_dump().items() if v is not None}
        try:
            return monitor.watchlist.update(wid, **fields)
        except KeyError as exc:
            raise HTTPException(404, "not on the watchlist") from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.delete("/api/watchlist/{wid}", status_code=204)
    def delete_watch(wid: str):
        try:
            monitor.watchlist.remove(wid)
        except KeyError as exc:
            raise HTTPException(404, "not on the watchlist") from exc
        monitor.changes.remove_watch(wid)
        return Response(status_code=204)

    @app.post("/api/watchlist/{wid}/run", status_code=202)
    def run_watch(wid: str):
        try:
            item = monitor.watchlist.get(wid)
        except KeyError as exc:
            raise HTTPException(404, "not on the watchlist") from exc
        return start_watch(item)

    @app.get("/api/changes")
    def get_changes(limit: int = 100):
        return {
            "events": monitor.changes.list(limit=min(max(limit, 1), 500)),
            "unread": monitor.changes.unread(),
        }

    @app.post("/api/changes/read", status_code=204)
    def mark_changes_read():
        monitor.changes.mark_read()
        return Response(status_code=204)

    @app.get("/api/monitor/background")
    def background_status():
        return {**bg_task.status(), "command": bg_task.command(None if is_default_root else root)}

    @app.post("/api/monitor/background")
    def background_set(req: BackgroundUpdate):
        try:
            if req.enabled:
                bg_task.install(None if is_default_root else root)
            else:
                bg_task.uninstall()
        except RuntimeError as exc:
            raise HTTPException(400, str(exc)) from exc
        return background_status()

    # ------------------------------------------------------------------ in-app scheduler

    if scheduler:
        stop = threading.Event()
        app.state.scheduler_stop = stop

        def loop():
            stop.wait(10)  # let the UI come up first
            while not stop.is_set():
                try:
                    for item in monitor.watchlist.due():
                        try:
                            start_watch(item)
                        except HTTPException as exc:
                            log.info("deferred %s: %s", item["target"], exc.detail)
                except Exception as exc:  # noqa: BLE001
                    log.warning("scheduler error: %s", exc)
                stop.wait(SCHEDULER_INTERVAL)

        threading.Thread(target=loop, daemon=True, name="domainscope-scheduler").start()

    return app
