"""FastAPI backend for the local UI.

Scans run in background threads; the browser follows progress over Server-Sent Events.
Finished scans are stored as JSON files so history survives restarts.
The server is meant to listen on 127.0.0.1 only and rejects other Host headers
(protects against DNS-rebinding attacks from websites you visit).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import threading
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
from domainscope.report import FORMATS, RENDERERS
from domainscope.scanner import ScanOptions
from domainscope.scanner import scan as default_scan
from domainscope.utils import normalize_domain, short_error

STATIC_DIR = Path(__file__).parent / "static"
ID_RE = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")
MAX_CONCURRENT = 3
MEDIA_TYPES = {
    "html": "text/html; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
    "json": "application/json",
}
LOCAL_HOSTS = ("127.0.0.1", "localhost")

ScanFn = Callable[..., dict]


def default_data_dir() -> Path:
    env = os.environ.get("DOMAINSCOPE_HOME")
    return Path(env) if env else Path.home() / ".domainscope"


def new_scan_id() -> str:
    return f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}"


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
        path = self._path(scan_id)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(result, default=str), encoding="utf-8")
        tmp.replace(path)

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
            try:
                result = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            meta = result.get("meta", {})
            out.append(
                {
                    "id": path.stem,
                    "domain": meta.get("domain"),
                    "started": meta.get("started"),
                    "duration_s": meta.get("duration_s"),
                    "passive": (meta.get("options") or {}).get("passive"),
                    "findings": (result.get("summary") or {}).get("findings", {}),
                }
            )
        return out


@dataclass
class Job:
    id: str
    domain: str
    options: dict
    started: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "running"
    events: list[dict] = field(default_factory=list)


class JobManager:
    def __init__(self, store: Store, scan_fn: ScanFn, max_concurrent: int = MAX_CONCURRENT):
        self.store = store
        self.scan_fn = scan_fn
        self.jobs: dict[str, Job] = {}
        self._slots = threading.BoundedSemaphore(max_concurrent)

    def start(self, domain: str, opts: ScanOptions) -> Job:
        if not self._slots.acquire(blocking=False):
            raise RuntimeError("too many scans running")
        job = Job(id=new_scan_id(), domain=domain, options=vars(opts).copy())
        self.jobs[job.id] = job
        threading.Thread(target=self._run, args=(job, opts), daemon=True).start()
        return job

    def _run(self, job: Job, opts: ScanOptions) -> None:
        def progress(step: str, message: str, ok: bool = True) -> None:
            job.events.append({"type": "progress", "step": step, "message": message, "ok": ok})

        try:
            result = self.scan_fn(job.domain, opts, progress)
            result.setdefault("meta", {})["id"] = job.id
            self.store.save(job.id, result)
            job.status = "done"
            job.events.append({"type": "done", "id": job.id})
        except Exception as exc:  # noqa: BLE001 - report any failure to the UI
            job.status = "error"
            job.events.append({"type": "error", "message": short_error(exc)})
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


def create_app(
    data_dir: Path | None = None,
    scan_fn: ScanFn = default_scan,
    allowed_hosts: Iterable[str] = LOCAL_HOSTS,
) -> FastAPI:
    app = FastAPI(title="domainscope", version=__version__, docs_url=None, redoc_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(allowed_hosts))

    store = Store(data_dir or default_data_dir())
    jobs = JobManager(store, scan_fn)
    app.state.store, app.state.jobs = store, jobs

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-store"})

    @app.get("/api/info")
    def info():
        return {"version": __version__, "data_dir": str(store.root)}

    @app.get("/api/scans")
    def list_scans():
        return {
            "running": [
                {"id": j.id, "domain": j.domain, "started": j.started, "options": j.options}
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
        try:
            job = jobs.start(domain, opts)
        except RuntimeError as exc:
            raise HTTPException(
                429, f"{MAX_CONCURRENT} scans are already running - wait for one to finish."
            ) from exc
        return {"id": job.id, "domain": domain}

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
            name = f"{result['meta']['domain']}_{scan_id}.{fmt}"
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

    return app
