"""Background checks via Windows Task Scheduler.

Registers an hourly task that runs `domainscope-watch run --quiet` with pythonw.exe
(no console window). Each run only scans watchlist items that are due, so hourly
is cheap and catches up after the PC was off. Runs while the user is logged in.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

TASK_NAME = "domainscope watch"


def supported() -> bool:
    return sys.platform == "win32"


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["schtasks", *args],
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def interpreter() -> Path:
    exe = Path(sys.executable)
    pyw = exe.with_name("pythonw.exe")
    return pyw if pyw.exists() else exe


def command(data_dir: Path | None = None) -> str:
    cmd = f'"{interpreter()}" -m domainscope.watch_cli'
    if data_dir:
        cmd += f' --data-dir "{data_dir}"'
    return cmd + " run --quiet"


def install(data_dir: Path | None = None, task_name: str = TASK_NAME) -> dict:
    if not supported():
        raise RuntimeError(
            "Background checks use Windows Task Scheduler. On macOS/Linux add "
            "'domainscope-watch run --quiet' to cron instead."
        )
    proc = _run(
        ["/Create", "/TN", task_name, "/TR", command(data_dir), "/SC", "HOURLY", "/MO", "1", "/F"]
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout).strip() or "schtasks failed")
    return status(task_name)


def uninstall(task_name: str = TASK_NAME) -> dict:
    if supported():
        proc = _run(["/Delete", "/TN", task_name, "/F"])
        if proc.returncode != 0 and "cannot find" not in (proc.stderr or "").lower():
            raise RuntimeError((proc.stderr or proc.stdout).strip() or "schtasks failed")
    return status(task_name)


def status(task_name: str = TASK_NAME) -> dict:
    info = {
        "supported": supported(),
        "installed": False,
        "next_run": None,
        "last_run": None,
        "last_result": None,
        "name": task_name,
    }
    if not supported():
        return info
    proc = _run(["/Query", "/TN", task_name, "/V", "/FO", "LIST"])
    if proc.returncode != 0:
        return info
    info["installed"] = True
    for line in proc.stdout.splitlines():
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "next run time":
            info["next_run"] = value
        elif key == "last run time":
            info["last_run"] = value
        elif key == "last result":
            info["last_result"] = value
    return info
