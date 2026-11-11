"""Alerts: Windows desktop notifications and Discord webhooks."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from xml.sax.saxutils import escape

import requests

from exposeye.utils import USER_AGENT, short_error

DISCORD_RE = re.compile(
    r"^https://(?:(?:ptb|canary)\.)?(?:discord|discordapp)\.com/api/webhooks/\d+/[\w-]+$"
)
COLORS = {"high": 0xDC2626, "medium": 0xD97706, "low": 0x0284C7, "info": 0x64748B}

# Windows PowerShell's AppUserModelID: lets an unpackaged script raise toast notifications.
_PS_APP_ID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
_PS_TOAST = r"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($env:DS_TOAST_XML)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:DS_TOAST_APP).Show($toast)
"""


def valid_discord_webhook(url: str) -> bool:
    return bool(DISCORD_RE.match(url.strip()))


def desktop(title: str, body: str) -> tuple[bool, str]:
    if sys.platform != "win32":
        return False, "desktop notifications are only implemented for Windows"
    # Text goes in via environment variables, never into the script itself (no injection).
    xml = (
        "<toast><visual><binding template='ToastGeneric'>"
        f"<text>{escape(title[:120])}</text><text>{escape(body[:400])}</text>"
        "</binding></visual></toast>"
    )
    env = {**os.environ, "DS_TOAST_XML": xml, "DS_TOAST_APP": _PS_APP_ID}
    try:
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                _PS_TOAST,
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, short_error(exc)
    if proc.returncode != 0:
        return False, short_error(RuntimeError(proc.stderr.strip() or "powershell failed"))
    return True, "sent"


def discord(webhook: str, title: str, body: str, severity: str = "info") -> tuple[bool, str]:
    if not valid_discord_webhook(webhook):
        return False, "not a Discord webhook URL"
    payload = {
        "username": "exposeye",
        "embeds": [
            {
                "title": title[:256],
                "description": body[:4000],
                "color": COLORS.get(severity, COLORS["info"]),
            }
        ],
    }
    try:
        resp = requests.post(webhook, json=payload, timeout=15, headers={"User-Agent": USER_AGENT})
    except requests.RequestException as exc:
        return False, short_error(exc)
    if resp.status_code >= 300:
        return False, f"Discord answered HTTP {resp.status_code}"
    return True, "sent"


class Notifier:
    """Sends alerts through whichever channels are enabled in Settings."""

    def __init__(self, settings):
        self.settings = settings

    def send(self, title: str, body: str, severity: str = "info") -> dict:
        results = {}
        if self.settings.get("desktop_notify", True):
            results["desktop"] = desktop(title, body)
        hook = self.settings.get("discord_webhook")
        if hook:
            results["discord"] = discord(hook, title, body, severity)
        return {k: {"ok": ok, "message": msg} for k, (ok, msg) in results.items()}
