"""Launch the exposeye UI: a native window if pywebview is installed, else your browser."""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn

from exposeye import __version__
from exposeye.web.server import create_app

DEFAULT_PORT = 8765


def _free_port(preferred: int) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="exposeye-app", description="exposeye desktop UI")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port (default {DEFAULT_PORT})")
    p.add_argument("--browser", action="store_true", help="open in your browser, not a window")
    p.add_argument("--no-open", action="store_true", help="just run the server")
    p.add_argument("--data-dir", type=Path, help="where scan history is stored (~/.exposeye)")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    port = _free_port(args.port)
    app = create_app(args.data_dir, scheduler=True)  # runs due watchlist checks while open
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.monotonic() + 15
    while not server.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            print("exposeye: the UI server failed to start.", file=sys.stderr)
            return 1
        time.sleep(0.05)

    url = f"http://127.0.0.1:{port}/"
    print(f"exposeye UI running at {url}")
    print(f"Scan history: {app.state.store.root}")

    if not args.browser and not args.no_open:
        try:
            import webview  # type: ignore[import-not-found]
        except ImportError:
            webview = None
            print('Tip: pip install -e ".[desktop]" to run it in its own window.')
        if webview is not None:
            try:
                webview.settings["ALLOW_DOWNLOADS"] = True
            except (AttributeError, KeyError, TypeError):
                pass
            webview.create_window("exposeye", url, width=1320, height=860, min_size=(960, 640))
            webview.start()  # blocks until the window is closed
            server.should_exit = True
            thread.join(timeout=5)
            return 0

    if not args.no_open:
        webbrowser.open(url)
    print("Press Ctrl+C to stop.")
    try:
        while thread.is_alive():
            thread.join(0.5)
    except KeyboardInterrupt:
        server.should_exit = True
        thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
