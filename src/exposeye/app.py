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


def _force_window_icon(window, icon_path: Path) -> None:
    """Force the window's small and big icons onto the native handle once it is shown.

    pywebview sets the WinForms Form.Icon, which fixes the title-bar icon, but the
    Windows taskbar button reads the window's "big" icon, which can stay the default
    Python/app icon. WM_SETICON sets both directly so the taskbar shows our icon too.
    """
    import ctypes
    from ctypes import wintypes

    def _apply(*_args) -> None:
        try:
            user32 = ctypes.windll.user32
            user32.LoadImageW.restype = wintypes.HANDLE
            user32.LoadImageW.argtypes = [
                wintypes.HINSTANCE,
                wintypes.LPCWSTR,
                wintypes.UINT,
                ctypes.c_int,
                ctypes.c_int,
                wintypes.UINT,
            ]
            user32.SendMessageW.restype = wintypes.LPARAM
            user32.SendMessageW.argtypes = [
                wintypes.HWND,
                wintypes.UINT,
                wintypes.WPARAM,
                wintypes.LPARAM,
            ]
            image_icon, load_from_file = 1, 0x0010
            wm_seticon, icon_small, icon_big = 0x0080, 0, 1
            path = str(icon_path)
            hwnd = window.native.Handle.ToInt64()
            big = user32.LoadImageW(None, path, image_icon, 32, 32, load_from_file)
            small = user32.LoadImageW(None, path, image_icon, 16, 16, load_from_file)
            if big:
                user32.SendMessageW(hwnd, wm_seticon, icon_big, big)
            if small:
                user32.SendMessageW(hwnd, wm_seticon, icon_small, small)
        except Exception:  # noqa: BLE001 - cosmetic only
            pass

    window.events.shown += _apply


def main(argv: list[str] | None = None) -> int:
    # Launched as a GUI app (pythonw, no console) there is no stdout/stderr, so print()
    # and library logging would crash. Give them a sink before anything writes.
    if sys.stdout is None or sys.stderr is None:
        import os

        sink = open(os.devnull, "w")  # noqa: SIM115 - lives for the whole process
        sys.stdout = sys.stdout or sink
        sys.stderr = sys.stderr or sink

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
            # Detach the taskbar button from the pythonw.exe process so it shows our own icon
            # (and groups as "exposeye") instead of the generic Python icon.
            if sys.platform == "win32":
                try:
                    import ctypes

                    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                        "exposeye.desktop.app"
                    )
                except Exception:  # noqa: BLE001 - cosmetic only
                    pass
            win = webview.create_window(
                "exposeye", url, width=1320, height=860, min_size=(960, 640)
            )
            icon = Path(__file__).parent / "web" / "static" / "logo.ico"
            if sys.platform == "win32" and icon.exists():
                _force_window_icon(win, icon)  # taskbar button, not just the title bar
            start_kw = {"icon": str(icon)} if icon.exists() else {}
            try:
                webview.start(**start_kw)  # blocks until the window is closed
            except TypeError:  # older pywebview without an icon parameter
                webview.start()
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
