"""domainscope-email: check where an email address has appeared in data breaches."""

from __future__ import annotations

import argparse
import getpass
import sys
import webbrowser

from rich.console import Console
from rich.table import Table

from domainscope import __version__
from domainscope.emailcheck import check_email
from domainscope.modules.breaches import PASSWORD_RISK_LABELS
from domainscope.modules.passwords import times_pwned
from domainscope.report import FORMATS, write_reports
from domainscope.settings import Settings
from domainscope.utils import make_session, normalize_email

EPILOG = """\
examples:
  domainscope-email you@example.com
  domainscope-email you@example.com --open
  domainscope-email --password            # check a password (typed hidden)

Breach data comes from XposedOrNot (free, ~25 checks/hour) or, if an API key is
set via --hibp-key, HIBP_API_KEY or the app's Settings page, Have I Been Pwned.
Check only your own email address, or someone else's with their consent.
"""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="domainscope-email",
        description="Email exposure check: data breaches, exposed passwords, public profile.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("emails", nargs="*", metavar="EMAIL", help="email address(es) to check")
    p.add_argument(
        "--password",
        action="store_true",
        help="check whether a password has leaked (prompted, never stored)",
    )
    p.add_argument("--hibp-key", help="Have I Been Pwned API key (or set HIBP_API_KEY)")
    p.add_argument("-o", "--output-dir", default="reports", help="report directory (reports)")
    p.add_argument("-f", "--format", default="html,md,json", help="report formats (all)")
    p.add_argument("--no-report", action="store_true", help="print results only")
    p.add_argument("--open", action="store_true", help="open the HTML report when done")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)
    console = Console()

    if not args.emails and not args.password:
        p.print_help()
        return 2

    exit_code = 0
    if args.password:
        exit_code = max(exit_code, _check_password(console))

    formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    if any(f not in FORMATS for f in formats):
        console.print(f"[red]Formats must be from: {', '.join(FORMATS)}[/]")
        return 2
    hibp_key = args.hibp_key or Settings().hibp_key

    def progress(step: str, message: str, ok: bool = True) -> None:
        mark = "[green][+][/]" if ok else "[yellow][!][/]"
        console.print(f"{mark} {(step + ' ').ljust(15, '.')} {message}", highlight=False)

    for raw in args.emails:
        try:
            email = normalize_email(raw)
        except ValueError as exc:
            console.print(f"[red]{exc}[/]")
            exit_code = 2
            continue
        console.rule(f"[bold]{email}")
        with console.status("checking...", spinner="dots"):
            result = check_email(email, hibp_key, progress)
        _print(console, result)
        if not args.no_report:
            paths = write_reports(result, args.output_dir, formats)
            for path in paths:
                console.print(f"[green][✓][/] report saved -> {path}")
            html = next((x for x in paths if x.suffix == ".html"), None)
            if args.open and html:
                webbrowser.open(html.resolve().as_uri())
    return exit_code


def _check_password(console: Console) -> int:
    password = getpass.getpass("Password to check (input hidden): ")
    if not password:
        console.print("[red]No password entered.[/]")
        return 2
    try:
        count = times_pwned(password, make_session())
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Password check failed: {exc}[/]")
        return 1
    finally:
        del password
    if count:
        console.print(
            f"[bold red]This password has appeared {count:,} times in data breaches. "
            "Stop using it everywhere.[/]"
        )
    else:
        console.print(
            "[green]Not found in any known breach.[/] A good sign, but still use "
            "unique passwords per site."
        )
    console.print("[dim]Only the first 5 characters of the password's SHA-1 hash were sent.[/]")
    return 0


def _print(console: Console, result: dict) -> None:
    items = result["breaches"]["items"]
    if items:
        table = Table(
            title=f"Breaches ({len(items)}) via {result['breaches']['provider']}", expand=True
        )
        table.add_column("Breach", ratio=2)
        table.add_column("Date", no_wrap=True)
        table.add_column("Password", ratio=2)
        table.add_column("Data exposed", ratio=4, overflow="fold")
        for b in items:
            pw = (
                f"[red]{PASSWORD_RISK_LABELS[b['password_risk']]}[/]"
                if b["password_exposed"]
                else "[dim]no[/]"
            )
            table.add_row(b["title"], b["date"], pw, ", ".join(b["data"]))
        console.print(table)
    elif result["breaches"]["checked"]:
        console.print("[green]Not found in any known breach.[/]")
    for module, err in result["errors"].items():
        console.print(f"[yellow][!][/] {module}: {err}", highlight=False)
    if result["advice"]:
        console.print("\n[bold]What to do[/]")
        for i, tip in enumerate(result["advice"], 1):
            console.print(f" {i}. [bold]{tip['title']}[/]: {tip['detail']}", highlight=False)


if __name__ == "__main__":
    sys.exit(main())
