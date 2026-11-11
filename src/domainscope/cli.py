"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
import webbrowser

from rich.console import Console
from rich.table import Table

from domainscope import __version__
from domainscope.report import FORMATS, write_reports
from domainscope.scanner import ScanOptions, scan
from domainscope.utils import normalize_domain

SEV_STYLE = {"high": "bold red", "medium": "yellow", "low": "cyan", "info": "dim"}

EPILOG = """\
examples:
  domainscope example.com
  domainscope example.com --passive --open
  domainscope example.com other.org -f html,json -o out/

Only scan domains you own or are authorised to assess. --passive limits
traffic to public data sources (RDAP, DNS, CT logs) and never connects to
the target's web servers.
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="domainscope",
        description="Passive-first domain reconnaissance with HTML/Markdown/JSON reports.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("domains", nargs="+", metavar="DOMAIN", help="domain(s) or URL(s) to scan")
    p.add_argument(
        "-o", "--output-dir", default="reports", help="report directory (default: reports)"
    )
    p.add_argument(
        "-f",
        "--format",
        default="html,md,json",
        help=f"comma-separated report formats from {', '.join(FORMATS)} (default: all)",
    )
    p.add_argument("--no-report", action="store_true", help="print results only, write no files")
    p.add_argument("--open", action="store_true", help="open the HTML report when done")
    p.add_argument("--passive", action="store_true", help="never connect to the target's hosts")
    p.add_argument("--no-subdomains", action="store_true", help="skip CT-log subdomain discovery")
    p.add_argument("--no-whois", action="store_true", help="skip registration (RDAP) lookup")
    p.add_argument("--no-email", action="store_true", help="skip SPF/DMARC/MTA-STS checks")
    p.add_argument(
        "--no-exposure", action="store_true", help="skip open-port/CVE lookup (Shodan InternetDB)"
    )
    p.add_argument("--probe-limit", type=int, default=25, help="max hosts to HTTP/TLS probe (25)")
    p.add_argument("--max-hosts", type=int, default=1000, help="max subdomains to resolve (1000)")
    p.add_argument("--workers", type=int, default=20, help="concurrent DNS workers (20)")
    p.add_argument("--timeout", type=float, default=10.0, help="network timeout in seconds (10)")
    p.add_argument(
        "--resolver",
        action="append",
        default=[],
        metavar="IP",
        help="DNS resolver to use, repeatable (default: system resolver)",
    )
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()

    formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    bad = [f for f in formats if f not in FORMATS]
    if bad:
        console.print(f"[red]Unknown format(s): {', '.join(bad)}[/]")
        return 2

    opts = ScanOptions(
        passive=args.passive,
        whois=not args.no_whois,
        email=not args.no_email,
        exposure=not args.no_exposure,
        subdomains=not args.no_subdomains,
        probe_limit=max(0, args.probe_limit),
        max_hosts=max(1, args.max_hosts),
        workers=max(1, args.workers),
        timeout=args.timeout,
        resolvers=args.resolver,
    )

    def progress(step: str, message: str, ok: bool = True) -> None:
        mark = "[green][+][/]" if ok else "[yellow][!][/]"
        console.print(f"{mark} {(step + ' ').ljust(14, '.')} {message}", highlight=False)

    exit_code = 0
    for raw in args.domains:
        try:
            domain = normalize_domain(raw)
        except ValueError as exc:
            console.print(f"[red]{exc}[/]")
            exit_code = 2
            continue

        console.rule(f"[bold]{domain}")
        try:
            with console.status("scanning...", spinner="dots"):
                result = scan(domain, opts, progress)
        except KeyboardInterrupt:
            console.print("[red]Interrupted.[/]")
            return 130

        _print_findings(console, result)

        if not args.no_report:
            paths = write_reports(result, args.output_dir, formats)
            for path in paths:
                console.print(f"[green][✓][/] report saved -> {path}")
            html = next((p for p in paths if p.suffix == ".html"), None)
            if args.open and html:
                webbrowser.open(html.resolve().as_uri())
        console.print(f"[dim]finished in {result['meta']['duration_s']}s[/]\n")
    return exit_code


def _print_findings(console: Console, result: dict) -> None:
    findings = result["findings"]
    if not findings:
        console.print("[green]No findings.[/]")
        return
    table = Table(title="Findings", show_lines=False, expand=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Module", no_wrap=True)
    table.add_column("Finding", ratio=2)
    table.add_column("Detail", overflow="fold", ratio=3)
    for f in findings:
        style = SEV_STYLE[f["severity"]]
        table.add_row(f"[{style}]{f['severity'].upper()}[/]", f["module"], f["title"], f["detail"])
    console.print(table)
    if result["errors"]:
        for module, err in result["errors"].items():
            console.print(f"[yellow][!][/] {module}: {err}", highlight=False)


if __name__ == "__main__":
    sys.exit(main())
