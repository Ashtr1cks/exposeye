"""exposeye-lab: CTF helpers from the terminal (auto-decoder and file analyser)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from exposeye import __version__
from exposeye.lab import decoder, files
from exposeye.lab.flags import DEFAULT_FORMATS, FlagHunter
from exposeye.settings import Settings

EPILOG = """\
examples:
  exposeye-lab decode "cGljb0NURntsNHkzcnN9"
  echo 4a4b4c | exposeye-lab decode -
  exposeye-lab file challenge.png
  exposeye-lab --flag "myctf{...}" file dump.bin
"""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="exposeye-lab",
        description="CTF lab: auto-decoder and file analyser",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--flag",
        action="append",
        metavar="FORMAT",
        help="flag format, e.g. 'picoCTF{...}' (repeatable; default: saved formats)",
    )
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("decode", help="auto-decode text (use - for stdin)")
    d.add_argument("text")
    d.add_argument("--depth", type=int, default=4)
    d.add_argument("--no-xor", action="store_true")
    d.add_argument("--no-caesar", action="store_true")
    f = sub.add_parser("file", help="analyse a file")
    f.add_argument("path", type=Path)
    args = p.parse_args(argv)
    console = Console()

    saved = Settings()
    hunter = FlagHunter(
        args.flag or saved.get("flag_formats", DEFAULT_FORMATS),
        bool(saved.get("flag_generic", True)),
    )

    if args.cmd == "decode":
        text = sys.stdin.read() if args.text == "-" else args.text
        r = decoder.decode(text, hunter, args.depth, not args.no_caesar, not args.no_xor)
        for flag in r["flags"]:
            console.print(
                f"[bold green]FLAG[/] {flag['value']}  [dim]via {' > '.join(flag.get('chain', [])) or 'input'}[/]",
                highlight=False,
            )
        table = Table(title=f"Top results ({r['explored']} candidates tried)", expand=True)
        table.add_column("Chain", ratio=2)
        table.add_column("Output", ratio=5, overflow="fold")
        for res in r["results"][:10]:
            table.add_row(" > ".join(res["chain"]), (res["text"] or f"[dim]{res['hex']}[/]")[:300])
        console.print(table)
        return 0 if r["flags"] else 1

    if not args.path.is_file():
        console.print(f"[red]No such file: {args.path}[/]")
        return 2
    if args.path.stat().st_size > files.MAX_FILE:
        console.print(f"[red]File too large (limit {files.MAX_FILE // 1048576} MB).[/]")
        return 2
    r = files.analyse(args.path.read_bytes(), args.path.name, hunter)
    console.print(
        f"[bold]{r['name']}[/]  {r['size']:,} bytes  ·  {r['type']['description']}  ·  entropy {r['entropy']}"
    )
    console.print(f"[dim]sha256 {r['hashes']['sha256']}[/]")
    for flag in r["flags"]:
        console.print(
            f"[bold green]FLAG[/] {flag['value']}  [dim]found in {flag['where']}[/]",
            highlight=False,
        )
    console.print("\n[bold]What to look at[/]")
    for hint in r["hints"]:
        console.print(f" • {hint}", highlight=False)
    if r["embedded"]:
        console.print("\n[bold]Embedded signatures[/]")
        for e in r["embedded"][:20]:
            console.print(
                f"  0x{e['offset']:08x}  {e['description']}"
                + (f"  [dim]({e['note']})[/]" if e.get("note") else "")
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
