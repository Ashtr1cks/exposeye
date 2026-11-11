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
    hp = sub.add_parser("hash", help="identify and crack a hash")
    hp.add_argument("value", help="the hash (use - for stdin, one per line)")
    hp.add_argument("--wordlist", type=Path, help="wordlist file, e.g. rockyou.txt")
    jp = sub.add_parser("jwt", help="decode and inspect a JWT")
    jp.add_argument("token", help="the JWT (use - for stdin)")
    jp.add_argument("--wordlist", type=Path, help="wordlist for the HMAC secret search")
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

    if args.cmd == "hash":
        return _cmd_hash(args, hunter, console)
    if args.cmd == "jwt":
        return _cmd_jwt(args, console)

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


def _words(wordlist):
    from exposeye.lab.hashes import BUILTIN_WORDS, iter_wordlist

    yield from BUILTIN_WORDS
    if wordlist:
        yield from iter_wordlist(wordlist)


def _cmd_hash(args, hunter, console) -> int:
    from exposeye.lab import hashes

    values = sys.stdin.read().split() if args.value == "-" else [args.value]
    found_any = False
    for value in values:
        types = hashes.identify(value)
        console.print(f"[bold]{value}[/]")
        console.print(
            "  types: " + (", ".join(t.name for t in types) or "unknown"), highlight=False
        )
        if hashes.crackable(value):
            r = hashes.crack(value, _words(args.wordlist))
            if r["found"]:
                found_any = True
                console.print(
                    f"  [bold green]CRACKED[/] {r['found']['password']}  [dim]({r['found']['type']}, {r['tried']:,} tried)[/]",
                    highlight=False,
                )
            else:
                console.print(
                    f"  [yellow]not in wordlist[/] ({r['tried']:,} tried)", highlight=False
                )
        else:
            console.print("  [dim]not crackable here (salted/slow) - use john or hashcat[/]")
    return 0 if found_any else 1


def _cmd_jwt(args, console) -> int:
    from exposeye.lab import jwt_tools

    token = sys.stdin.read().strip() if args.token == "-" else args.token
    info = jwt_tools.decode(token)
    if not info["valid"]:
        console.print(f"[red]{info['error']}[/]")
        return 2
    console.print(f"[bold]alg:[/] {info['alg']}")
    console.print_json(data=info["header"])
    console.print_json(data=info["payload"])
    for f in info["findings"]:
        colour = {"high": "red", "medium": "yellow"}.get(f["severity"], "cyan")
        console.print(
            f"[{colour}]{f['severity'].upper()}[/] {f['title']}: {f['detail']}", highlight=False
        )
    if info["alg"] in jwt_tools.HS:
        r = jwt_tools.find_secret(token, _words(args.wordlist))
        if r["secret"] is not None:
            console.print(
                f"[bold green]SECRET[/] {r['secret']}  [dim]({r['tried']:,} tried)[/]",
                highlight=False,
            )
            return 0
        console.print(f"[yellow]secret not in wordlist[/] ({r['tried']:,} tried)", highlight=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
