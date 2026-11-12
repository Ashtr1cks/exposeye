"""Auto-decoder: tries common CTF encodings, follows multi-layer chains, ranks the results.

The search is a small beam search: at each depth every applicable decoder is tried on the
current candidates, results are scored for "looks like plaintext / contains a flag", and the
most promising ones are expanded further. Brute-force families (Caesar, single-byte XOR) only
keep their best few keys so they don't flood the results.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import hashlib
import html
import lzma
import re
import string
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import unquote_to_bytes

from exposeye.lab import stego
from exposeye.lab.flags import FlagHunter

MAX_INPUT = 1_000_000
MAX_NODES = 4000
BEAM = 24

# ---------------------------------------------------------------- scoring

PRINTABLE = set(range(32, 127)) | {9, 10, 13}
# English letter frequencies (percent), for a chi-squared "looks like English" test.
EN_FREQ = {
    "a": 8.2,
    "b": 1.5,
    "c": 2.8,
    "d": 4.3,
    "e": 12.7,
    "f": 2.2,
    "g": 2.0,
    "h": 6.1,
    "i": 7.0,
    "j": 0.15,
    "k": 0.77,
    "l": 4.0,
    "m": 2.4,
    "n": 6.7,
    "o": 7.5,
    "p": 1.9,
    "q": 0.095,
    "r": 6.0,
    "s": 6.3,
    "t": 9.1,
    "u": 2.8,
    "v": 0.98,
    "w": 2.4,
    "x": 0.15,
    "y": 2.0,
    "z": 0.074,
}
COMMON_WORDS = re.compile(
    r"\b(the|and|you|that|was|for|are|with|this|have|from|flag|ctf|secret|password|key|is|it|of|to|in|"
    r"hello|world|congrat\w*|well done|here|your|answer)\b",
    re.I,
)


_TEXTY = frozenset(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \t\n\r.,:;/\"'(){}[]-_=+@"
)


def text_quality(data: bytes) -> float:
    """Flag-free "does this look like real text/data?" measure (0..1). Letters, digits, spaces and
    common text punctuation score high; random symbol soup (e.g. a wrong ROT47 branch) scores low.
    Used only to re-sort results under "Most readable", so JSON and other non-English output surfaces."""
    if not data:
        return 0.0
    sample = data[:2048]
    return sum(b in _TEXTY for b in sample) / len(sample)


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(b in PRINTABLE for b in data) / len(data)


def english_score(text: str) -> float:
    """0..1, higher = more like English."""
    letters = [c for c in text.lower() if c in EN_FREQ]
    if len(letters) < 4:
        return 0.15 if text.strip() else 0.0
    n = len(letters)
    chi = sum((letters.count(ch) - n * f / 100) ** 2 / (n * f / 100) for ch, f in EN_FREQ.items())
    freq = max(0.0, 1 - chi / (n * 6 + 150))
    letter_ratio = len(letters) / max(len(text), 1)
    spaces = text.count(" ") / max(len(text), 1)
    words = min(len(COMMON_WORDS.findall(text)) * 0.12, 0.36)
    space_bonus = 0.12 if 0.08 <= spaces <= 0.3 else 0.0
    return min(1.0, 0.45 * freq + 0.25 * min(letter_ratio / 0.75, 1) + space_bonus + words)


def score(data: bytes, flags: list[dict]) -> float:
    if any(f["confidence"] == "high" for f in flags):
        return 3.0
    if flags:
        return 2.0
    p = printable_ratio(data)
    if p < 0.85:
        return p * 0.3
    text = data.decode("latin-1")
    return 0.35 * p + 0.65 * english_score(text)


# ---------------------------------------------------------------- decoders

Decoded = list[tuple[str, bytes]]  # (label, output)

B64_RE = re.compile(rb"^[A-Za-z0-9+/\s]+={0,3}\s*$")
B64URL_RE = re.compile(rb"^[A-Za-z0-9_\-\s]+={0,3}\s*$")
B32_RE = re.compile(rb"^[A-Za-z2-7\s]+={0,8}\s*$")
B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_RE = re.compile(rb"^[1-9A-HJ-NP-Za-km-z]+$")
HEX_RE = re.compile(rb"^(?:0x)?[0-9a-fA-F]+$")
BIN_RE = re.compile(rb"^[01\s]+$")
MORSE_RE = re.compile(rb"^[.\-/\s|_]+$")
NUM_TOKENS_RE = re.compile(rb"^\s*\d{1,3}(?:[\s,;]+\d{1,3})+\s*$")
OCT_TOKENS_RE = re.compile(rb"^\s*[0-7]{3}(?:[\s,;]+[0-7]{3})+\s*$")
URL_RE = re.compile(rb"%[0-9a-fA-F]{2}")
HTML_RE = re.compile(rb"&(#\d+|#x[0-9a-fA-F]+|[a-z]+);")
ESC_RE = re.compile(rb"\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})")

MORSE = {
    ".-": "A",
    "-...": "B",
    "-.-.": "C",
    "-..": "D",
    ".": "E",
    "..-.": "F",
    "--.": "G",
    "....": "H",
    "..": "I",
    ".---": "J",
    "-.-": "K",
    ".-..": "L",
    "--": "M",
    "-.": "N",
    "---": "O",
    ".--.": "P",
    "--.-": "Q",
    ".-.": "R",
    "...": "S",
    "-": "T",
    "..-": "U",
    "...-": "V",
    ".--": "W",
    "-..-": "X",
    "-.--": "Y",
    "--..": "Z",
    "-----": "0",
    ".----": "1",
    "..---": "2",
    "...--": "3",
    "....-": "4",
    ".....": "5",
    "-....": "6",
    "--...": "7",
    "---..": "8",
    "----.": "9",
    ".-.-.-": ".",
    "--..--": ",",
    "..--..": "?",
    "-.-.--": "!",
    "-....-": "-",
    "-..-.": "/",
    ".--.-.": "@",
    "-.--.": "(",
    "-.--.-": ")",
    "..--.-": "_",
    "---...": ":",
    ".----.": "'",
    ".-..-.": '"',
    "-...-": "=",
    ".-.-.": "+",
}


def _compact(data: bytes) -> bytes:
    return re.sub(rb"\s+", b"", data)


def d_base64(data: bytes) -> Decoded:
    s = _compact(data)
    if len(s) < 4:
        return []
    out = []
    if B64_RE.match(data):
        try:
            out.append(("base64", base64.b64decode(s + b"=" * (-len(s) % 4), validate=True)))
        except (binascii.Error, ValueError):
            pass
    if (b"-" in s or b"_" in s) and B64URL_RE.match(data):
        try:
            out.append(("base64url", base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))))
        except (binascii.Error, ValueError):
            pass
    return out


def d_base32(data: bytes) -> Decoded:
    s = _compact(data).upper()
    if len(s) < 8 or not B32_RE.match(data):
        return []
    try:
        return [("base32", base64.b32decode(s + b"=" * (-len(s) % 8)))]
    except (binascii.Error, ValueError):
        return []


def d_base58(data: bytes) -> Decoded:
    s = data.strip()
    if len(s) < 4 or not B58_RE.match(s):
        return []
    n = 0
    for ch in s:
        n = n * 58 + B58_ALPHABET.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip(b"1"))
    return [("base58", b"\x00" * pad + raw)]


def d_base85(data: bytes) -> Decoded:
    s = data.strip()
    out = []
    if s.startswith(b"<~") and s.endswith(b"~>"):
        try:
            out.append(("ascii85", base64.a85decode(s, adobe=True)))
        except ValueError:
            pass
    elif len(s) >= 5 and all(32 < c < 127 for c in s):
        for label, fn in (("base85", base64.b85decode), ("ascii85", base64.a85decode)):
            try:
                out.append((label, fn(s)))
            except ValueError:
                pass
    return out


def d_hex(data: bytes) -> Decoded:
    s = re.sub(rb"0x|\\x|[\s:,]", b"", data)
    if len(s) < 4 or len(s) % 2 or not HEX_RE.match(s):
        return []
    return [("hex", bytes.fromhex(s.decode()))]


def d_binary(data: bytes) -> Decoded:
    s = _compact(data)
    if len(s) < 8 or not BIN_RE.match(data):
        return []
    tokens = data.split()
    if len(tokens) > 1 and all(len(t) in (7, 8) for t in tokens):
        return [("binary", bytes(int(t, 2) for t in tokens))]
    if len(s) % 8:
        return []
    return [("binary", bytes(int(s[i : i + 8], 2) for i in range(0, len(s), 8)))]


def d_decimal(data: bytes) -> Decoded:
    if not NUM_TOKENS_RE.match(data):
        return []
    vals = [int(t) for t in re.split(rb"[\s,;]+", data.strip())]
    return [("decimal", bytes(vals))] if all(v < 256 for v in vals) else []


def d_octal(data: bytes) -> Decoded:
    if not OCT_TOKENS_RE.match(data):
        return []
    vals = [int(t, 8) for t in re.split(rb"[\s,;]+", data.strip())]
    return [("octal", bytes(vals))] if all(v < 256 for v in vals) else []


def d_url(data: bytes) -> Decoded:
    return [("url", unquote_to_bytes(data.replace(b"+", b" ")))] if URL_RE.search(data) else []


def d_html(data: bytes) -> Decoded:
    if not HTML_RE.search(data):
        return []
    return [("html entities", html.unescape(data.decode("latin-1")).encode("utf-8", "replace"))]


def d_escapes(data: bytes) -> Decoded:
    if not ESC_RE.search(data):
        return []
    try:
        return [
            (
                "escapes",
                data.decode("latin-1").encode("latin-1").decode("unicode_escape").encode("utf-8"),
            )
        ]
    except (UnicodeDecodeError, UnicodeEncodeError):
        return []


def d_morse(data: bytes) -> Decoded:
    s = data.strip()
    if len(s) < 3 or not MORSE_RE.match(s) or not re.search(rb"[.\-]", s):
        return []
    text = s.decode().replace("_", "-").replace("|", "/")
    words = []
    for word in re.split(r"\s*/\s*|\s{3,}", text):
        letters = [MORSE.get(code) for code in word.split()]
        if any(ch is None for ch in letters):
            return []
        words.append("".join(letters))
    return [("morse", " ".join(words).encode())]


def _shift(text: str, n: int) -> str:
    out = []
    for c in text:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + n) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + n) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def d_caesar(data: bytes, keep: int = 2) -> Decoded:
    if printable_ratio(data) < 0.95 or not re.search(rb"[A-Za-z]{3}", data):
        return []
    text = data.decode("latin-1")
    options = []
    for n in range(1, 26):
        shifted = _shift(text, n)
        label = "rot13" if n == 13 else f"caesar -{26 - n}"
        options.append((english_score(shifted), label, shifted.encode("latin-1")))
    options.sort(key=lambda o: -o[0])
    return [(label, out) for _, label, out in options[:keep]]


def d_rot47(data: bytes) -> Decoded:
    if printable_ratio(data) < 0.95:
        return []
    return [("rot47", bytes(33 + (c + 14) % 94 if 33 <= c <= 126 else c for c in data))]


def d_atbash(data: bytes) -> Decoded:
    if not re.search(rb"[A-Za-z]{3}", data):
        return []
    table = bytes.maketrans(
        string.ascii_lowercase.encode() + string.ascii_uppercase.encode(),
        string.ascii_lowercase[::-1].encode() + string.ascii_uppercase[::-1].encode(),
    )
    return [("atbash", data.translate(table))]


def d_reverse(data: bytes) -> Decoded:
    return [("reverse", data[::-1])] if len(data) >= 4 else []


def d_xor(data: bytes, keep: int = 3) -> Decoded:
    if len(data) < 4 or len(data) > 200_000:
        return []
    if printable_ratio(data) > 0.95 and english_score(data[:4096].decode("latin-1")) > 0.45:
        return []  # already readable text
    sample = data[:4096]
    options = []
    for key in range(1, 256):
        out = bytes(b ^ key for b in sample)
        if printable_ratio(out) < 0.9:
            continue
        options.append((english_score(out.decode("latin-1")), key))
    options.sort(key=lambda o: -o[0])
    return [(f"xor key 0x{key:02x}", bytes(b ^ key for b in data)) for _, key in options[:keep]]


def d_compressed(data: bytes) -> Decoded:
    for magic, label, fn in (
        (b"\x1f\x8b", "gunzip", gzip.decompress),
        (b"BZh", "bunzip2", bz2.decompress),
        (b"\xfd7zXZ", "unxz", lzma.decompress),
    ):
        if data.startswith(magic):
            try:
                return [(label, fn(data)[:MAX_INPUT])]
            except (OSError, EOFError, ValueError, lzma.LZMAError):
                return []
    if len(data) > 2 and data[0] == 0x78 and (data[0] * 256 + data[1]) % 31 == 0:
        try:
            return [("zlib inflate", zlib.decompress(data)[:MAX_INPUT])]
        except zlib.error:
            return []
    return []


def d_zero_width(data: bytes) -> Decoded:
    """Text hidden in invisible Unicode characters (zero-width space/joiner...)."""
    try:
        return stego.zero_width(data.decode("utf-8"))
    except UnicodeDecodeError:
        return []


def d_whitespace(data: bytes) -> Decoded:
    """Bits hidden as spaces/tabs at the ends of lines."""
    try:
        return stego.whitespace(data.decode("utf-8"))
    except UnicodeDecodeError:
        return []


DECODERS: list[Callable[[bytes], Decoded]] = [
    d_zero_width,
    d_whitespace,
    d_compressed,
    d_base64,
    d_base32,
    d_base58,
    d_base85,
    d_hex,
    d_binary,
    d_decimal,
    d_octal,
    d_url,
    d_html,
    d_escapes,
    d_morse,
    d_rot47,
    d_atbash,
    d_reverse,
    d_xor,
]
# Families that can spit out "plausible" garbage on nearly any input: only expand from them once.
WEAK = ("caesar", "rot13", "rot47", "atbash", "reverse", "xor")


@dataclass
class Node:
    data: bytes
    chain: tuple[str, ...]
    score: float = 0.0
    flags: list[dict] = field(default_factory=list)


def decode(
    text: str,
    hunter: FlagHunter | None = None,
    max_depth: int = 4,
    try_caesar: bool = True,
    try_xor: bool = True,
) -> dict:
    hunter = hunter or FlagHunter()
    raw = text.encode("utf-8")[:MAX_INPUT]
    root_flags = hunter.scan_bytes(raw)
    seen = {hashlib.sha1(raw).digest()}
    results: list[Node] = []
    frontier = [Node(raw, (), score(raw, root_flags), root_flags)]
    nodes = 0

    for _depth in range(max(1, min(max_depth, 6))):
        children: list[Node] = []
        for parent in frontier:
            ops = list(DECODERS)
            if not try_xor:
                ops.remove(d_xor)
            outputs: Decoded = []
            for op in ops:
                try:
                    outputs.extend(op(parent.data))
                except Exception:  # noqa: BLE001 - one odd decoder must never break the search
                    continue
            if try_caesar:
                outputs.extend(d_caesar(parent.data))
            for label, out in outputs:
                if not out or len(out) > MAX_INPUT:
                    continue
                # don't chain two brute-force/cosmetic steps of the same family back to back
                if (
                    parent.chain
                    and parent.chain[-1].split()[0] in WEAK
                    and label.split()[0] in WEAK
                ):
                    continue
                digest = hashlib.sha1(out).digest()
                if digest in seen:
                    continue
                seen.add(digest)
                nodes += 1
                flags = hunter.scan_bytes(out)
                children.append(Node(out, parent.chain + (label,), score(out, flags), flags))
                if nodes >= MAX_NODES:
                    break
        if not children:
            break
        results.extend(children)
        # Expand the most promising: high scores, plus anything that still looks encoded.
        children.sort(key=lambda n: -n.score)
        encoded_looking = [
            n
            for n in children
            if printable_ratio(n.data) > 0.95
            and any(rx.match(n.data.strip()) for rx in (B64_RE, B32_RE, HEX_RE, BIN_RE, MORSE_RE))
        ]
        frontier = list({id(n): n for n in children[:BEAM] + encoded_looking[:BEAM]}.values())
        if nodes >= MAX_NODES:
            break

    # Once a flag in a known format is found, "possible" look-alikes (e.g. ROT-shifted copies of it)
    # are ranked as ordinary text so real alternatives aren't buried under them.
    if any(f["confidence"] == "high" for n in results for f in n.flags):
        for n in results:
            if n.flags and not any(f["confidence"] == "high" for f in n.flags):
                n.score = min(score(n.data, []), 0.99)
    results.sort(key=lambda n: (-n.score, len(n.chain)))
    out = []
    for n in results[:30]:
        printable = printable_ratio(n.data) > 0.9
        out.append(
            {
                "chain": list(n.chain),
                "score": round(n.score, 3),
                "quality": round(text_quality(n.data), 3),
                "printable": printable,
                "text": n.data.decode("utf-8", "replace")[:5000] if printable else None,
                "hex": n.data[:256].hex(" ") if not printable else None,
                "length": len(n.data),
                "flags": n.flags,
            }
        )
    flags = {f["value"]: f for f in root_flags}
    for n in results:
        for f in n.flags:
            flags.setdefault(f["value"], {**f, "chain": list(n.chain)})
    confirmed = [f for f in flags.values() if f["confidence"] == "high"]
    # Once a flag in a known format is found, "possible" look-alikes (e.g. ROT-shifted copies) are noise.
    possible = list(flags.values())
    clean = [f for f in possible if not any(step.split()[0] in WEAK for step in f.get("chain", []))]
    summary = confirmed or clean or possible[:5]
    return {"results": out, "flags": summary, "explored": nodes}
