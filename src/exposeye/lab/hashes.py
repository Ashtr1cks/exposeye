"""Hash identification and dictionary lookup for CTF challenges.

- Guess the algorithm of a hash from its shape (length, charset, known prefixes).
- Check a hash against a wordlist (a small built-in common-password list, or one the
  user points to, e.g. rockyou.txt). This is the standard "crack this CTF hash" workflow;
  it only confirms weak/known passwords, the same as John the Ripper or hashcat in dictionary mode.

No hashing beyond hashlib, no network. Salted/slow schemes (bcrypt, argon2) are identified
but not cracked here - the app points you to john/hashcat for those.
"""

from __future__ import annotations

import binascii
import hashlib
import hmac
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

MAX_WORDLIST_BYTES = 200 * 1024 * 1024
BUILTIN_WORDS = [
    "password",
    "123456",
    "123456789",
    "12345678",
    "12345",
    "qwerty",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "111111",
    "1234567",
    "dragon",
    "baseball",
    "iloveyou",
    "trustno1",
    "sunshine",
    "master",
    "welcome",
    "shadow",
    "ashley",
    "superman",
    "qazwsx",
    "michael",
    "admin",
    "root",
    "toor",
    "password1",
    "password123",
    "p@ssw0rd",
    "hello",
    "secret",
    "flag",
    "ctf",
    "test",
    "guest",
    "changeme",
    "god",
    "love",
    "sex",
    "money",
    "live",
    "hunter2",
    "pokemon",
    "starwars",
    "whatever",
    "zaq12wsx",
    "princess",
    "login",
    "qwerty123",
]


@dataclass(frozen=True)
class HashType:
    name: str
    algo: str | None  # a hashlib name when we can verify it, else None
    note: str = ""


# ---------------------------------------------------------------- identification

_HEX = re.compile(r"^[0-9a-fA-F]+$")
# raw-hex schemes keyed by digest length (nibbles)
_BY_LEN: dict[int, list[HashType]] = {
    32: [
        HashType("MD5", "md5"),
        HashType("MD4", "md4"),
        HashType("NTLM", "ntlm", "Windows password hash"),
        HashType("MD2", None),
    ],
    40: [HashType("SHA-1", "sha1"), HashType("RIPEMD-160", "ripemd160")],
    56: [HashType("SHA-224", "sha224"), HashType("SHA3-224", "sha3_224")],
    64: [
        HashType("SHA-256", "sha256"),
        HashType("SHA3-256", "sha3_256"),
        HashType("BLAKE2s", "blake2s"),
        HashType("SHA-512/256", None),
    ],
    96: [HashType("SHA-384", "sha384"), HashType("SHA3-384", "sha3_384")],
    128: [
        HashType("SHA-512", "sha512"),
        HashType("SHA3-512", "sha3_512"),
        HashType("BLAKE2b", "blake2b"),
        HashType("Whirlpool", "whirlpool"),
    ],
    16: [HashType("CRC-64 / MySQL<4.1", None)],
    8: [HashType("CRC-32 / Adler-32", None)],
}
# schemes with an identifying prefix
_PREFIX: list[tuple[re.Pattern, HashType]] = [
    (
        re.compile(r"^\$2[aby]\$\d\d\$.{53}$"),
        HashType("bcrypt", None, "slow salted hash - use john/hashcat"),
    ),
    (
        re.compile(r"^\$argon2(id|i|d)\$"),
        HashType("Argon2", None, "slow salted hash - use john/hashcat"),
    ),
    (re.compile(r"^\$y\$"), HashType("yescrypt", None, "Linux shadow - use john/hashcat")),
    (re.compile(r"^\$6\$"), HashType("sha512crypt", None, "Linux shadow ($6$) - use john/hashcat")),
    (re.compile(r"^\$5\$"), HashType("sha256crypt", None, "Linux shadow ($5$) - use john/hashcat")),
    (re.compile(r"^\$1\$"), HashType("md5crypt", None, "Linux shadow ($1$) - use john/hashcat")),
    (re.compile(r"^\$P\$|^\$H\$"), HashType("phpass", None, "WordPress/phpBB - use john/hashcat")),
    (re.compile(r"^\{SSHA\}"), HashType("SSHA (LDAP)", None)),
    (re.compile(r"^\{SHA\}"), HashType("SHA-1 (LDAP base64)", None)),
    (
        re.compile(r"^[0-9a-f]{32}:[0-9a-zA-Z]+$", re.I),
        HashType("md5($pass.$salt)", None, "salted MD5"),
    ),
    (re.compile(r"^[0-9a-f]{32}:.{1,}$", re.I), HashType("salted MD5", None)),
    (re.compile(r"^[A-Za-z0-9./]{13}$"), HashType("DES crypt", None, "classic Unix crypt")),
    (re.compile(r"^\*[0-9A-F]{40}$"), HashType("MySQL 4.1+ (SHA-1 x2)", None)),
    (re.compile(r"^[0-9a-f]{32}$", re.I), None),  # placeholder: handled by length table
]


def identify(value: str) -> list[HashType]:
    h = value.strip()
    out: list[HashType] = []
    for pat, ht in _PREFIX:
        if ht is not None and pat.match(h):
            out.append(ht)
    if _HEX.match(h):
        out.extend(_BY_LEN.get(len(h), []))
    if not out and h.startswith("$"):
        out.append(HashType("crypt-style hash", None, "unrecognised $-scheme; try john/hashcat"))
    # de-dup by name, keep order
    seen, uniq = set(), []
    for ht in out:
        if ht.name not in seen:
            seen.add(ht.name)
            uniq.append(ht)
    return uniq


# ---------------------------------------------------------------- verifiers


def _md4(data: bytes) -> bytes:
    """Pure-Python MD4 (OpenSSL 3 often disables it, which NTLM needs)."""
    try:
        return hashlib.new("md4", data).digest()
    except (ValueError, TypeError):
        pass
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    msg = bytearray(data)
    orig = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += orig.to_bytes(8, "little")
    mask = 0xFFFFFFFF

    def rol(x, n):
        x &= mask
        return ((x << n) | (x >> (32 - n))) & mask

    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + i : off + i + 4], "little") for i in range(0, 64, 4)]
        aa, bb, cc, dd = a, b, c, d
        for i in (0, 4, 8, 12):
            a = rol((a + ((b & c) | (~b & d)) + x[i]) & mask, 3)
            d = rol((d + ((a & b) | (~a & c)) + x[i + 1]) & mask, 7)
            c = rol((c + ((d & a) | (~d & b)) + x[i + 2]) & mask, 11)
            b = rol((b + ((c & d) | (~c & a)) + x[i + 3]) & mask, 19)
        for i in (0, 1, 2, 3):
            a = rol((a + ((b & c) | (b & d) | (c & d)) + x[i] + 0x5A827999) & mask, 3)
            d = rol((d + ((a & b) | (a & c) | (b & c)) + x[i + 4] + 0x5A827999) & mask, 5)
            c = rol((c + ((d & a) | (d & b) | (a & b)) + x[i + 8] + 0x5A827999) & mask, 9)
            b = rol((b + ((c & d) | (c & a) | (d & a)) + x[i + 12] + 0x5A827999) & mask, 13)
        for i in (0, 2, 1, 3):
            a = rol((a + (b ^ c ^ d) + x[i] + 0x6ED9EBA1) & mask, 3)
            d = rol((d + (a ^ b ^ c) + x[i + 8] + 0x6ED9EBA1) & mask, 9)
            c = rol((c + (d ^ a ^ b) + x[i + 4] + 0x6ED9EBA1) & mask, 11)
            b = rol((b + (c ^ d ^ a) + x[i + 12] + 0x6ED9EBA1) & mask, 15)
        a, b, c, d = (a + aa) & mask, (b + bb) & mask, (c + cc) & mask, (d + dd) & mask
    return b"".join(v.to_bytes(4, "little") for v in (a, b, c, d))


def _ntlm(word: str) -> str:
    return _md4(word.encode("utf-16-le")).hex()


def _raw(algo: str) -> Callable[[str], str] | None:
    try:
        hashlib.new(algo)
    except (ValueError, TypeError):
        return None
    return lambda word: hashlib.new(algo, word.encode("utf-8", "replace")).hexdigest()


def verifier(ht: HashType) -> Callable[[str], str] | None:
    """A function word -> hex digest for schemes we can compute, else None."""
    if ht.algo == "ntlm":
        return _ntlm
    if ht.algo:
        return _raw(ht.algo)
    return None


def crackable(value: str) -> list[HashType]:
    return [ht for ht in identify(value) if verifier(ht) is not None]


# ---------------------------------------------------------------- dictionary lookup


def iter_wordlist(path, limit_bytes: int = MAX_WORDLIST_BYTES) -> Iterable[str]:
    read = 0
    with open(path, "rb") as fh:
        for line in fh:
            read += len(line)
            if read > limit_bytes:
                return
            word = line.rstrip(b"\r\n")
            if word:
                yield word.decode("utf-8", "replace")


def crack(value: str, words: Iterable[str], max_words: int = 5_000_000) -> dict:
    """Try each candidate word against every algorithm this hash could be. First match wins."""
    target = value.strip().lower()
    types = crackable(value)
    if not types:
        return {"found": None, "types_tried": [], "tried": 0, "exhausted": True}
    verifiers = [(ht, verifier(ht)) for ht in types]
    tried = 0
    for word in words:
        tried += 1
        if tried > max_words:
            return {
                "found": None,
                "types_tried": [ht.name for ht in types],
                "tried": tried - 1,
                "exhausted": False,
            }
        for ht, vf in verifiers:
            try:
                if hmac.compare_digest(vf(word), target):
                    return {
                        "found": {"password": word, "type": ht.name},
                        "tried": tried,
                        "types_tried": [ht.name for ht in types],
                        "exhausted": True,
                    }
            except (binascii.Error, ValueError):
                continue
    return {
        "found": None,
        "types_tried": [ht.name for ht in types],
        "tried": tried,
        "exhausted": True,
    }


def crack_builtin(value: str) -> dict:
    """Quick check against the small common-password list (used when no wordlist is given)."""
    result = crack(value, BUILTIN_WORDS)
    result["wordlist"] = "built-in common passwords"
    return result
