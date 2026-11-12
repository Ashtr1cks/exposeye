"""RSA helpers for CTF challenges: recover the plaintext from the kind of broken or
small RSA that shows up in challenges, and parse public keys.

Everything is offline and pure-Python. What it can do:
- Decrypt when you already have the private pieces (d, or p and q).
- Factor a small or weak modulus (trial division, Fermat for close primes, Pollard's rho).
- Small-exponent attack (e.g. e=3 with no padding: plain e-th root of the ciphertext).
- Wiener's attack (small private exponent d).
- Common-modulus attack (same n, two coprime exponents, two ciphertexts).
- Read n and e out of a PEM/DER public key.

It will NOT break correctly-sized, properly-padded RSA - nothing can without the key.
"""

from __future__ import annotations

import base64
import math
import re
import time
from dataclasses import dataclass

TRIAL_LIMIT = 1_000_000
FERMAT_ITERS = 50_000
RHO_ITERS = 400_000
TIME_BUDGET = 8.0  # seconds; secure moduli won't factor, so give up quickly


# ---------------------------------------------------------------- number helpers


def iroot(n: int, k: int) -> tuple[int, bool]:
    """Integer k-th root of n; returns (root, exact)."""
    if n < 0:
        raise ValueError("negative")
    if n == 0:
        return 0, True
    if k == 1:
        return n, True
    lo, hi = 0, 1 << (n.bit_length() // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid**k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo, lo**k == n


def long_to_bytes(n: int) -> bytes:
    if n <= 0:
        return b""
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _as_text(m: int) -> dict:
    raw = long_to_bytes(m)
    try:
        text = raw.decode("utf-8")
        printable = all(32 <= b < 127 or b in (9, 10, 13) for b in raw)
    except UnicodeDecodeError:
        text, printable = None, False
    return {
        "int": m,
        "bytes_hex": raw.hex(),
        "text": text if printable else None,
        "preview": raw.decode("latin-1")[:200],
    }


# ---------------------------------------------------------------- factoring


def _pollard_rho(n: int, deadline: float) -> int | None:
    if n % 2 == 0:
        return 2
    import random

    for _ in range(4):
        x = y = random.randint(2, n - 1)
        c = random.randint(1, n - 1)
        d = 1
        steps = 0
        while d == 1 and steps < RHO_ITERS:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
            steps += 1
            if steps % 4096 == 0 and time.monotonic() > deadline:
                return None
        if 1 < d < n:
            return d
    return None


def factorize(n: int, budget: float = TIME_BUDGET) -> tuple[int, int] | None:
    """Return (p, q) for a semiprime n if we can split it in the time budget, else None."""
    if n < 4:
        return None
    if n % 2 == 0:
        return 2, n // 2
    deadline = time.monotonic() + budget
    # small trial division
    f = 3
    while f <= TRIAL_LIMIT and f * f <= n:
        if n % f == 0:
            return f, n // f
        f += 2
        if f % 100000 == 1 and time.monotonic() > deadline:
            return None
    # Fermat: good when p and q are close (even for large n)
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for i in range(FERMAT_ITERS):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if 1 < p < n:
                return p, q
        a += 1
        if i % 4096 == 0 and time.monotonic() > deadline:
            break
    # Pollard's rho for medium factors (hopeless on a secure modulus, so it's time-bounded)
    if time.monotonic() < deadline:
        d = _pollard_rho(n, deadline)
        if d and 1 < d < n:
            return d, n // d
    return None


# ---------------------------------------------------------------- attacks


@dataclass
class RSAResult:
    method: str
    recovered: dict | None = None  # the message, via _as_text
    detail: str = ""
    p: int | None = None
    q: int | None = None
    d: int | None = None


def _decrypt_with_pq(n, e, c, p, q) -> RSAResult:
    phi = (p - 1) * (q - 1)
    try:
        d = pow(e, -1, phi)
    except ValueError:
        return RSAResult(
            "factored",
            detail=f"e is not invertible mod phi (gcd(e,phi) != 1). p={p}, q={q}",
            p=p,
            q=q,
        )
    m = pow(c, d, n) if c is not None else None
    return RSAResult(
        "factored",
        recovered=_as_text(m) if m is not None else None,
        detail="Factored n into p and q, then derived d.",
        p=p,
        q=q,
        d=d,
    )


def wiener(n: int, e: int) -> int | None:
    """Recover d when it is small (d < n^0.25 / 3), via continued fractions of e/n."""

    # continued-fraction convergents of e/n
    def convergents(a, b):
        cf = []
        while b:
            cf.append(a // b)
            a, b = b, a % b
        num0, num1, den0, den1 = 1, cf[0], 0, 1
        yield cf[0], 1
        for q in cf[1:]:
            num0, num1 = num1, q * num1 + num0
            den0, den1 = den1, q * den1 + den0
            yield num1, den1

    for k, d in convergents(e, n):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # solve x^2 - (n - phi + 1) x + n = 0 ; integer roots -> p, q
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        s = math.isqrt(disc)
        if s * s == disc and (b + s) % 2 == 0:
            return d
    return None


def solve(
    n: int,
    e: int,
    c: int | None = None,
    p: int | None = None,
    q: int | None = None,
    d: int | None = None,
) -> RSAResult:
    """Pick and run whichever attack the given parameters allow."""
    if d is not None and n is not None and c is not None:
        return RSAResult(
            "private key given",
            recovered=_as_text(pow(c, d, n)),
            detail="Used the supplied d.",
            d=d,
        )
    if p is not None and q is None and n is not None and n % p == 0:
        q = n // p
    if q is not None and p is None and n is not None and n % q == 0:
        p = n // q
    if p is not None and q is not None:
        return _decrypt_with_pq(n, e, c, p, q)

    # small-exponent / no padding: the e-th root of c is the message
    if c is not None and e is not None and e <= 11:
        root, exact = iroot(c, e)
        if exact:
            return RSAResult(
                "small exponent (e-th root)",
                recovered=_as_text(root),
                detail=f"c has an exact {e}-th root, so m^{e} < n (no padding).",
            )

    # try to factor n
    if n is not None:
        pq = factorize(n)
        if pq:
            return _decrypt_with_pq(n, e, c, *pq)

    # Wiener (small d)
    if n is not None and e is not None:
        dw = wiener(n, e)
        if dw is not None:
            m = pow(c, dw, n) if c is not None else None
            return RSAResult(
                "Wiener (small d)",
                recovered=_as_text(m) if m is not None else None,
                detail="Private exponent d was small enough for Wiener's attack.",
                d=dw,
            )

    return RSAResult(
        "none",
        detail="Couldn't recover the key. n is likely a secure size with no weakness, "
        "or more parameters are needed. For big n, try factordb.com or RsaCtfTool.",
    )


def common_modulus(n: int, e1: int, c1: int, e2: int, c2: int) -> RSAResult:
    """Same message encrypted under the same n with two coprime exponents."""
    g = math.gcd(e1, e2)
    if g != 1:
        return RSAResult(
            "common modulus",
            detail=f"The two exponents share a factor (gcd={g}); attack needs them coprime.",
        )
    # e1*a + e2*b = 1
    _, a, b = _egcd(e1, e2)
    m1 = pow(c1, a, n) if a >= 0 else pow(pow(c1, -1, n), -a, n)
    m2 = pow(c2, b, n) if b >= 0 else pow(pow(c2, -1, n), -b, n)
    m = (m1 * m2) % n
    return RSAResult(
        "common modulus",
        recovered=_as_text(m),
        detail="Same n and message under two coprime exponents - combined with Bezout coefficients.",
    )


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


# ---------------------------------------------------------------- public-key parsing


def _der_ints(der: bytes) -> list[int]:
    """Walk DER and collect every SEQUENCE of exactly two INTEGERs; drill into BIT STRINGs."""
    found: list[tuple[int, int]] = []

    def read_len(data, i):
        ln = data[i]
        i += 1
        if ln & 0x80:
            k = ln & 0x7F
            ln = int.from_bytes(data[i : i + k], "big")
            i += k
        return ln, i

    def walk(data):
        i = 0
        while i + 2 <= len(data):
            tag = data[i]
            ln, j = read_len(data, i + 1)
            body = data[j : j + ln]
            if tag == 0x30:  # SEQUENCE
                ints = _two_ints(body)
                if ints:
                    found.append(ints)
                walk(body)
            elif tag == 0x03 and body:  # BIT STRING: content after the unused-bits byte
                try:
                    walk(body[1:])
                except Exception:  # noqa: BLE001
                    pass
            i = j + ln

    def _two_ints(seq):
        items, i = [], 0
        while i + 2 <= len(seq) and len(items) <= 2:
            tag = seq[i]
            ln, j = read_len(seq, i + 1)
            if tag == 0x02:
                items.append(int.from_bytes(seq[j : j + ln], "big"))
            else:
                return None
            i = j + ln
        return (items[0], items[1]) if len(items) == 2 and i >= len(seq) else None

    walk(der)
    return found


def parse_pubkey(text: str) -> dict | None:
    """Extract (n, e) from a PEM or raw DER RSA public key."""
    text = text.strip()
    der = None
    m = re.search(r"-----BEGIN [^-]+-----(.+?)-----END", text, re.S)
    if m:
        try:
            der = base64.b64decode("".join(m.group(1).split()))
        except (ValueError, base64.binascii.Error):
            return None
    elif re.fullmatch(r"[0-9a-fA-F\s]+", text) and len(text.split()) == 0:
        try:
            der = bytes.fromhex(text)
        except ValueError:
            return None
    if der is None:
        return None
    pairs = _der_ints(der)
    if not pairs:
        return None
    # RSAPublicKey is {n, e}: n is the big one, e the small (often 65537)
    n, e = max(pairs, key=lambda p: p[0])
    if e > n:
        n, e = e, n
    return {"n": n, "e": e, "bits": n.bit_length()}
