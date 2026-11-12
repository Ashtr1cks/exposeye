"""Classical / keyed-cipher crackers for CTF challenges.

Where the Decoder handles keyless encodings and simple shifts, these recover text that
needs a key worked out from the ciphertext itself:
- Vigenere: decrypt with a key, or crack it (key length by index of coincidence, then
  each column solved by letter-frequency).
- Repeating-key XOR: the Cryptopals attack - key size by Hamming distance, each byte by
  single-byte XOR frequency.
- Affine: brute-force the 311 possible (a, b) keys.
- Rail-fence (zig-zag transposition): brute-force the number of rails.

All pure-Python and offline. Results are scored by how English-like they look.
"""

from __future__ import annotations

import string
from dataclasses import dataclass

from exposeye.lab.decoder import english_score, printable_ratio

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


@dataclass
class Cracked:
    text: str
    key: str
    detail: str = ""
    score: float = 0.0


# ---------------------------------------------------------------- Vigenere


def vigenere_decrypt(text: str, key: str) -> str:
    key = [c for c in key.lower() if c.isalpha()]
    if not key:
        return text
    out, ki = [], 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = ord(key[ki % len(key)]) - ord("a")
            out.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def _ioc(letters: str) -> float:
    n = len(letters)
    if n < 2:
        return 0.0
    counts = [letters.count(c) for c in string.ascii_lowercase]
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))


def _best_shift(column: str) -> int:
    best, best_chi = 0, 1e18
    n = len(column) or 1
    for shift in range(26):
        shifted = [(ord(c) - ord("a") - shift) % 26 for c in column]
        chi = 0.0
        for i, letter in enumerate(string.ascii_lowercase):
            expected = n * EN_FREQ[letter] / 100
            observed = shifted.count(i)
            chi += (observed - expected) ** 2 / (expected or 1e-9)
        if chi < best_chi:
            best_chi, best = chi, shift
    return best


def vigenere_crack(text: str, max_keylen: int = 20) -> Cracked | None:
    letters = [c.lower() for c in text if c.isalpha()]
    if len(letters) < 20:
        return None
    joined = "".join(letters)
    # key length: columns whose IoC is closest to English (~0.066) are the likeliest lengths
    scored = []
    for klen in range(1, min(max_keylen, len(joined) // 2) + 1):
        avg = sum(_ioc(joined[i::klen]) for i in range(klen)) / klen
        scored.append((abs(avg - 0.066), klen))
    scored.sort()
    # Try the most promising lengths plus their divisors (a multiple of the real length also has
    # good IoC), then keep the decryption that reads best as English - the true length usually wins.
    candidates: set[int] = set()
    for _, klen in scored[:5]:
        candidates.add(klen)
        for div in range(1, klen):
            if klen % div == 0:
                candidates.add(div)
    best = None
    for klen in sorted(candidates):
        key = "".join(chr(_best_shift(joined[i::klen]) + ord("a")) for i in range(klen))
        plain = vigenere_decrypt(text, key)
        sc = english_score(plain)
        if best is None or sc > best.score + 1e-9:
            best = Cracked(plain, key, f"Key length {klen} (index of coincidence).", round(sc, 3))
    return best


# ---------------------------------------------------------------- repeating-key XOR


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b, strict=False))


def xor_repeating_crack(data: bytes, max_keysize: int = 40) -> dict | None:
    if len(data) < 8:
        return None
    sizes = []
    for ks in range(1, min(max_keysize, len(data) // 4) + 1):
        nblocks = min(12, len(data) // ks)  # more blocks -> less noisy distance estimate
        blocks = [data[i * ks : (i + 1) * ks] for i in range(nblocks)]
        dist = 0.0
        pairs = 0
        for i in range(len(blocks)):
            for j in range(i + 1, len(blocks)):
                if len(blocks[i]) == len(blocks[j]) == ks:
                    dist += _hamming(blocks[i], blocks[j]) / ks
                    pairs += 1
        if pairs:
            sizes.append((dist / pairs, ks))
    sizes.sort()
    # a multiple of the real key size also scores low, so also try the divisors of the top
    # candidates - the true (smallest) size has the most data per column and recovers best.
    candidates: set[int] = set()
    for _, ks in sizes[:5]:
        candidates.add(ks)
        for div in range(1, ks):
            if ks % div == 0:
                candidates.add(div)
    best = None
    for ks in sorted(candidates):
        key = bytes(_best_xor_byte(data[i::ks]) for i in range(ks))
        plain = bytes(b ^ key[i % ks] for i, b in enumerate(data))
        score = printable_ratio(plain) * 0.4 + english_score(plain.decode("latin-1")) * 0.6
        if best is None or score > best["score"] + 1e-9:
            best = {
                "keysize": ks,
                "key": key,
                "key_text": _show(key),
                "text": plain.decode("utf-8", "replace")[:5000],
                "printable": printable_ratio(plain) > 0.9,
                "score": round(score, 3),
            }
    return best


def _best_xor_byte(column: bytes) -> int:
    best, best_score = 0, -1.0
    for k in range(256):
        out = bytes(b ^ k for b in column)
        if printable_ratio(out) < 0.8:
            continue
        s = english_score(out.decode("latin-1"))
        if s > best_score:
            best_score, best = s, k
    return best


def _show(key: bytes) -> str:
    try:
        t = key.decode("ascii")
        if all(32 <= ord(c) < 127 for c in t):
            return t
    except UnicodeDecodeError:
        pass
    return key.hex()


# ---------------------------------------------------------------- Affine


def affine_crack(text: str) -> Cracked | None:
    coprime = [a for a in range(1, 26) if _gcd(a, 26) == 1]
    best = None
    for a in coprime:
        a_inv = pow(a, -1, 26)
        for b in range(26):
            out = []
            for ch in text:
                if ch.isalpha():
                    base = ord("A") if ch.isupper() else ord("a")
                    y = ord(ch) - base
                    out.append(chr((a_inv * (y - b)) % 26 + base))
                else:
                    out.append(ch)
            plain = "".join(out)
            sc = english_score(plain)
            if best is None or sc > best.score:
                best = Cracked(plain, f"a={a}, b={b}", f"Affine key a={a}, b={b}.", round(sc, 3))
    return best


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


# ---------------------------------------------------------------- Rail fence


def railfence_decrypt(text: str, rails: int) -> str:
    if rails < 2:
        return text
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    counts = [0] * rails
    for i in range(len(text)):
        counts[pattern[i % len(pattern)]] += 1
    pos = 0
    filled = [""] * rails
    for r in range(rails):
        filled[r] = text[pos : pos + counts[r]]
        pos += counts[r]
    pointers = [0] * rails
    out = []
    for i in range(len(text)):
        r = pattern[i % len(pattern)]
        out.append(filled[r][pointers[r]])
        pointers[r] += 1
    return "".join(out)


def railfence_crack(text: str, max_rails: int = 12) -> list[Cracked]:
    out = []
    for rails in range(2, min(max_rails, len(text)) + 1):
        plain = railfence_decrypt(text, rails)
        out.append(Cracked(plain, str(rails), f"{rails} rails.", round(english_score(plain), 3)))
    out.sort(key=lambda c: -c.score)
    return out[:5]
