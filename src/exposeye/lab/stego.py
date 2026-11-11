"""Steganography helpers: images, audio and text.

Images  - LSB extraction in many orders (zsteg-style), bit-plane rendering (Stegsolve-style)
Audio   - WAV spectrograms (mix and left-minus-right), sample LSB, DTMF tones, Morse code
Text    - zero-width Unicode characters and trailing-whitespace encodings
"""

from __future__ import annotations

import base64
import io
import itertools
import re
import shutil
import struct
import unicodedata
import wave

import numpy as np
from PIL import Image, UnidentifiedImageError

from exposeye.lab.flags import FlagHunter

PRINTABLE = np.zeros(256, dtype=bool)
PRINTABLE[32:127] = True
PRINTABLE[[9, 10, 13]] = True
MAX_PIXELS = 25_000_000
LOSSLESS = {"PNG", "BMP", "GIF", "TIFF", "WEBP", "PPM", "TGA", "ICO"}


def _png_b64(img: Image.Image) -> str:
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=False)
    return base64.b64encode(buf.getvalue()).decode()


def _evaluate(payload: bytes, hunter: FlagHunter) -> dict:
    """How promising is an extracted byte stream? (flags, file header, readable text)."""
    from exposeye.lab.files import identify  # local import: files.py imports this module

    head = np.frombuffer(payload[:512], dtype=np.uint8)
    printable = float(PRINTABLE[head].mean()) if len(head) else 0.0
    bad = np.flatnonzero(~PRINTABLE[head])
    prefix = int(bad[0]) if len(bad) else len(head)
    flags = hunter.scan(payload.decode("latin-1"))
    magic = identify(payload)
    return {
        "printable": round(printable, 3),
        "text_prefix": prefix,
        "flags": flags,
        "magic": magic["description"] if magic else None,
        "preview": payload[:200].decode("latin-1"),
        "score": (3 if flags else 0) + (1.5 if magic else 0) + printable + min(prefix, 64) / 32,
    }


def _pack(bits: np.ndarray, lsb_first: bool) -> bytes:
    usable = len(bits) - len(bits) % 8
    return np.packbits(bits[:usable], bitorder="little" if lsb_first else "big").tobytes()


# ================================================================ images


def open_image(data: bytes) -> Image.Image | None:
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError, ValueError, SyntaxError):
        return None
    if img.width * img.height > MAX_PIXELS:
        return None
    return img


def _channels(img: Image.Image) -> tuple[np.ndarray, list[str]]:
    has_alpha = "A" in img.getbands() or (img.mode == "P" and "transparency" in img.info)
    rgb = img.convert("RGBA" if has_alpha else "RGB")
    return np.asarray(rgb), (["R", "G", "B", "A"] if has_alpha else ["R", "G", "B"])


def lsb_scan(img: Image.Image, hunter: FlagHunter, max_bytes: int = 4096) -> dict:
    """Try the extraction orders CTF tools use; return the most promising ones."""
    arr, names = _channels(img)
    nch = len(names)
    need_bits = max_bytes * 8
    orders = {
        "rows": arr,
        "columns": arr.transpose(1, 0, 2),
        "rows, reversed": arr[::-1, ::-1],
    }
    sets = {n: [i] for i, n in enumerate(names)}
    sets.update({"RGB": [0, 1, 2], "BGR": [2, 1, 0]})
    if nch == 4:
        sets["RGBA"] = [0, 1, 2, 3]
    candidates, tried = [], 0
    for order, a in orders.items():
        flat = a.reshape(-1, nch)
        for cname, idx in sets.items():
            pixels = -(-need_bits // len(idx))
            vals = flat[:pixels][:, idx].reshape(-1)
            for bit in (0, 1, 2):
                bits = ((vals >> bit) & 1).astype(np.uint8)
                for packing in ("msb-first", "lsb-first"):
                    tried += 1
                    payload = _pack(bits[:need_bits], packing == "lsb-first")
                    candidates.append(
                        {
                            "channels": cname,
                            "bit": bit,
                            "order": order,
                            "packing": packing,
                            **_evaluate(payload, hunter),
                        }
                    )
    if img.mode == "P":  # palette images: the hidden bits live in the colour *indices*
        idx = np.asarray(img)
        for order, a in {"rows": idx, "columns": idx.T}.items():
            vals = a.reshape(-1)[:need_bits]
            for bit in (0, 1):
                for packing in ("msb-first", "lsb-first"):
                    tried += 1
                    payload = _pack(((vals >> bit) & 1).astype(np.uint8), packing == "lsb-first")
                    candidates.append(
                        {
                            "channels": "palette index",
                            "bit": bit,
                            "order": order,
                            "packing": packing,
                            **_evaluate(payload, hunter),
                        }
                    )
    candidates.sort(key=lambda c: -c["score"])
    # keep variety: the same text found via several orders is listed once
    seen, best = set(), []
    for c in candidates:
        key = c["preview"][:40]
        if key in seen:
            continue
        seen.add(key)
        best.append(c)
        if len(best) == 10:
            break
    return {"candidates": best, "tried": tried}


def plane_options(img: Image.Image) -> list[str]:
    _, names = _channels(img)
    opts = [*names, "Luminance"]
    if img.mode == "P":
        opts.append("Palette index")
    return opts


def render_plane(
    img: Image.Image, channel: str, bit: int, mode: str, max_side: int = 2048
) -> Image.Image:
    """One Stegsolve-style view of the image."""
    arr, names = _channels(img)
    if channel == "Palette index" and img.mode == "P":
        values = np.asarray(img)
    elif channel == "Luminance":
        values = np.asarray(img.convert("L"))
    elif channel in names:
        values = arr[:, :, names.index(channel)]
    else:
        raise ValueError(f"unknown channel {channel!r}")
    if mode == "bit":
        out = Image.fromarray((((values >> bit) & 1) * 255).astype(np.uint8), "L")
    elif mode == "channel":
        out = Image.fromarray(values.astype(np.uint8), "L")
    elif mode == "inverted":
        out = Image.fromarray((255 - values).astype(np.uint8), "L")
    elif mode == "random":
        # every distinct value gets an unrelated colour: reveals text hidden in near-identical shades
        lut = np.random.default_rng(1337).integers(0, 256, size=(256, 3), dtype=np.uint8)
        out = Image.fromarray(lut[values.astype(np.uint8)], "RGB")
    else:
        raise ValueError(f"unknown mode {mode!r}")
    if max(out.size) > max_side:
        scale = max_side / max(out.size)
        out = out.resize(
            (max(1, int(out.width * scale)), max(1, int(out.height * scale))), Image.NEAREST
        )
    return out


def plane_thumbnails(img: Image.Image, size: int = 150) -> list[dict]:
    """Every bit plane of every channel, as small thumbnails for an at-a-glance overview."""
    arr, names = _channels(img)
    step = max(1, -(-max(img.width, img.height) // size))
    small = arr[::step, ::step]  # nearest-neighbour sampling keeps bits intact
    thumbs = []
    for ci, cname in enumerate(names):
        chan = small[:, :, ci]
        for bit in range(8):
            plane = Image.fromarray((((chan >> bit) & 1) * 255).astype(np.uint8), "L")
            thumbs.append({"channel": cname, "bit": bit, "png": _png_b64(plane)})
    return thumbs


def image_stego(data: bytes, hunter: FlagHunter) -> dict | None:
    img = open_image(data)
    if img is None:
        return None
    lossless = img.format in LOSSLESS
    result = {"lossless": lossless, "channels": plane_options(img), "planes": plane_thumbnails(img)}
    if lossless:
        result.update(lsb_scan(img, hunter))
    return result


# ================================================================ audio

DTMF_ROWS = [697, 770, 852, 941]
DTMF_COLS = [1209, 1336, 1477, 1633]
DTMF_KEYS = ["123A", "456B", "789C", "*0#D"]
MAX_AUDIO_SECONDS = 180


def _read_wav(data: bytes) -> tuple[np.ndarray, int, int, bytes] | None:
    if not (data[:4] == b"RIFF" and data[8:12] == b"WAVE"):
        return None
    try:
        with wave.open(io.BytesIO(data)) as w:
            nch, width, rate = w.getnchannels(), w.getsampwidth(), w.getframerate()
            raw = w.readframes(min(w.getnframes(), rate * MAX_AUDIO_SECONDS))
    except (wave.Error, EOFError, struct.error):
        return None
    if width == 1:
        samples = np.frombuffer(raw, dtype=np.uint8).astype(np.int16) - 128
    elif width == 2:
        samples = np.frombuffer(raw, dtype="<i2")
    elif width == 3:
        b = (
            np.frombuffer(raw[: len(raw) - len(raw) % 3], dtype=np.uint8)
            .reshape(-1, 3)
            .astype(np.int32)
        )
        samples = b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16)
        samples = np.where(samples & 0x800000, samples - 0x1000000, samples)
    elif width == 4:
        samples = np.frombuffer(raw, dtype="<i4")
    else:
        return None
    samples = samples[: len(samples) - len(samples) % nch].reshape(-1, nch)
    return samples, rate, width, raw


def _colormap() -> np.ndarray:
    """A perceptual dark-to-bright palette (close to 'inferno')."""
    anchors = np.array(
        [
            [0, 0, 4],
            [40, 11, 84],
            [101, 21, 110],
            [159, 42, 99],
            [212, 72, 66],
            [245, 125, 21],
            [250, 193, 39],
            [252, 255, 164],
        ],
        dtype=float,
    )
    x = np.linspace(0, len(anchors) - 1, 256)
    lo = np.floor(x).astype(int)
    hi = np.minimum(lo + 1, len(anchors) - 1)
    t = (x - lo)[:, None]
    return (anchors[lo] * (1 - t) + anchors[hi] * t).astype(np.uint8)


CMAP = _colormap()


def spectrogram(x: np.ndarray, rate: int, width: int = 1400, height: int = 420) -> str:
    x = x.astype(np.float32)
    n_fft = 2048 if rate >= 32000 else 1024 if rate >= 16000 else 512
    if len(x) < n_fft:
        x = np.pad(x, (0, n_fft - len(x)))
    hop = max(n_fft // 4, (len(x) - n_fft) // (width * 2) + 1)
    frames = np.lib.stride_tricks.sliding_window_view(x, n_fft)[::hop] * np.hanning(n_fft).astype(
        np.float32
    )
    mag = np.abs(np.fft.rfft(frames, axis=1))
    db = 20 * np.log10(mag + 1e-6)
    lo, hi = np.percentile(db, 5), np.percentile(db, 99.7)
    norm = np.clip((db - lo) / max(hi - lo, 1e-6), 0, 1)
    pixels = (norm.T[::-1] * 255).astype(np.uint8)  # frequency on the y axis, low at the bottom
    img = Image.fromarray(CMAP[pixels], "RGB").resize((width, height), Image.BILINEAR)
    return _png_b64(img)


def _dtmf(mono: np.ndarray, rate: int) -> str | None:
    if rate < 4000:
        return None
    n = int(rate * 0.04)
    if len(mono) < n * 3:
        return None
    frames = mono[: len(mono) - len(mono) % n].astype(np.float32).reshape(-1, n)
    spec = np.abs(np.fft.rfft(frames * np.hanning(n), axis=1))
    freqs = np.fft.rfftfreq(n, 1 / rate)

    def power(f):
        return spec[:, np.argmin(np.abs(freqs - f))]

    rows = np.stack([power(f) for f in DTMF_ROWS], axis=1)
    cols = np.stack([power(f) for f in DTMF_COLS], axis=1)
    total = spec.sum(axis=1) + 1e-9
    r, c = rows.argmax(axis=1), cols.argmax(axis=1)
    strong = (rows.max(axis=1) + cols.max(axis=1)) / total > 0.08
    loud = total > np.percentile(total, 60) * 0.5
    keys = [
        DTMF_KEYS[ri][ci] if (s and lo) else None
        for ri, ci, s, lo in zip(r, c, strong, loud, strict=True)
    ]
    out, prev, run = [], None, 0
    for k in keys + [None]:
        if k == prev:
            run += 1
            continue
        if prev is not None and run >= 2:
            out.append(prev)
        prev, run = k, 1
    digits = "".join(out)
    return digits if len(digits) >= 3 else None


def _morse_audio(mono: np.ndarray, rate: int) -> str | None:
    from exposeye.lab.decoder import MORSE

    step = max(1, int(rate * 0.005))
    env = (
        np.abs(mono[: len(mono) - len(mono) % step].astype(np.float32))
        .reshape(-1, step)
        .mean(axis=1)
    )
    if not len(env) or env.max() <= 0:
        return None
    on = env > env.max() * 0.35
    edges = np.flatnonzero(np.diff(on.astype(np.int8))) + 1
    runs = np.split(on, edges)
    lengths = [(bool(r[0]), len(r)) for r in runs if len(r)]
    ons = [n for state, n in lengths if state]
    if len(ons) < 6:
        return None
    unit = np.percentile(ons, 25)
    if unit < 2:
        return None
    code, out = "", []
    for state, n in lengths:
        if state:
            code += "." if n < unit * 2 else "-"
        elif n >= unit * 5:
            out.extend([code, " "]) if code else out.append(" ")
            code = ""
        elif n >= unit * 2:
            out.append(code)
            code = ""
    out.append(code)
    letters = []
    for symbol in out:
        if symbol == " ":
            letters.append(" ")
        elif symbol:
            letters.append(MORSE.get(symbol, "?"))
    text = re.sub(r"\s+", " ", "".join(letters)).strip()
    valid = sum(ch not in "? " for ch in text)
    if valid < 3 or text.count("?") > valid * 0.3:
        return None
    return text


def audio_stego(data: bytes, hunter: FlagHunter) -> dict | None:
    wav = _read_wav(data)
    if wav is None:
        return None
    samples, rate, width, raw = wav
    nch = samples.shape[1]
    mono = samples.mean(axis=1)
    result = {
        "channels": nch,
        "rate": rate,
        "bits": width * 8,
        "duration": round(len(samples) / rate, 2) if rate else 0,
        "spectrograms": [{"label": "All channels mixed", "png": spectrogram(mono, rate)}],
        "max_freq": rate // 2,
    }
    if nch == 2:
        diff = samples[:, 0].astype(np.float32) - samples[:, 1]
        if np.abs(diff).mean() > 1e-3 * (np.abs(mono).mean() + 1):
            result["spectrograms"].append(
                {
                    "label": "Left minus right (reveals signals hidden in stereo)",
                    "png": spectrogram(diff, rate),
                }
            )
    # LSB of the samples (interleaved and per channel)
    candidates = []
    need = 4096 * 8
    streams = {"all samples": samples.reshape(-1)}
    if nch > 1:
        streams.update({f"channel {i + 1}": samples[:, i] for i in range(nch)})
    for name, s in streams.items():
        for bit in (0, 1):
            bits = ((s[:need] >> bit) & 1).astype(np.uint8)
            for packing in ("msb-first", "lsb-first"):
                payload = _pack(bits, packing == "lsb-first")
                candidates.append(
                    {
                        "channels": name,
                        "bit": bit,
                        "order": "time",
                        "packing": packing,
                        **_evaluate(payload, hunter),
                    }
                )
    candidates.sort(key=lambda c: -c["score"])
    result["lsb"] = candidates[:6]
    result["dtmf"] = _dtmf(mono, rate)
    result["morse"] = _morse_audio(mono, rate)
    return result


# ================================================================ text

ZERO_WIDTH = "​‌‍⁠﻿‎‏᠎‪‫‬‭‮⁡⁢⁣⁤"


def _char_name(c: str) -> str:
    return f"U+{ord(c):04X} {unicodedata.name(c, '')}".strip()


def _bits_to_bytes(bits: str) -> bytes:
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits) - len(bits) % 8, 8))


def _printable(b: bytes) -> float:
    return float(PRINTABLE[np.frombuffer(b, dtype=np.uint8)].mean()) if b else 0.0


def zero_width(text: str) -> list[tuple[str, bytes]]:
    seq = [c for c in text if c in ZERO_WIDTH]
    if len(seq) < 8:
        return []
    symbols = sorted(set(seq))
    out: list[tuple[float, str, bytes]] = []
    if len(symbols) == 2:
        for zero in symbols:
            bits = "".join("0" if c == zero else "1" for c in seq)
            data = _bits_to_bytes(bits)
            out.append((_printable(data), f"zero-width binary ({_char_name(zero)} = 0)", data))
    elif len(symbols) in (3, 4):
        base = len(symbols)
        per_byte = 6 if base == 3 else 4
        for perm in itertools.permutations(symbols):
            digit = {c: i for i, c in enumerate(perm)}
            vals = [
                sum(
                    digit[c] * base ** (per_byte - 1 - k)
                    for k, c in enumerate(seq[i : i + per_byte])
                )
                for i in range(0, len(seq) - len(seq) % per_byte, per_byte)
            ]
            if vals and max(vals) < 256:
                data = bytes(vals)
                out.append((_printable(data), f"zero-width base-{base}", data))
    out.sort(key=lambda o: -o[0])
    return [(label, data) for score, label, data in out[:2] if score > 0.8]


def whitespace(text: str) -> list[tuple[str, bytes]]:
    tails = [m.group(1) for line in text.splitlines() if (m := re.search(r"[^ \t]([ \t]+)$", line))]
    if len(tails) < 4:
        return []
    joined = "".join(tails)
    out = []
    for zero, label in ((" ", "space = 0, tab = 1"), ("\t", "tab = 0, space = 1")):
        data = _bits_to_bytes("".join("0" if c == zero else "1" for c in joined))
        if _printable(data) > 0.8:
            out.append((f"trailing whitespace ({label})", data))
    return out


def text_stego(data: bytes, hunter: FlagHunter) -> list[dict]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []
    found = []
    for label, payload in zero_width(text) + whitespace(text):
        found.append(
            {
                "method": label,
                "output": payload.decode("utf-8", "replace")[:2000],
                "flags": hunter.scan(payload.decode("latin-1")),
            }
        )
    zw = sum(c in ZERO_WIDTH for c in text)
    if zw and not found:
        found.append(
            {
                "method": f"{zw} zero-width characters present but not decodable as binary/base-k",
                "output": "",
                "flags": [],
            }
        )
    return found


# ================================================================ external tools


def jpeg_tools() -> dict:
    return {name: bool(shutil.which(name)) for name in ("steghide", "stegseek", "outguess")}
