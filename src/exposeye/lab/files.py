"""File analyser for CTF forensics/stego challenges.

Files are only ever *read* - nothing is executed or extracted to disk. Covers:
real file type (magic bytes) vs extension, hashes, entropy, strings, embedded files
(binwalk-style signature scan), data appended after the end of a file, metadata
(EXIF/GPS, PNG text chunks, PDF info, ZIP listing, Office properties), PNG chunk/CRC checks
with automatic recovery of tampered dimensions, and LSB steganography for lossless images.
"""

from __future__ import annotations

import hashlib
import io
import math
import re
import struct
import zipfile
import zlib
from pathlib import PurePath

import numpy as np
from PIL import ExifTags, Image, UnidentifiedImageError

from exposeye.lab import stego
from exposeye.lab.flags import FlagHunter

MAX_FILE = 50 * 1024 * 1024
Image.MAX_IMAGE_PIXELS = 60_000_000  # refuse decompression bombs

# (magic, offset, short type, description, strong enough to search for inside files)
SIGNATURES: list[tuple[bytes, int, str, str, bool]] = [
    (b"\x89PNG\r\n\x1a\n", 0, "png", "PNG image", True),
    (b"\xff\xd8\xff", 0, "jpg", "JPEG image", False),
    (b"\xff\xd8\xff\xe0", 0, "jpg", "JPEG image (JFIF)", True),
    (b"\xff\xd8\xff\xe1", 0, "jpg", "JPEG image (EXIF)", True),
    (b"\xff\xd8\xff\xdb", 0, "jpg", "JPEG image", True),
    (b"GIF87a", 0, "gif", "GIF image", True),
    (b"GIF89a", 0, "gif", "GIF image", True),
    (b"BM", 0, "bmp", "BMP image", False),
    (b"%PDF-", 0, "pdf", "PDF document", True),
    (b"PK\x03\x04", 0, "zip", "ZIP archive (also DOCX/XLSX/PPTX/JAR/APK)", True),
    (b"PK\x05\x06", 0, "zip", "ZIP archive (empty)", False),
    (b"\x1f\x8b\x08", 0, "gz", "gzip compressed data", True),
    (b"BZh91AY&SY", 0, "bz2", "bzip2 compressed data", True),
    (b"\xfd7zXZ\x00", 0, "xz", "XZ compressed data", True),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z", "7-Zip archive", True),
    (b"Rar!\x1a\x07", 0, "rar", "RAR archive", True),
    (b"ustar", 257, "tar", "TAR archive", False),
    (b"\x7fELF", 0, "elf", "ELF executable (Linux)", True),
    (b"MZ", 0, "exe", "Windows executable (PE)", False),
    (b"\xcf\xfa\xed\xfe", 0, "macho", "Mach-O executable (macOS, 64-bit)", True),
    (b"\xca\xfe\xba\xbe", 0, "class", "Java class / Mach-O universal binary", True),
    (b"SQLite format 3\x00", 0, "sqlite", "SQLite database", True),
    (b"\xd4\xc3\xb2\xa1", 0, "pcap", "PCAP network capture", True),
    (b"\xa1\xb2\xc3\xd4", 0, "pcap", "PCAP network capture", True),
    (b"\x0a\x0d\x0d\x0a", 0, "pcapng", "PCAPNG network capture", False),
    (b"RIFF", 0, "riff", "RIFF container (WAV/AVI/WEBP)", False),
    (b"ID3", 0, "mp3", "MP3 audio (ID3)", False),
    (b"OggS", 0, "ogg", "Ogg audio/video", True),
    (b"fLaC", 0, "flac", "FLAC audio", True),
    (b"-----BEGIN ", 0, "pem", "PEM text (key/certificate)", True),
    (b"\x00\x00\x01\x00", 0, "ico", "Windows icon", False),
]

EXT_ALIASES = {
    "jpeg": "jpg",
    "docx": "zip",
    "xlsx": "zip",
    "pptx": "zip",
    "jar": "zip",
    "apk": "zip",
    "odt": "zip",
    "wav": "riff",
    "avi": "riff",
    "webp": "riff",
    "dll": "exe",
    "cap": "pcap",
    "tgz": "gz",
    "db": "sqlite",
    "key": "pem",
    "crt": "pem",
    "cer": "pem",
}

URL_RE = re.compile(rb"https?://[^\s\"'<>]{4,200}")
EMAIL_RE = re.compile(rb"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63})+")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
B64_BLOB_RE = re.compile(rb"\b[A-Za-z0-9+/]{24,}={0,2}")
KEYWORD_RE = re.compile(rb"pass(word)?|secret|key|token|admin|flag|ctf|hidden", re.I)


# ---------------------------------------------------------------- basics


def identify(data: bytes) -> dict | None:
    for magic, offset, kind, desc, _strong in SIGNATURES:
        if data[offset : offset + len(magic)] == magic:
            return {"type": kind, "description": desc}
    return None


_ASCII = np.zeros(256, dtype=bool)
_ASCII[0x20:0x7F] = True


def _entropy_from_counts(counts: np.ndarray) -> float:
    n = counts.sum()
    if not n:
        return 0.0
    p = counts[counts > 0] / n
    return float(-(p * np.log2(p)).sum())


def entropy(chunk: bytes) -> float:
    return (
        _entropy_from_counts(np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256))
        if chunk
        else 0.0
    )


def entropy_profile(data: bytes, points: int = 128) -> tuple[float, list[float]]:
    """Overall entropy plus a per-block profile (vectorised: fast even on 50 MB files)."""
    if not data:
        return 0.0, []
    arr = np.frombuffer(data, dtype=np.uint8)
    block = max(256, math.ceil(len(arr) / points))
    total = np.zeros(256, dtype=np.int64)
    profile = []
    for i in range(0, len(arr), block):
        counts = np.bincount(arr[i : i + block], minlength=256)
        total += counts
        profile.append(round(_entropy_from_counts(counts), 3))
    return round(_entropy_from_counts(total), 3), profile[:points]


def _runs(mask: np.ndarray, min_len: int) -> tuple[np.ndarray, np.ndarray]:
    edges = np.diff(np.concatenate(([0], mask.view(np.int8), [0])))
    starts, ends = np.flatnonzero(edges == 1), np.flatnonzero(edges == -1)
    keep = ends - starts >= min_len
    return starts[keep], ends[keep]


def strings(data: bytes, min_len: int = 5, limit: int = 4000) -> list[dict]:
    """Printable ASCII and UTF-16LE runs, found with array operations instead of a regex."""
    arr = np.frombuffer(data, dtype=np.uint8)
    found = []
    starts, ends = _runs(_ASCII[arr], min_len)
    for s, e in zip(starts[:limit], ends[:limit], strict=True):
        found.append({"offset": int(s), "text": data[s:e].decode("ascii"), "encoding": "ascii"})
    for parity in (0, 1):
        if len(found) >= limit:
            break
        pairs = arr[parity : parity + (len(arr) - parity) // 2 * 2].reshape(-1, 2)
        if not len(pairs):
            continue
        starts, ends = _runs(_ASCII[pairs[:, 0]] & (pairs[:, 1] == 0), min_len)
        for s, e in zip(starts, ends, strict=True):
            off = parity + 2 * int(s)
            found.append(
                {
                    "offset": off,
                    "text": data[off : parity + 2 * int(e)].decode("utf-16-le"),
                    "encoding": "utf-16",
                }
            )
            if len(found) >= limit:
                break
    found.sort(key=lambda x: x["offset"])
    return found


def interesting(data: bytes) -> dict:
    def uniq(rx, cap=50):
        return sorted({m.group().decode("latin-1") for m in rx.finditer(data)})[:cap]

    ips = [ip for ip in uniq(IP_RE) if all(int(p) < 256 for p in ip.split("."))]
    return {
        "urls": uniq(URL_RE),
        "emails": uniq(EMAIL_RE),
        "ips": ips,
        "base64": uniq(B64_BLOB_RE, 25),
    }


def hexdump(data: bytes, start: int = 0, length: int = 512) -> str:
    lines = []
    for off in range(start, min(start + length, len(data)), 16):
        row = data[off : off + 16]
        hx = " ".join(f"{b:02x}" for b in row)
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{off:08x}  {hx:<47}  {txt}")
    return "\n".join(lines)


# ---------------------------------------------------------------- embedded files & trailing data


def embedded(data: bytes, own_type: str | None, limit: int = 200) -> list[dict]:
    hits = []
    for magic, offset, kind, desc, strong in SIGNATURES:
        if not strong or offset:
            continue
        if kind == own_type and kind in ("zip", "pdf"):
            continue  # a ZIP's own member headers / PDF revisions aren't "hidden files"
        start = 1
        while len(hits) < limit:
            i = data.find(magic, start)
            if i < 0:
                break
            hits.append({"offset": i, "type": kind, "description": desc})
            start = i + 1
    hits.sort(key=lambda h: h["offset"])
    # JPEG thumbnails inside EXIF are normal, not hidden data.
    for h in hits:
        if h["type"] == "jpg" and own_type == "jpg" and h["offset"] < 70_000:
            h["note"] = "probably the EXIF thumbnail"
    # collapse duplicates at the same offset (e.g. two JPEG variants)
    out, seen = [], set()
    for h in hits:
        if h["offset"] not in seen:
            seen.add(h["offset"])
            out.append(h)
    for i, h in enumerate(out):
        h["end"] = out[i + 1]["offset"] if i + 1 < len(out) else len(data)
    return out


def _jpeg_end(data: bytes) -> int | None:
    """Walk JPEG markers to the real end-of-image (FFD9), skipping entropy-coded data correctly."""
    i = 2
    n = len(data)
    while i + 4 <= n:
        if data[i] != 0xFF:
            return None
        marker = data[i + 1]
        if marker == 0xD9:
            return i + 2
        if marker in (0x01, *range(0xD0, 0xD8)):
            i += 2
            continue
        length = struct.unpack(">H", data[i + 2 : i + 4])[0]
        i += 2 + length
        if marker == 0xDA:  # start of scan: skip compressed data up to the next real marker
            while i + 1 < n:
                if data[i] == 0xFF and data[i + 1] not in (0x00, *range(0xD0, 0xD8)):
                    break
                i += 1
    return None


def trailing(data: bytes, kind: str | None) -> dict | None:
    end = None
    if kind == "png":
        i = data.find(b"IEND\xaeB`\x82")
        end = i + 8 if i >= 0 else None
    elif kind == "jpg":
        end = _jpeg_end(data)
    elif kind == "pdf":
        i = data.rfind(b"%%EOF")
        if i >= 0:
            end = i + 5
            while end < len(data) and data[end] in b"\r\n \t":
                end += 1
    elif kind == "zip":
        i = data.rfind(b"PK\x05\x06")
        if i >= 0 and i + 22 <= len(data):
            end = i + 22 + struct.unpack("<H", data[i + 20 : i + 22])[0]
    elif kind == "gif":
        end = None  # needs a full block parser; embedded-signature scan still covers most cases
    if end is None or end >= len(data):
        return None
    extra = data[end:]
    return {
        "offset": end,
        "size": len(extra),
        "type": (identify(extra) or {}).get("description"),
        "preview": extra[:300].decode("latin-1"),
        "hex": hexdump(extra, 0, 128),
    }


# ---------------------------------------------------------------- metadata


def _gps(gps: dict) -> dict | None:
    def deg(v, ref):
        d, m, s = (float(x) for x in v)
        val = d + m / 60 + s / 3600
        return -val if ref in ("S", "W") else val

    try:
        lat = deg(gps[2], gps.get(1, "N"))
        lon = deg(gps[4], gps.get(3, "E"))
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return None
    return {
        "lat": round(lat, 6),
        "lon": round(lon, 6),
        "maps": f"https://www.openstreetmap.org/?mlat={lat:.6f}&mlon={lon:.6f}#map=16/{lat:.6f}/{lon:.6f}",
    }


def image_meta(data: bytes) -> dict | None:
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError, ValueError, SyntaxError):
        return None
    meta = {
        "format": img.format,
        "width": img.width,
        "height": img.height,
        "mode": img.mode,
        "exif": {},
        "text": {},
    }
    try:
        exif = img.getexif()
        for tag, value in exif.items():
            name = ExifTags.TAGS.get(tag, str(tag))
            if isinstance(value, bytes):
                value = value.decode("utf-8", "replace").strip("\x00")[:500]
            meta["exif"][name] = str(value)[:500]
        gps_ifd = exif.get_ifd(0x8825)
        if gps_ifd:
            meta["gps"] = _gps(dict(gps_ifd))
        sub = exif.get_ifd(0x8769)  # Exif sub-IFD: camera settings, UserComment, dates
        for tag, value in sub.items():
            name = ExifTags.TAGS.get(tag, str(tag))
            if isinstance(value, bytes):
                value = value.decode("utf-8", "replace").strip("\x00")[:500]
            meta["exif"][name] = str(value)[:500]
    except Exception:  # noqa: BLE001 - corrupt EXIF is common in CTFs; keep going
        pass
    for key, value in (img.info or {}).items():
        if key in (
            "exif",
            "icc_profile",
            "transparency",
            "dpi",
            "gamma",
            "interlace",
            "aspect",
            "duration",
            "loop",
        ):
            continue
        meta["text"][str(key)] = (
            value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
        )[:2000]
    return meta


def png_chunks(data: bytes) -> dict | None:
    """List PNG chunks, check CRCs, and recover the real size if IHDR was tampered with."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    chunks, i, problems = [], 8, []
    while i + 12 <= len(data):
        length = struct.unpack(">I", data[i : i + 4])[0]
        ctype = data[i + 4 : i + 8]
        body = data[i + 8 : i + 8 + length]
        if len(body) < length or i + 12 + length > len(data):
            problems.append(f"chunk {ctype.decode('latin-1')} at {i} is truncated")
            break
        crc = struct.unpack(">I", data[i + 8 + length : i + 12 + length])[0]
        ok = zlib.crc32(ctype + body) & 0xFFFFFFFF == crc
        chunks.append(
            {"type": ctype.decode("latin-1"), "offset": i, "length": length, "crc_ok": ok}
        )
        if not ok:
            problems.append(f"bad CRC on {ctype.decode('latin-1')} chunk at offset {i}")
        i += 12 + length
        if ctype == b"IEND":
            break
    standard = {
        "IHDR",
        "PLTE",
        "IDAT",
        "IEND",
        "tEXt",
        "zTXt",
        "iTXt",
        "bKGD",
        "cHRM",
        "gAMA",
        "hIST",
        "iCCP",
        "pHYs",
        "sBIT",
        "sPLT",
        "sRGB",
        "tIME",
        "tRNS",
        "eXIf",
        "acTL",
        "fcTL",
        "fdAT",
    }
    unusual = sorted({c["type"] for c in chunks} - standard)
    result = {"chunks": chunks, "problems": problems, "unusual": unusual, "fixed_size": None}
    ihdr = chunks[0] if chunks and chunks[0]["type"] == "IHDR" else None
    if ihdr and not ihdr["crc_ok"]:
        result["fixed_size"] = _fix_ihdr(data)
    return result


def _fix_ihdr(data: bytes) -> dict | None:
    """CTF classic: height/width edited so part of the image is hidden. Brute-force the CRC."""
    body = bytearray(data[16:29])
    want = struct.unpack(">I", data[29:33])[0]
    width, height = struct.unpack(">II", body[:8])
    for h in range(1, 8193):
        body[4:8] = struct.pack(">I", h)
        if zlib.crc32(b"IHDR" + bytes(body)) & 0xFFFFFFFF == want:
            return {"width": width, "height": h, "original": [width, height]}
    body[4:8] = struct.pack(">I", height)
    for w in range(1, 8193):
        body[0:4] = struct.pack(">I", w)
        if zlib.crc32(b"IHDR" + bytes(body)) & 0xFFFFFFFF == want:
            return {"width": w, "height": height, "original": [width, height]}
    return None


def fixed_png(data: bytes, width: int, height: int) -> bytes:
    patched = bytearray(data)
    patched[16:24] = struct.pack(">II", width, height)
    return bytes(patched)


def pdf_meta(data: bytes) -> dict:
    info = {}
    for key in (
        "Title",
        "Author",
        "Subject",
        "Keywords",
        "Creator",
        "Producer",
        "CreationDate",
        "ModDate",
    ):
        m = re.search(rb"/" + key.encode() + rb"\s*\((.{0,300}?)(?<!\\)\)", data, re.S)
        if m:
            info[key] = m.group(1).decode("latin-1")
    return {
        "info": info,
        "pages": len(re.findall(rb"/Type\s*/Page\b", data)),
        "javascript": bool(re.search(rb"/JavaScript|/JS\b", data)),
        "embedded_files": bool(re.search(rb"/EmbeddedFile", data)),
        "auto_action": bool(re.search(rb"/OpenAction|/AA\b", data)),
        "revisions": data.count(b"%%EOF"),
    }


MAX_ZIP_MEMBER = 1024 * 1024  # only read small members (zip-bomb safety)
MAX_ZIP_TOTAL = 8 * 1024 * 1024


def zip_meta(data: bytes, where: str = "file") -> dict | None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError):
        return None
    entries = []
    for info in zf.infolist()[:500]:
        entries.append(
            {
                "name": info.filename,
                "size": info.file_size,
                "compressed": info.compress_size,
                "encrypted": bool(info.flag_bits & 0x1),
                "modified": "{:04d}-{:02d}-{:02d} {:02d}:{:02d}".format(*info.date_time[:5]),
            }
        )
    office = {}
    if "docProps/core.xml" in zf.namelist():
        xml = zf.read("docProps/core.xml")[:20000].decode("utf-8", "replace")
        for tag in (
            "title",
            "subject",
            "creator",
            "keywords",
            "description",
            "lastModifiedBy",
            "created",
            "modified",
        ):
            m = re.search(rf"<[^>]*{tag}[^>]*>([^<]{{0,300}})<", xml)
            if m:
                office[tag] = m.group(1)
    # Read small, unencrypted members in memory so their text can be searched for flags.
    texts, budget = {}, MAX_ZIP_TOTAL
    for info in zf.infolist()[:500]:
        if info.is_dir() or info.flag_bits & 0x1 or info.file_size > min(MAX_ZIP_MEMBER, budget):
            continue
        try:
            with zf.open(info) as fh:
                content = fh.read(MAX_ZIP_MEMBER)
        except (
            zipfile.BadZipFile,
            RuntimeError,
            NotImplementedError,
            OSError,
            zlib.error,
            EOFError,
        ):
            continue
        budget -= len(content)
        texts[info.filename] = content.decode("latin-1")
    return {
        "where": where,
        "texts": texts,
        "entries": entries,
        "comment": zf.comment.decode("utf-8", "replace"),
        "encrypted": any(e["encrypted"] for e in entries),
        "office": office,
    }


def binary_meta(data: bytes, kind: str | None) -> dict | None:
    if kind == "elf" and len(data) >= 20:
        bits = {1: 32, 2: 64}.get(data[4])
        endian = "<" if data[5] == 1 else ">"
        etype, machine = struct.unpack(endian + "HH", data[16:20])
        machines = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64", 8: "MIPS", 243: "RISC-V"}
        types = {1: "relocatable", 2: "executable", 3: "shared object / PIE", 4: "core dump"}
        return {
            "format": "ELF",
            "bits": bits,
            "endian": "little" if endian == "<" else "big",
            "arch": machines.get(machine, str(machine)),
            "kind": types.get(etype, str(etype)),
            "stripped_hint": b".symtab" not in data,
        }
    if kind == "exe" and len(data) >= 64:
        pe = struct.unpack("<I", data[60:64])[0]
        if data[pe : pe + 4] == b"PE\x00\x00":
            machine, _, stamp = struct.unpack("<HHI", data[pe + 4 : pe + 12])
            return {
                "format": "PE",
                "arch": {0x14C: "x86", 0x8664: "x86-64", 0xAA64: "ARM64"}.get(
                    machine, hex(machine)
                ),
                "timestamp": stamp,
                "dotnet_hint": b"mscoree.dll" in data.lower(),
            }
    return None


# ---------------------------------------------------------------- top level


def analyse(data: bytes, name: str, hunter: FlagHunter | None = None) -> dict:
    hunter = hunter or FlagHunter()
    kind_info = identify(data)
    kind = kind_info["type"] if kind_info else None
    ext = PurePath(name).suffix.lower().lstrip(".")
    ext_kind = EXT_ALIASES.get(ext, ext) or None
    mismatch = bool(
        kind and ext_kind and ext_kind != kind and not (kind == "zip" and ext in EXT_ALIASES)
    )

    strs = strings(data)
    # Flags, URLs etc. are printable text, so the extracted strings contain all of them:
    # searching those instead of the raw bytes is far faster on big files.
    text_blob = "\n".join(s["text"] for s in strs)
    overall_entropy, profile = entropy_profile(data)
    result: dict = {
        "name": name,
        "size": len(data),
        "type": kind_info or {"type": None, "description": "unknown (no known signature)"},
        "extension": ext or None,
        "extension_mismatch": mismatch,
        "hashes": {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),  # noqa: S324
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "entropy": overall_entropy,
        "entropy_profile": profile,
        "strings": strs,
        "interesting": interesting(text_blob.encode("utf-8", "replace")),
        "hexdump": hexdump(data),
        "embedded": embedded(data, kind),
        "trailing": trailing(data, kind),
    }
    result["image"] = image_meta(data)
    result["png"] = png_chunks(data)
    result["pdf"] = pdf_meta(data) if kind == "pdf" else None
    # The archive may be the file itself, appended after it, or embedded inside it.
    zip_src = None
    if kind == "zip":
        zip_src = (data, "file")
    elif result["trailing"] and data[result["trailing"]["offset"] :].startswith(b"PK\x03\x04"):
        zip_src = (data[result["trailing"]["offset"] :], "appended data")
    else:
        emb = next((e for e in result["embedded"] if e["type"] == "zip"), None)
        if emb:
            zip_src = (data[emb["offset"] :], f"embedded at offset {emb['offset']}")
    result["zip"] = zip_meta(*zip_src) if zip_src else None
    result["binary"] = binary_meta(data, kind)
    result["lsb"] = stego.image_stego(data, hunter) if result["image"] else None
    result["audio"] = stego.audio_stego(data, hunter) if kind == "riff" else None
    looks_like_text = not kind and strs and sum(len(s["text"]) for s in strs) > len(data) * 0.6
    result["text_stego"] = stego.text_stego(data, hunter) if looks_like_text or kind is None else []
    result["jpeg_tools"] = stego.jpeg_tools() if kind == "jpg" else None

    # Flag hunt across everything we extracted.
    sources: dict[str, str] = {}
    if result["image"]:
        sources["metadata"] = "\n".join(
            [*result["image"]["exif"].values(), *result["image"]["text"].values()]
        )
    if result["trailing"]:
        sources["appended data"] = result["trailing"]["preview"]
    if result["zip"]:
        sources["zip"] = (
            result["zip"]["comment"] + "\n" + "\n".join(e["name"] for e in result["zip"]["entries"])
        )
        for member, text in result["zip"].pop("texts").items():
            sources[f"zip member {member}"] = text
    if result["pdf"]:
        sources["pdf metadata"] = "\n".join(result["pdf"]["info"].values())
    sources["strings"] = text_blob  # last, so the more specific locations above win
    flags: dict[str, dict] = {}
    for where, text in sources.items():
        for f in hunter.scan(text):
            flags.setdefault(f["value"], {**f, "where": where})
    for cand in (result["lsb"] or {}).get("candidates", []):
        for f in cand["flags"]:
            where = f"LSB {cand['channels']} bit {cand['bit']} ({cand['order']}, {cand['packing']})"
            flags.setdefault(f["value"], {**f, "where": where})
    for cand in (result["audio"] or {}).get("lsb", []):
        for f in cand["flags"]:
            flags.setdefault(
                f["value"], {**f, "where": f"audio LSB, {cand['channels']} bit {cand['bit']}"}
            )
    for item in result["text_stego"]:
        for f in item["flags"]:
            flags.setdefault(f["value"], {**f, "where": item["method"]})
    if result["audio"]:
        for key in ("dtmf", "morse"):
            if result["audio"][key]:
                for f in hunter.scan(result["audio"][key]):
                    flags.setdefault(f["value"], {**f, "where": f"audio {key.upper()}"})
    confirmed = [f for f in flags.values() if f["confidence"] == "high"]
    result["flags"] = confirmed or list(flags.values())[:10]
    result["hints"] = hints(result)
    return result


def hints(r: dict) -> list[str]:
    """Plain-English next steps, the way an experienced player would think about this file."""
    out = []
    if r["extension_mismatch"]:
        out.append(
            f"The extension says .{r['extension']} but the content is {r['type']['description']}. Rename it and open it as that."
        )
    if r["trailing"]:
        t = r["trailing"]
        out.append(
            f"{t['size']} bytes are hidden after the end of the file (offset {t['offset']})"
            + (f", and they look like a {t['type']}" if t["type"] else "")
            + ". Extract them below."
        )
    real = [e for e in r["embedded"] if not e.get("note")]
    if real:
        out.append(
            f"Found {len(real)} embedded file signature(s), e.g. {real[0]['description']} at offset {real[0]['offset']}. Try extracting them."
        )
    if r["png"] and r["png"]["fixed_size"]:
        f = r["png"]["fixed_size"]
        out.append(
            f"The PNG header's checksum doesn't match: the real size is {f['width']}×{f['height']} "
            f"(file claims {f['original'][0]}×{f['original'][1]}). Download the repaired image to see the hidden part."
        )
    elif r["png"] and r["png"]["problems"]:
        out.append(
            "Some PNG chunks have bad checksums or are truncated: the file may have been edited by hand."
        )
    if r["png"] and r["png"]["unusual"]:
        out.append(
            f"Non-standard PNG chunk(s): {', '.join(r['png']['unusual'])}. Their contents often hide data."
        )
    if r["image"] and r["image"].get("gps"):
        out.append("The image has GPS coordinates. Open them on the map (classic OSINT challenge).")
    if r["image"] and (r["image"]["exif"] or r["image"]["text"]):
        out.append("Check the metadata: comments, author and description fields often hold clues.")
    top = (r["lsb"] or {}).get("candidates") or []
    if top and (
        top[0]["flags"]
        or top[0]["magic"]
        or top[0]["text_prefix"] >= 8
        or top[0]["printable"] > 0.9
    ):
        c = top[0]
        what = f"a hidden {c['magic']}" if c["magic"] and not c["flags"] else "readable text"
        out.append(
            f"The least-significant bits ({c['channels']}, bit {c['bit']}, {c['order']}) contain {what}: LSB steganography. See the Steganography tab."
        )
    elif r["lsb"]:
        out.append(
            "No readable LSB message found automatically. Flick through the bit planes in the Steganography tab: hidden text or shapes are often visible there."
        )
    if r["type"]["type"] == "jpg":
        tools = r.get("jpeg_tools") or {}
        have = [k for k, v in tools.items() if v]
        out.append(
            "JPEGs hide data in the compressed image data (steghide, OutGuess, JSteg), so LSB doesn't apply. "
            "Try `stegseek file.jpg rockyou.txt` to crack steghide passwords, or `steghide extract -sf file.jpg` with an empty password."
            + (
                f" Installed here: {', '.join(have)}."
                if have
                else " (None of these tools are installed on this PC.)"
            )
        )
    a = r.get("audio")
    if a:
        out.append(
            "Audio file: look at the spectrogram in the Audio tab. Messages and images are often drawn into it"
            + (" (check the left-minus-right view too)." if len(a["spectrograms"]) > 1 else ".")
        )
        if a["dtmf"]:
            out.append(f"Phone keypad (DTMF) tones decoded: {a['dtmf']}")
        if a["morse"]:
            out.append(f"Morse code decoded from the audio: {a['morse']}")
    elif r["type"]["type"] in ("mp3", "ogg", "flac"):
        out.append(
            "Compressed audio: convert it to WAV (e.g. `ffmpeg -i in.mp3 out.wav`) and analyse that for spectrograms and LSB, or open it in Sonic Visualiser / Audacity."
        )
    for item in r.get("text_stego") or []:
        out.append(
            f"Hidden text found using {item['method']}."
            if item["output"]
            else f"{item['method'][0].upper()}{item['method'][1:]}."
        )
    if r["zip"] and r["zip"]["encrypted"]:
        out.append(
            "The ZIP is password-protected. Look for the password elsewhere in the challenge, or try a wordlist (e.g. with John the Ripper's zip2john)."
        )
    if r["pdf"] and (r["pdf"]["javascript"] or r["pdf"]["embedded_files"]):
        out.append("The PDF contains JavaScript or embedded files. Extract and inspect them.")
    if r["entropy"] > 7.5 and not r["type"]["type"]:
        out.append("Very high entropy with no known header: probably encrypted or compressed data.")
    if r["binary"]:
        out.append(
            "It's an executable. Use a disassembler (Ghidra, IDA Free) for reversing; strings below may already leak the flag."
        )
    if r["type"]["type"] in ("pcap", "pcapng"):
        out.append(
            "It's a network capture. Open it in Wireshark (a PCAP analyser is planned for the Lab)."
        )
    if not out:
        out.append(
            "Nothing obviously hidden. Check the strings, the metadata and the entropy graph for anything odd."
        )
    return out
