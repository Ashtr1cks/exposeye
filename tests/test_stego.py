import io
import wave

import numpy as np
import pytest
from PIL import Image

from exposeye.lab import decoder, files, stego
from exposeye.lab.flags import FlagHunter

HUNTER = FlagHunter()


def bits_of(msg: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(msg, dtype=np.uint8))


def png(img) -> bytes:
    buf = io.BytesIO()
    img.save(buf, img.format or "PNG")
    return buf.getvalue()


# ---------------------------------------------------------------- images


def test_lsb_column_order_green_bit1():
    rng = np.random.default_rng(0)
    arr = rng.integers(0, 256, size=(64, 80, 3), dtype=np.uint8)
    bits = bits_of(b"flag{columns_and_bit_one}\x00")
    col = arr.transpose(1, 0, 2).copy()  # write in column-major order
    g = col[:, :, 1].reshape(-1)
    g[: len(bits)] = (g[: len(bits)] & ~np.uint8(2)) | (bits << 1)
    col[:, :, 1] = g.reshape(col.shape[:2])
    img = Image.fromarray(col.transpose(1, 0, 2))
    res = stego.lsb_scan(img, HUNTER)
    top = res["candidates"][0]
    assert (top["channels"], top["bit"], top["order"]) == ("G", 1, "columns")
    assert top["flags"][0]["value"] == "flag{columns_and_bit_one}"
    assert res["tried"] == 90  # 3 orders x 5 channel sets x 3 bits x 2 packings (RGB image)


def test_palette_index_lsb():
    idx = np.random.default_rng(1).integers(0, 16, size=(40, 40), dtype=np.uint8)
    bits = bits_of(b"flag{palette}\x00")
    flat = idx.reshape(-1)
    flat[: len(bits)] = (flat[: len(bits)] & 0xFE) | bits
    img = Image.fromarray(flat.reshape(40, 40), "P")
    # random palette: colour bits are unrelated to index bits, so only the index holds the message
    img.putpalette(np.random.default_rng(9).integers(0, 256, size=768).astype(int).tolist())
    data = png(img)
    res = stego.image_stego(data, HUNTER)
    assert res["candidates"][0]["channels"] == "palette index"
    assert "Palette index" in res["channels"]


@pytest.mark.parametrize("mode", ["bit", "channel", "inverted", "random"])
def test_render_plane_modes(mode):
    img = Image.new("RGBA", (30, 20), (1, 2, 3, 255))
    out = stego.render_plane(img, "A" if mode == "bit" else "R", 0, mode)
    assert out.size == (30, 20)


def test_render_plane_rejects_unknown():
    with pytest.raises(ValueError):
        stego.render_plane(Image.new("RGB", (4, 4)), "X", 0, "bit")


def test_jpeg_gets_tool_hint():
    buf = io.BytesIO()
    Image.new("RGB", (16, 16)).save(buf, "JPEG")
    r = files.analyse(buf.getvalue(), "photo.jpg")
    assert any("stegseek" in h for h in r["hints"])
    assert r["lsb"]["lossless"] is False and "candidates" not in r["lsb"]


# ---------------------------------------------------------------- audio

RATE = 8000


def wav_bytes(samples: np.ndarray, channels: int = 1) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(samples.astype("<i2").tobytes())
    return buf.getvalue()


def tone(freqs, seconds):
    t = np.arange(int(RATE * seconds)) / RATE
    return sum(np.sin(2 * np.pi * f * t) for f in freqs) * 8000 / len(freqs)


def test_audio_lsb_and_spectrograms():
    rng = np.random.default_rng(2)
    left = rng.integers(-3000, 3000, size=RATE * 2).astype(np.int16)
    right = left.copy()
    right[:RATE] += (tone([1000], 1) / 4).astype(np.int16)  # something only in one channel
    inter = np.stack([left, right], axis=1).reshape(-1)
    bits = bits_of(b"flag{in_the_samples}\x00")
    inter[: len(bits)] = (inter[: len(bits)] & ~1) | bits
    r = files.analyse(wav_bytes(inter, 2), "song.wav")
    a = r["audio"]
    assert a["channels"] == 2 and a["rate"] == RATE and a["duration"] == 2.0
    assert len(a["spectrograms"]) == 2  # mixed + left-minus-right
    assert "flag{in_the_samples}" in [f["value"] for f in r["flags"]]
    assert any("spectrogram" in h for h in r["hints"])


def test_dtmf_tones_decoded():
    rows, cols = [697, 770, 852, 941], [1209, 1336, 1477, 1633]
    keys = ["123A", "456B", "789C", "*0#D"]
    pos = {k: (rows[i], cols[j]) for i, row in enumerate(keys) for j, k in enumerate(row)}
    parts = []
    for k in "1337":
        parts += [tone(pos[k], 0.2), np.zeros(int(RATE * 0.1))]
    r = stego.audio_stego(wav_bytes(np.concatenate(parts)), HUNTER)
    assert r["dtmf"] == "1337"


def test_morse_audio_decoded():
    from exposeye.lab.decoder import MORSE

    code = {v: k for k, v in MORSE.items()}
    unit = 0.06
    parts = []
    for wi, word in enumerate("SOS HELP".split()):
        if wi:
            parts.append(np.zeros(int(RATE * unit * 7)))
        for li, letter in enumerate(word):
            if li:
                parts.append(np.zeros(int(RATE * unit * 3)))
            for si, sym in enumerate(code[letter]):
                if si:
                    parts.append(np.zeros(int(RATE * unit)))
                parts.append(tone([700], unit * (1 if sym == "." else 3)))
    r = stego.audio_stego(wav_bytes(np.concatenate(parts)), HUNTER)
    assert r["morse"] == "SOS HELP"


# ---------------------------------------------------------------- text

ZW0, ZW1 = "​", "‌"


def hide_zero_width(cover: str, secret: str) -> str:
    bits = "".join(f"{b:08b}" for b in secret.encode())
    return cover[:5] + "".join(ZW0 if b == "0" else ZW1 for b in bits) + cover[5:]


def test_zero_width_in_decoder_and_file():
    text = hide_zero_width("Nothing unusual about this sentence.", "flag{invisible_ink}")
    assert "flag{invisible_ink}" in [f["value"] for f in decoder.decode(text)["flags"]]
    r = files.analyse(text.encode("utf-8"), "note.txt")
    assert r["text_stego"] and r["text_stego"][0]["method"].startswith("zero-width binary")
    assert "flag{invisible_ink}" in [f["value"] for f in r["flags"]]


def test_trailing_whitespace():
    bits = "".join(f"{b:08b}" for b in b"flag{tabs}")
    lines = [
        f"line {i}" + "".join(" " if b == "0" else "\t" for b in bits[i * 8 : i * 8 + 8])
        for i in range(len(bits) // 8)
    ]
    text = "\n".join(lines)
    out = dict(stego.whitespace(text))
    assert out["trailing whitespace (space = 0, tab = 1)"] == b"flag{tabs}"
    assert "flag{tabs}" in [f["value"] for f in decoder.decode(text)["flags"]]


def test_no_false_positive_on_plain_text():
    assert stego.zero_width("plain old text") == []
    assert stego.whitespace("no\ntrailing\nwhitespace\nhere\n") == []
