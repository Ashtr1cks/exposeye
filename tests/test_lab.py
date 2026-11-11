import base64
import codecs
import io
import struct
import zipfile
import zlib

import pytest
from PIL import Image, PngImagePlugin

from exposeye.lab import decoder, files
from exposeye.lab.flags import FlagHunter, compile_formats, find_flags

# ---------------------------------------------------------------- flag hunter


def test_flag_formats_and_dedupe():
    h = FlagHunter(["picoCTF{...}", "CTF{...}", "re:secret_[0-9]+"])
    found = h.scan("x picoCTF{abc_123} y secret_42 z")
    values = [f["value"] for f in found]
    assert "picoCTF{abc_123}" in values and "secret_42" in values
    assert "CTF{abc_123}" not in values  # contained in the longer flag
    assert h.scan("FLAG{nope}") == [] or h.scan("FLAG{nope}")[0]["confidence"] == "possible"


def test_generic_flags_are_possible_only():
    out = find_flags("seen: xyz{s0me_th1ng}", compile_formats([]), generic=True)
    assert out == [{"value": "xyz{s0me_th1ng}", "format": "generic", "confidence": "possible"}]
    assert find_flags("seen: xyz{s0me_th1ng}", compile_formats([]), generic=False) == []


def test_bad_regex_format_is_rejected():
    with pytest.raises(ValueError):
        compile_formats(["re:([unclosed"])


# ---------------------------------------------------------------- decoder

FLAG = "picoCTF{l4y3rs_0n_l4y3rs}"


def flags_of(text, **kw):
    return [f["value"] for f in decoder.decode(text, **kw)["flags"]]


@pytest.mark.parametrize(
    "encoded",
    [
        base64.b64encode(FLAG.encode()).decode(),
        base64.b32encode(FLAG.encode()).decode(),
        FLAG.encode().hex(),
        " ".join(format(b, "08b") for b in FLAG.encode()),
        " ".join(str(b) for b in FLAG.encode()),
        codecs.encode(FLAG, "rot13"),
        base64.b64encode(codecs.encode(FLAG, "rot13").encode().hex().encode()).decode(),  # 3 layers
        base64.b85encode(FLAG.encode()).decode(),
        "".join(f"%{b:02x}" for b in FLAG.encode()),
    ],
)
def test_decoder_finds_flag_through_layers(encoded):
    assert FLAG in flags_of(encoded)


def test_decoder_xor_and_compression():
    xored = bytes(b ^ 0x42 for b in b"here is your flag: CTF{x0r_b4by}").hex()
    assert "CTF{x0r_b4by}" in flags_of(xored)
    gz = base64.b64encode(zlib.compress(b"flag{squeezed}")).decode()
    assert "flag{squeezed}" in flags_of(gz)


def test_decoder_morse_and_base58():
    out = decoder.decode(".-- . .-.. .-.. / -.. --- -. .")
    assert out["results"][0]["text"] == "WELL DONE"
    assert decoder.decode("Cn8eVZg")["results"][0]["text"] == "hello"


def test_decoder_caesar_ranks_english_first():
    top = decoder.decode("Aol zljyla tlzzhnl pz olyl")["results"][0]
    assert top["text"] == "The secret message is here" and top["chain"] == ["caesar -7"]


def test_decoder_options_disable_brute_force():
    xored = bytes(b ^ 0x42 for b in b"here is your flag: CTF{x0r_b4by}").hex()
    assert flags_of(xored, try_xor=False) == []


def test_decoder_handles_garbage_quickly():
    out = decoder.decode("!!! ??? ### not encoded at all ~~~")
    assert out["flags"] == [] and out["explored"] < decoder.MAX_NODES


# ---------------------------------------------------------------- file analyser


def png_bytes(img, **kw):
    buf = io.BytesIO()
    img.save(buf, "PNG", **kw)
    return buf.getvalue()


def lsb_image(message: bytes, size=(64, 64)):
    img = Image.new("RGB", size, (120, 80, 200))
    px = img.load()
    bits = [int(b) for byte in message for b in f"{byte:08b}"]
    i = 0
    for y in range(size[1]):
        for x in range(size[0]):
            if i >= len(bits):
                return img
            r, g, b = px[x, y]
            px[x, y] = ((r & ~1) | bits[i], g, b)
            i += 1
    return img


def test_png_with_lsb_metadata_and_appended_zip():
    info = PngImagePlugin.PngInfo()
    info.add_text("Comment", "nothing here... CTF{in_the_metadata}")
    data = png_bytes(lsb_image(b"flag{lsb_hidden}" + b"\x00" * 8), pnginfo=info)
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("secret.txt", "flag{appended_zip}")
    data += zbuf.getvalue()

    r = files.analyse(data, "challenge.png")
    assert r["type"]["type"] == "png" and not r["extension_mismatch"]
    assert r["trailing"]["size"] == len(zbuf.getvalue()) and "ZIP" in r["trailing"]["type"]
    assert any(e["type"] == "zip" for e in r["embedded"])
    assert r["image"]["text"]["Comment"].endswith("CTF{in_the_metadata}")
    top = r["lsb"]["candidates"][0]
    assert (
        top["channels"] == "R" and top["bit"] == 0 and top["preview"].startswith("flag{lsb_hidden}")
    )
    found = {f["value"]: f["where"] for f in r["flags"]}
    assert "CTF{in_the_metadata}" in found
    assert "flag{lsb_hidden}" in found and found["flag{lsb_hidden}"].startswith("LSB R bit 0")
    assert len(r["lsb"]["planes"]) == 6
    assert any("hidden after the end" in h for h in r["hints"])


def test_png_tampered_height_is_recovered():
    img = Image.new("RGB", (40, 60), (255, 255, 255))
    for y in range(40, 60):
        for x in range(40):
            img.putpixel((x, y), (0, 0, 0))
    data = bytearray(png_bytes(img))
    data[20:24] = struct.pack(">I", 30)  # claim the image is only 30px tall; CRC left unchanged
    r = files.analyse(bytes(data), "cropped.png")
    fixed = r["png"]["fixed_size"]
    assert fixed == {"width": 40, "height": 60, "original": [40, 30]}
    repaired = files.fixed_png(bytes(data), fixed["width"], fixed["height"])
    assert Image.open(io.BytesIO(repaired)).size == (40, 60)
    assert any("real size is 40×60" in h for h in r["hints"])


def test_jpeg_exif_gps_and_artist():
    img = Image.new("RGB", (32, 32), (10, 200, 10))
    exif = Image.Exif()
    exif[0x013B] = "flag{exif_artist}"  # Artist
    gps = {1: "S", 2: (37.0, 54.0, 36.0), 3: "E", 4: (145.0, 8.0, 24.0)}
    exif[0x8825] = gps
    buf = io.BytesIO()
    img.save(buf, "JPEG", exif=exif)
    r = files.analyse(buf.getvalue() + b"trailing secret", "photo.jpg")
    assert r["image"]["exif"]["Artist"] == "flag{exif_artist}"
    assert r["image"]["gps"]["lat"] == pytest.approx(-37.91, abs=0.01)
    assert r["image"]["gps"]["lon"] == pytest.approx(145.14, abs=0.01)
    assert r["trailing"]["preview"] == "trailing secret"
    assert "flag{exif_artist}" in [f["value"] for f in r["flags"]]


def test_extension_mismatch_zip_listing_and_strings():
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("notes/readme.txt", "see http://example.com/secret and admin@example.com")
        z.comment = b"password is hunter2"
    r = files.analyse(zbuf.getvalue(), "totally_an_image.png")
    assert r["extension_mismatch"] is True and r["type"]["type"] == "zip"
    assert (
        r["zip"]["entries"][0]["name"] == "notes/readme.txt"
        and r["zip"]["comment"] == "password is hunter2"
    )
    assert any("extension says .png" in h for h in r["hints"])


def test_elf_header_and_entropy():
    elf = (
        b"\x7fELF\x02\x01\x01"
        + b"\x00" * 9
        + struct.pack("<HH", 3, 62)
        + b"\x00" * 100
        + b"hello flag{in_strings} world"
    )
    r = files.analyse(elf, "chall")
    assert r["binary"]["arch"] == "x86-64" and r["binary"]["bits"] == 64
    assert "flag{in_strings}" in [f["value"] for f in r["flags"]]
    assert files.entropy(b"\x00" * 100) == 0 and files.entropy(bytes(range(256))) == 8


def test_confirmed_flag_not_swallowed_by_generic_match():
    # "notes.txtflag{x}" makes the generic pattern match "txtflag{x}"; the real flag must survive
    out = FlagHunter().scan("secret/notes.txtflag{appended}PK")
    assert [f["value"] for f in out] == ["flag{appended}"]


def test_flags_inside_compressed_zip_appended_to_png():
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("deep/inner.txt", "padding " * 50 + "flag{deflated_inside_zip}")
    data = png_bytes(Image.new("RGB", (8, 8))) + zbuf.getvalue()
    r = files.analyse(data, "innocent.png")
    assert (
        r["zip"]["where"] == "appended data" and r["zip"]["entries"][0]["name"] == "deep/inner.txt"
    )
    assert {"value": "flag{deflated_inside_zip}", "where": "zip member deep/inner.txt"}.items() <= {
        **next(f for f in r["flags"] if f["value"] == "flag{deflated_inside_zip}")
    }.items()
    assert "texts" not in r["zip"]  # member contents aren't sent to the browser
