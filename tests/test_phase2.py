import base64
import hashlib
import hmac
import json
import struct

import pytest
from fastapi.testclient import TestClient

from exposeye.lab import hashes, jwt_tools, pcap
from exposeye.web.server import create_app

ALGOS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def b64j(obj) -> bytes:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=")


def make_jwt(payload, secret="secret", alg="HS256"):
    si = b64j({"alg": alg, "typ": "JWT"}) + b"." + b64j(payload)
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), si, ALGOS[alg]).digest()).rstrip(b"=")
    return (si + b"." + sig).decode()


# ---------------------------------------------------------------- hashes


def test_identify_common_hashes():
    assert "MD5" in [t.name for t in hashes.identify("5f4dcc3b5aa765d61d8327deb882cf99")]
    assert "SHA-256" in [t.name for t in hashes.identify("a" * 64)]
    assert "SHA-1" in [t.name for t in hashes.identify("b" * 40)]
    assert any("bcrypt" in t.name for t in hashes.identify("$2b$12$" + "a" * 53))
    assert any("sha512crypt" in t.name for t in hashes.identify("$6$salt$" + "x" * 86))


@pytest.mark.parametrize(
    "algo,word,name",
    [
        ("md5", "password", "MD5"),
        ("sha1", "letmein", "SHA-1"),
        ("sha256", "flag", "SHA-256"),
        ("sha512", "monkey", "SHA-512"),
    ],
)
def test_crack_builtin(algo, word, name):
    digest = hashlib.new(algo, word.encode()).hexdigest()
    assert hashes.crack_builtin(digest)["found"] == {"password": word, "type": name}


def test_ntlm_pure_python_md4():
    assert hashes._md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
    res = hashes.crack_builtin(hashes._ntlm("password"))
    assert res["found"] == {"password": "password", "type": "NTLM"}


def test_crack_reports_exhaustion():
    r = hashes.crack(hashlib.md5(b"not-in-list-xyz").hexdigest(), ["a", "b", "c"])
    assert r["found"] is None and r["exhausted"] and r["tried"] == 3


def test_slow_hash_not_crackable():
    assert hashes.crackable("$2b$12$" + "a" * 53) == []


# ---------------------------------------------------------------- jwt


def test_jwt_decode_and_findings():
    info = jwt_tools.decode(make_jwt({"user": "guest", "admin": False, "exp": 9999999999}))
    assert info["valid"] and info["payload"]["user"] == "guest"
    assert any(f["title"].startswith("Symmetric") for f in info["findings"])
    assert any(c["claim"] == "exp" and c["note"] == "still valid" for c in info["claims"])


def test_jwt_alg_none_flagged():
    info = jwt_tools.decode(jwt_tools.forge_none({"user": "admin"}))
    assert info["alg"] == "none"
    assert info["findings"][0]["title"] == "alg: none"
    assert info["findings"][0]["severity"] == "high"


def test_jwt_weak_secret_and_resign():
    token = make_jwt({"user": "guest"}, secret="secret")
    assert jwt_tools.find_secret_builtin(token)["secret"] == "secret"
    assert jwt_tools.decode(jwt_tools.resign(token, "secret"))["valid"]
    miss = jwt_tools.find_secret(make_jwt({"x": 1}, secret="zzz-unknown"), ["a", "b"])
    assert miss["secret"] is None


def test_jwt_invalid():
    assert jwt_tools.decode("not.a.jwt.x")["valid"] is False
    assert jwt_tools.decode("@@@.@@@")["valid"] is False


def test_jwt_rsa_confusion_hint():
    token = f"{b64j({'alg': 'RS256'}).decode()}.{b64j({'user': 'x'}).decode()}.AAAA"
    titles = [f["title"] for f in jwt_tools.decode(token)["findings"]]
    assert any("Asymmetric" in t for t in titles)


# ---------------------------------------------------------------- pcap


def _eth(etype=0x0800):
    return b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01" + struct.pack(">H", etype)


def _ip4(s):
    return bytes(int(x) for x in s.split("."))


def _ip(src, dst, proto, payload):
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0)
    return hdr + _ip4(src) + _ip4(dst) + payload


def _tcp(sport, dport, payload):
    return struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x18, 1024, 0, 0) + payload


def _udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def _dns(name):
    q = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)


def _pcap(packets):
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
    for p in packets:
        out += struct.pack("<IIII", 0, 0, len(p), len(p)) + p
    return bytes(out)


def test_pcap_dns_http_creds_flags():
    auth = base64.b64encode(b"admin:s3cr3t").decode()
    http = (
        f"GET /secret HTTP/1.1\r\nHost: target.local\r\nAuthorization: Basic {auth}\r\n\r\n"
    ).encode()
    data = _pcap(
        [
            _eth() + _ip("10.0.0.5", "10.0.0.1", 17, _udp(5000, 53, _dns("flag.example.com"))),
            _eth() + _ip("10.0.0.5", "93.184.216.34", 6, _tcp(40000, 80, http)),
            _eth() + _ip("10.0.0.5", "10.0.0.9", 6, _tcp(40001, 21, b"USER bob\r\n")),
            _eth() + _ip("10.0.0.5", "10.0.0.9", 6, _tcp(40001, 21, b"PASS flag{ftp_clear}\r\n")),
        ]
    )
    r = pcap.analyse(data)
    assert r["packets"] == 4
    assert {p["name"] for p in r["protocols"]} >= {"DNS", "HTTP", "FTP"}
    assert r["dns"][0]["name"] == "flag.example.com"
    assert (r["http"][0]["method"], r["http"][0]["path"]) == ("GET", "/secret")
    creds = {(c["protocol"], c["data"]) for c in r["credentials"]}
    assert ("HTTP Basic", "admin:s3cr3t") in creds
    assert ("FTP", "PASS flag{ftp_clear}") in creds
    assert "flag{ftp_clear}" in [f["value"] for f in r["flags"]]


def test_pcap_bad_magic():
    with pytest.raises(pcap.PcapError):
        list(pcap._iter_pcap(b"not a pcap file at all........"))


# ---------------------------------------------------------------- API


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(tmp_path, allowed_hosts=["testserver"]))


def test_hash_api(client, tmp_path):
    md5 = hashlib.md5(b"password").hexdigest()
    r = client.post("/api/lab/hash", json={"hashes": [md5, "$2b$12$" + "a" * 53]}).json()
    assert r["results"][0]["result"]["found"]["password"] == "password"
    assert "result" not in r["results"][1]  # bcrypt not crackable here
    sha = hashlib.sha256(b"my-unique-pw").hexdigest()
    r = client.post("/api/lab/hash", json={"hashes": [sha], "extra_words": "my-unique-pw"}).json()
    assert r["results"][0]["result"]["found"]["password"] == "my-unique-pw"
    wl = tmp_path / "wl.txt"
    wl.write_text("aaa\nfrom-a-file\nbbb\n")
    hv = hashlib.md5(b"from-a-file").hexdigest()
    r = client.post("/api/lab/hash", json={"hashes": [hv], "wordlist": str(wl)}).json()
    assert r["results"][0]["result"]["found"]["password"] == "from-a-file"
    bad = client.post("/api/lab/hash", json={"hashes": ["x"], "wordlist": str(tmp_path / "nope")})
    assert bad.status_code == 400


def test_jwt_api(client):
    token = make_jwt({"user": "guest", "admin": False})
    r = client.post("/api/lab/jwt", json={"token": token}).json()
    assert r["valid"] and r["secret_search"]["secret"] == "secret"
    forged = client.post(
        "/api/lab/jwt", json={"token": token, "forge_payload": '{"admin": true}'}
    ).json()
    assert jwt_tools.decode(forged["forged_none"])["payload"] == {"admin": True}
    resigned = client.post("/api/lab/jwt", json={"token": token, "resign_secret": "secret"}).json()
    assert resigned["resigned"]
    bad = client.post("/api/lab/jwt", json={"token": token, "forge_payload": "not json"})
    assert bad.status_code == 400


def test_pcap_via_file_analyser(client):
    pkt = _eth() + _ip("10.0.0.5", "10.0.0.1", 17, _udp(5000, 53, _dns("hidden.flag.com")))
    r = client.post("/api/lab/files?name=capture.pcap", content=_pcap([pkt])).json()
    assert r["type"]["type"] == "pcap"
    assert r["pcap"]["dns"][0]["name"] == "hidden.flag.com"
    assert any("Network tab" in h for h in r["hints"])
