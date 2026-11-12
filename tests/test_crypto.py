import base64

import pytest
from fastapi.testclient import TestClient

from exposeye.lab import classical, rsa
from exposeye.web.server import create_app

# ---------------------------------------------------------------- RSA


def test_rsa_trial_factor():
    p, q, e = 1000003, 1000033, 65537
    n = p * q
    m = 424242
    r = rsa.solve(n, e, pow(m, e, n))
    assert r.method == "factored" and r.recovered["int"] == m


def test_rsa_fermat_close_primes():
    p, q, e = 1000000007, 1000000009, 65537
    n = p * q
    m = 424242
    r = rsa.solve(n, e, pow(m, e, n))
    assert r.recovered["int"] == m


def test_rsa_cube_root_small_e():
    n = (10**40) * (10**40 + 1)
    c = pow(int.from_bytes(b"flag{cube}", "big"), 3)  # m^3 < n so no modular reduction
    r = rsa.solve(n, 3, c)
    assert r.method.startswith("small exponent") and r.recovered["text"] == "flag{cube}"


def test_rsa_given_p():
    p, q, e = 1000003, 1000033, 65537
    n = p * q
    m = 123456
    r = rsa.solve(n, e, pow(m, e, n), p=p)
    assert r.recovered["int"] == m and r.q == q


def test_rsa_common_modulus():
    p, q = 1000003, 1000033
    n = p * q
    m = 777
    r = rsa.common_modulus(n, 17, pow(m, 17, n), 65537, pow(m, 65537, n))
    assert r.recovered["int"] == m


def test_rsa_wiener_small_d():
    import math

    p, q = 1000003, 1000033
    n, phi = p * q, (1000003 - 1) * (1000033 - 1)
    d = 7
    while math.gcd(d, phi) != 1:
        d += 2
    e = pow(d, -1, phi)
    assert rsa.wiener(n, e) == d


def test_rsa_secure_n_gives_up_fast():
    import time

    secure = 25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357  # noqa: E501
    t0 = time.monotonic()
    assert rsa.factorize(secure, budget=0.5) is None
    assert time.monotonic() - t0 < 3


def _pem(n, e):
    def di(v):
        b = v.to_bytes((v.bit_length() + 8) // 8, "big")
        return b"\x02" + _ln(len(b)) + b

    def _ln(x):
        if x < 0x80:
            return bytes([x])
        bb = x.to_bytes((x.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(bb)]) + bb

    body = di(n) + di(e)
    seq = b"\x30" + _ln(len(body)) + body
    return (
        "-----BEGIN RSA PUBLIC KEY-----\n"
        + base64.encodebytes(seq).decode()
        + "-----END RSA PUBLIC KEY-----"
    )  # noqa: E501


def test_rsa_parse_pubkey():
    parsed = rsa.parse_pubkey(_pem(0xC0FFEE1234567890ABCDEF, 65537))
    assert parsed["n"] == 0xC0FFEE1234567890ABCDEF and parsed["e"] == 65537


def test_iroot():
    assert rsa.iroot(27, 3) == (3, True)
    assert rsa.iroot(28, 3) == (3, False)


# ---------------------------------------------------------------- classical

PLAIN = (
    "the quick brown fox jumps over the lazy dog and then the dog runs back "
    "across the field while the sun sets slowly behind the distant hills tonight"
)


def _vig(text, key):
    k = [c for c in key.lower() if c.isalpha()]
    out, ki = [], 0
    for ch in text:
        if ch.isalpha():
            out.append(chr((ord(ch.lower()) - 97 + ord(k[ki % len(k)]) - 97) % 26 + 97))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def test_vigenere_decrypt_roundtrip():
    assert classical.vigenere_decrypt(_vig(PLAIN, "lemon"), "lemon") == PLAIN


def test_vigenere_crack():
    r = classical.vigenere_crack(_vig(PLAIN, "lemon"))
    assert r.key == "lemon" and "quick brown fox" in r.text


def test_xor_repeating_crack():
    key = b"ICE"
    data = bytes(b ^ key[i % 3] for i, b in enumerate((PLAIN * 2).encode()))
    r = classical.xor_repeating_crack(data)
    assert r["keysize"] == 3 and r["key"] == b"ICE" and "quick brown fox" in r["text"]


def test_affine_crack():
    ct = "".join(chr((5 * (ord(c) - 97) + 8) % 26 + 97) if c.isalpha() else c for c in PLAIN)
    r = classical.affine_crack(ct)
    assert "quick brown fox" in r.text and r.key == "a=5, b=8"


def test_railfence_crack():
    def enc(text, rails):
        pat = list(range(rails)) + list(range(rails - 2, 0, -1))
        rows = [""] * rails
        for i, ch in enumerate(text):
            rows[pat[i % len(pat)]] += ch
        return "".join(rows)

    cands = classical.railfence_crack(enc(PLAIN, 3))
    assert any("quick brown fox" in c.text for c in cands)
    assert cands[0].key == "3"


# ---------------------------------------------------------------- API


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(tmp_path, allowed_hosts=["testserver"]))


def test_rsa_api_factor(client):
    p, q, e = 1000003, 1000033, 65537
    n = p * q
    m = 424242
    r = client.post("/api/lab/rsa", json={"n": str(n), "e": str(e), "c": str(pow(m, e, n))}).json()
    assert r["method"] == "factored" and r["recovered"]["int"] == str(m)
    assert r["p"] in (str(p), str(q))


def test_rsa_api_common_modulus(client):
    p, q = 1000003, 1000033
    n = p * q
    m = 777
    r = client.post(
        "/api/lab/rsa",
        json={
            "n": str(n),
            "e": "17",
            "c": str(pow(m, 17, n)),
            "e2": "65537",
            "c2": str(pow(m, 65537, n)),
        },
    ).json()
    assert r["recovered"]["int"] == str(m)


def test_rsa_api_errors(client):
    assert client.post("/api/lab/rsa", json={"e": "65537"}).status_code == 400  # no n/p/q
    assert client.post("/api/lab/rsa", json={"n": "not-a-number"}).status_code == 400


def test_cipher_api_vigenere(client):
    ct = _vig(PLAIN, "lemon")
    r = client.post("/api/lab/cipher", json={"input": ct, "mode": "vigenere"}).json()
    assert r["results"][0]["key"] == "lemon" and "quick brown fox" in r["results"][0]["text"]
    # with a supplied key
    r = client.post(
        "/api/lab/cipher", json={"input": ct, "mode": "vigenere", "key": "lemon"}
    ).json()
    assert r["results"][0]["text"] == PLAIN


def test_cipher_api_xor_hex(client):
    key = b"ICE"
    data = bytes(b ^ key[i % 3] for i, b in enumerate((PLAIN * 2).encode()))
    r = client.post(
        "/api/lab/cipher", json={"input": data.hex(), "mode": "xor", "is_hex": True}
    ).json()
    assert r["results"][0]["key"] == "ICE" and "quick brown fox" in r["results"][0]["text"]


def test_cipher_api_auto(client):
    ct = "".join(chr((5 * (ord(c) - 97) + 8) % 26 + 97) if c.isalpha() else c for c in PLAIN)
    r = client.post("/api/lab/cipher", json={"input": ct, "mode": "auto"}).json()  # noqa: E501
    assert any("quick brown fox" in res["text"] for res in r["results"])
