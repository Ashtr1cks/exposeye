import json
import time

import pytest
from fastapi.testclient import TestClient

from exposeye.web.server import create_app


def fake_scan(domain, opts, progress):
    progress("DNS", "A:1", True)
    progress("Email sec", "SPF missing", False)
    return {
        "meta": {
            "domain": domain,
            "started": "2026-01-01T00:00:00+00:00",
            "duration_s": 0.1,
            "options": vars(opts),
            "version": "test",
        },
        "rdap": None,
        "dns": {"records": {"A": ["1.2.3.4"]}, "dnssec": False, "wildcard_ips": []},
        "email": None,
        "hosts": [],
        "http": [],
        "tls": [],
        "findings": [
            {"severity": "low", "module": "email", "title": "No SPF record", "detail": ""}
        ],
        "errors": {},
        "summary": {
            "findings": {"high": 0, "medium": 0, "low": 1, "info": 0},
            "hosts_total": 0,
            "hosts_live": 0,
            "unique_ips": 0,
            "networks": 0,
            "hosts_probed": 0,
            "truncated": False,
        },
    }


def failing_scan(domain, opts, progress):
    raise RuntimeError("boom")


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path, scan_fn=fake_scan, allowed_hosts=["testserver"])
    return TestClient(app)


def read_events(client, scan_id):
    events = []
    with client.stream("GET", f"/api/scans/{scan_id}/events") as resp:
        assert resp.status_code == 200
        for line in resp.iter_lines():
            if line.startswith("data: "):
                events.append(json.loads(line[6:]))
    return events


def test_index_and_static(client):
    assert "exposeye" in client.get("/").text
    assert client.get("/static/app.js").status_code == 200


def test_rejects_invalid_domain(client):
    resp = client.post("/api/scans", json={"domain": "not a domain"})
    assert resp.status_code == 400


def test_full_scan_lifecycle(client):
    resp = client.post("/api/scans", json={"domain": "https://Example.com/x", "email": False})
    assert resp.status_code == 202
    scan_id = resp.json()["id"]
    assert resp.json()["target"] == "example.com"

    events = read_events(client, scan_id)
    assert [e["type"] for e in events] == ["progress", "progress", "done"]

    result = client.get(f"/api/scans/{scan_id}").json()
    assert result["meta"]["id"] == scan_id
    assert result["meta"]["options"]["email"] is False

    listing = client.get("/api/scans").json()
    assert listing["scans"][0]["id"] == scan_id
    assert listing["scans"][0]["findings"]["low"] == 1

    html = client.get(f"/api/scans/{scan_id}/report/html?download=true")
    assert html.status_code == 200
    assert "attachment" in html.headers["content-disposition"]
    assert client.get(f"/api/scans/{scan_id}/report/md").text.startswith("# exposeye report")
    assert client.get(f"/api/scans/{scan_id}/report/exe").status_code == 404

    # reconnecting to a finished scan replays and ends with "done"
    assert read_events(client, scan_id)[-1] == {"type": "done", "id": scan_id}

    assert client.delete(f"/api/scans/{scan_id}").status_code == 204
    assert client.get(f"/api/scans/{scan_id}").status_code == 404


def test_scan_error_is_reported(tmp_path):
    client = TestClient(create_app(tmp_path, scan_fn=failing_scan, allowed_hosts=["testserver"]))
    scan_id = client.post("/api/scans", json={"domain": "example.com"}).json()["id"]
    events = read_events(client, scan_id)
    assert events[-1] == {"type": "error", "message": "boom"}


def test_path_traversal_and_unknown_ids(client):
    assert client.get("/api/scans/..%2F..%2Fsecret").status_code == 404
    assert client.get("/api/scans/20260101-000000-abcdef").status_code == 404
    assert client.delete("/api/scans/nope").status_code == 404


def test_untrusted_host_header_rejected(tmp_path):
    client = TestClient(create_app(tmp_path, scan_fn=fake_scan))  # only 127.0.0.1/localhost
    assert client.get("/", headers={"host": "evil.example"}).status_code == 400


def test_concurrency_limit(tmp_path):
    def slow_scan(domain, opts, progress):
        time.sleep(0.5)
        return fake_scan(domain, opts, progress)

    client = TestClient(create_app(tmp_path, scan_fn=slow_scan, allowed_hosts=["testserver"]))
    codes = [
        client.post("/api/scans", json={"domain": "example.com"}).status_code for _ in range(4)
    ]
    assert codes == [202, 202, 202, 429]


def test_bundled_graph_library_is_served(client):
    js = client.get("/static/vendor/cytoscape-3.34.4.min.js")
    assert js.status_code == 200 and "cytoscape" in js.text[:2000].lower()
    assert (
        "MIT" in client.get("/static/vendor/cytoscape.LICENSE.txt").text
        or "Permission is hereby granted" in client.get("/static/vendor/cytoscape.LICENSE.txt").text
    )


def test_lab_api(client):
    import base64
    import io
    import struct

    from PIL import Image

    r = client.post(
        "/api/lab/decode", json={"input": base64.b64encode(b"flag{api_works}").decode()}
    )
    assert r.status_code == 200 and r.json()["flags"][0]["value"] == "flag{api_works}"

    # custom flag format via settings
    assert client.put("/api/settings", json={"flag_formats": ["myctf{...}"]}).status_code == 200
    r = client.post("/api/lab/decode", json={"input": base64.b64encode(b"myctf{custom}").decode()})
    assert [f["value"] for f in r.json()["flags"]] == ["myctf{custom}"]
    assert client.put("/api/settings", json={"flag_formats": ["re:([bad"]}).status_code == 400

    # upload a PNG with a tampered height and data appended after IEND
    img = Image.new("RGB", (20, 40), (0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    data = bytearray(buf.getvalue())
    data[20:24] = struct.pack(">I", 10)
    data += b"myctf{after_iend}"
    up = client.post("/api/lab/files?name=../../evil name.png", content=bytes(data))
    assert up.status_code == 200
    res = up.json()
    assert res["png"]["fixed_size"]["height"] == 40
    assert "myctf{after_iend}" in [f["value"] for f in res["flags"]]

    ex = client.get(
        f"/api/lab/files/{res['id']}/extract", params={"start": res["trailing"]["offset"]}
    )
    assert ex.content == b"myctf{after_iend}"
    assert (
        "evil_name_offset" in ex.headers["content-disposition"]
        and ".." not in ex.headers["content-disposition"]
    )

    fixed = client.get(f"/api/lab/files/{res['id']}/fixed-png", params={"width": 20, "height": 40})
    assert Image.open(io.BytesIO(fixed.content)).size == (20, 40)

    assert client.get("/api/lab/files/nope/extract").status_code == 404
    assert client.post("/api/lab/files?name=x", content=b"").status_code == 400


def test_lab_plane_endpoint(client):
    import io

    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGBA", (12, 8), (3, 2, 1, 255)).save(buf, "PNG")
    fid = client.post("/api/lab/files?name=p.png", content=buf.getvalue()).json()["id"]
    r = client.get(f"/api/lab/files/{fid}/plane", params={"channel": "R", "bit": 1, "mode": "bit"})
    assert r.status_code == 200 and Image.open(io.BytesIO(r.content)).size == (12, 8)
    assert (
        client.get(
            f"/api/lab/files/{fid}/plane", params={"channel": "A", "mode": "random"}
        ).status_code
        == 200
    )
    assert client.get(f"/api/lab/files/{fid}/plane", params={"bit": 9}).status_code == 400
    assert client.get(f"/api/lab/files/{fid}/plane", params={"channel": "Z"}).status_code == 400
