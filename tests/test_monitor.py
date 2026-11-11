import copy
import json
import time

import pytest
from fastapi.testclient import TestClient

from exposeye.monitor import task
from exposeye.monitor.diff import diff, is_alert
from exposeye.monitor.notify import valid_discord_webhook
from exposeye.monitor.runner import Monitor, summarise
from exposeye.monitor.watchlist import INTERVALS, SLACK, ChangeLog, Watchlist
from exposeye.storage import FileLock, Store
from exposeye.web.server import create_app


def host(name, ips, **kw):
    return {
        "name": name,
        "ips": ips,
        "cname": kw.get("cname"),
        "dangling": kw.get("dangling", False),
        "wildcard": False,
        "interesting": kw.get("interesting", False),
        "from_ct": True,
        "asn": [],
    }


def domain_scan(**over):
    base = {
        "meta": {
            "kind": "domain",
            "domain": "example.com",
            "started": "2026-01-01T00:00:00+00:00",
            "options": {"passive": False},
        },
        "rdap": {
            "registrar": "Reg A",
            "status": ["active"],
            "expires": "2027-01-01T00:00:00Z",
            "days_to_expiry": 300,
        },
        "dns": {
            "records": {
                "A": ["1.1.1.1"],
                "NS": ["ns1.a.com"],
                "MX": ["10 mx.a.com"],
                "TXT": ["v=spf1 -all", "google-site-verification=x"],
                "CAA": [],
            },
            "dnssec": True,
            "wildcard_ips": [],
        },
        "email": {
            "spf": {"record": "v=spf1 -all", "all": "-"},
            "dmarc": {"record": "v=DMARC1; p=reject", "policy": "reject"},
            "mta_sts": False,
        },
        "subdomain_sources": {"counts": {"crt.sh": 3}, "errors": {}},
        "hosts": [
            host("example.com", ["1.1.1.1"]),
            host("www.example.com", ["1.1.1.1"]),
            host("old.example.com", ["2.2.2.2"]),
        ],
        "asn": {"1.1.1.1": {"asn": "13335", "as_name": "CLOUDFLARE"}},
        "http": [
            {
                "host": "example.com",
                "reachable": True,
                "status": 200,
                "tech": ["nginx"],
                "headers": {"missing": [{"header": "content-security-policy"}], "leaks": []},
            }
        ],
        "tls": [
            {
                "host": "example.com",
                "valid": True,
                "days_left": 45,
                "issuer": "LE",
                "not_after": "2026-03-01T00:00:00+00:00",
            }
        ],
        "findings": [],
    }
    for key, value in over.items():
        base[key] = value
    return base


def titles(changes):
    return {c["title"] for c in changes}


# ---------------------------------------------------------------- diff engine


def test_identical_scans_have_no_changes():
    assert diff(domain_scan(), domain_scan()) == []


def test_detects_regressions():
    old = domain_scan()
    new = copy.deepcopy(old)
    new["hosts"].append(host("admin.example.com", ["3.3.3.3"], interesting=True))
    new["hosts"].append(host("shop.example.com", [], cname="x.herokuapp.com", dangling=True))
    new["dns"]["records"]["NS"] = ["ns1.evil.com"]
    new["dns"]["dnssec"] = False
    new["email"]["dmarc"] = {"record": "v=DMARC1; p=none", "policy": "none"}
    new["email"]["spf"] = {"record": "v=spf1 ~all", "all": "~"}
    new["tls"][0].update(days_left=20)
    new["rdap"]["registrar"] = "Reg B"
    changes = diff(old, new)
    t = titles(changes)
    assert "1 new live host(s)" in t
    assert "New dangling CNAME: shop.example.com" in t
    assert "Name servers changed" in t
    assert "DNSSEC was turned off" in t
    assert "DMARC policy weakened" in t
    assert "SPF became less strict" in t
    assert "Certificate on example.com expires in 20 days" in t
    assert "Registrar changed" in t
    sev = {c["title"]: c["severity"] for c in changes}
    assert sev["New dangling CNAME: shop.example.com"] == "high"
    assert sev["1 new live host(s)"] == "medium"  # admin.* is "interesting"
    assert changes[0]["severity"] == "high"  # sorted worst first
    # SPF lives in TXT too, but must not be double-reported as a TXT change
    assert "TXT records changed" not in t


def test_detects_improvements():
    old = domain_scan()
    old["email"]["dmarc"] = {"record": "v=DMARC1; p=none", "policy": "none"}
    new = domain_scan()
    new["http"][0]["headers"]["missing"] = []
    new["tls"][0]["not_after"] = "2026-06-01T00:00:00+00:00"
    changes = diff(old, new)
    good = {c["title"] for c in changes if c["improvement"]}
    assert {
        "DMARC policy strengthened",
        "Security headers added",
        "Certificates renewed on 1 host(s)",
    } <= good
    assert not any(is_alert(c) for c in changes)


def test_failed_ct_source_is_not_reported_as_disappearance():
    old = domain_scan()
    new = domain_scan(
        subdomain_sources={"counts": {}, "errors": {"crt.sh": "HTTP 502"}},
        hosts=[host("example.com", ["1.1.1.1"]), host("www.example.com", ["1.1.1.1"])],
    )
    assert diff(old, new) == []


def test_old_baseline_without_ct_does_not_flood_new_hosts():
    old = domain_scan(
        subdomain_sources=None,
        hosts=[host("example.com", ["1.1.1.1"]), host("www.example.com", ["1.1.1.1"])],
    )
    new = domain_scan()
    assert "1 new live host(s)" not in titles(diff(old, new))


def test_host_that_stops_resolving_is_reported():
    new = domain_scan()
    new["hosts"][2] = host("old.example.com", [])
    assert "1 host(s) stopped resolving" in titles(diff(domain_scan(), new))


def test_passive_scans_skip_web_and_tls():
    old = domain_scan()
    new = domain_scan(http=[], tls=[])
    new["meta"]["options"]["passive"] = True
    assert diff(old, new) == []


def test_email_diff_new_breaches():
    def e(names, pw=()):
        return {
            "meta": {"kind": "email"},
            "breaches": {
                "checked": True,
                "items": [
                    {"name": n, "title": n, "date": "2024-01-01", "password_exposed": n in pw}
                    for n in names
                ],
            },
            "gravatar": None,
            "domain_info": {"mx": ["10 mx"]},
        }

    changes = diff(e(["A"]), e(["A", "B", "C"], pw=("C",)))
    assert [c["severity"] for c in changes] == ["high", "medium"]
    assert "C (2024)" in changes[0]["detail"]
    # a failed lookup must not look like "all breaches are new"
    failed = e([])
    failed["breaches"]["checked"] = False
    assert diff(failed, e(["A", "B"])) == []


def test_cannot_compare_different_kinds():
    with pytest.raises(ValueError):
        diff(domain_scan(), {"meta": {"kind": "email"}})


def test_summarise_counts_only_alerts():
    title, body, sev = summarise(
        "example.com",
        diff(domain_scan(), domain_scan(dns={**domain_scan()["dns"], "dnssec": False})),
    )
    assert title == "example.com: 1 change(s) need attention"
    assert sev == "medium" and "DNSSEC" in body


# ---------------------------------------------------------------- storage, watchlist, log


def test_file_lock_is_exclusive(tmp_path):
    lock = tmp_path / "x.lock"
    with FileLock(lock):
        with pytest.raises(TimeoutError):
            with FileLock(lock, timeout=0.2):
                pass
    with FileLock(lock, timeout=0.2):
        pass  # released properly


def test_watchlist_due_claim_and_retry(tmp_path):
    wl = Watchlist(tmp_path)
    item = wl.add("domain", "example.com")
    with pytest.raises(ValueError):
        wl.add("domain", "example.com")
    assert [i["id"] for i in wl.due()] == [item["id"]]  # never run -> due now

    assert wl.claim(item["id"]) is True
    assert wl.claim(item["id"]) is False  # second process can't double-run
    assert wl.due() == []

    wl.finish(item["id"], error="boom")
    assert wl.due() == []  # waits an hour before retrying
    assert wl.get(item["id"])["last_error"] == "boom"

    wl.update(item["id"], retry_at=None, last_run=time.time() - INTERVALS["daily"] + SLACK + 60)
    assert wl.due() == []  # not yet
    wl.update(item["id"], last_run=time.time() - INTERVALS["daily"])
    assert len(wl.due()) == 1
    wl.update(item["id"], enabled=False)
    assert wl.due() == []
    with pytest.raises(ValueError):
        wl.update(item["id"], target="evil.com")


def test_changelog(tmp_path):
    log = ChangeLog(tmp_path)
    log.add({"watch_id": "a", "target": "x", "changes": []})
    log.add({"watch_id": "b", "target": "y", "changes": []})
    assert log.unread() == 2
    assert [e["target"] for e in log.list()] == ["y", "x"]  # newest first
    log.mark_read()
    assert log.unread() == 0
    log.remove_watch("a")
    assert [e["target"] for e in log.list()] == ["y"]


def test_store_previous(tmp_path):
    store = Store(tmp_path)
    store.save("20260101-000000-aaaaaa", domain_scan())
    store.save("20260102-000000-bbbbbb", {"meta": {"kind": "domain", "domain": "other.com"}})
    store.save("20260103-000000-cccccc", domain_scan())
    prev = store.previous("domain", "example.com", "20260103-000000-cccccc")
    assert prev[0] == "20260101-000000-aaaaaa"
    assert store.previous("domain", "example.com", "20260101-000000-aaaaaa") is None


# ---------------------------------------------------------------- runner


class FakeNotifier:
    def __init__(self):
        self.sent = []

    def send(self, title, body, severity="info"):
        self.sent.append((title, body, severity))
        return {}


def test_monitor_baseline_then_change(tmp_path):
    scans = [domain_scan(), domain_scan(dns={**domain_scan()["dns"], "dnssec": False})]
    notifier = FakeNotifier()
    mon = Monitor(tmp_path, scan_fn=lambda d, o, p: copy.deepcopy(scans.pop(0)), notifier=notifier)
    item = mon.watchlist.add("domain", "example.com")

    first = mon.run_item(mon.watchlist.get(item["id"]))
    assert first["status"] == "ok" and first["event"]["baseline"] is True
    assert notifier.sent == []

    time.sleep(1.1)  # scan ids are second-resolution
    second = mon.run_item(mon.watchlist.get(item["id"]))
    assert second["event"]["changes"][0]["title"] == "DNSSEC was turned off"
    assert notifier.sent and notifier.sent[0][2] == "medium"
    state = mon.watchlist.get(item["id"])
    assert state["last_change_count"] == 1 and not state["running"]
    assert mon.changes.unread() == 2


def test_monitor_records_failures(tmp_path):
    def boom(*a):
        raise RuntimeError("network down")

    mon = Monitor(tmp_path, scan_fn=boom, notifier=FakeNotifier())
    item = mon.watchlist.add("domain", "example.com")
    res = mon.run_item(mon.watchlist.get(item["id"]))
    assert res["status"] == "error"
    state = mon.watchlist.get(item["id"])
    assert state["last_error"] == "network down" and not state["running"]


# ---------------------------------------------------------------- alerts & task


def test_discord_webhook_validation():
    assert valid_discord_webhook("https://discord.com/api/webhooks/123/abc_DEF-9")
    assert valid_discord_webhook("https://canary.discord.com/api/webhooks/1/x")
    assert not valid_discord_webhook("https://evil.com/api/webhooks/123/abc")
    assert not valid_discord_webhook("http://discord.com/api/webhooks/123/abc")
    assert not valid_discord_webhook("https://discord.com.evil.com/api/webhooks/1/x")


def test_task_command_uses_module_and_data_dir(tmp_path):
    cmd = task.command(tmp_path)
    assert "-m exposeye.watch_cli" in cmd and str(tmp_path) in cmd and cmd.endswith("run --quiet")


# ---------------------------------------------------------------- API


def test_monitoring_api(tmp_path):
    scans = [domain_scan(), domain_scan(dns={**domain_scan()["dns"], "dnssec": False})]
    notifier = FakeNotifier()
    client = TestClient(
        create_app(
            tmp_path,
            scan_fn=lambda d, o, p: copy.deepcopy(scans.pop(0)),
            allowed_hosts=["testserver"],
            notifier=notifier,
        )
    )

    assert client.post("/api/watchlist", json={"target": "not a domain"}).status_code == 400
    item = client.post("/api/watchlist", json={"target": "https://Example.com"}).json()
    assert item["target"] == "example.com" and item["kind"] == "domain"
    assert client.post("/api/watchlist", json={"target": "example.com"}).status_code == 400

    def run_and_wait():
        job = client.post(f"/api/watchlist/{item['id']}/run").json()
        with client.stream("GET", f"/api/scans/{job['id']}/events") as s:
            list(s.iter_lines())
        for _ in range(50):  # after_save runs right after the job finishes
            if not client.get("/api/watchlist").json()["items"][0]["running"]:
                return job["id"]
            time.sleep(0.05)
        raise AssertionError("watch never finished")

    run_and_wait()
    time.sleep(1.1)
    second = run_and_wait()

    events = client.get("/api/changes").json()
    assert events["unread"] == 2
    assert events["events"][0]["changes"][0]["title"] == "DNSSEC was turned off"
    assert notifier.sent

    d = client.get(f"/api/scans/{second}/diff").json()
    assert d["previous"] and d["changes"][0]["title"] == "DNSSEC was turned off"

    assert client.post("/api/changes/read").status_code == 204
    assert client.get("/api/monitor/summary").json() == {"unread": 0, "watching": 1}

    paused = client.patch(f"/api/watchlist/{item['id']}", json={"enabled": False}).json()
    assert paused["enabled"] is False and paused["next_due"] is None
    assert (
        client.patch(f"/api/watchlist/{item['id']}", json={"interval": "hourly"}).status_code == 400
    )

    assert (
        client.put("/api/settings", json={"discord_webhook": "https://evil.com/x"}).status_code
        == 400
    )
    ok = client.put(
        "/api/settings", json={"discord_webhook": "https://discord.com/api/webhooks/1/abcdefghijk"}
    )
    assert ok.json()["discord_webhook_set"] is True
    assert "abcdefghijk" not in json.dumps(client.get("/api/settings").json())

    assert client.delete(f"/api/watchlist/{item['id']}").status_code == 204
    assert client.get("/api/changes").json()["events"] == []


def test_watch_with_baseline_scan(tmp_path):
    client = TestClient(create_app(tmp_path, allowed_hosts=["testserver"], notifier=FakeNotifier()))
    store = Store(tmp_path)
    store.save("20260101-000000-aaaaaa", domain_scan())
    item = client.post(
        "/api/watchlist",
        json={"target": "example.com", "baseline_scan_id": "20260101-000000-aaaaaa"},
    ).json()
    assert item["last_scan_id"] == "20260101-000000-aaaaaa"
    assert client.get("/api/watchlist").json()["items"][0]["next_due"] > item["last_run_iso"]
