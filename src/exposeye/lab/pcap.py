"""Read a network capture (pcap / pcapng) and summarise it, the way a quick Wireshark
pass would: protocol and conversation breakdown, DNS questions, HTTP requests, and
credentials that were sent in the clear (HTTP Basic auth, FTP, Telnet).

Used on CTF challenge captures or captures you took of your own traffic. Parsing is
done by hand (Ethernet/IPv4/IPv6/TCP/UDP) so there's no extra dependency.
"""

from __future__ import annotations

import base64
import re
import struct
from collections import Counter, defaultdict

from exposeye.lab.flags import FlagHunter

MAX_PACKETS = 200_000
ETH_IP4, ETH_IP6, ETH_ARP, ETH_VLAN = 0x0800, 0x86DD, 0x0806, 0x8100
PORT_NAMES = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP",
    8443: "HTTPS",
}


class PcapError(Exception):
    pass


# ---------------------------------------------------------------- file formats


def _iter_pcap(data: bytes):
    if len(data) < 24:
        raise PcapError("file too short to be a pcap")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        le = magic == b"\xd4\xc3\xb2\xa1"
        endian = "<" if le else ">"
        link = struct.unpack(endian + "I", data[20:24])[0]
        off = 24
        while off + 16 <= len(data):
            ts_s, ts_u, caplen, _orig = struct.unpack(endian + "IIII", data[off : off + 16])
            off += 16
            if caplen > len(data) - off or caplen > 262144:
                break
            yield ts_s + ts_u / 1e6, link, data[off : off + caplen]
            off += caplen
    elif magic == b"\x0a\x0d\x0d\x0a":
        yield from _iter_pcapng(data)
    else:
        raise PcapError("not a pcap or pcapng file")


def _iter_pcapng(data: bytes):
    off = 0
    endian = "<"
    link_by_iface: dict[int, int] = {}
    iface = 0
    while off + 12 <= len(data):
        btype = struct.unpack(endian + "I", data[off : off + 4])[0]
        if off == 0:
            bom = data[off + 8 : off + 12]
            endian = "<" if bom == b"\x1a\x2b\x3c\x4d" else ">"
            btype = struct.unpack(endian + "I", data[off : off + 4])[0]
        blen = struct.unpack(endian + "I", data[off + 4 : off + 8])[0]
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8 : off + blen - 4]
        if btype == 0x00000001:  # interface description
            link_by_iface[iface] = struct.unpack(endian + "H", body[0:2])[0]
            iface += 1
        elif btype == 0x00000006 and len(body) >= 20:  # enhanced packet
            ifid, _th, _tl, caplen = struct.unpack(endian + "IIII", body[0:16])
            pkt = body[20 : 20 + caplen]
            yield 0.0, link_by_iface.get(ifid, 1), pkt
        elif btype == 0x00000003 and len(body) >= 4:  # simple packet
            yield 0.0, link_by_iface.get(0, 1), body[4:]
        off += blen


# ---------------------------------------------------------------- packet dissection


def _parse_eth(frame: bytes):
    if len(frame) < 14:
        return None
    etype = struct.unpack(">H", frame[12:14])[0]
    payload = frame[14:]
    if etype == ETH_VLAN and len(payload) >= 4:
        etype = struct.unpack(">H", payload[2:4])[0]
        payload = payload[4:]
    return etype, payload


def _parse_ip(etype: int, payload: bytes):
    if etype == ETH_IP4 and len(payload) >= 20:
        ihl = (payload[0] & 0x0F) * 4
        proto = payload[9]
        src = ".".join(map(str, payload[12:16]))
        dst = ".".join(map(str, payload[16:20]))
        return src, dst, proto, payload[ihl:]
    if etype == ETH_IP6 and len(payload) >= 40:
        proto = payload[6]
        src = _ipv6(payload[8:24])
        dst = _ipv6(payload[24:40])
        return src, dst, proto, payload[40:]
    return None


def _ipv6(raw: bytes) -> str:
    groups = [f"{(raw[i] << 8) | raw[i + 1]:x}" for i in range(0, 16, 2)]
    return ":".join(groups)


def _l4(proto: int, seg: bytes):
    if proto == 6 and len(seg) >= 20:  # TCP
        sport, dport = struct.unpack(">HH", seg[0:4])
        off = (seg[12] >> 4) * 4
        return "TCP", sport, dport, seg[off:]
    if proto == 17 and len(seg) >= 8:  # UDP
        sport, dport = struct.unpack(">HH", seg[0:4])
        return "UDP", sport, dport, seg[8:]
    if proto == 1:
        return "ICMP", None, None, seg
    return {58: "ICMPv6", 2: "IGMP"}.get(proto, f"IP proto {proto}"), None, None, seg


# ---------------------------------------------------------------- application layer


def _dns_questions(payload: bytes) -> list[str]:
    if len(payload) < 12:
        return []
    qd = struct.unpack(">H", payload[4:6])[0]
    names, off = [], 12
    for _ in range(min(qd, 10)):
        labels = []
        while off < len(payload):
            ln = payload[off]
            if ln == 0:
                off += 1
                break
            if ln & 0xC0:  # compression pointer
                off += 2
                break
            labels.append(payload[off + 1 : off + 1 + ln].decode("latin-1"))
            off += 1 + ln
        if labels:
            names.append(".".join(labels))
        off += 4
    return names


_HTTP_REQ = re.compile(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (\S+) HTTP/1\.[01]\r\n")
_HOST = re.compile(rb"\r\nHost: ([^\r\n]+)", re.I)
_AUTH = re.compile(rb"\r\nAuthorization: Basic ([A-Za-z0-9+/=]+)", re.I)
_COOKIE = re.compile(rb"\r\nCookie: ([^\r\n]+)", re.I)


def _http(payload: bytes, src, dst, dport) -> tuple[dict | None, dict | None]:
    m = _HTTP_REQ.match(payload)
    if not m:
        return None, None
    host = h.group(1).decode("latin-1") if (h := _HOST.search(payload)) else ""
    req = {
        "method": m.group(1).decode(),
        "host": host,
        "path": m.group(2).decode("latin-1"),
        "src": src,
        "dst": dst,
    }
    cred = None
    if a := _AUTH.search(payload):
        try:
            user_pass = base64.b64decode(a.group(1)).decode("latin-1")
            cred = {"protocol": "HTTP Basic", "server": f"{host or dst}:{dport}", "data": user_pass}
        except (ValueError, UnicodeError):
            pass
    return req, cred


def _plaintext_cred(proto_name: str, payload: bytes, src, dst, sport, dport) -> dict | None:
    text = payload[:512].decode("latin-1")
    if proto_name == "FTP" and (m := re.match(r"(USER|PASS) (.+?)[\r\n]", text)):
        return {"protocol": "FTP", "server": f"{dst}:{dport}", "data": f"{m.group(1)} {m.group(2)}"}
    if dport == 110 and (m := re.match(r"(USER|PASS) (.+?)[\r\n]", text)):
        return {
            "protocol": "POP3",
            "server": f"{dst}:{dport}",
            "data": f"{m.group(1)} {m.group(2)}",
        }
    return None


# ---------------------------------------------------------------- top level


def analyse(data: bytes, hunter: FlagHunter | None = None) -> dict:
    hunter = hunter or FlagHunter()
    protocols: Counter = Counter()
    talkers: Counter = Counter()
    conversations: Counter = Counter()
    ports: Counter = Counter()
    dns: Counter = Counter()
    http: list[dict] = []
    creds: list[dict] = []
    tcp_streams: dict[tuple, bytearray] = defaultdict(bytearray)
    flags: dict[str, dict] = {}
    count = 0
    truncated = False

    for _ts, _link, frame in _iter_pcap(data):
        count += 1
        if count > MAX_PACKETS:
            truncated = True
            break
        eth = _parse_eth(frame)
        if not eth:
            continue
        etype, payload = eth
        if etype == ETH_ARP:
            protocols["ARP"] += 1
            continue
        ip = _parse_ip(etype, payload)
        if not ip:
            continue
        src, dst, proto, seg = ip
        name, sport, dport, app = _l4(proto, seg)
        talkers[src] += 1
        if sport is not None:
            svc = PORT_NAMES.get(dport) or PORT_NAMES.get(sport) or name
            protocols[svc] += 1
            ports[dport if dport in PORT_NAMES else sport] += 1
            conversations[tuple(sorted([src, dst]))] += 1
            if svc == "DNS" and app:
                for q in _dns_questions(app):
                    dns[q] += 1
            elif app and name == "TCP":
                key = (src, sport, dst, dport)
                if len(tcp_streams[key]) < 65536:
                    tcp_streams[key] += app
                if dport in (80, 8080) or b"HTTP/1." in app[:16]:
                    req, cred = _http(app, src, dst, dport)
                    if req and len(http) < 500:
                        http.append(req)
                    if cred:
                        creds.append(cred)
                c = _plaintext_cred(svc, app, src, dst, sport, dport)
                if c:
                    creds.append(c)
        else:
            protocols[name] += 1
        for f in hunter.scan_bytes(app or seg):
            flags.setdefault(f["value"], {**f, "where": f"{name} {src}->{dst}"})

    # de-duplicate credentials, reassemble FTP USER+PASS pairs
    creds = _dedupe(creds)
    convs = [{"a": a, "b": b, "packets": n} for (a, b), n in conversations.most_common(15)]
    return {
        "packets": count - (1 if truncated else 0),
        "truncated": truncated,
        "protocols": [{"name": k, "packets": v} for k, v in protocols.most_common(20)],
        "top_talkers": [{"host": k, "packets": v} for k, v in talkers.most_common(10)],
        "conversations": convs,
        "ports": [
            {"port": p, "service": PORT_NAMES.get(p, "?"), "packets": n}
            for p, n in ports.most_common(15)
        ],
        "dns": [{"name": k, "count": v} for k, v in dns.most_common(60)],
        "http": http[:200],
        "credentials": creds,
        "flags": list(flags.values()),
    }


def _dedupe(creds: list[dict]) -> list[dict]:
    seen, out = set(), []
    for c in creds:
        key = (c["protocol"], c["server"], c["data"])
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out
