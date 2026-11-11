# domainscope

[![CI](https://github.com/Ashtr1cks/domainscope/actions/workflows/ci.yml/badge.svg)](https://github.com/Ashtr1cks/domainscope/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Passive-first domain reconnaissance (OSINT): a desktop app and a CLI.** Point it at a domain
and get registration data, DNS and email-security posture, subdomains from Certificate
Transparency logs, hosting/ASN mapping, and (optionally) HTTP/TLS checks, with every finding
explained in plain English. Export any scan as HTML, Markdown or JSON.

No API keys, no accounts, and nothing to configure.

![domainscope results view](docs/app-results.png)

## The app

Pick what you want to find out, type a domain, and press **Run scan**. No commands to remember.

| Task | What it does |
|---|---|
| **Full recon** | Everything below in one go |
| **Quiet look** | Public sources only; never contacts the domain's servers |
| **Email spoofing check** | SPF, DMARC, MTA-STS: can someone send fake mail as this domain? |
| **Find subdomains** | Certificate-log search, dangling-CNAME / takeover detection |
| **Website security check** | Security headers, TLS certificate, version leaks |
| **Who owns it?** | Registrar, dates, name servers, abuse contact |

Results show a one-line verdict, severity counts, and tabs for findings, hosts, DNS, email,
websites and registration. Each finding has a **What does this mean?** explanation. Scans are
saved to `~/.domainscope` so your history persists, and the app shows the equivalent CLI command
for every scan so you can script it later.

<details><summary>Screenshot: new scan form</summary>

![domainscope new scan form](docs/app-new-scan.png)
</details>

**Start it:**

- **Windows:** double-click **`Start domainscope.cmd`**. The first run sets everything up.
- **Any OS:** `pip install -e ".[desktop]"` then run `domainscope-app`

It opens in its own window (via [pywebview](https://pywebview.flowrl.com/)), or in your browser
if pywebview isn't installed or you pass `--browser`. The server only listens on `127.0.0.1` and
rejects requests with any other `Host` header, which blocks DNS-rebinding attacks.

## The CLI

```text
$ domainscope example.com --open
[+] WHOIS ........ RESERVED-Internet Assigned Numbers Authority, created 1995-08-14
[+] DNS .......... A:6, AAAA:6, MX:1, NS:2, TXT:2, SOA:1
[!] Email sec .... SPF -all, DMARC p=reject
[+] CT logs ...... 14 unique names (crt.sh 14, certspotter 3)
[+] Resolve ...... 6/14 hosts resolve
[+] ASN .......... 12 IPs across 1 networks
[+] HTTP ......... 6/6 probed hosts responded
[+] TLS .......... 6 certificates, 0 problems
[✓] report saved -> reports/example.com_20260101-120000.html
```

## What it checks

| Module | Source | What you get | Touches target? |
|---|---|---|---|
| **Registration** | [RDAP](https://about.rdap.org/) (WHOIS successor) | Registrar, dates, status, name servers, abuse contact, domain age | No |
| **DNS** | Your resolver | A/AAAA/CNAME/MX/NS/TXT/SOA/CAA, DNSSEC, wildcard detection | Via DNS only |
| **Email security** | DNS | SPF (qualifier, lookup count), DMARC policy, MTA-STS, TLS-RPT | Via DNS only |
| **Subdomains** | [crt.sh](https://crt.sh), [Cert Spotter](https://sslmate.com/certspotter/) | Every hostname that ever appeared on a public TLS certificate | No |
| **Resolution** | DNS | Live vs historical hosts, CNAME chains, **dangling CNAMEs** (subdomain-takeover candidates) | Via DNS only |
| **Hosting / ASN** | [Team Cymru](https://www.team-cymru.com/ip-asn-mapping) over DNS | IP → ASN, prefix, network owner | No |
| **HTTP** | Direct | Status, title, redirects, missing security headers, version leaks, tech fingerprint | **Yes** |
| **TLS** | Direct | Certificate validity, issuer, expiry, SANs, protocol | **Yes** |

Findings are graded **high / medium / low / info**. Examples: `+all` SPF, a missing DMARC
record, dangling CNAMEs to takeover-prone providers, expiring certificates, missing HSTS/CSP, and
`Server: Apache/2.4.41` version disclosure.

## Install

Requires Python 3.10+.

```bash
git clone https://github.com/Ashtr1cks/domainscope.git
cd domainscope
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e ".[desktop]"   # drop [desktop] if you only want the CLI + browser UI
```

Or install it as a global CLI with [pipx](https://pipx.pypa.io/): `pipx install .`

## Usage

```bash
domainscope example.com                    # full scan, all report formats into ./reports
domainscope example.com --passive --open   # no direct contact with target; open HTML when done
domainscope https://shop.example.com/x     # URLs are fine, it extracts the host
domainscope a.com b.org -f json -o out/    # several domains, JSON only
domainscope example.com --resolver 1.1.1.1 --probe-limit 50
python -m domainscope --help               # works without the console script too
```

| Option | Default | Description |
|---|---|---|
| `--passive` | off | Skip HTTP/TLS probing; only public data sources and DNS are used |
| `--no-subdomains` | off | Skip Certificate Transparency discovery |
| `--no-whois` | off | Skip the registration (RDAP) lookup |
| `--no-email` | off | Skip SPF/DMARC/MTA-STS checks |
| `-f, --format` | `html,md,json` | Report formats to write |
| `-o, --output-dir` | `reports` | Where reports go |
| `--open` | off | Open the HTML report in your browser |
| `--no-report` | off | Print findings only |
| `--probe-limit` | 25 | Max hosts to HTTP/TLS probe |
| `--max-hosts` | 1000 | Max discovered names to resolve |
| `--workers` | 20 | DNS concurrency |
| `--timeout` | 10 | Network timeout (seconds) |
| `--resolver IP` | system | DNS resolver (repeatable) |

The JSON report has a stable structure (`meta`, `rdap`, `dns`, `email`, `hosts`, `asn`, `http`,
`tls`, `findings`, `summary`, `errors`), so you can pipe it into `jq` or other tools.

## Project layout

```text
src/domainscope/
├── app.py              # desktop launcher (pywebview window or browser)
├── web/
│   ├── server.py       # FastAPI API: background scans, SSE progress, history
│   └── static/         # single-page UI (vanilla JS, no build step)
├── cli.py              # argparse + rich terminal UI
├── scanner.py          # runs modules, aggregates findings
├── report.py           # JSON / Markdown / HTML rendering
├── templates/          # Jinja2 report templates (HTML is self-contained)
└── modules/
    ├── rdap.py         # registration data
    ├── dns_records.py  # records, wildcard, resolution, dangling CNAMEs
    ├── email_security.py
    ├── subdomains.py   # crt.sh + Cert Spotter
    ├── asn.py          # Team Cymru DNS lookups
    ├── http_probe.py   # headers, fingerprinting
    └── tls_info.py     # certificate inspection (stdlib ssl)
tests/                  # offline unit + API tests (no network needed)
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

To add a module, write a function that returns plain dicts, add a `findings()` helper that yields
`(severity, title, detail)` tuples, and call both from `scanner.py`.

## Roadmap

- [ ] Optional API-key sources (SecurityTrails, Shodan, VirusTotal) via env vars
- [ ] Historical snapshots from the Wayback Machine (`/robots.txt`, old endpoints)
- [ ] Zone transfer (AXFR) check against each authoritative NS
- [ ] Diff two JSON reports to spot new subdomains over time
- [ ] Export findings to CSV / STIX

## Legal and ethical use

This tool is for **education, defensive security, and authorised assessments**. Passive mode
uses only public data. Active mode sends ordinary HTTP(S) requests, which is roughly what a
browser does, but you should still only scan domains you own or have written permission to
test. You are responsible for how you use it.

## License

[MIT](LICENSE)
