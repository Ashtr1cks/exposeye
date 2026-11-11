"use strict";

/* ================================================================== helpers */

const SVGNS = "http://www.w3.org/2000/svg";
const SEVS = ["high", "medium", "low", "info"];
const main = document.getElementById("main");

// Build DOM safely: strings always become text nodes, never HTML.
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "checked" || k === "value") el[k] = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : String(kid));
  }
  return el;
}

const ICONS = {
  radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 12l6-6"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M3 3l18 18M10.6 6.1A10 10 0 0112 6c6.5 0 10 6 10 6a17 17 0 01-3.2 3.9M6.3 7.6A17 17 0 002 12s3.5 6 10 6a9.7 9.7 0 004.4-1"/><path d="M9.9 10a3 3 0 004.2 4.2"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
  shieldMail: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M8 10h8v5H8zM8 10l4 3 4-3"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3M14 9l2 2"/>',
  tree: '<circle cx="6" cy="6" r="2"/><circle cx="18" cy="12" r="2"/><circle cx="18" cy="19" r="2"/><path d="M6 8v9a2 2 0 002 2h8M6 12h10"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/>',
  id: '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="12" r="2.5"/><path d="M14 10h4M14 14h4"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18"/>',
  sliders: '<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 01-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 010-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 014 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 010 4h-.1a1.7 1.7 0 00-1.5 1z"/>',
  play: '<path d="M7 5l12 7-12 7z"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 012-2h10"/>',
  download: '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
  external: '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 01-1 1H5a1 1 0 01-1-1V7a1 1 0 011-1h5"/>',
  refresh: '<path d="M20 11a8 8 0 10-2.3 5.7M20 4v7h-7"/>',
  trash: '<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>',
  flag: '<path d="M5 21V4M5 4h11l-2 4 2 4H5"/>',
  upload: '<path d="M12 16V4M7 9l5-5 5 5M5 20h14"/>',
  expand: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>',
  shrink: '<path d="M9 4v5H4M15 4v5h5M9 20v-5H4M15 20v-5h5"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
  bell: '<path d="M6 8a6 6 0 0112 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.9 1.9 0 003.4 0"/>',
  diff: '<path d="M8 3v12M4 7l4-4 4 4M16 21V9M12 17l4 4 4-4"/>',
  pause: '<path d="M8 5v14M16 5v14"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  send: '<path d="M22 2L11 13M22 2l-7 20-4-9-9-4z"/>',
};

function icon(name) {
  const svg = document.createElementNS(SVGNS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.innerHTML = ICONS[name]; // static constants only
  return svg;
}

function render(...nodes) {
  main.replaceChildren(...nodes);
  window.scrollTo(0, 0);
}

const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* ignore */ } },
};

let toastTimer;
function toast(msg) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 2400);
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); }
  catch {
    const ta = h("textarea", {}, text);
    document.body.append(ta); ta.select(); document.execCommand("copy"); ta.remove();
  }
  toast("Copied to clipboard");
}

const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
const plural = (n, word) => `${n.toLocaleString()} ${word}${n === 1 ? "" : "s"}`;
const safeUrl = (u) => (typeof u === "string" && /^https?:\/\//i.test(u) ? u : null);
const fmtNum = (n) => (typeof n === "number" ? n.toLocaleString() : n || "");

function relTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  const s = (Date.now() - d.getTime()) / 1000;
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (s < 60) return "just now";
  if (s < 3600) return rtf.format(-Math.round(s / 60), "minute");
  if (s < 86400) return rtf.format(-Math.round(s / 3600), "hour");
  if (s < 86400 * 7) return rtf.format(-Math.round(s / 86400), "day");
  return d.toLocaleDateString();
}

const api = {
  async req(method, path, body) {
    const res = await fetch(path, {
      method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      let msg = res.statusText;
      try {
        const j = await res.json();
        msg = typeof j.detail === "string" ? j.detail : (j.detail?.[0]?.msg || msg);
      } catch { /* not json */ }
      throw new Error(msg);
    }
    return res.status === 204 ? null : res.json();
  },
  get: (p) => api.req("GET", p),
  post: (p, b) => api.req("POST", p, b),
  put: (p, b) => api.req("PUT", p, b),
  del: (p) => api.req("DELETE", p),
};

/* ================================================================== tasks */

const DEFAULT_OPTS = { whois: true, email: true, subdomains: true, exposure: true, passive: false, probe_limit: 25 };

const TASKS = [
  { id: "full", kind: "domain", icon: "radar", title: "Full recon", badge: "Recommended",
    desc: "Everything: who owns it, DNS, email security, subdomains and website checks.", opts: {} },
  { id: "quiet", kind: "domain", icon: "eye", title: "Quiet look",
    desc: "Public sources only. Never connects to the domain's own servers.", opts: { passive: true } },
  { id: "emailsec", kind: "domain", icon: "mail", title: "Email spoofing check",
    desc: "Can someone send fake email as this domain? Checks SPF, DMARC and MTA-STS.",
    opts: { whois: false, subdomains: false, exposure: false, passive: true } },
  { id: "subs", kind: "domain", icon: "tree", title: "Find subdomains",
    desc: "Lists hostnames from public certificate logs and flags takeover risks.",
    opts: { whois: false, email: false, exposure: false, passive: true } },
  { id: "ports", kind: "domain", icon: "server", title: "Open ports & vulnerabilities", badge: "New",
    desc: "Exposed services (RDP, databases…) and known CVEs on every IP, from Shodan's public data.",
    opts: { whois: false, email: false, passive: true } },
  { id: "web", kind: "domain", icon: "lock", title: "Website security check",
    desc: "Security headers, TLS certificate and server versions for the main site.",
    opts: { whois: false, email: false, subdomains: false, exposure: false, probe_limit: 2 } },
  { id: "owner", kind: "domain", icon: "id", title: "Who owns it?",
    desc: "Registrar, creation and expiry dates, name servers and abuse contact.",
    opts: { email: false, subdomains: false, exposure: false, passive: true } },
  { id: "exposure", kind: "email", icon: "shieldMail", title: "Email exposure check", badge: "New",
    desc: "Which data breaches include this email, and were passwords leaked?", opts: {} },
  { id: "password", kind: "password", icon: "key", title: "Has my password leaked?",
    desc: "Checks a password against 900M+ leaked passwords without sending it anywhere.", opts: {} },
];

const KIND_UI = {
  domain: { step: "Which domain?", placeholder: "example.com", type: "text", run: "Run scan",
    hint: "A domain or a full URL both work. Try: ", examples: ["example.com", "github.com", "monash.edu"] },
  email: { step: "Which email address?", placeholder: "you@example.com", type: "email", run: "Check email",
    hint: "Check your own email, or someone else's with their consent.", examples: [] },
  password: { step: "Which password?", placeholder: "Type the password to check", type: "password", run: "Check password",
    hint: "Your password never leaves this computer. Only the first 5 characters of its SHA-1 hash are sent (k-anonymity).", examples: [] },
};

const taskById = (id) => TASKS.find((t) => t.id === id);
const taskOpts = (t) => ({ ...DEFAULT_OPTS, ...t.opts });
const sameOpts = (a, b) => ["whois", "email", "subdomains", "exposure", "passive"].every((k) => !!a[k] === !!b[k])
  && (a.passive || a.probe_limit === b.probe_limit);
const matchDomainTask = (opts) => TASKS.find((t) => t.kind === "domain" && sameOpts(taskOpts(t), opts));

function buildCommand(domain, o) {
  const parts = ["exposeye", domain || "<domain>"];
  if (o.passive) parts.push("--passive");
  if (!o.whois) parts.push("--no-whois");
  if (!o.email) parts.push("--no-email");
  if (!o.subdomains) parts.push("--no-subdomains");
  if (o.exposure === false) parts.push("--no-exposure");
  if (!o.passive && o.probe_limit !== 25) parts.push(`--probe-limit ${o.probe_limit}`);
  return parts.join(" ");
}

function expectedSteps(job) {
  if (job.kind === "email") return 3;
  const o = { ...DEFAULT_OPTS, ...(job.options || {}) };
  return (o.whois ? 1 : 0) + 1 + (o.email ? 1 : 0) + (o.subdomains ? 1 : 0) + 2 + (o.exposure ? 1 : 0) + (o.passive ? 1 : 2);
}

/* plain-English explanations for findings */
const EXPLAIN = [
  [/^No SPF record/, "SPF lists which mail servers may send email for this domain. Without it, receivers can't tell real mail from forged mail, so phishing in this domain's name is easier."],
  [/^SPF allows all senders/, "+all tells receivers that ANY server on the internet may send mail as this domain. That defeats the purpose of SPF entirely."],
  [/^SPF is neutral/, "?all means \"no opinion\" about unlisted senders, so forged mail is not rejected."],
  [/^SPF uses softfail/, "~all asks receivers to accept but flag mail from unlisted servers. Common while rolling out; -all is stricter."],
  [/^SPF has no 'all'/, "Without an 'all' rule, mail from unlisted servers gets a neutral result and is usually accepted."],
  [/^SPF exceeds 10/, "SPF checking gives up after 10 DNS lookups and fails, so even legitimate mail can be rejected."],
  [/^Multiple SPF/, "A domain must have exactly one SPF record. Having two or more makes SPF checks fail."],
  [/^No DMARC/, "DMARC tells receivers what to do when SPF/DKIM checks fail (reject or quarantine) and where to send reports. Without it, spoofed mail is usually delivered."],
  [/^DMARC policy is p=none/, "p=none only monitors: spoofed email is still delivered. Owners usually move to quarantine or reject once reports look clean."],
  [/^DMARC has no aggregate/, "Without rua= the owner gets no reports about who is sending mail using their domain."],
  [/^DMARC applies to a subset/, "pct below 100 applies the policy to only a percentage of failing mail."],
  [/^No MTA-STS/, "MTA-STS forces other mail servers to use verified TLS when delivering mail here. Without it, an attacker on the network path could downgrade delivery to plaintext."],
  [/^Dangling CNAME/, "This subdomain points to a hostname that no longer exists. On shared hosting platforms an attacker may be able to claim that name and serve their own content on the subdomain (subdomain takeover)."],
  [/potentially sensitive subdomain/, "Names like admin, dev, vpn or staging often host less-hardened systems. They are worth reviewing, with permission."],
  [/^Strict-Transport-Security/, "HSTS makes browsers always use HTTPS for this site, which prevents SSL-stripping attacks (for example on public Wi-Fi)."],
  [/^Content-Security-Policy/, "CSP limits which scripts a page may load. It is one of the strongest defences against cross-site scripting (XSS)."],
  [/^X-Frame-Options/, "Stops other websites from embedding this page in a frame, which prevents clickjacking."],
  [/^X-Content-Type-Options/, "'nosniff' stops browsers guessing file types, which blocks some content-injection tricks."],
  [/^Referrer-Policy/, "Controls how much of the page URL is shared with other sites when visitors click links."],
  [/^Permissions-Policy/, "Restricts powerful browser features (camera, microphone, location) that the page and its embeds can use."],
  [/^Version disclosure/, "Exact software versions help attackers match the server to known vulnerabilities (CVEs)."],
  [/^HTTP not redirected/, "Visitors who type the address without https:// stay on an unencrypted connection."],
  [/^TLS certificate problem/, "Browsers will show a security warning. It can mean a misconfigured server, or that traffic is being intercepted."],
  [/^TLS certificate on .* expires/, "When the certificate expires, visitors get a browser warning. Renewal should be automated."],
  [/^Legacy TLS/, "TLS 1.0 and 1.1 are deprecated and have known weaknesses."],
  [/^DNSSEC not enabled/, "DNSSEC signs DNS answers so resolvers can detect forged responses, such as in DNS cache-poisoning (Kaminsky) attacks."],
  [/^No CAA record/, "CAA lists which certificate authorities may issue certificates for this domain, which limits mis-issuance."],
  [/^Wildcard DNS/, "Every subdomain resolves, even made-up ones. exposeye marks those hosts so they aren't mistaken for real systems."],
  [/^Recently registered/, "Newly registered domains are often used for phishing. Be careful if this isn't a domain you recognise."],
  [/^Domain registration expires soon/, "If the registration lapses, anyone could register the domain and take over its email and website."],
  [/^(RDP|SMB|NetBIOS|VNC|Telnet) \(port/, "Remote-access and file-sharing services are among the most attacked things on the internet: brute-forced passwords and wormable bugs (like WannaCry on SMB) lead straight to ransomware. Put them behind a VPN or firewall."],
  [/^(MySQL|PostgreSQL|Microsoft SQL Server|Oracle DB|MongoDB|Redis|Elasticsearch|Memcached) \(port/, "Databases should never be reachable from the internet. Exposed ones are scanned within hours and frequently have weak or no passwords, leading to data theft or ransom."],
  [/^Docker API/, "An unauthenticated Docker API lets anyone run containers on the host, which is effectively full control of the machine."],
  [/^(FTP|SNMP|LDAP|Microsoft RPC|Kibana|WinRM.*) \(port/, "This service leaks information or credentials, or offers an attack path when exposed. Restrict it to internal networks or a VPN."],
  [/^Known-exploited vulnerabilities/, "These CVEs are on CISA's Known Exploited Vulnerabilities list: attackers are using them in real attacks right now. They should be patched first, before anything else."],
  [/^Vulnerabilities likely to be exploited/, "EPSS estimates at least a 50% chance of exploitation in the next 30 days. Verify the version and patch soon. (CVEs are inferred from version banners, so some may already be fixed by backported patches.)"],
  [/^Vulnerabilities with elevated exploit risk/, "EPSS estimates a 10–50% chance of exploitation in the next 30 days. Worth checking after the urgent ones."],
  [/^Other reported vulnerabilities/, "Lower-risk CVEs matched to this software version. Keep the software updated; these rarely need emergency action."],
  [/^End-of-life software/, "The vendor no longer ships security fixes for this software, so new vulnerabilities will never be patched. Plan an upgrade."],
  [/^Password exposed in readable/, "These sites stored passwords in plain text or with weak hashing, so attackers can read or quickly crack them. Anyone who reused that password elsewhere is at real risk of account takeover."],
  [/^Password hash exposed/, "The sites stored passwords as hashes. Strong hashes are slow to crack but weak or common passwords can still be recovered. Changing them is the safe move."],
  [/^Sensitive personal or financial data/, "Financial or identity data can be used for fraud or identity theft. Watch your accounts and consider credit monitoring."],
  [/^Email found in/, "The address appeared in these breaches. Even without passwords, leaked details make phishing and spam more targeted."],
  [/^Public Gravatar profile/, "Gravatar shows the same profile on every site that uses it, so anyone who knows the email can see these details and linked accounts."],
  [/^Public Gravatar avatar/, "The avatar picture can link this email to accounts on other sites."],
  [/^Email domain can't receive mail/, "Without MX records the domain doesn't accept email, so the address is probably invalid or retired."],
  [/^Disposable email address/, "Throwaway inbox services are public or short-lived. Don't use them for anything important."],
];
const explain = (title) => EXPLAIN.find(([re]) => re.test(title))?.[1];

const RISK = {
  plaintext: ["warn", "Password readable (plain text)"],
  easytocrack: ["warn", "Password weakly hashed"],
  hardtocrack: ["note", "Password strongly hashed"],
  unknown: ["note", "Password exposed"],
};

/* ================================================================== state & history */

const state = { stream: null, tick: null, jobs: {}, history: [], running: [], cy: null, mapCleanup: null, monitorTimer: null,
  settings: null, labInput: null, labFile: null };

function closeStream() {
  if (state.stream) { state.stream.close(); state.stream = null; }
  if (state.tick) { clearInterval(state.tick); state.tick = null; }
}

async function loadHistory() {
  try {
    const data = await api.get("/api/scans");
    state.history = data.scans;
    state.running = data.running;
  } catch { /* server may be restarting */ }
  drawHistory();
}

function drawHistory() {
  const ul = document.getElementById("history");
  const current = location.hash.split("/")[2];
  const items = [];
  for (const j of state.running) {
    items.push(h("li", {}, h("a", { href: `#/progress/${j.id}`, class: j.id === current ? "active" : null },
      h("div", { class: "h-domain" }, h("span", { class: "spinner", style: "width:12px;height:12px;border-width:2px" }), j.target),
      h("div", { class: "h-meta" }, "running…"))));
  }
  for (const s of state.history) {
    const f = s.findings || {};
    items.push(h("li", {}, h("a", { href: `#/scan/${s.id}`, class: s.id === current ? "active" : null },
      h("div", { class: "h-domain" }, s.kind === "email" ? icon("mail") : icon("globe"), h("span", { class: "h-text" }, s.target)),
      h("div", { class: "h-meta" },
        h("span", {}, relTime(s.started)),
        s.kind === "email" && s.breaches != null ? h("span", {}, plural(s.breaches, "breach")) : null,
        f.high ? h("span", { class: "sev-dot high", title: "high" }, f.high) : null,
        f.medium ? h("span", { class: "sev-dot medium", title: "medium" }, f.medium) : null,
        s.passive ? h("span", {}, "passive") : null))));
  }
  ul.replaceChildren(...(items.length ? items : [h("li", { class: "history-empty" }, "No scans yet")]));
  document.getElementById("settingsLink").classList.toggle("active", location.hash === "#/settings");
  document.getElementById("monitorLink").classList.toggle("active", location.hash === "#/monitor");
  document.getElementById("decoderLink").classList.toggle("active", location.hash === "#/lab/decode");
  document.getElementById("fileLink").classList.toggle("active", location.hash === "#/lab/file");
  document.getElementById("hashLink").classList.toggle("active", location.hash === "#/lab/hash");
  document.getElementById("jwtLink").classList.toggle("active", location.hash === "#/lab/jwt");
}

async function refreshBadge() {
  try {
    const s = await api.get("/api/monitor/summary");
    const badge = document.getElementById("monitorBadge");
    badge.textContent = s.unread > 99 ? "99+" : String(s.unread);
    badge.hidden = !s.unread;
  } catch { /* ignore */ }
}

/* ================================================================== routing */

function route() {
  closeStream();
  teardownMap();
  clearTimeout(state.monitorTimer);
  const [, view, id, sub] = location.hash.split("/");
  if (view === "scan" && id) showResult(id, sub);
  else if (view === "progress" && id) showProgress(id);
  else if (view === "compare" && id) showCompare(id);
  else if (view === "monitor") showMonitor();
  else if (view === "lab" && id === "decode") showDecoder();
  else if (view === "lab" && id === "file") showFileLab();
  else if (view === "lab" && id === "hash") showHashes();
  else if (view === "lab" && id === "jwt") showJwt();
  else if (view === "settings") showSettings();
  else showNew();
  drawHistory();
}
window.addEventListener("hashchange", route);

async function startJob(path, body, kind, options) {
  const res = await api.post(path, body);
  const job = { id: res.id, kind, target: res.target, options };
  state.jobs[res.id] = job;
  state.running.unshift(job);
  location.hash = `#/progress/${res.id}`;
}
const startDomainScan = (domain, opts) => startJob("/api/scans", { domain, ...opts }, "domain", opts);
const startEmailCheck = (email) => startJob("/api/email-checks", { email }, "email", {});

/* password check: runs entirely in the browser (k-anonymity) */
async function pwnedCount(password) {
  if (!window.crypto?.subtle) throw new Error("This browser can't hash passwords securely here.");
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(password));
  const hex = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  const prefix = hex.slice(0, 5);
  const suffix = hex.slice(5);
  const url = `https://api.pwnedpasswords.com/range/${prefix}`;
  let res;
  try { res = await fetch(url, { headers: { "Add-Padding": "true" } }); }
  catch { res = await fetch(url); } // in case the padding header is blocked by CORS
  if (!res.ok) throw new Error(`Password service error (${res.status})`);
  for (const line of (await res.text()).split("\n")) {
    const [s, c] = line.trim().split(":");
    if (s === suffix) return parseInt(c, 10) || 0;
  }
  return 0;
}

/* ================================================================== view: new */

function showNew() {
  let opts = { ...DEFAULT_OPTS, ...store.get("ds.opts", {}) };
  let taskId = store.get("ds.task", null);
  if (!taskById(taskId)) taskId = matchDomainTask(opts)?.id || null;
  if (taskById(taskId)?.kind === "domain" && !sameOpts(taskOpts(taskById(taskId)), opts)) taskId = matchDomainTask(opts)?.id || null;
  const kindOf = () => taskById(taskId)?.kind || "domain";
  const values = { domain: store.get("ds.lastDomain", ""), email: store.get("ds.lastEmail", ""), password: "" };
  let shownKind = null;

  const input = h("input", { type: "text", class: "domain-input", spellcheck: "false", autocomplete: "off", "aria-label": "Target" });
  const reveal = h("button", { type: "button", class: "btn reveal", title: "Show password", "aria-label": "Show password",
    onclick: () => {
      const showing = input.type === "text";
      input.type = showing ? "password" : "text";
      reveal.replaceChildren(icon(showing ? "eye" : "eyeOff"));
    } }, icon("eye"));
  const err = h("div", { class: "form-error", role: "alert" });
  const runLabel = h("span", {});
  const runBtn = h("button", { type: "submit", class: "btn btn-primary btn-lg" }, icon("play"), runLabel);
  const cmd = h("code", {});
  const stepTitle = h("span", {});
  const hint = h("div", { class: "hint" });
  const pwResult = h("div", { class: "pw-result", "aria-live": "polite" });
  const tasksBox = h("div", { class: "tasks", role: "radiogroup", "aria-label": "What do you want to find out?" });
  const toggles = {};
  const probeOut = h("output", {});
  const probe = h("input", { type: "range", min: "1", max: "100", "aria-label": "Websites to check" });
  const probeRow = h("div", { class: "range-row panel-row" },
    h("div", { class: "toggle-text" }, h("strong", {}, "Websites to check"), h("span", {}, "Maximum number of hosts to visit")),
    probe, probeOut);
  const legal = h("div", { class: "legal" });

  // Multi-select feature cards: click to switch each check on/off; selected ones are highlighted.
  const FEATURES = [
    ["whois", "id", "Registration details", "Owner/registrar, creation and expiry dates"],
    ["email", "mail", "Email security", "SPF, DMARC, MTA-STS: can the domain be spoofed?"],
    ["subdomains", "tree", "Find subdomains", "Search public certificate logs"],
    ["exposure", "server", "Open ports & CVEs", "Exposed services and known vulnerabilities per IP (passive)"],
    ["web", "globe", "Visit websites", "Security headers and TLS certificates (makes the scan active)"],
  ];
  const featureCard = ([key, ic, title, desc]) => {
    const card = h("button", {
      type: "button", class: "feature", "aria-pressed": "false",
      onclick: () => {
        if (key === "web") opts.passive = !opts.passive; else opts[key] = !opts[key];
        taskId = matchDomainTask(opts)?.id || null;
        sync();
      },
    },
      h("span", { class: "feature-check", "aria-hidden": "true" }),
      h("span", { class: "task-icon" }, icon(ic)),
      h("span", { class: "feature-text" }, h("strong", {}, title), h("span", {}, desc)));
    toggles[key] = card;
    return card;
  };
  const customNote = h("span", { class: "opt" });
  const optionsBlock = h("div", {},
    h("div", { class: "step-title" }, h("span", { class: "step-num" }, "3"), "Choose what to check ", customNote),
    h("div", { class: "features", role: "group", "aria-label": "Checks to run" }, FEATURES.map(featureCard)),
    probeRow);

  for (const t of TASKS) {
    tasksBox.append(h("label", { class: "task", "data-id": t.id },
      h("input", { type: "radio", name: "task", value: t.id, onchange: () => {
        taskId = t.id;
        if (t.kind === "domain") opts = taskOpts(t);
        sync();
        input.focus();
      } }),
      t.badge ? h("span", { class: "task-badge" }, t.badge) : null,
      h("div", { class: "task-head" }, h("span", { class: "task-icon" }, icon(t.icon)), t.title),
      h("div", { class: "task-desc" }, t.desc)));
  }

  function sync() {
    const kind = kindOf();
    const ui = KIND_UI[kind];
    if (kind !== shownKind) {
      if (shownKind && shownKind !== "password") values[shownKind] = input.value;
      input.value = values[kind] || "";
      input.type = ui.type;
      input.placeholder = ui.placeholder;
      input.autocomplete = kind === "email" ? "email" : "off";
      stepTitle.textContent = ui.step;
      runLabel.textContent = ui.run;
      hint.replaceChildren(ui.hint, ...ui.examples.flatMap((d, i) => [i ? ", " : "",
        h("button", { type: "button", onclick: () => { input.value = d; sync(); input.focus(); } }, d)]));
      reveal.hidden = kind !== "password";
      reveal.replaceChildren(icon("eye"));
      optionsBlock.hidden = kind !== "domain";
      pwResult.replaceChildren();
      err.textContent = "";
      legal.textContent = kind === "domain"
        ? "Only scan domains you own or have permission to test. 'Quiet look' uses public data only."
        : kind === "email" ? "Breach data comes from XposedOrNot (free) or Have I Been Pwned if you add a key in Settings."
        : "Nothing is saved. The check uses the Pwned Passwords k-anonymity API.";
      shownKind = kind;
    }
    for (const card of tasksBox.children) {
      const sel = card.dataset.id === taskId;
      card.classList.toggle("selected", sel);
      card.querySelector("input").checked = sel;
    }
    for (const [k, el] of Object.entries(toggles)) {
      const on = k === "web" ? !opts.passive : !!opts[k];
      el.classList.toggle("selected", on);
      el.setAttribute("aria-pressed", String(on));
    }
    customNote.textContent = kind === "domain" && !taskId
      ? "(custom selection: click cards to turn checks on or off)"
      : "(click cards to turn checks on or off)";
    probe.value = String(Math.max(1, opts.probe_limit));
    probeOut.textContent = probe.value;
    probeRow.hidden = opts.passive;
    cmd.textContent = kind === "domain" ? buildCommand(input.value.trim(), opts)
      : kind === "email" ? `exposeye-email ${input.value.trim() || "<email>"}`
      : "exposeye-email --password";
    store.set("ds.opts", opts);
    store.set("ds.task", taskId);
  }

  probe.addEventListener("input", () => { opts.probe_limit = Number(probe.value); taskId = matchDomainTask(opts)?.id || null; sync(); });
  input.addEventListener("input", () => { err.textContent = ""; sync(); });

  const form = h("form", {
    novalidate: true,
    onsubmit: async (e) => {
      e.preventDefault();
      const kind = kindOf();
      const value = kind === "password" ? input.value : input.value.trim();
      if (!value) { err.textContent = `Type ${kind === "domain" ? "a domain" : kind === "email" ? "an email address" : "a password"} first.`; input.focus(); return; }
      runBtn.disabled = true;
      err.textContent = "";
      try {
        if (kind === "password") {
          pwResult.replaceChildren(h("div", { class: "muted" }, "Checking…"));
          const count = await pwnedCount(value);
          input.value = "";
          pwResult.replaceChildren(passwordResult(count));
          runBtn.disabled = false;
          return;
        }
        if (kind === "email") { store.set("ds.lastEmail", value); await startEmailCheck(value); }
        else { store.set("ds.lastDomain", value); await startDomainScan(value, { ...opts }); }
      } catch (ex) {
        err.textContent = ex.message;
        pwResult.replaceChildren();
        runBtn.disabled = false;
      }
    },
  },
    h("div", { class: "step-title" }, h("span", { class: "step-num" }, "1"), "What do you want to find out?"),
    tasksBox,
    h("div", { class: "step-title" }, h("span", { class: "step-num" }, "2"), stepTitle),
    h("div", { class: "domain-row" }, input, reveal),
    hint,
    err,
    pwResult,
    optionsBlock,
    h("div", { class: "command" }, h("span", { class: "label" }, "Command"), cmd,
      h("button", { type: "button", class: "btn btn-ghost", title: "Copy command", onclick: () => copyText(cmd.textContent) }, icon("copy"), "Copy")),
    h("div", { class: "run-row" }, runBtn, legal));

  render(h("section", {},
    h("div", { class: "hero" }, h("h1", {}, "New scan"),
      h("p", {}, "Pick what you want to know, fill in the blank, and press the button. exposeye does the rest.")),
    form));
  sync();
  input.focus();
}

function passwordResult(count) {
  if (count > 0) {
    return h("div", { class: "verdict bad" }, h("div", {},
      h("strong", {}, `This password has appeared ${count.toLocaleString()} times in data breaches.`),
      h("div", { style: "font-weight:400;margin-top:4px" },
        "Attackers try leaked passwords first. Stop using it everywhere it's used, and switch to a unique password from a password manager.")));
  }
  return h("div", { class: "verdict good" }, h("div", {},
    h("strong", {}, "Not found in any known data breach."),
    h("div", { style: "font-weight:400;margin-top:4px" },
      "That's a good sign, though not a guarantee of strength. Use it on one site only.")));
}

/* ================================================================== view: progress */

async function showProgress(id) {
  let job = state.jobs[id] || state.running.find((j) => j.id === id);
  if (!job) {
    await loadHistory();
    job = state.running.find((j) => j.id === id);
    if (!job) { location.hash = `#/scan/${id}`; return; }
  }
  const total = expectedSteps(job);
  let done = 0;

  const bar = h("div", {});
  const timer = h("span", { class: "muted" }, "0s");
  const working = h("li", { class: "step" }, h("span", { class: "spinner" }), h("span", { class: "step-name" }, "Working"),
    h("span", { class: "step-msg" }, job.kind === "email" ? "Searching breach databases…" : "Querying public sources…"));
  const steps = h("ol", { class: "steps" }, working);

  render(h("section", {}, h("div", { class: "progress-card" },
    h("div", { class: "progress-head" }, h("h1", {}, job.target), timer),
    h("div", { class: "bar" }, bar),
    h("div", { class: "muted" }, job.kind === "email"
      ? "Checking breaches, the email's domain and public profiles…"
      : "Scanning… certificate-log searches can take up to a minute. You can start other scans meanwhile."),
    steps)));

  const t0 = Date.now();
  state.tick = setInterval(() => { timer.textContent = `${Math.round((Date.now() - t0) / 1000)}s`; }, 500);

  const es = new EventSource(`/api/scans/${id}/events`);
  state.stream = es;
  es.onmessage = (msg) => {
    const e = JSON.parse(msg.data);
    if (e.type === "progress") {
      done += 1;
      bar.style.width = `${Math.min(95, (done / total) * 100)}%`;
      steps.insertBefore(h("li", { class: `step ${e.ok ? "ok" : "warn"}` },
        h("span", { class: "icon" }, e.ok ? "✓" : "!"),
        h("span", { class: "step-name" }, e.step),
        h("span", { class: "step-msg" }, e.message)), working);
    } else if (e.type === "done") {
      bar.style.width = "100%";
      closeStream();
      loadHistory();
      setTimeout(() => { location.hash = `#/scan/${e.id}`; }, 350);
    } else if (e.type === "error") {
      closeStream();
      working.replaceWith(h("li", { class: "step err" }, h("span", { class: "icon" }, "✕"),
        h("span", { class: "step-name" }, "Failed"), h("span", { class: "step-msg" }, e.message)));
      loadHistory();
    }
  };
}

/* ================================================================== view: result (shared) */

const tabState = { domain: "findings", email: "breaches" };

async function showResult(id, tab) {
  render(h("div", { class: "empty" }, h("span", { class: "spinner", style: "display:inline-block" })));
  let r;
  try { r = await api.get(`/api/scans/${id}`); }
  catch (ex) {
    render(h("div", { class: "empty" }, h("h2", {}, "Scan not found"), h("p", {}, ex.message), h("a", { class: "btn", href: "#/" }, "Start a new scan")));
    return;
  }
  const isEmail = r.meta.kind === "email";
  if (tab) tabState[isEmail ? "email" : "domain"] = tab;
  const mode = !isEmail && r.meta.options?.passive === false ? "full" : "passive";
  const wb = await watchButton(isEmail ? "email" : "domain", isEmail ? r.meta.email : r.meta.domain, mode, id);
  if (isEmail) showEmailResult(r, id, wb);
  else showDomainResult(r, id, wb);
}

async function watchButton(kind, target, mode, scanId) {
  let wl = { items: [] };
  try { wl = await api.get("/api/watchlist"); } catch { /* ignore */ }
  const existing = wl.items.find((i) => i.kind === kind && i.target === target);
  if (existing) return h("a", { class: "btn btn-watching", href: "#/monitor" }, icon("bell"), "Watching");
  const btn = h("button", { class: "btn", type: "button", title: "Re-check on a schedule and alert on changes" }, icon("bell"), "Watch");
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      await api.post("/api/watchlist", { target, interval: "daily", mode, baseline_scan_id: scanId });
      toast(`Watching ${target}. You'll be told when something changes.`);
      btn.replaceWith(h("a", { class: "btn btn-watching", href: "#/monitor" }, icon("bell"), "Watching"));
      refreshBadge();
    } catch (ex) { toast(ex.message); btn.disabled = false; }
  });
  return btn;
}

function actionBar(id, onRescan, rescanLabel, watchBtn) {
  const del = h("button", { class: "btn btn-danger", type: "button" }, icon("trash"), "Delete");
  let armed = false;
  del.addEventListener("click", async () => {
    if (!armed) {
      armed = true; del.classList.add("confirm"); del.lastChild.textContent = "Click again to delete";
      setTimeout(() => { armed = false; del.classList.remove("confirm"); del.lastChild.textContent = "Delete"; }, 3000);
      return;
    }
    await api.del(`/api/scans/${id}`);
    toast("Deleted");
    await loadHistory();
    location.hash = "#/";
  });
  return h("div", { class: "actions" },
    watchBtn,
    h("a", { class: "btn", href: `#/compare/${id}`, title: "Compare with the previous scan of this target" }, icon("diff"), "What changed"),
    h("a", { class: "btn", href: `/api/scans/${id}/report/html`, target: "_blank", rel: "noopener" }, icon("external"), "Open report"),
    h("a", { class: "btn", href: `/api/scans/${id}/report/html?download=true`, download: "" }, icon("download"), "HTML"),
    h("a", { class: "btn", href: `/api/scans/${id}/report/md?download=true`, download: "" }, icon("download"), "Markdown"),
    h("a", { class: "btn", href: `/api/scans/${id}/report/json?download=true`, download: "" }, icon("download"), "JSON"),
    h("button", { class: "btn", type: "button", onclick: async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      try { await onRescan(); } catch (ex) { toast(ex.message); btn.disabled = false; }
    } }, icon("refresh"), rescanLabel),
    del);
}

function tabbed(kind, tabs, views) {
  const panel = h("div", {});
  const bar = h("div", { class: "tabs", role: "tablist" });
  if (!tabs.some(([k]) => k === tabState[kind])) tabState[kind] = tabs[0][0];
  function open(key, arg) {
    teardownMap();
    tabState[kind] = key;
    // Reflect the tab in the URL (bookmarkable) without re-running the router.
    const parts = location.hash.split("/");
    if (parts[1] === "scan" && parts[2]) history.replaceState(null, "", `#/scan/${parts[2]}/${key}`);
    for (const b of bar.children) b.classList.toggle("active", b.dataset.key === key);
    panel.replaceChildren(views[key](arg));
  }
  for (const [key, label, n] of tabs) {
    bar.append(h("button", { class: "tab", role: "tab", "data-key": key, onclick: () => open(key) },
      label, n != null ? h("span", { class: "count" }, n) : null));
  }
  return { bar, panel, open, first: () => open(tabState[kind]) };
}

function commandBox(label, command) {
  return h("div", { class: "command", style: "margin-top:22px" }, h("span", { class: "label" }, label),
    h("code", {}, command),
    h("button", { type: "button", class: "btn btn-ghost", onclick: () => copyText(command) }, icon("copy"), "Copy"));
}

function resultHeader(title, metaBits, actions) {
  return h("div", { class: "result-head" },
    h("div", {}, h("h1", {}, title), h("div", { class: "result-meta" }, metaBits)),
    actions);
}

/* ================================================================== domain result */

function showDomainResult(r, id, watchBtn) {
  const o = { ...DEFAULT_OPTS, ...(r.meta.options || {}) };
  const counts = r.summary.findings;
  const http = r.http || [];
  const tabs = [
    ["findings", "Findings", r.findings.length],
    ["hosts", "Hosts", r.hosts.length],
    mapEligible(r) ? ["map", "Map", null] : null,
    ["dns", "DNS", null],
    r.email ? ["email", "Email security", null] : null,
    r.exposure ? ["exposure", "Ports & CVEs", r.summary.open_ports ?? null] : null,
    http.length ? ["web", "Websites & TLS", http.length] : null,
    r.rdap || r.errors?.whois ? ["whois", "Registration", null] : null,
  ].filter(Boolean);
  let sevFilter = "all";
  const t = tabbed("domain", tabs, {
    findings: () => findingsView(r, sevFilter), hosts: () => hostsView(r), dns: () => dnsView(r),
    email: () => domainEmailView(r.email), web: () => webView(r), whois: () => whoisView(r),
    exposure: () => exposureView(r),
    map: () => mapView(r),
  });

  const verdict = counts.high
    ? h("div", { class: "verdict bad" }, `${plural(counts.high, "serious issue")} found. Start with the red items below.`)
    : counts.medium
      ? h("div", { class: "verdict warn" }, `No serious issues, but ${plural(counts.medium, "medium-risk item")} worth fixing.`)
      : h("div", { class: "verdict good" }, "No serious issues found. Remaining items are hardening suggestions.");

  const sevCard = (s) => h("button", { class: `card ${s}`, type: "button", title: `Show ${s} findings`,
    onclick: () => { sevFilter = s; t.open("findings"); } },
    h("div", { class: "n" }, counts[s]), h("div", { class: "l" }, s));

  render(h("section", {},
    resultHeader(r.meta.domain, [
      h("span", {}, new Date(r.meta.started).toLocaleString()), "·", h("span", {}, `${r.meta.duration_s}s`),
      h("span", { class: `badge ${o.passive ? "" : "accent"}` }, o.passive ? "passive" : "active")],
    actionBar(id, () => startDomainScan(r.meta.domain, o), "Scan again", watchBtn)),
    verdict,
    h("div", { class: "cards" }, SEVS.map(sevCard),
      h("div", { class: "card" }, h("div", { class: "n" }, r.summary.hosts_live, h("span", { class: "sub" }, ` / ${r.summary.hosts_total}`)), h("div", { class: "l" }, "hosts live")),
      h("div", { class: "card" }, h("div", { class: "n" }, r.summary.unique_ips), h("div", { class: "l" }, "unique IPs")),
      h("div", { class: "card" }, h("div", { class: "n" }, r.summary.networks), h("div", { class: "l" }, "networks"))),
    t.bar, t.panel,
    commandBox("Same scan in terminal", buildCommand(r.meta.domain, o))));
  t.first();
}

function findingsView(r, initial) {
  let active = initial || "all";
  let q = "";
  const chips = h("div", { class: "chips" });
  const list = h("div", { class: "findings" });
  const search = h("input", { type: "search", class: "search", placeholder: "Search findings…", "aria-label": "Search findings" });

  function draw() {
    chips.replaceChildren(...["all", ...SEVS].map((s) => {
      const n = s === "all" ? r.findings.length : r.findings.filter((f) => f.severity === s).length;
      return h("button", { type: "button", class: `chip ${active === s ? "active" : ""}`, onclick: () => { active = s; draw(); } },
        s === "all" ? "All" : cap(s), h("span", { class: "count" }, n));
    }));
    const items = r.findings.filter((f) => (active === "all" || f.severity === active)
      && (!q || `${f.title} ${f.detail} ${f.module}`.toLowerCase().includes(q)));
    list.replaceChildren(...(items.length ? items.map(findingCard)
      : [h("div", { class: "empty" }, r.findings.length ? "No findings match this filter." : "Nothing to report. Nice!")]));
  }
  search.addEventListener("input", () => { q = search.value.toLowerCase(); draw(); });
  draw();
  return h("div", {}, h("div", { class: "toolbar" }, chips, search), list, errorsNotice(r));
}

function errorsNotice(r) {
  const errs = Object.entries(r.errors || {});
  return errs.length ? h("div", { class: "notice" }, h("strong", {}, "Some sources didn't respond: "),
    errs.map(([m, e], i) => [i ? "; " : "", `${m} (${e})`]), ". Results may be incomplete; try again later.") : null;
}

function findingCard(f) {
  const why = explain(f.title);
  return h("article", { class: `finding sev-${f.severity}` },
    h("span", { class: `pill ${f.severity}` }, f.severity),
    h("div", {},
      h("div", { class: "finding-title" }, f.title),
      f.detail ? h("div", { class: "finding-detail mono" }, f.detail) : null,
      why ? h("details", {}, h("summary", {}, "What does this mean?"), h("p", {}, why)) : null),
    h("span", { class: "module" }, f.module));
}

function hostsView(r) {
  const httpBy = Object.fromEntries((r.http || []).map((p) => [p.host, p]));
  let q = "";
  let liveOnly = store.get("ds.liveOnly", false);
  const body = h("tbody", {});
  const search = h("input", { type: "search", class: "search", placeholder: "Filter hosts, IPs, networks…", "aria-label": "Filter hosts" });
  const live = h("input", { type: "checkbox", checked: liveOnly });
  const counter = h("span", { class: "muted" });

  function draw() {
    const rows = r.hosts.filter((x) => (!liveOnly || x.ips.length)
      && (!q || [x.name, ...x.ips, x.cname || "", ...(x.asn || [])].join(" ").toLowerCase().includes(q)));
    counter.textContent = `${rows.length} of ${r.hosts.length}`;
    body.replaceChildren(...rows.map((x) => {
      const p = httpBy[x.name];
      const url = safeUrl(p?.final_url);
      return h("tr", {},
        h("td", { class: "mono" }, url ? h("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, x.name) : x.name),
        h("td", { class: "mono" }, x.ips.length ? x.ips.join(", ") : h("span", { class: "muted" }, "doesn't resolve")),
        h("td", { class: "mono" }, x.cname || ""),
        h("td", {}, (x.asn || []).join(", ")),
        h("td", {}, (x.ports || []).map(portChip), x.vulns?.length ? h("span", { class: "tag warn", title: "Reported vulnerabilities" }, `${x.vulns.length} CVEs`) : null),
        h("td", {}, p ? (p.reachable ? [h("span", { class: `status-${String(p.status)[0]}` }, p.status), " ", p.title || ""] : h("span", { class: "muted" }, "no response")) : ""),
        h("td", {},
          x.dangling ? h("span", { class: "tag warn" }, "dangling CNAME") : null,
          x.wildcard ? h("span", { class: "tag" }, "wildcard") : null,
          x.interesting ? h("span", { class: "tag note" }, "interesting") : null,
          !x.ips.length && x.from_ct ? h("span", { class: "tag" }, "historical") : null));
    }));
  }
  search.addEventListener("input", () => { q = search.value.toLowerCase(); draw(); });
  live.addEventListener("change", () => { liveOnly = live.checked; store.set("ds.liveOnly", liveOnly); draw(); });
  draw();

  const src = r.subdomain_sources;
  return h("div", { class: "panel" },
    h("div", { class: "toolbar" }, search,
      h("label", { class: "toggle inline" }, live, h("span", { class: "switch" }), h("span", {}, "Live hosts only")),
      counter),
    src ? h("p", { class: "muted", style: "margin:0 0 10px" }, "Sources: ",
      Object.entries(src.counts).map(([s, n]) => h("span", { class: "tag good" }, `${s}: ${n}`)),
      Object.keys(src.errors).map((s) => h("span", { class: "tag warn", title: src.errors[s] }, `${s}: failed`))) : null,
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Host", "IP addresses", "Points to", "Network", "Open ports", "Website", "Notes"].map((x) => h("th", {}, x)))),
      body)));
}

/* ---- open ports & vulnerabilities ---- */

const RISKY_PORTS = {
  21: "FTP", 23: "Telnet", 135: "Microsoft RPC", 139: "NetBIOS", 445: "SMB", 161: "SNMP", 389: "LDAP",
  1433: "MS SQL", 1521: "Oracle DB", 2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
  5601: "Kibana", 5900: "VNC", 5985: "WinRM", 5986: "WinRM", 6379: "Redis", 9200: "Elasticsearch",
  11211: "Memcached", 27017: "MongoDB",
};
const COMMON_PORTS = { 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS",
  465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S", 8080: "HTTP-alt", 8443: "HTTPS-alt" };
const portLabel = (p) => RISKY_PORTS[p] || COMMON_PORTS[p] || "";

function portChip(p) {
  const risky = p in RISKY_PORTS;
  const label = portLabel(p);
  return h("span", { class: `tag ${risky ? "warn" : ""}`, title: risky ? `${label}: shouldn't be exposed to the internet` : label || `port ${p}` },
    label ? `${p} ${label}` : String(p));
}

function cveChip(id, meta) {
  const m = meta || {};
  const cls = m.kev ? "warn" : m.priority === "high" ? "warn" : m.priority === "medium" ? "note" : "";
  const epss = m.epss != null ? ` · ${(m.epss * 100).toFixed(m.epss < 0.1 ? 1 : 0)}%` : "";
  return h("a", { class: `tag ${cls}`, href: `https://nvd.nist.gov/vuln/detail/${id}`, target: "_blank", rel: "noopener noreferrer",
    title: m.kev ? `Known exploited: ${m.kev_name || ""}${m.ransomware ? " (used by ransomware)" : ""}` : "Open in the National Vulnerability Database" },
  m.kev ? "⚠ " : "", id, epss);
}

function exposureView(r) {
  const exp = r.exposure;
  const ipHosts = {};
  for (const x of r.hosts) for (const ip of x.ips) (ipHosts[ip] ||= []).push(x.name);
  const ips = Object.entries(exp.ips).sort((a, b) => b[1].vulns.length - a[1].vulns.length || b[1].ports.length - a[1].ports.length);
  const cves = Object.entries(exp.cves);
  const kev = cves.filter(([, m]) => m.kev);
  const risky = ips.filter(([, i]) => i.ports.some((p) => p in RISKY_PORTS));
  const rank = (m) => (m.kev ? 2 : 0) + (m.epss || 0);

  const ipRows = ips.map(([ip, info]) => {
    const sorted = [...info.vulns].sort((a, b) => rank(exp.cves[b] || {}) - rank(exp.cves[a] || {}));
    const top = sorted.slice(0, 6);
    const rest = sorted.slice(6);
    return h("tr", {},
      h("td", { class: "mono" }, ip, h("div", { class: "muted", style: "font-family:inherit;font-size:12.5px" },
        (ipHosts[ip] || info.hostnames || []).slice(0, 3).join(", "))),
      h("td", {}, (r.asn?.[ip]?.as_name) || ""),
      h("td", {}, info.ports.length ? info.ports.map(portChip) : h("span", { class: "muted" }, "none seen")),
      h("td", {}, sorted.length ? [top.map((c) => cveChip(c, exp.cves[c])),
        rest.length ? h("details", { class: "inline-more" }, h("summary", {}, `+${rest.length} more`), rest.map((c) => cveChip(c, exp.cves[c]))) : null]
        : h("span", { class: "muted" }, "none reported")),
      h("td", {}, info.tags.map((t) => h("span", { class: `tag ${t.startsWith("eol") ? "warn" : ""}` }, t))));
  });

  return h("div", {},
    h("div", { class: "tiles" },
      tile("Open ports", risky.length ? "bad" : "neutral", String(r.summary.open_ports ?? 0),
        risky.length ? `${plural(risky.length, "IP")} expose risky services (red).` : `Across ${plural(Object.keys(exp.ips).length, "IP")} Shodan has data for.`),
      tile("Known exploited", kev.length ? "bad" : "good", String(kev.length),
        kev.length ? "In CISA's Known Exploited Vulnerabilities list. Patch these first." : "No CVEs from CISA's known-exploited list."),
      tile("Reported CVEs", cves.length ? "warn" : "good", String(cves.length),
        cves.length ? "Ranked by EPSS: the chance of exploitation in the next 30 days." : "No vulnerabilities reported."),
      tile("IPs checked", exp.ok ? "neutral" : "warn", `${exp.checked}`,
        exp.failed ? `${exp.failed} lookups failed; results may be incomplete.` : "Public IPs looked up in Shodan InternetDB.")),
    h("div", { class: "notice", style: "margin:0 0 14px" },
      "Passive data from Shodan's weekly internet scans; exposeye didn't connect to these hosts. ",
      "CVEs are inferred from software versions, and vendors often patch without changing the version, so treat them as leads to verify. ",
      "Click a CVE for details. % = EPSS exploit probability, ⚠ = known exploited."),
    ips.length ? h("div", { class: "panel" }, h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["IP / hosts", "Network", "Open ports", "Vulnerabilities (most urgent first)", "Tags"].map((x) => h("th", {}, x)))),
      h("tbody", {}, ipRows))))
      : h("div", { class: "panel" }, h("div", { class: "empty" }, "Shodan has no data for these IPs. That usually means nothing notable is exposed.")),
    errorsNotice({ errors: Object.fromEntries(Object.entries(exp.errors || {}).map(([k, v]) => [`exposure:${k}`, v])) }));
}

/* ---- association map (Cytoscape.js, bundled locally) ---- */

const MEDIUM_PORTS = new Set([21, 135, 161, 389, 5601, 5985, 5986]);
const RISK_RANK = { none: 0, low: 1, medium: 2, high: 3 };
const worse = (a, b) => (RISK_RANK[b] > RISK_RANK[a] ? b : a);
const MAP_MIN_HOSTS = 1; // even a small map shows how hosts, IPs and providers connect
const MAP_MAX_HOSTS = 300;

let cytoscapeLoading = null;
function loadCytoscape() {
  if (window.cytoscape) return Promise.resolve(window.cytoscape);
  cytoscapeLoading ||= new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = "/static/vendor/cytoscape-3.34.4.min.js";
    s.onload = () => resolve(window.cytoscape);
    s.onerror = () => { cytoscapeLoading = null; reject(new Error("Couldn't load the graph library.")); };
    document.head.append(s);
  });
  return cytoscapeLoading;
}

function destroyMap() {
  if (state.cy) { state.cy.destroy(); state.cy = null; }
}

function teardownMap() {
  destroyMap();
  if (state.mapCleanup) { state.mapCleanup(); state.mapCleanup = null; }
}

const mapEligible = (r) => r.hosts.filter((x) => x.ips.length && !x.wildcard).length >= MAP_MIN_HOSTS;

function ipRisk(exp, ip) {
  const info = exp?.ips?.[ip];
  if (!info) return "none";
  let risk = "none";
  for (const p of info.ports) if (p in RISKY_PORTS) risk = worse(risk, MEDIUM_PORTS.has(p) ? "medium" : "high");
  for (const c of info.vulns) {
    const m = exp.cves?.[c] || {};
    risk = worse(risk, m.kev ? "high" : m.priority || "low");
  }
  if (info.tags.some((t) => t.startsWith("eol"))) risk = worse(risk, "medium");
  return risk;
}

function hostRisk(x, r, tlsBy) {
  let risk = x.dangling ? "high" : "none";
  for (const ip of x.ips) risk = worse(risk, ipRisk(r.exposure, ip));
  const t = tlsBy[x.name];
  if (t && !t.valid && t.error) risk = worse(risk, "high");
  return risk;
}

// Registry names like "AMAZON-02" or "MICROSOFT-CORP-MSN-AS-BLOCK" -> names people recognise.
const PROVIDERS = [
  [/^AMAZON/i, "Amazon AWS"], [/^CLOUDFLARE/i, "Cloudflare"], [/^MICROSOFT/i, "Microsoft Azure"],
  [/^GOOGLE/i, "Google Cloud"], [/LINODE/i, "Linode (Akamai)"], [/^AKAMAI/i, "Akamai"], [/^FASTLY/i, "Fastly"],
  [/^DIGITALOCEAN/i, "DigitalOcean"], [/^HETZNER/i, "Hetzner"], [/^OVH/i, "OVH"], [/^GITHUB/i, "GitHub"],
  [/^ORACLE/i, "Oracle Cloud"], [/^VERCEL/i, "Vercel"], [/^NETLIFY/i, "Netlify"], [/^SHOPIFY/i, "Shopify"],
  [/^AUTOMATTIC/i, "Automattic (WordPress)"], [/INCAPSULA|IMPERVA/i, "Imperva"], [/^TELSTRA/i, "Telstra"],
  [/^OPTUS/i, "Optus"], [/^ZEN-ECN|^ZEN/i, "Zen"], [/^SQUARESPACE/i, "Squarespace"], [/^WIX/i, "Wix"],
];
const netName = (r, ip) => {
  const a = r.asn?.[ip];
  if (!a) return "Unknown network";
  const raw = (a.as_name || `AS${a.asn}`).split(/ - |,/)[0].trim();
  const known = PROVIDERS.find(([re]) => re.test(raw));
  if (known) return known[1];
  return raw.replace(/-(AS|ASN|NET|AS-BLOCK|AP|BLOCK)(-\d+)?$/i, "").replace(/-\d+$/, "") || raw;
};

function buildGraph(r, opt) {
  const domain = r.meta.domain;
  const grouped = opt.layout !== "free";
  const tlsBy = Object.fromEntries((r.tls || []).map((t) => [t.host, t]));
  const nodes = new Map();
  const edges = [];
  const edgeIds = new Set();
  const node = (id, data) => {
    if (!nodes.has(id)) nodes.set(id, { data: { id, size: 20, risk: "none", ...data } });
    return nodes.get(id).data;
  };
  const edge = (source, target, kind) => {
    const id = `e:${source}>${target}`;
    if (!edgeIds.has(id)) { edgeIds.add(id); edges.push({ data: { id, source, target, kind } }); }
  };
  const group = (key, name, special) => {
    const gid = `g:${key}`;
    node(gid, { name, label: name, kind: "group", special: !!special });
    return gid;
  };
  const bump = (id, risk) => { const d = nodes.get(id).data; d.risk = worse(d.risk, risk); };
  const short = (name) => (name === domain ? domain : name.endsWith(`.${domain}`) ? name.slice(0, -domain.length - 1) : name);

  let hosts = r.hosts.filter((x) => !x.wildcard && (opt.historical || x.ips.length || x.cname));
  hosts = hosts.map((x) => ({ x, risk: hostRisk(x, r, tlsBy) }));
  if (opt.riskyOnly) hosts = hosts.filter((h) => RISK_RANK[h.risk] >= 2 || h.x.name === domain);
  hosts.sort((a, b) => RISK_RANK[b.risk] - RISK_RANK[a.risk] || a.x.name.localeCompare(b.x.name));
  const truncated = hosts.length > MAP_MAX_HOSTS;
  hosts = hosts.slice(0, MAP_MAX_HOSTS);

  const rootId = `h:${domain}`;
  node(rootId, { label: domain, kind: "root", name: domain, size: 34 });
  for (const { x, risk } of hosts) {
    const id = `h:${x.name}`;
    const isRoot = id === rootId;
    const d = node(id, {});
    Object.assign(d, {
      label: isRoot ? domain : short(x.name), kind: isRoot ? "root" : "host", name: x.name,
      size: isRoot ? 34 : 18 + Math.min((x.ports || []).length, 8) * 3,
      historical: !x.ips.length, interesting: !!x.interesting,
    });
    d.risk = worse(d.risk, risk);
    if (grouped && !isRoot) {
      d.parent = x.ips.length ? group(netName(r, x.ips[0]), netName(r, x.ips[0])) : group("__unresolved", "Not resolving", true);
      bump(d.parent, risk);
    }
    if (!grouped && !isRoot) edge(rootId, id, "sub");

    if (x.cname) {
      const internal = x.cname === domain || x.cname.endsWith(`.${domain}`);
      const tid = internal ? `h:${x.cname}` : `x:${x.cname}`;
      const t = internal
        ? node(tid, { label: short(x.cname), kind: "host", name: x.cname, size: 18 })
        : node(tid, { label: x.cname, kind: "external", name: x.cname, size: 22 });
      if (grouped && !t.parent && tid !== rootId) {
        t.parent = internal ? group("__unresolved", "Not resolving", true) : group("__external", "Outside services", true);
      }
      if (x.dangling) { t.risk = "high"; if (t.parent) bump(t.parent, "high"); }
      edge(id, tid, x.dangling ? "dangling" : "cname");
    }

    for (const ip of x.ips) {
      const net = netName(r, ip);
      const ir = ipRisk(r.exposure, ip);
      const ipSize = 12 + Math.min((r.exposure?.ips?.[ip]?.ports || []).length, 8) * 2;
      if (grouped) {
        const gid = group(net, net);
        bump(gid, ir);
        if (!opt.compact) {
          node(`i:${ip}`, { label: ip, kind: "ip", name: ip, network: net, risk: ir, size: ipSize, parent: gid });
          edge(id, `i:${ip}`, "ip");
        }
      } else {
        const nid = `n:${net}`;
        node(nid, { label: net, kind: "network", name: net, size: 30 });
        bump(nid, ir);
        if (opt.compact) {
          edge(id, nid, "ip");
        } else {
          node(`i:${ip}`, { label: ip, kind: "ip", name: ip, network: net, risk: ir, size: ipSize });
          edge(id, `i:${ip}`, "ip");
          edge(`i:${ip}`, nid, "net");
        }
      }
    }
  }

  if (grouped) {
    const all = [...nodes.values()].map((n) => n.data);
    for (const g of all.filter((n) => n.kind === "group")) {
      const members = all.filter((n) => n.parent === g.id);
      if (!members.length) { nodes.delete(g.id); continue; }
      const hostsN = members.filter((n) => n.kind === "host").length;
      g.label = g.id === "g:__external" ? `${g.name} · ${members.length}` : `${g.name} · ${plural(hostsN, "host")}`;
      if (g.id !== "g:__external") edge(rootId, g.id, "grp");
    }
  }
  // Parents first, so every compound node exists before its children.
  const list = [...nodes.values()];
  const ordered = [...list.filter((n) => n.data.kind === "group"), ...list.filter((n) => n.data.kind !== "group")];
  return { elements: [...ordered, ...edges], truncated, hostCount: hosts.length, grouped };
}

const REGION_PAD = 26;
const REGION_MIN_W = 160;
const REGION_MIN_H = 90;

// Lay out each provider region on its own, then pack the regions into centred rows with gaps.
function groupedLayout(cy, cytoscape) {
  const groups = cy.nodes('[kind = "group"]');
  const boxes = [];
  groups.forEach((g) => {
    const kids = g.children();
    const inner = kids.edgesWith(kids);
    const side = Math.max(130, Math.sqrt(kids.length) * 100);
    if (kids.length === 1) {
      kids.position({ x: 0, y: 0 });
    } else {
      // Run the sub-layout in a throwaway headless graph so the compound parent doesn't interfere.
      const sub = cytoscape({
        headless: true, styleEnabled: true,
        style: [{ selector: "node", style: { width: "data(size)", height: "data(size)" } }],
        elements: [
          ...kids.map((n) => ({ data: { id: n.id(), size: n.data("size") || 20 } })),
          ...inner.map((e) => ({ data: { id: e.id(), source: e.source().id(), target: e.target().id() } })),
        ],
      });
      const bb = { x1: 0, y1: 0, w: side, h: side };
      sub.layout(inner.length
        ? { name: "cose", animate: false, randomize: true, fit: false, boundingBox: bb, padding: 0,
          nodeRepulsion: () => 22000, idealEdgeLength: () => 55, gravity: 0.7, numIter: 1500, nodeOverlap: 24 }
        : { name: "grid", fit: false, boundingBox: { x1: 0, y1: 0, w: side, h: Math.max(side, kids.length * 60) }, avoidOverlap: true,
          avoidOverlapPadding: 40, cols: kids.length <= 8 ? 1 : undefined }).run();
      const pos = {};
      sub.nodes().forEach((n) => { pos[n.id()] = { x: n.position("x"), y: n.position("y") }; });
      sub.destroy();
      kids.positions((n) => pos[n.id()]);
    }
    const bb = kids.boundingBox({ includeLabels: false });
    // The region's real size: its contents plus padding, never smaller than the minimum.
    boxes.push({ g, bb, w: Math.max(bb.w + 2 * REGION_PAD, REGION_MIN_W), h: Math.max(bb.h + 2 * REGION_PAD, REGION_MIN_H) });
  });

  boxes.sort((a, b) => b.w * b.h - a.w * a.h);
  const gap = 110;
  const area = boxes.reduce((s, b) => s + (b.w + gap) * (b.h + gap), 0);
  const rowMax = Math.max(650, Math.sqrt(area) * 1.7);
  const rows = [[]];
  let rowW = 0;
  for (const b of boxes) {
    if (rows.at(-1).length && rowW + b.w > rowMax) { rows.push([]); rowW = 0; }
    rows.at(-1).push(b);
    rowW += b.w + gap;
  }
  const width = Math.max(...rows.map((row) => row.reduce((s, b) => s + b.w, 0) + gap * (row.length - 1)));
  let y = 0;
  for (const row of rows) {
    const rw = row.reduce((s, b) => s + b.w, 0) + gap * (row.length - 1);
    let x = (width - rw) / 2;
    const rowH = Math.max(...row.map((b) => b.h));
    for (const b of row) {
      // centre the contents inside the region's slot
      const dx = x + (b.w - b.bb.w) / 2 - b.bb.x1;
      const dy = y + (rowH - b.bb.h) / 2 - b.bb.y1;
      b.g.children().positions((n) => ({ x: n.position("x") + dx, y: n.position("y") + dy }));
      x += b.w + gap;
    }
    y += rowH + gap;
  }
  cy.nodes('[kind = "root"]').position({ x: width / 2, y: -150 });
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// Semantic zoom: `z` holds the current and "fit" zoom. Zooming in makes dots grow slower than the
// space between them (less clutter), keeps text a constant on-screen size, and reveals labels in tiers.
function labelTier(d) {
  if (d.kind === "root" || d.kind === "network" || d.kind === "group") return 0;
  if (d.risk === "high" || d.risk === "medium" || d.interesting || d.kind === "external") return 1;
  return d.kind === "host" ? 2 : 3;
}

function mapStyle(z) {
  const c = {
    high: cssVar("--high"), medium: cssVar("--medium"), low: cssVar("--low"), text: cssVar("--text"),
    muted: cssVar("--muted"), border: cssVar("--border"), panel: cssVar("--panel"), accent: cssVar("--accent"),
    bg: cssVar("--panel-2"),
  };
  const rel = () => Math.max(z.zoom / z.base, 0.05);
  const k = () => Math.pow(rel(), -0.55); // dots grow ~rel^0.45 on screen while spacing grows ~rel
  const ek = () => Math.pow(rel(), -0.75);
  const px = (n) => n / z.zoom; // a constant number of screen pixels
  const tier = () => (rel() < 1.5 ? 1 : rel() < 2.6 ? 2 : 3);
  const label = (ele) => (ele.hasClass("labelled") || labelTier(ele.data()) <= tier() ? ele.data("label") : "");
  const size = (fixed) => (ele) => (fixed ?? ele.data("size")) * k();
  const riskColor = (key) => `node[risk = "${key}"]`;
  return [
    { selector: "node", style: {
      label, "font-size": () => px(11), color: c.text, "text-valign": "bottom", "text-margin-y": () => px(4),
      "text-outline-color": c.panel, "text-outline-width": () => px(2.5), "background-color": c.muted,
      width: size(), height: size(), "border-width": 0 } },
    { selector: 'node[kind = "root"]', style: { "background-color": c.accent, shape: "round-diamond", width: size(34), height: size(34),
      "font-size": () => px(13), "font-weight": 700 } },
    { selector: 'node[kind = "host"]', style: { shape: "ellipse" } },
    { selector: 'node[kind = "ip"]', style: { shape: "round-rectangle", "font-size": () => px(9.5), "background-color": c.muted, color: c.muted } },
    { selector: 'node[kind = "external"]', style: { shape: "round-tag", width: size(22), height: size(22), "background-color": "#8b5cf6" } },
    { selector: 'node[kind = "network"]', style: { shape: "round-rectangle", width: size(34), height: size(34), "background-color": c.bg,
      "border-width": () => px(2), "border-color": c.muted, "border-style": "dashed", "font-size": () => px(12), "font-weight": 700, color: c.text } },
    { selector: "node[?historical]", style: { opacity: 0.45 } },
    { selector: "node[?interesting]", style: { "border-width": () => px(2), "border-color": c.medium } },
    { selector: riskColor("low"), style: { "background-color": c.low } },
    { selector: riskColor("medium"), style: { "background-color": c.medium } },
    { selector: riskColor("high"), style: { "background-color": c.high } },
    { selector: 'node[kind = "network"][risk = "high"]', style: { "background-color": c.bg, "border-color": c.high } },
    { selector: 'node[kind = "network"][risk = "medium"]', style: { "background-color": c.bg, "border-color": c.medium } },
    // Provider regions (compound nodes). Fill stays neutral; the border shows the worst risk inside.
    { selector: 'node[kind = "group"]', style: {
      shape: "round-rectangle", "background-color": c.bg, "background-opacity": 0.92, "border-width": () => px(1.5),
      "border-color": c.border, "border-style": "solid", label: "data(label)", "text-valign": "top", "text-halign": "center",
      "text-margin-y": () => px(-6), "font-size": () => px(12.5), "font-weight": 700, color: c.muted, padding: REGION_PAD,
      "compound-sizing-wrt-labels": "exclude", "min-width": REGION_MIN_W, "min-height": REGION_MIN_H,
      "text-wrap": "ellipsis", "text-max-width": (ele) => ele.width() + 80 } },
    { selector: 'node[kind = "group"][risk = "low"]', style: { "background-color": c.bg, "border-color": c.low } },
    { selector: 'node[kind = "group"][risk = "medium"]', style: { "background-color": c.bg, "border-color": c.medium, "border-width": () => px(2) } },
    { selector: 'node[kind = "group"][risk = "high"]', style: { "background-color": c.bg, "border-color": c.high, "border-width": () => px(2.5) } },
    { selector: 'node[kind = "group"][?special]', style: { "border-style": "dashed" } },
    { selector: "edge", style: { width: () => 1.2 * ek(), "line-color": c.muted, "curve-style": "haystack", opacity: 0.55 } },
    { selector: 'edge[kind = "sub"]', style: { opacity: 0.22 } },
    { selector: 'edge[kind = "grp"]', style: { "curve-style": "straight", opacity: 0.3, width: () => 1.6 * ek(), "z-compound-depth": "bottom" } },
    { selector: 'edge[kind = "net"]', style: { "line-style": "dotted", opacity: 0.5 } },
    { selector: 'edge[kind = "cname"]', style: { "line-style": "dashed", "line-color": "#8b5cf6", "curve-style": "bezier", width: () => 1.4 * ek() } },
    { selector: 'edge[kind = "dangling"]', style: { "line-style": "dashed", "line-color": c.high, "curve-style": "bezier", width: () => 2 * ek() } },
    { selector: ".faded", style: { opacity: 0.12, "text-opacity": 0 } },
    { selector: "node:selected", style: { "border-width": () => px(3), "border-color": c.accent } },
    { selector: ".match", style: { "border-width": () => px(3), "border-color": c.accent } },
  ];
}

function mapView(r) {
  const saved = store.get("ds.map", {});
  const opt = {
    layout: saved.layout === "free" ? "free" : "grouped",
    riskyOnly: !!saved.riskyOnly, historical: !!saved.historical,
    compact: saved.compact ?? r.hosts.filter((x) => x.ips.length).length > 60,
  };
  const graphBox = h("div", { class: "map-canvas", role: "img", "aria-label": "Association map of hosts, IP addresses and hosting providers" });
  const details = h("aside", { class: "map-details" });
  const note = h("div", { class: "muted map-note" });
  const search = h("input", { type: "search", class: "search", placeholder: "Find a host, IP or provider…", "aria-label": "Search the map" });
  const fullBtn = h("button", { class: "btn btn-sm", type: "button", title: "Full screen" }, icon("expand"), "Full screen");
  const layoutSel = h("select", { "aria-label": "Map layout" },
    h("option", { value: "grouped" }, "Grouped by provider"), h("option", { value: "free" }, "Free-form"));
  layoutSel.value = opt.layout;
  layoutSel.addEventListener("change", () => { opt.layout = layoutSel.value; store.set("ds.map", opt); draw(); });

  const toggle = (key, label) => {
    const box = h("input", { type: "checkbox", checked: opt[key] });
    box.addEventListener("change", () => { opt[key] = box.checked; store.set("ds.map", opt); draw(); });
    return h("label", { class: "toggle inline" }, box, h("span", { class: "switch" }), h("span", {}, label));
  };

  function showDetails(n) {
    if (!n) {
      details.replaceChildren(h("h3", {}, "Click anything on the map"),
        h("p", { class: "muted" }, "Hover to highlight connections. Drag to rearrange. Scroll to zoom: dots spread out and more names appear as you go in."),
        h("ul", { class: "legend" },
          legendItem("diamond accent", "The domain"),
          legendItem("region", opt.layout === "free" ? "Hosting network (provider)" : "Region = hosting provider (border = worst risk inside)"),
          legendItem("dot", "Subdomain / host (bigger = more open ports)"),
          legendItem("square", "IP address"),
          legendItem("tag", "Outside service (CNAME)"),
          legendItem("dot high", "Serious risk: known-exploited CVE, risky port, takeover"),
          legendItem("dot medium", "Elevated risk"),
          legendItem("dot low", "Low risk"),
          legendItem("dot ring", "Sensitive-sounding name (admin, dev, vpn…)"),
          legendItem("line dangling", "Dangling CNAME (takeover risk)")));
      return;
    }
    const d = n.data();
    const kinds = { root: "Domain", host: "Host", ip: "IP address", network: "Hosting network", external: "Outside service",
      group: d.id === "g:__external" ? "Outside services" : d.id === "g:__unresolved" ? "Not resolving" : "Hosting provider" };
    const kids = [h("div", { class: "map-kind" }, kinds[d.kind]), h("h3", { class: "mono" }, d.name)];
    if (d.risk !== "none") kids.push(h("span", { class: `pill ${d.risk}` }, `${d.risk} risk`));
    const x = r.hosts.find((hh) => hh.name === d.name);
    const exp = r.exposure || { ips: {}, cves: {} };
    const row = (k, v) => (v ? h("div", { class: "row" }, h("span", {}, k), v) : null);
    const rank = (c) => (exp.cves[c]?.kev ? 2 : 0) + (exp.cves[c]?.epss || 0);
    if ((d.kind === "host" || d.kind === "root") && x) {
      const p = (r.http || []).find((pp) => pp.host === x.name);
      const ports = [...new Set(x.ports || [])];
      const vulns = [...(x.vulns || [])].sort((a, b) => rank(b) - rank(a));
      kids.push(
        row("IPs", x.ips.length ? h("span", { class: "mono" }, x.ips.join(", ")) : h("span", { class: "muted" }, "doesn't resolve")),
        row("Points to", x.cname ? h("span", { class: "mono" }, x.cname) : null),
        row("Network", (x.asn || []).join(", ")),
        row("Ports", ports.length ? ports.map(portChip) : null),
        row("CVEs", vulns.length ? [vulns.slice(0, 6).map((c) => cveChip(c, exp.cves[c])), vulns.length > 6 ? h("span", { class: "muted" }, ` +${vulns.length - 6} more`) : null] : null),
        row("Website", p ? (p.reachable ? [h("span", { class: `status-${String(p.status)[0]}` }, p.status), " ", p.title || ""] : "no response") : null),
        x.dangling ? h("div", { class: "notice danger" }, "Dangling CNAME: the target no longer exists. Someone may be able to claim it and take over this subdomain.") : null,
        x.interesting ? h("div", { class: "notice" }, "Name suggests a sensitive system (admin, dev, vpn…). Worth reviewing.") : null);
      const url = safeUrl(p?.final_url);
      if (url) kids.push(h("a", { class: "btn btn-sm", href: url, target: "_blank", rel: "noopener noreferrer" }, icon("external"), "Open website"));
    } else if (d.kind === "ip") {
      const info = exp.ips[d.name];
      const on = n.connectedEdges().sources().filter((s) => s.id() !== n.id() && s.data("kind") !== "ip").map((s) => s.data("name"));
      kids.push(row("Network", d.network), row("Hosts here", on.length ? h("span", { class: "mono" }, on.join(", ")) : null),
        row("Ports", info?.ports.length ? info.ports.map(portChip) : h("span", { class: "muted" }, "none seen")),
        row("CVEs", info?.vulns.length ? [info.vulns.slice(0, 8).map((c) => cveChip(c, exp.cves[c])), info.vulns.length > 8 ? ` +${info.vulns.length - 8} more` : null] : null),
        row("Tags", info?.tags.length ? info.tags.map((t) => h("span", { class: "tag" }, t)) : null));
    } else if (d.kind === "group") {
      const members = n.children();
      const names = members.filter('[kind = "host"], [kind = "external"]').map((m) => m.data("name"));
      const ips = members.filter('[kind = "ip"]');
      const risky = members.filter('[risk = "high"], [risk = "medium"]').filter('[kind != "ip"]').map((m) => m.data("name"));
      const why = d.id === "g:__external"
        ? "Services outside the domain that subdomains point to (CNAME). You depend on them, and a deleted account can lead to a subdomain takeover."
        : d.id === "g:__unresolved"
          ? "Names seen in certificate logs that don't resolve now. Mostly harmless leftovers, but dangling ones can be taken over."
          : "Everything in this region runs on the same provider. An outage, misconfiguration or compromised server here can affect all of it.";
      kids.push(row("Hosts", String(members.filter('[kind = "host"]').length)), row("IP addresses", ips.length ? String(ips.length) : null),
        row("Needs attention", risky.length ? h("span", { class: "mono" }, risky.join(", ")) : null),
        h("p", { class: "muted" }, why), h("div", { class: "mono map-list" }, names.slice(0, 40).join("\n")));
    } else if (d.kind === "network") {
      const ipNodes = opt.compact ? state.cy.collection() : n.connectedEdges().sources();
      const hostNames = new Set((opt.compact ? n.connectedEdges().sources()
        : ipNodes.connectedEdges().sources().filter((s) => s.data("kind") !== "ip")).map((s) => s.data("name")));
      kids.push(row("IP addresses", ipNodes.length ? String(ipNodes.length) : null), row("Hosts", String(hostNames.size)),
        h("p", { class: "muted" }, "Everything hosted here shares infrastructure: a problem with this provider or server can affect all of them."),
        h("div", { class: "mono map-list" }, [...hostNames].slice(0, 30).join("\n")));
    } else if (d.kind === "external") {
      const from = n.connectedEdges().sources().map((s) => s.data("name"));
      kids.push(row("Used by", h("span", { class: "mono" }, from.join(", "))),
        h("p", { class: "muted" }, "A service outside the domain that subdomains point to (via CNAME). You depend on it, and if the account is deleted the subdomain can be taken over."),
        d.risk === "high" ? h("div", { class: "notice danger" }, "This target no longer exists (dangling). High takeover risk.") : null);
    }
    details.replaceChildren(...kids.filter(Boolean));
  }

  const z = { zoom: 1, base: 1 };
  // Labels and sizes are relative to the "fit" zoom of the current container.
  function calibrate() {
    const cy = state.cy;
    if (!cy) return;
    z.base = cy.zoom();
    z.zoom = cy.zoom();
    cy.style().update();
  }
  function refit() {
    setTimeout(() => {
      const cy = state.cy;
      if (!cy) return;
      cy.resize();
      cy.fit(undefined, 30);
      calibrate();
    }, 120);
  }

  function draw() {
    destroyMap();
    const g = buildGraph(r, opt);
    note.textContent = `${plural(g.hostCount, "host")} shown${g.truncated ? ` (top ${MAP_MAX_HOSTS} by risk)` : ""}` +
      (g.grouped ? " · grouped by provider" : "") + (opt.compact ? " · IPs hidden" : "") + (opt.riskyOnly ? " · risky only" : "") +
      " · scroll to zoom: more names appear as you zoom in";
    showDetails(null);
    loadCytoscape().then((cytoscape) => {
      if (!graphBox.isConnected) return;
      z.zoom = 1; z.base = 1;
      const cy = cytoscape({
        container: graphBox, elements: g.elements, style: mapStyle(z), wheelSensitivity: 0.25, minZoom: 0.05, maxZoom: 8,
        layout: g.grouped ? { name: "preset" } : { name: "cose", animate: false, randomize: true, padding: 24, nodeRepulsion: () => 26000,
          idealEdgeLength: (e) => ({ sub: 95, ip: 45, net: 55, cname: 60, dangling: 60 }[e.data("kind")] || 60),
          edgeElasticity: (e) => (e.data("kind") === "sub" ? 40 : 120), nodeOverlap: 20, gravity: 0.2,
          numIter: 2500, componentSpacing: 80 },
      });
      state.cy = cy;
      if (g.grouped) groupedLayout(cy, cytoscape);
      cy.fit(undefined, 30);
      calibrate();

      let queued = false;
      cy.on("zoom", () => {
        if (queued) return;
        queued = true;
        setTimeout(() => { queued = false; if (state.cy === cy) { z.zoom = cy.zoom(); cy.style().update(); } }, 16);
      });
      const clear = () => cy.elements().removeClass("faded labelled");
      const focus = (ele) => {
        cy.elements().removeClass("labelled").addClass("faded");
        let hood;
        if (ele.data("kind") === "group") {
          const inside = ele.descendants();
          hood = ele.union(inside).union(inside.connectedEdges()).union(ele.connectedEdges());
          hood = hood.union(hood.connectedNodes());
        } else {
          hood = ele.closedNeighborhood();
          // Follow host -> IP -> hosting network so the whole chain stays visible.
          const ipEdges = hood.nodes('[kind = "ip"]').connectedEdges('[kind = "net"]');
          hood = hood.union(ipEdges).union(ipEdges.targets());
        }
        hood = hood.union(hood.nodes().ancestors()); // keep the regions around them visible
        hood.removeClass("faded");
        hood.nodes().addClass("labelled"); // always label what you're looking at
      };
      cy.on("mouseover", "node", (e) => focus(e.target));
      cy.on("mouseout", "node", () => { const sel = cy.$("node:selected"); if (sel.length) focus(sel); else clear(); });
      cy.on("tap", "node", (e) => { showDetails(e.target); focus(e.target); });
      cy.on("tap", (e) => { if (e.target === cy) { clear(); showDetails(null); } });
      if (search.value) runSearch();
    }).catch((ex) => graphBox.replaceChildren(h("div", { class: "empty" }, ex.message)));
  }

  function runSearch() {
    const cy = state.cy;
    if (!cy) return;
    const q = search.value.trim().toLowerCase();
    cy.elements().removeClass("match faded labelled");
    if (!q) return;
    const hits = cy.nodes().filter((n) => String(n.data("name")).toLowerCase().includes(q));
    cy.elements().addClass("faded");
    hits.addClass("match labelled").removeClass("faded");
    hits.ancestors().removeClass("faded");
    if (hits.length === 1) { cy.animate({ center: { eles: hits }, zoom: z.base * 2.2 }, { duration: 300 }); showDetails(hits[0]); }
    else if (hits.length) cy.fit(hits, 60);
  }
  search.addEventListener("input", runSearch);

  const savePng = () => {
    if (!state.cy) return;
    const blob = state.cy.png({ full: true, scale: 2, bg: cssVar("--panel"), output: "blob" });
    const a = h("a", { href: URL.createObjectURL(blob), download: `${r.meta.domain}-map.png` });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  };

  const view = h("div", { class: "map-wrap" },
    h("div", { class: "toolbar" }, search, layoutSel,
      toggle("riskyOnly", "Risky only"), toggle("compact", "Hide IPs"), toggle("historical", "Include historical"),
      h("button", { class: "btn btn-sm", type: "button", title: "Fit to screen", onclick: () => state.cy?.fit(undefined, 30) }, "Fit"),
      h("button", { class: "btn btn-sm", type: "button", onclick: savePng }, icon("download"), "Save PNG"),
      fullBtn),
    note,
    h("div", { class: "map-layout" }, h("div", { class: "panel map-panel" }, graphBox), details));

  // Full screen: real browser full screen when available, otherwise a full-window overlay.
  async function setFull(on) {
    view.classList.toggle("is-full", on);
    fullBtn.replaceChildren(icon(on ? "shrink" : "expand"), on ? "Exit full screen" : "Full screen");
    fullBtn.title = on ? "Exit full screen (Esc)" : "Full screen";
    if (on && view.requestFullscreen && !document.fullscreenElement) {
      try { await view.requestFullscreen(); } catch { /* the overlay fallback stays */ }
    } else if (!on && document.fullscreenElement) {
      try { await document.exitFullscreen(); } catch { /* ignore */ }
    }
    refit();
  }
  fullBtn.addEventListener("click", () => setFull(!view.classList.contains("is-full")));
  const onFsChange = () => { if (!document.fullscreenElement && view.classList.contains("is-full")) setFull(false); };
  const onKey = (e) => { if (e.key === "Escape" && view.classList.contains("is-full") && !document.fullscreenElement) setFull(false); };
  document.addEventListener("fullscreenchange", onFsChange);
  document.addEventListener("keydown", onKey);
  state.mapCleanup = () => {
    document.removeEventListener("fullscreenchange", onFsChange);
    document.removeEventListener("keydown", onKey);
    if (document.fullscreenElement === view) document.exitFullscreen().catch(() => {});
  };

  setTimeout(draw, 0); // runs after the view is in the page (and, unlike rAF, also in background tabs)
  return view;
}

function legendItem(shape, text) {
  return h("li", {}, h("span", { class: `lg ${shape}` }), text);
}

function tile(title, cls, status, text) {
  const tagCls = { good: "good", warn: "note", bad: "warn", neutral: "" }[cls];
  return h("div", { class: `tile ${cls}` },
    h("div", { class: "tile-head" }, title, h("span", { class: `tag ${tagCls}` }, status)),
    h("p", {}, text));
}

function dnsView(r) {
  const recs = Object.entries(r.dns.records).filter(([, v]) => v.length);
  return h("div", {},
    h("div", { class: "tiles" },
      tile("DNSSEC", r.dns.dnssec ? "good" : "warn", r.dns.dnssec ? "Enabled" : "Off",
        r.dns.dnssec ? "DNS answers are cryptographically signed." : "DNS answers are not signed."),
      tile("CAA", r.dns.records.CAA?.length ? "good" : "warn", r.dns.records.CAA?.length ? "Set" : "Missing",
        r.dns.records.CAA?.length ? "Certificate issuance is restricted." : "Any CA may issue certificates."),
      tile("Wildcard DNS", r.dns.wildcard_ips.length ? "warn" : "good", r.dns.wildcard_ips.length ? "Yes" : "No",
        r.dns.wildcard_ips.length ? `Made-up names resolve to ${r.dns.wildcard_ips.join(", ")}` : "Only real names resolve.")),
    h("div", { class: "panel" }, h("h3", {}, "Records"),
      recs.length ? h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", { style: "width:90px" }, "Type"), h("th", {}, "Value"))),
        h("tbody", {}, recs.map(([rt, vals]) => h("tr", {}, h("td", {}, h("strong", {}, rt)),
          h("td", {}, vals.map((v) => h("div", {}, h("code", {}, v))))))))) : h("p", { class: "muted" }, "No records found.")));
}

function spfTile(spf) {
  return !spf ? tile("SPF", "bad", "Missing", "No list of allowed mail senders.")
    : spf.all === "-" ? tile("SPF", "good", "Strict (-all)", "Unlisted senders are rejected.")
    : spf.all === "~" ? tile("SPF", "warn", "Soft (~all)", "Unlisted senders are flagged, not rejected.")
    : spf.all === "+" ? tile("SPF", "bad", "Open (+all)", "Anyone may send as this domain!")
    : tile("SPF", "warn", spf.all ? `${spf.all}all` : "No 'all'", "Unlisted senders are not rejected.");
}

function dmarcTile(dmarc) {
  return !dmarc ? tile("DMARC", "bad", "Missing", "Spoofed mail isn't blocked or reported.")
    : dmarc.policy === "reject" ? tile("DMARC", "good", "Reject", "Spoofed mail is rejected.")
    : dmarc.policy === "quarantine" ? tile("DMARC", "good", "Quarantine", "Spoofed mail goes to spam.")
    : tile("DMARC", "warn", `p=${dmarc.policy || "?"}`, "Monitoring only: spoofed mail is still delivered.");
}

function domainEmailView(e) {
  return h("div", {},
    h("div", { class: "tiles" }, spfTile(e.spf), dmarcTile(e.dmarc),
      tile("MTA-STS", e.mta_sts ? "good" : "warn", e.mta_sts ? "Enabled" : "Off", "Forces encrypted mail delivery."),
      tile("TLS-RPT", e.tls_rpt ? "good" : "warn", e.tls_rpt ? "Enabled" : "Off", "Reports mail-delivery TLS failures.")),
    h("div", { class: "panel" }, h("h3", {}, "Raw records"),
      h("dl", { class: "kv" },
        h("dt", {}, "Receives mail (MX)"), h("dd", {}, e.has_mx ? "Yes" : "No"),
        h("dt", {}, "SPF"), h("dd", {}, e.spf ? h("code", {}, e.spf.record) : "—"),
        e.spf ? [h("dt", {}, "SPF lookups"), h("dd", {}, `${e.spf.lookup_count} of 10 allowed (top level)`)] : null,
        h("dt", {}, "DMARC"), h("dd", {}, e.dmarc ? h("code", {}, e.dmarc.record) : "—"))));
}

function webView(r) {
  const tlsBy = Object.fromEntries((r.tls || []).map((x) => [x.host, x]));
  return h("div", { class: "web-grid" }, (r.http || []).map((p) => {
    const t = tlsBy[p.host];
    if (!p.reachable) {
      return h("div", { class: "web-card" }, h("h4", {}, p.host, h("span", { class: "tag" }, "no response")),
        h("div", { class: "row muted" }, (p.errors || []).join("; ")));
    }
    const url = safeUrl(p.final_url);
    return h("div", { class: "web-card" },
      h("h4", {}, url ? h("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, p.host) : p.host,
        h("span", { class: `status-${String(p.status)[0]}` }, p.status)),
      p.title ? h("div", { class: "row" }, h("span", {}, "Title"), p.title) : null,
      p.server ? h("div", { class: "row" }, h("span", {}, "Server"), h("code", {}, p.server)) : null,
      p.tech.length ? h("div", { class: "row" }, h("span", {}, "Built with"), p.tech.map((x) => h("span", { class: "tag" }, x))) : null,
      h("div", { class: "row" }, h("span", {}, "Headers"),
        p.headers.missing.length
          ? p.headers.missing.map((m) => h("span", { class: `tag ${m.severity === "low" ? "note" : ""}`, title: m.label }, `no ${m.header}`))
          : h("span", { class: "tag good" }, "all security headers set")),
      p.headers.leaks.length ? h("div", { class: "row" }, h("span", {}, "Leaks"), p.headers.leaks.map((x) => h("span", { class: "tag warn" }, x))) : null,
      t ? h("div", { class: "row" }, h("span", {}, "TLS"),
        t.valid
          ? [h("span", { class: `tag ${t.days_left < 14 ? "warn" : "good"}` }, `valid · ${t.days_left} days left`), " ", h("span", { class: "muted" }, `${t.issuer || ""} · ${t.protocol || ""}`)]
          : h("span", { class: "tag warn" }, t.error || "invalid")) : null,
      p.http_redirects_to_https === false ? h("div", { class: "row" }, h("span", {}, "HTTP"), h("span", { class: "tag note" }, "doesn't redirect to HTTPS")) : null);
  }));
}

function whoisView(r) {
  const d = r.rdap;
  if (!d) return h("div", { class: "panel" }, h("p", { class: "muted" }, `Registration data unavailable: ${r.errors?.whois || "not found"}`));
  const row = (k, v) => [h("dt", {}, k), h("dd", {}, v == null || v === "" ? "—" : v)];
  const date = (iso) => (iso ? new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : null);
  return h("div", { class: "panel" }, h("dl", { class: "kv" },
    row("Registrar", d.registrar),
    row("Registrant", d.registrant || h("span", { class: "muted" }, "hidden / redacted")),
    row("Created", d.created ? date(d.created) + (d.age_days != null ? ` (${(d.age_days / 365).toFixed(1)} years ago)` : "") : null),
    row("Last updated", date(d.updated)),
    row("Expires", d.expires ? `${date(d.expires)} (in ${d.days_to_expiry} days)` : null),
    row("Status", d.status.length ? d.status.map((s) => h("span", { class: "tag" }, s)) : null),
    row("Name servers", d.nameservers.length ? h("span", { class: "mono" }, d.nameservers.join(", ")) : null),
    row("DNSSEC at registry", d.dnssec_signed == null ? null : d.dnssec_signed ? "signed" : "unsigned"),
    row("Abuse contact", d.abuse_email)));
}

/* ================================================================== email result */

function showEmailResult(r, id, watchBtn) {
  const s = r.summary;
  const items = r.breaches.items;
  const tabs = [
    ["breaches", "Breaches", items.length],
    ["advice", "What to do", r.advice.length],
    ["findings", "Findings", r.findings.length],
    ["domain", "Email domain", null],
    ["profile", "Public profile", null],
  ];
  const t = tabbed("email", tabs, {
    breaches: (pwOnly) => breachesView(r, pwOnly), advice: () => adviceView(r), findings: () => findingsView(r),
    domain: () => emailDomainView(r), profile: () => profileView(r),
  });

  let verdict;
  if (!r.breaches.checked) {
    verdict = h("div", { class: "verdict warn" }, `Breach lookup failed: ${r.errors.breaches || "unknown error"}`);
  } else if (s.password_breaches) {
    verdict = h("div", { class: "verdict bad" }, `Passwords linked to this email were exposed in ${plural(s.password_breaches, "breach")}. Change those passwords now. See "What to do".`);
  } else if (s.breaches) {
    verdict = h("div", { class: "verdict warn" }, `Found in ${plural(s.breaches, "breach")}, but no passwords were exposed. Expect more targeted spam and phishing.`);
  } else {
    verdict = h("div", { class: "verdict good" }, "Good news: this email isn't in any known data breach.");
  }

  render(h("section", {},
    resultHeader(r.meta.email, [
      h("span", {}, new Date(r.meta.started).toLocaleString()), "·", h("span", {}, `${r.meta.duration_s}s`),
      h("span", { class: "badge accent" }, `via ${r.breaches.provider}`)],
    actionBar(id, () => startEmailCheck(r.meta.email), "Check again", watchBtn)),
    verdict,
    h("div", { class: "cards" },
      h("button", { class: "card high", type: "button", onclick: () => t.open("breaches") }, h("div", { class: "n" }, s.breaches), h("div", { class: "l" }, "breaches")),
      h("button", { class: "card medium", type: "button", onclick: () => t.open("breaches", true) }, h("div", { class: "n" }, s.password_breaches), h("div", { class: "l" }, "passwords exposed")),
      h("div", { class: "card high" }, h("div", { class: "n" }, s.plaintext_breaches), h("div", { class: "l" }, "readable / weak")),
      h("div", { class: "card" }, h("div", { class: "n" }, s.first_year || "—",
        s.latest_year && s.latest_year !== s.first_year ? h("span", { class: "sub" }, ` → ${s.latest_year}`) : null), h("div", { class: "l" }, "years"))),
    t.bar, t.panel,
    commandBox("Same check in terminal", `exposeye-email ${r.meta.email}`)));
  t.first();
}

function breachesView(r, passwordsFirst) {
  const items = r.breaches.items;
  if (!items.length) {
    return h("div", { class: "panel" }, h("div", { class: "empty" },
      r.breaches.checked ? "Not found in any known breach." : `Lookup failed: ${r.errors.breaches || ""}`));
  }
  let q = "";
  let pwOnly = !!passwordsFirst;
  const list = h("div", { class: "breach-list" });
  const search = h("input", { type: "search", class: "search", placeholder: "Search breaches or data types…", "aria-label": "Search breaches" });
  const pwBox = h("input", { type: "checkbox", checked: pwOnly });
  const counter = h("span", { class: "muted" });

  function draw() {
    const rows = items.filter((b) => (!pwOnly || b.password_exposed)
      && (!q || `${b.title} ${b.domain} ${b.data.join(" ")} ${b.industry}`.toLowerCase().includes(q)));
    counter.textContent = `${rows.length} of ${items.length}`;
    list.replaceChildren(...(rows.length ? rows.map(breachCard) : [h("div", { class: "empty" }, "No breaches match.")]));
  }
  search.addEventListener("input", () => { q = search.value.toLowerCase(); draw(); });
  pwBox.addEventListener("change", () => { pwOnly = pwBox.checked; draw(); });
  draw();
  return h("div", {},
    h("div", { class: "toolbar" }, search,
      h("label", { class: "toggle inline" }, pwBox, h("span", { class: "switch" }), h("span", {}, "Exposed passwords only")),
      counter),
    list);
}

function breachCard(b) {
  const risk = b.password_exposed ? RISK[b.password_risk] || RISK.unknown : null;
  return h("article", { class: `breach-card ${b.password_exposed ? "pw" : ""}` },
    h("div", { class: "breach-head" },
      h("div", {},
        h("div", { class: "breach-title" }, b.title),
        h("div", { class: "breach-sub" },
          b.domain ? h("span", { class: "mono" }, b.domain) : null,
          b.industry ? h("span", {}, b.industry) : null,
          b.records ? h("span", {}, `${fmtNum(b.records)} accounts`) : null)),
      h("div", { class: "breach-date" }, b.date || "date unknown")),
    risk ? h("div", {}, h("span", { class: `tag ${risk[0]}` }, risk[1]), h("span", { class: "muted", style: "font-size:13px;margin-left:6px" }, "Change this password, and anywhere you reused it.")) : null,
    h("div", { class: "breach-data" }, b.data.map((d) => h("span", { class: `tag ${/password/i.test(d) ? "warn" : ""}` }, d))),
    b.description ? h("details", {}, h("summary", {}, "About this breach"), h("p", {}, b.description)) : null);
}

function adviceView(r) {
  return h("div", { class: "advice" }, r.advice.map((tip, i) => h("article", { class: `advice-item p-${tip.priority}` },
    h("div", { class: "advice-num" }, i + 1),
    h("div", {}, h("div", { class: "finding-title" }, tip.title), h("p", {}, tip.detail)),
    h("span", { class: `pill ${tip.priority === "high" ? "high" : tip.priority === "medium" ? "medium" : "low"}` }, tip.priority))));
}

function emailDomainView(r) {
  const d = r.domain_info;
  const p = d.provider_type;
  return h("div", {},
    h("div", { class: "tiles" },
      tile("Provider", p === "disposable" ? "warn" : "neutral", { disposable: "Disposable", free: "Free webmail", custom: "Own domain" }[p],
        p === "disposable" ? "A throwaway inbox service." : p === "free" ? "A large public email provider." : "A company or personal domain."),
      tile("Receives mail", d.mx.length ? "good" : "bad", d.mx.length ? "Yes" : "No", d.mx.length ? `${plural(d.mx.length, "mail server")} (MX)` : "No MX records."),
      spfTile(d.email_security.spf), dmarcTile(d.email_security.dmarc)),
    h("div", { class: "panel" },
      h("dl", { class: "kv" },
        h("dt", {}, "Domain"), h("dd", { class: "mono" }, r.meta.domain),
        h("dt", {}, "Mail servers"), h("dd", { class: "mono" }, d.mx.join(", ") || "—"),
        h("dt", {}, "SPF"), h("dd", {}, d.email_security.spf ? h("code", {}, d.email_security.spf.record) : "—"),
        h("dt", {}, "DMARC"), h("dd", {}, d.email_security.dmarc ? h("code", {}, d.email_security.dmarc.record) : "—")),
      p === "custom" ? h("div", { class: "notice" }, "Want the full picture? ",
        h("a", { href: "#/", onclick: () => { store.set("ds.lastDomain", r.meta.domain); store.set("ds.task", "full"); store.set("ds.opts", DEFAULT_OPTS); } },
          `Run a full domain scan on ${r.meta.domain}`), ".") : null));
}

function profileView(r) {
  const g = r.gravatar;
  if (!g) return h("div", { class: "panel" }, h("p", { class: "muted" }, `Gravatar lookup failed: ${r.errors?.gravatar || "unknown"}`));
  if (!g.profile && !g.has_avatar) {
    return h("div", { class: "panel" }, h("div", { class: "empty" }, "Nothing public on Gravatar for this email."));
  }
  const p = g.profile || {};
  const avatar = safeUrl(g.avatar_url);
  const row = (k, v) => (v ? [h("dt", {}, k), h("dd", {}, v)] : null);
  const profileUrl = safeUrl(p.profile_url);
  return h("div", { class: "panel profile" },
    avatar ? h("img", { src: avatar, alt: "Gravatar avatar", class: "avatar", referrerpolicy: "no-referrer" }) : null,
    h("div", {},
      h("h3", {}, p.display_name || "Avatar only"),
      h("dl", { class: "kv" },
        row("Location", p.location), row("Job", [p.job_title, p.company].filter(Boolean).join(" at ")),
        row("Pronouns", p.pronouns), row("About", p.description),
        row("Profile", profileUrl ? h("a", { href: profileUrl, target: "_blank", rel: "noopener noreferrer" }, profileUrl) : null),
        p.verified_accounts?.length ? [h("dt", {}, "Linked accounts"), h("dd", {}, p.verified_accounts.map((a) => {
          const u = safeUrl(a.url);
          return u ? h("a", { class: "tag", href: u, target: "_blank", rel: "noopener noreferrer" }, a.service || "account") : h("span", { class: "tag" }, a.service || "account");
        }))] : null),
      h("p", { class: "muted", style: "font-size:13px" }, "Anyone who knows this email can see this profile.")));
}

/* ================================================================== monitoring */

function whenTime(iso) {
  if (!iso) return "";
  const s = (new Date(iso).getTime() - Date.now()) / 1000;
  if (s <= 60) return "any minute";
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (s < 3600) return rtf.format(Math.round(s / 60), "minute");
  if (s < 86400) return rtf.format(Math.round(s / 3600), "hour");
  return rtf.format(Math.round(s / 86400), "day");
}

function changeRow(c) {
  const label = c.improvement ? "improved" : c.severity;
  return h("div", { class: `change ${c.improvement ? "good" : `sev-${c.severity}`}` },
    h("span", { class: `pill ${c.improvement ? "good" : c.severity}` }, label),
    h("div", {},
      h("div", { class: "finding-title" }, c.title),
      c.detail ? h("div", { class: "finding-detail mono" }, c.detail) : null),
    h("span", { class: "module" }, c.category));
}

function changeList(changes, limit) {
  const box = h("div", { class: "changes" });
  const draw = (n) => {
    const rows = changes.slice(0, n).map(changeRow);
    if (changes.length > n) {
      rows.push(h("button", { type: "button", class: "btn btn-ghost more", onclick: () => draw(changes.length) },
        `Show all ${changes.length} changes`));
    }
    box.replaceChildren(...rows);
  };
  draw(limit || changes.length);
  return box;
}

async function showMonitor() {
  render(h("div", { class: "empty" }, h("span", { class: "spinner", style: "display:inline-block" })));
  let wl, ch, bg, st;
  try {
    [wl, ch, bg, st] = await Promise.all([api.get("/api/watchlist"), api.get("/api/changes?limit=100"),
      api.get("/api/monitor/background"), api.get("/api/settings")]);
  } catch (ex) { render(h("div", { class: "empty" }, ex.message)); return; }
  const unreadIds = new Set(ch.events.filter((e) => !e.read).map((e) => e.id));
  if (unreadIds.size) api.post("/api/changes/read").then(refreshBadge).catch(() => {});

  /* --- add form --- */
  const target = h("input", { type: "text", class: "domain-input", placeholder: "example.com or you@example.com", spellcheck: "false", autocomplete: "off", "aria-label": "Domain or email to watch" });
  const interval = h("select", { "aria-label": "How often" }, h("option", { value: "daily" }, "Every day"), h("option", { value: "weekly" }, "Every week"));
  const mode = h("select", { "aria-label": "Scan type" }, h("option", { value: "passive" }, "Passive (public data only)"), h("option", { value: "full" }, "Full (also visits websites)"));
  const err = h("div", { class: "form-error", role: "alert" });
  target.addEventListener("input", () => { mode.hidden = target.value.includes("@"); err.textContent = ""; });
  const addForm = h("form", { class: "watch-add", onsubmit: async (e) => {
    e.preventDefault();
    if (!target.value.trim()) { err.textContent = "Type a domain or email first."; return; }
    try {
      const item = await api.post("/api/watchlist", { target: target.value.trim(), interval: interval.value, mode: mode.value });
      toast(`Watching ${item.target}. Taking the first snapshot now…`);
      try { await api.post(`/api/watchlist/${item.id}/run`); } catch (ex) { toast(ex.message); }
      loadHistory();
      showMonitor();
    } catch (ex) { err.textContent = ex.message; }
  } }, target, interval, mode, h("button", { class: "btn btn-primary", type: "submit" }, icon("plus"), "Watch"));

  /* --- watchlist --- */
  const anyRunning = wl.items.some((i) => i.running);
  const watchRows = wl.items.map((i) => {
    const status = !i.enabled ? h("span", { class: "tag" }, "paused")
      : i.running ? h("span", { class: "tag note" }, "checking…")
      : i.last_error ? h("span", { class: "tag warn", title: i.last_error }, "last check failed")
      : !i.last_run ? h("span", { class: "tag" }, "waiting for first check")
      : i.last_change_count ? h("span", { class: "tag note" }, `${i.last_change_count} change(s)`)
      : h("span", { class: "tag good" }, "no changes");
    const del = h("button", { class: "btn btn-ghost btn-sm btn-danger", type: "button", title: "Stop watching" }, icon("trash"));
    let armed = false;
    del.addEventListener("click", async () => {
      if (!armed) { armed = true; del.classList.add("confirm"); del.title = "Click again to stop watching"; toast("Click again to stop watching"); setTimeout(() => { armed = false; del.classList.remove("confirm"); }, 3000); return; }
      await api.del(`/api/watchlist/${i.id}`); toast(`Stopped watching ${i.target}`); refreshBadge(); showMonitor();
    });
    return h("tr", {},
      h("td", {}, h("div", { class: "watch-target" }, icon(i.kind === "email" ? "mail" : "globe"),
        i.last_scan_id ? h("a", { href: `#/scan/${i.last_scan_id}`, class: "mono" }, i.target) : h("span", { class: "mono" }, i.target))),
      h("td", {}, i.interval === "daily" ? "Daily" : "Weekly", i.kind === "domain" ? h("span", { class: "muted" }, ` · ${i.mode}`) : null),
      h("td", {}, i.last_run_iso ? relTime(i.last_run_iso) : "—"),
      h("td", {}, i.enabled ? (i.running ? "now" : whenTime(i.next_due)) : "—"),
      h("td", {}, status),
      h("td", { class: "row-actions" },
        h("button", { class: "btn btn-ghost btn-sm", type: "button", title: "Check now", disabled: i.running || !i.enabled,
          onclick: async () => { try { await api.post(`/api/watchlist/${i.id}/run`); toast(`Checking ${i.target}…`); loadHistory(); showMonitor(); } catch (ex) { toast(ex.message); } } }, icon("refresh")),
        h("button", { class: "btn btn-ghost btn-sm", type: "button", title: i.enabled ? "Pause" : "Resume",
          onclick: async () => { await api.req("PATCH", `/api/watchlist/${i.id}`, { enabled: !i.enabled }); showMonitor(); } }, icon(i.enabled ? "pause" : "play")),
        del));
  });

  /* --- background task --- */
  const bgBtn = h("button", { class: `btn ${bg.installed ? "btn-danger" : "btn-primary"}`, type: "button" }, bg.installed ? "Turn off" : "Turn on background checks");
  bgBtn.addEventListener("click", async () => {
    bgBtn.disabled = true;
    try { await api.post("/api/monitor/background", { enabled: !bg.installed }); toast(bg.installed ? "Background checks turned off" : "Background checks turned on"); showMonitor(); }
    catch (ex) { toast(ex.message); bgBtn.disabled = false; }
  });
  const bgPanel = h("div", { class: "panel" }, h("h3", {}, "Background checks"),
    !bg.supported
      ? [h("p", { class: "muted" }, "Automatic background checks use Windows Task Scheduler. On macOS/Linux, add this to cron (hourly):"), h("code", {}, bg.command)]
      : bg.installed
        ? [h("div", { class: "verdict good" }, "On. Windows checks every hour for anything that's due, even when this app is closed (while you're signed in)."),
          h("p", { class: "muted" }, `Next run: ${bg.next_run || "?"} · Last run: ${bg.last_run || "never"}`), bgBtn]
        : [h("div", { class: "verdict warn" }, "Off. Checks only run while this app is open."),
          h("p", { class: "muted" }, "Turn this on to let Windows Task Scheduler run due checks every hour in the background. No window pops up; you get a notification only when something changes."), bgBtn]);

  /* --- alerts --- */
  const desk = h("input", { type: "checkbox", checked: st.desktop_notify });
  desk.addEventListener("change", async () => { await api.put("/api/settings", { desktop_notify: desk.checked }); toast(desk.checked ? "Desktop notifications on" : "Desktop notifications off"); });
  const hook = h("input", { type: "password", placeholder: st.discord_webhook_set ? `Saved (…${st.discord_webhook_masked})` : "https://discord.com/api/webhooks/…", autocomplete: "off", spellcheck: "false", "aria-label": "Discord webhook URL" });
  const hookErr = h("div", { class: "form-error", role: "alert" });
  const alertsPanel = h("div", { class: "panel" }, h("h3", {}, "Alerts"),
    h("p", { class: "muted" }, "You're alerted only when something changes for the worse (new hosts, weaker email security, expiring certificates, new breaches…). Improvements show in the timeline quietly."),
    h("label", { class: "toggle inline", style: "margin:6px 0 14px" }, desk, h("span", { class: "switch" }), h("span", {}, "Windows desktop notifications")),
    h("div", { class: "toggle-text" }, h("strong", {}, "Discord alerts (optional)"),
      h("span", {}, "In Discord: Server settings → Integrations → Webhooks → New webhook → Copy URL. Alerts then reach your phone too.")),
    h("form", { class: "domain-row", style: "margin-top:8px", onsubmit: async (e) => {
      e.preventDefault(); hookErr.textContent = "";
      try { await api.put("/api/settings", { discord_webhook: hook.value.trim() }); toast("Discord webhook saved"); showMonitor(); }
      catch (ex) { hookErr.textContent = ex.message; }
    } }, hook, h("button", { class: "btn btn-primary", type: "submit" }, "Save"),
      st.discord_webhook_set ? h("button", { class: "btn btn-danger", type: "button", onclick: async () => { await api.put("/api/settings", { discord_webhook: null }); toast("Discord webhook removed"); showMonitor(); } }, "Remove") : null),
    hookErr,
    h("button", { class: "btn", type: "button", style: "margin-top:10px", onclick: async (e) => {
      const b = e.currentTarget; b.disabled = true;
      try {
        const res = await api.post("/api/notify/test");
        toast(Object.entries(res).map(([k, v]) => `${k}: ${v.ok ? "sent" : v.message}`).join(" · "));
      } catch (ex) { toast(ex.message); }
      b.disabled = false;
    } }, icon("send"), "Send a test alert"));

  /* --- timeline --- */
  const timeline = ch.events.length ? ch.events.map((ev) => h("article", { class: `event ${unreadIds.has(ev.id) ? "unread" : ""}` },
    h("div", { class: "event-head" },
      h("div", { class: "watch-target" }, icon(ev.kind === "email" ? "mail" : "globe"), h("strong", { class: "mono" }, ev.target)),
      h("span", { class: "muted" }, relTime(ev.at)),
      ev.baseline ? h("span", { class: "tag" }, "first snapshot")
        : h("span", { class: `tag ${ev.changes.some((c) => !c.improvement && c.severity !== "info") ? "note" : "good"}` }, plural(ev.changes.length, "change")),
      unreadIds.has(ev.id) ? h("span", { class: "tag accent-tag" }, "new") : null,
      h("span", { class: "event-links" },
        h("a", { href: `#/scan/${ev.scan_id}` }, "View scan"),
        ev.previous_id ? h("a", { href: `#/compare/${ev.scan_id}` }, "Compare") : null)),
    ev.baseline ? h("p", { class: "muted", style: "margin:6px 0 0" }, "Baseline saved. Future checks are compared with this snapshot.")
      : changeList(ev.changes, 5)))
    : [h("div", { class: "empty" }, "No changes yet. They'll show up here after watched items are re-checked.")];

  render(h("section", { class: "monitor" },
    h("div", { class: "hero" }, h("h1", {}, "Monitoring"),
      h("p", {}, "Watch domains you own and your own email addresses. exposeye re-checks them on a schedule and tells you what changed.")),
    h("div", { class: "panel" }, h("h3", {}, "Watch something new"), addForm, err),
    h("div", { class: "panel" }, h("h3", {}, `Watchlist (${wl.items.length})`),
      wl.items.length ? h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Target", "Every", "Last check", "Next check", "Status", ""].map((x) => h("th", {}, x)))),
        h("tbody", {}, watchRows)))
        : h("div", { class: "empty" }, "Nothing watched yet. Add a domain above, or press Watch on any scan result.")),
    h("div", { class: "monitor-grid" }, bgPanel, alertsPanel),
    h("h2", { class: "section-title" }, "Recent changes"),
    h("div", { class: "timeline" }, timeline)));

  if (anyRunning) state.monitorTimer = setTimeout(() => { if (location.hash === "#/monitor") showMonitor(); }, 4000);
}

async function showCompare(id) {
  render(h("div", { class: "empty" }, h("span", { class: "spinner", style: "display:inline-block" })));
  let d;
  try { d = await api.get(`/api/scans/${id}/diff`); }
  catch (ex) { render(h("div", { class: "empty" }, h("h2", {}, "Can't compare"), h("p", {}, ex.message))); return; }
  const back = h("a", { class: "btn", href: `#/scan/${id}` }, "Back to scan");
  const head = h("div", { class: "result-head" },
    h("div", {}, h("h1", {}, `What changed: ${d.target}`),
      h("div", { class: "result-meta" }, d.previous
        ? [h("span", {}, new Date(d.previous.started).toLocaleString()), "→", h("span", {}, new Date(d.current.started).toLocaleString())]
        : h("span", {}, "No earlier scan to compare with"))),
    h("div", { class: "actions" }, back));
  if (!d.previous) {
    render(h("section", {}, head, h("div", { class: "panel" }, h("div", { class: "empty" },
      `This is the first scan of ${d.target}, so there's nothing to compare yet. Scan it again later, or press Watch to have it re-checked automatically.`))));
    return;
  }
  const bad = d.changes.filter((c) => !c.improvement && c.severity !== "info").length;
  const good = d.changes.filter((c) => c.improvement).length;
  const verdict = !d.changes.length ? h("div", { class: "verdict good" }, "Nothing changed between these two scans.")
    : bad ? h("div", { class: "verdict warn" }, `${plural(d.changes.length, "change")}: ${bad} need attention${good ? `, ${good} improved` : ""}.`)
    : h("div", { class: "verdict good" }, `${plural(d.changes.length, "change")}, none of them problems${good ? ` (${good} improved)` : ""}.`);
  render(h("section", {}, head, verdict, d.changes.length ? changeList(d.changes) : null,
    h("p", { class: "muted", style: "margin-top:16px;font-size:13px" },
      "Only areas measured in both scans are compared. If a data source failed or a check was switched off in either scan, that area is skipped rather than reported as removed."),
    h("a", { class: "btn", href: `#/scan/${d.previous.id}` }, "Open the earlier scan")));
}

/* ================================================================== lab (CTF tools) */

const LAB_EXAMPLE = "NzM3OTZlNzQ3YjZhNzI3OTcwNjI3YTcyNWY2NzYyNWY2Nzc1NzI1Zjc5NmU2Zjdk"; // base64 > hex > ROT13

async function labSettings(force) {
  if (!state.settings || force) {
    try { state.settings = await api.get("/api/settings"); } catch { state.settings = { flag_formats: [], flag_generic: true }; }
  }
  return state.settings;
}

// Split text around flag values and wrap them in <mark> (DOM nodes only, never HTML strings).
function highlightFlags(text, flags) {
  const conf = Object.fromEntries((flags || []).map((f) => [f.value, f.confidence]));
  const values = Object.keys(conf).filter(Boolean).sort((a, b) => b.length - a.length);
  if (!values.length || !text) return [text];
  const re = new RegExp(values.map((v) => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "g");
  const out = [];
  let last = 0;
  for (const m of text.matchAll(re)) {
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(h("mark", { class: `flag-mark ${conf[m[0]] === "high" ? "" : "possible"}` }, m[0]));
    last = m.index + m[0].length;
  }
  out.push(text.slice(last));
  return out;
}

function flagBanner(flags) {
  if (!flags?.length) return null;
  const confirmed = flags.some((f) => f.confidence === "high");
  return h("div", { class: `flag-banner ${confirmed ? "" : "possible"}` },
    h("div", { class: "flag-head" }, icon("flag"),
      confirmed ? `${plural(flags.length, "flag")} found` : "Possible flags (not in your configured formats)"),
    flags.map((f) => h("div", { class: "flag-row" },
      h("code", { class: "flag-value" }, f.value),
      h("span", { class: "muted" },
        f.chain ? `via ${f.chain.length ? f.chain.join(" → ") : "the input itself"}` : f.where ? `in ${f.where}` : ""),
      h("button", { class: "btn btn-sm btn-ghost", type: "button", onclick: () => copyText(f.value) }, icon("copy"), "Copy"))));
}

function formatsLine(s) {
  return h("div", { class: "formats-line muted" }, "Flag formats: ",
    (s.flag_formats || []).map((f) => h("code", {}, f)), s.flag_generic ? " + anything shaped like xyz{…}" : "",
    " · ", h("a", { href: "#/settings" }, "change"));
}

function sendToDecoder(text) {
  state.labInput = text;
  location.hash = "#/lab/decode";
}

/* ---- decoder ---- */

async function showDecoder() {
  const s = await labSettings();
  const input = h("textarea", { class: "lab-input mono", rows: "6", spellcheck: "false", "aria-label": "Text to decode",
    placeholder: "Paste encoded text: base64, hex, binary, Caesar/ROT, XOR, Morse, URL encoding… even several layers deep" });
  input.value = state.labInput ?? store.get("ds.lab.input", "");
  state.labInput = null;
  const depth = h("select", { "aria-label": "Maximum layers" }, [1, 2, 3, 4, 5, 6].map((n) => h("option", { value: String(n) }, `${n} layer${n > 1 ? "s" : ""}`)));
  depth.value = String(store.get("ds.lab.depth", 4));
  const caesar = h("input", { type: "checkbox", checked: store.get("ds.lab.caesar", true) });
  const xor = h("input", { type: "checkbox", checked: store.get("ds.lab.xor", true) });
  const out = h("div", { class: "lab-results" });
  const err = h("div", { class: "form-error", role: "alert" });
  const run = h("button", { class: "btn btn-primary", type: "submit" }, icon("play"), "Decode");

  async function decodeNow() {
    const text = input.value;
    if (!text.trim()) { err.textContent = "Paste something to decode first."; return; }
    err.textContent = "";
    store.set("ds.lab.input", text.length < 20000 ? text : "");
    store.set("ds.lab.depth", Number(depth.value));
    store.set("ds.lab.caesar", caesar.checked);
    store.set("ds.lab.xor", xor.checked);
    run.disabled = true;
    out.replaceChildren(h("div", { class: "empty" }, h("span", { class: "spinner", style: "display:inline-block" })));
    const t0 = performance.now();
    try {
      const r = await api.post("/api/lab/decode", { input: text, depth: Number(depth.value), caesar: caesar.checked, xor: xor.checked });
      const ms = Math.round(performance.now() - t0);
      out.replaceChildren(
        flagBanner(r.flags) || h("div", { class: "notice" }, "No flag found yet. The most readable results are below; you can decode any of them further."),
        h("div", { class: "muted lab-meta" }, `${plural(r.explored, "candidate")} tried in ${ms} ms`),
        ...(r.results.length ? resultList(r.results)
          : [h("div", { class: "empty" }, "Nothing decoded. It may be a cipher that needs a key (Vigenère, AES…) or not encoded at all.")]));
    } catch (ex) { out.replaceChildren(); err.textContent = ex.message; }
    run.disabled = false;
  }

  // Show what matters first: every result containing a flag plus the next few best; the long tail
  // of brute-force guesses stays behind a button.
  function resultList(results) {
    const confirmed = (res) => res.flags.some((f) => f.confidence === "high");
    const anyConfirmed = results.some(confirmed);
    const withFlags = results.filter((res) => (anyConfirmed ? confirmed(res) : res.flags.length)).length;
    const first = withFlags ? withFlags + 3 : 8;
    const cards = results.slice(0, first).map(resultCard);
    if (results.length > first) {
      const more = h("button", { class: "btn btn-ghost show-more", type: "button" }, `Show ${results.length - first} more results`);
      more.addEventListener("click", () => more.replaceWith(...results.slice(first).map(resultCard)));
      cards.push(more);
    }
    return cards;
  }

  function resultCard(res) {
    const chain = h("div", { class: "chain" }, h("span", { class: "chain-step start" }, "input"),
      res.chain.map((c) => [h("span", { class: "chain-arrow" }, "→"), h("span", { class: "chain-step" }, c)]));
    const body = res.printable
      ? h("pre", { class: "lab-output" }, highlightFlags(res.text, res.flags))
      : h("pre", { class: "lab-output muted" }, `binary (${res.length} bytes): ${res.hex}`);
    const high = res.flags.some((f) => f.confidence === "high");
    const maybe = !high && res.flags.length > 0;
    return h("article", { class: `lab-card ${high ? "has-flag" : maybe ? "maybe-flag" : ""}` },
      h("div", { class: "lab-card-head" }, chain,
        h("span", { class: "score", title: "How readable / flag-like the output is" },
          high ? "flag!" : maybe ? "maybe" : `${Math.round(Math.min(res.score, 1) * 100)}%`)),
      body,
      h("div", { class: "lab-actions" },
        res.printable ? h("button", { class: "btn btn-sm", type: "button", onclick: () => copyText(res.text) }, icon("copy"), "Copy") : null,
        res.printable ? h("button", { class: "btn btn-sm", type: "button", onclick: () => { input.value = res.text; decodeNow(); window.scrollTo(0, 0); } }, icon("refresh"), "Decode this further") : null));
  }

  input.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); decodeNow(); } });
  const form = h("form", { class: "panel", onsubmit: (e) => { e.preventDefault(); decodeNow(); } },
    input,
    h("div", { class: "lab-controls" }, run,
      h("button", { class: "btn btn-ghost", type: "button", onclick: () => { input.value = ""; out.replaceChildren(); input.focus(); } }, "Clear"),
      depth,
      h("label", { class: "toggle inline" }, caesar, h("span", { class: "switch" }), h("span", {}, "Caesar / ROT")),
      h("label", { class: "toggle inline" }, xor, h("span", { class: "switch" }), h("span", {}, "XOR brute force")),
      h("button", { class: "btn btn-ghost", type: "button", onclick: () => { input.value = LAB_EXAMPLE; decodeNow(); } }, "Try an example")),
    h("div", { class: "muted lab-tip" }, "Tip: Ctrl+Enter decodes. Everything runs on this PC."),
    err);

  render(h("section", {},
    h("div", { class: "hero" }, h("h1", {}, "Decoder"),
      h("p", {}, "Paste anything encoded. Layers are unwrapped automatically and results are ranked by how readable they are, so a flag jumps to the top.")),
    formatsLine(s), form, out));
  if (input.value) decodeNow(); else input.focus();
}

/* ---- file analyser ---- */

function sparkline(values) {
  const w = 320, hgt = 56;
  if (!values?.length) return null;
  const step = values.length > 1 ? w / (values.length - 1) : w;
  const pts = values.map((v, i) => `${(i * step).toFixed(1)},${(hgt - (v / 8) * hgt).toFixed(1)}`).join(" ");
  const svg = document.createElementNS(SVGNS, "svg");
  svg.setAttribute("viewBox", `0 0 ${w} ${hgt}`);
  svg.setAttribute("class", "sparkline");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Entropy across the file (0 to 8 bits per byte)");
  const line = document.createElementNS(SVGNS, "polyline");
  line.setAttribute("points", pts);
  const high = document.createElementNS(SVGNS, "line");
  const y = hgt - (7.5 / 8) * hgt;
  for (const [k, v] of Object.entries({ x1: 0, x2: w, y1: y, y2: y, class: "threshold" })) high.setAttribute(k, v);
  svg.append(high, line);
  return svg;
}

function fileSize(n) {
  return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
}

async function showFileLab() {
  const s = await labSettings();
  const picker = h("input", { type: "file", hidden: true });
  const status = h("div", { class: "form-error", role: "alert" });
  const results = h("div", {});
  const drop = h("div", { class: "dropzone", tabindex: "0", role: "button", "aria-label": "Choose or drop a file to analyse" },
    icon("upload"), h("strong", {}, "Drop a challenge file here, or click to choose"),
    h("span", { class: "muted" }, "Images, archives, PDFs, binaries, dumps… up to 50 MB. Files are only read, never run, and stay on this PC."));

  async function analyse(file) {
    if (!file) return;
    status.textContent = "";
    if (file.size > 50 * 1048576) { status.textContent = "Files up to 50 MB are supported."; return; }
    results.replaceChildren(h("div", { class: "empty" }, h("span", { class: "spinner", style: "display:inline-block" }), h("div", {}, `Analysing ${file.name}…`)));
    try {
      const res = await fetch(`/api/lab/files?name=${encodeURIComponent(file.name)}`, { method: "POST", body: file });
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || res.statusText);
      state.labFile = await res.json();
      results.replaceChildren(fileReport(state.labFile));
    } catch (ex) { results.replaceChildren(); status.textContent = ex.message; }
  }
  picker.addEventListener("change", () => analyse(picker.files[0]));
  drop.addEventListener("click", () => picker.click());
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); picker.click(); } });
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); analyse(e.dataTransfer.files[0]); });

  render(h("section", {},
    h("div", { class: "hero" }, h("h1", {}, "File analyser"),
      h("p", {}, "Finds what's hidden in a file: the real type, embedded files, data after the end, metadata, tampered PNG headers, LSB steganography and flags.")),
    formatsLine(s), drop, picker, status, results));
  if (state.labFile) results.replaceChildren(fileReport(state.labFile));
}

function fileReport(r) {
  const dl = (path, label) => h("a", { class: "btn btn-sm", href: path, download: "" }, icon("download"), label);
  const extractUrl = (start, end) => `/api/lab/files/${r.id}/extract?start=${start}${end != null ? `&end=${end}` : ""}`;
  const hiddenCount = (r.trailing ? 1 : 0) + r.embedded.filter((e) => !e.note).length + (r.png?.fixed_size ? 1 : 0);
  const tabs = [
    ["overview", "Overview", null],
    ["strings", "Strings", r.strings.length],
    ["hidden", "Hidden data", hiddenCount || null],
    ["meta", "Metadata", null],
    r.lsb || r.text_stego?.length ? ["stego", "Steganography", null] : null,
    r.audio ? ["audio", "Audio", null] : null,
    r.pcap && !r.pcap.error ? ["network", "Network", r.pcap.credentials.length || null] : null,
    ["hex", "Hex", null],
  ].filter(Boolean);
  const t = tabbed("file", tabs, {
    overview: () => fileOverview(r),
    strings: () => fileStrings(r),
    hidden: () => fileHidden(r, dl, extractUrl),
    meta: () => fileMeta(r),
    stego: () => fileStego(r),
    audio: () => fileAudio(r),
    network: () => fileNetwork(r),
    hex: () => h("div", { class: "panel" }, h("pre", { class: "hexdump" }, r.hexdump || "(empty)"),
      h("p", { class: "muted" }, "First 512 bytes.")),
  });
  const view = h("div", { class: "file-report" },
    h("div", { class: "result-head" },
      h("div", {}, h("h1", { class: "mono" }, r.name),
        h("div", { class: "result-meta" }, h("span", {}, fileSize(r.size)), "·",
          h("span", { class: `badge ${r.type.type ? "accent" : ""}` }, r.type.description),
          r.extension_mismatch ? h("span", { class: "badge warn-badge" }, `not really .${r.extension}`) : null))),
    flagBanner(r.flags),
    h("div", { class: "panel hints" }, h("h3", {}, "What to look at"),
      h("ol", {}, r.hints.map((x) => h("li", {}, x)))),
    t.bar, t.panel);
  t.first();
  return view;
}

function fileOverview(r) {
  const chips = (items, label) => (items?.length ? [h("dt", {}, label), h("dd", {}, items.map((v) =>
    label === "Base64-looking"
      ? h("button", { class: "tag tag-btn", type: "button", title: "Send to the decoder", onclick: () => sendToDecoder(v) }, v.length > 40 ? `${v.slice(0, 40)}…` : v)
      : h("span", { class: "tag" }, v)))] : null);
  return h("div", {},
    h("div", { class: "tiles" },
      tile("Real type", r.type.type ? "neutral" : "warn", r.type.type || "unknown", r.type.description),
      tile("Extension", r.extension_mismatch ? "bad" : "good", r.extension ? `.${r.extension}` : "none",
        r.extension_mismatch ? "Doesn't match the content!" : "Matches the content."),
      h("div", { class: `tile ${r.entropy > 7.5 ? "warn" : "neutral"}` },
        h("div", { class: "tile-head" }, "Entropy", h("span", { class: "tag" }, `${r.entropy} / 8`)),
        sparkline(r.entropy_profile),
        h("p", {}, r.entropy > 7.5 ? "Very random: compressed or encrypted." : "Spikes can mark hidden compressed/encrypted data."))),
    h("div", { class: "panel" }, h("h3", {}, "Hashes"),
      h("dl", { class: "kv" }, Object.entries(r.hashes).map(([k, v]) => [h("dt", {}, k.toUpperCase()),
        h("dd", {}, h("code", {}, v), " ", h("button", { class: "btn btn-sm btn-ghost", type: "button", onclick: () => copyText(v) }, icon("copy")))]))),
    h("div", { class: "panel" }, h("h3", {}, "Interesting strings"),
      h("dl", { class: "kv" }, chips(r.interesting.urls, "URLs"), chips(r.interesting.emails, "Emails"),
        chips(r.interesting.ips, "IP addresses"), chips(r.interesting.base64, "Base64-looking")),
      !(r.interesting.urls.length || r.interesting.emails.length || r.interesting.ips.length || r.interesting.base64.length)
        ? h("p", { class: "muted" }, "None found.") : h("p", { class: "muted" }, "Click a base64-looking string to decode it.")));
}

function fileStrings(r) {
  let q = "";
  let only = false;
  const list = h("div", { class: "strings-list" });
  const search = h("input", { type: "search", class: "search", placeholder: "Filter strings…", "aria-label": "Filter strings" });
  const onlyBox = h("input", { type: "checkbox" });
  const counter = h("span", { class: "muted" });
  const flagValues = new Set(r.flags.map((f) => f.value));
  const interestingRe = /https?:\/\/|@|\{.*\}|pass|secret|key|token|admin|flag|ctf|hidden/i;
  function draw() {
    const rows = r.strings.filter((x) => (!q || x.text.toLowerCase().includes(q)) && (!only || interestingRe.test(x.text)));
    counter.textContent = `${rows.length} of ${r.strings.length}${r.strings.length >= 4000 ? " (first 4000)" : ""}`;
    list.replaceChildren(...rows.slice(0, 1500).map((x) => h("div", { class: "string-row" },
      h("span", { class: "offset" }, `0x${x.offset.toString(16).padStart(6, "0")}`),
      h("span", { class: "string-text" }, highlightFlags(x.text, r.flags)),
      x.encoding !== "ascii" ? h("span", { class: "tag" }, x.encoding) : null,
      h("button", { class: "btn btn-sm btn-ghost send", type: "button", title: "Send to the decoder", onclick: () => sendToDecoder(x.text) }, "decode"))));
    if (rows.length > 1500) list.append(h("div", { class: "muted" }, `…${rows.length - 1500} more. Use the filter.`));
    if (![...flagValues].length && !rows.length) list.append(h("div", { class: "empty" }, "No matching strings."));
  }
  search.addEventListener("input", () => { q = search.value.toLowerCase(); draw(); });
  onlyBox.addEventListener("change", () => { only = onlyBox.checked; draw(); });
  draw();
  return h("div", { class: "panel" },
    h("div", { class: "toolbar" }, search,
      h("label", { class: "toggle inline" }, onlyBox, h("span", { class: "switch" }), h("span", {}, "Interesting only")), counter),
    list);
}

function fileHidden(r, dl, extractUrl) {
  const parts = [];
  if (r.png?.fixed_size) {
    const f = r.png.fixed_size;
    parts.push(h("div", { class: "panel" }, h("h3", {}, "Tampered PNG header"),
      h("p", {}, `The header claims ${f.original[0]}×${f.original[1]}, but its checksum only matches ${f.width}×${f.height}. Part of the image is being hidden.`),
      dl(`/api/lab/files/${r.id}/fixed-png?width=${f.width}&height=${f.height}`, `Download repaired PNG (${f.width}×${f.height})`)));
  }
  if (r.trailing) {
    parts.push(h("div", { class: "panel" }, h("h3", {}, "Data after the end of the file"),
      h("p", {}, `${fileSize(r.trailing.size)} starting at offset 0x${r.trailing.offset.toString(16)}`, r.trailing.type ? `, looks like: ${r.trailing.type}` : "", "."),
      h("pre", { class: "hexdump" }, r.trailing.hex),
      dl(extractUrl(r.trailing.offset), "Extract appended data")));
  }
  parts.push(h("div", { class: "panel" }, h("h3", {}, `Embedded file signatures (${r.embedded.length})`),
    r.embedded.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Offset", "Looks like", "Size to next", ""].map((x) => h("th", {}, x)))),
      h("tbody", {}, r.embedded.map((e) => h("tr", {},
        h("td", { class: "mono" }, `0x${e.offset.toString(16)}`),
        h("td", {}, e.description, e.note ? h("span", { class: "muted" }, ` (${e.note})`) : null),
        h("td", {}, fileSize(e.end - e.offset)),
        h("td", {}, dl(extractUrl(e.offset, e.end), "Extract")))))))
      : h("p", { class: "muted" }, "No other file signatures inside this file.")));
  if (r.png) {
    parts.push(h("div", { class: "panel" }, h("h3", {}, "PNG chunks"),
      r.png.problems.length ? h("div", { class: "notice danger" }, r.png.problems.join("; ")) : null,
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Chunk", "Offset", "Length", "CRC"].map((x) => h("th", {}, x)))),
        h("tbody", {}, r.png.chunks.slice(0, 200).map((c) => h("tr", {},
          h("td", { class: "mono" }, c.type, r.png.unusual.includes(c.type) ? h("span", { class: "tag note" }, "unusual") : null),
          h("td", { class: "mono" }, `0x${c.offset.toString(16)}`), h("td", {}, c.length),
          h("td", {}, c.crc_ok ? h("span", { class: "tag good" }, "ok") : h("span", { class: "tag warn" }, "bad")))))))));
  }
  return h("div", {}, parts);
}

function fileMeta(r) {
  const kv = (obj) => h("dl", { class: "kv" }, Object.entries(obj).map(([k, v]) => [h("dt", {}, k), h("dd", { class: "mono" }, highlightFlags(String(v), r.flags))]));
  const parts = [];
  if (r.image) {
    const g = r.image.gps;
    parts.push(h("div", { class: "panel" }, h("h3", {}, `Image: ${r.image.format} ${r.image.width}×${r.image.height} (${r.image.mode})`),
      g ? h("div", { class: "notice" }, `GPS: ${g.lat}, ${g.lon} `, h("a", { href: g.maps, target: "_blank", rel: "noopener noreferrer" }, "open map")) : null,
      Object.keys(r.image.exif).length ? [h("h4", {}, "EXIF"), kv(r.image.exif)] : null,
      Object.keys(r.image.text).length ? [h("h4", {}, "Embedded text"), kv(r.image.text)] : null,
      !Object.keys(r.image.exif).length && !Object.keys(r.image.text).length && !g ? h("p", { class: "muted" }, "No EXIF or text metadata.") : null));
  }
  if (r.pdf) {
    parts.push(h("div", { class: "panel" }, h("h3", {}, `PDF (${r.pdf.pages} page${r.pdf.pages === 1 ? "" : "s"}, ${r.pdf.revisions} revision${r.pdf.revisions === 1 ? "" : "s"})`),
      kv(r.pdf.info),
      h("p", {}, ["javascript", "embedded_files", "auto_action"].map((k) => h("span", { class: `tag ${r.pdf[k] ? "warn" : "good"}` }, `${k.replace("_", " ")}: ${r.pdf[k] ? "yes" : "no"}`))),
      r.pdf.revisions > 1 ? h("p", { class: "muted" }, "Multiple revisions: older versions of the content may still be inside the file.") : null));
  }
  if (r.zip) {
    parts.push(h("div", { class: "panel" }, h("h3", {}, `ZIP archive in ${r.zip.where} (${r.zip.entries.length} entries${r.zip.encrypted ? ", password-protected" : ""})`),
      r.zip.comment ? h("div", { class: "notice" }, "Archive comment: ", h("code", {}, r.zip.comment)) : null,
      Object.keys(r.zip.office).length ? [h("h4", {}, "Office document properties"), kv(r.zip.office)] : null,
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Name", "Size", "Modified", ""].map((x) => h("th", {}, x)))),
        h("tbody", {}, r.zip.entries.slice(0, 300).map((e) => h("tr", {},
          h("td", { class: "mono" }, highlightFlags(e.name, r.flags)), h("td", {}, fileSize(e.size)), h("td", {}, e.modified),
          h("td", {}, e.encrypted ? h("span", { class: "tag warn" }, "encrypted") : null))))))));
  }
  if (r.binary) parts.push(h("div", { class: "panel" }, h("h3", {}, "Executable"), kv(r.binary)));
  if (!parts.length) parts.push(h("div", { class: "panel" }, h("div", { class: "empty" }, "No format-specific metadata for this file type.")));
  return h("div", {}, parts);
}

function lsbTable(rows, flagsFor, tried) {
  return h("div", {},
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Channels", "Bit", "Order", "Packing", "Readable text", "Starts with"].map((x) => h("th", {}, x)))),
      h("tbody", {}, rows.map((c) => h("tr", { class: c.flags.length ? "flag-row-hit" : "" },
        h("td", {}, c.channels), h("td", {}, c.bit), h("td", {}, c.order), h("td", { class: "muted" }, c.packing),
        h("td", {}, c.text_prefix >= 6 ? `${c.text_prefix} chars` : `${Math.round(c.printable * 100)}%`,
          c.magic ? h("span", { class: "tag note" }, c.magic) : null),
        h("td", { class: "mono lsb-preview" }, highlightFlags(c.preview.replace(/[^\x20-\x7e]/g, "·"), c.flags))))))),
    tried ? h("p", { class: "muted", style: "margin:8px 0 0;font-size:12.5px" },
      `Best of ${tried} channel / bit / order / packing combinations tried.`) : null);
}

function textStegoPanel(r) {
  return h("div", { class: "panel" }, h("h3", {}, "Hidden text"),
    r.text_stego.map((t) => h("div", { class: "text-stego" },
      h("div", { class: "finding-title" }, t.method),
      t.output ? h("pre", { class: "lab-output" }, highlightFlags(t.output, t.flags)) : null,
      t.output ? h("button", { class: "btn btn-sm", type: "button", onclick: () => sendToDecoder(t.output) }, "Send to decoder") : null)));
}

function planeViewer(r) {
  const s = { channel: r.lsb.channels[0], bit: 0, mode: "bit", actual: false };
  const img = h("img", { class: "plane-view", alt: "Selected bit plane" });
  const caption = h("div", { class: "plane-caption" });
  const chSel = h("select", { "aria-label": "Channel" }, r.lsb.channels.map((c) => h("option", { value: c }, c)));
  const modeSel = h("select", { "aria-label": "View" },
    [["bit", "Bit plane"], ["channel", "Full channel"], ["inverted", "Inverted"], ["random", "Random colours"]]
      .map(([v, l]) => h("option", { value: v }, l)));
  const bitBtns = [7, 6, 5, 4, 3, 2, 1, 0].map((b) => h("button", { type: "button", class: "bit-btn", "data-bit": b,
    title: `Bit ${b}${b === 0 ? " (least significant)" : b === 7 ? " (most significant)" : ""}`,
    onclick: () => { s.bit = b; s.mode = "bit"; update(); } }, String(b)));
  const download = h("a", { class: "btn btn-sm", download: "" }, icon("download"), "Save view");
  const sizeBtn = h("button", { class: "btn btn-sm", type: "button", onclick: () => { s.actual = !s.actual; update(); } });
  // Stegsolve-style stepping: every bit of every channel, in order
  const sequence = r.lsb.channels.flatMap((c) => [0, 1, 2, 3, 4, 5, 6, 7].map((b) => [c, b]));
  const step = (d) => {
    if (s.mode !== "bit") {
      const i = r.lsb.channels.indexOf(s.channel);
      s.channel = r.lsb.channels[(i + d + r.lsb.channels.length) % r.lsb.channels.length];
    } else {
      const i = sequence.findIndex(([c, b]) => c === s.channel && b === s.bit);
      [s.channel, s.bit] = sequence[(i + d + sequence.length) % sequence.length];
    }
    update();
  };
  function update() {
    const url = `/api/lab/files/${r.id}/plane?channel=${encodeURIComponent(s.channel)}&bit=${s.bit}&mode=${s.mode}`;
    img.src = url;
    img.classList.toggle("actual", s.actual);
    download.href = url;
    download.setAttribute("download", `${r.name.replace(/\.[^.]+$/, "")}_${s.channel}_${s.mode === "bit" ? `bit${s.bit}` : s.mode}.png`);
    chSel.value = s.channel;
    modeSel.value = s.mode;
    sizeBtn.textContent = s.actual ? "Fit to panel" : "Actual size";
    for (const b of bitBtns) b.classList.toggle("active", s.mode === "bit" && Number(b.dataset.bit) === s.bit);
    caption.textContent = s.mode === "bit"
      ? `${s.channel} · bit ${s.bit}: white = 1, black = 0${s.bit <= 1 ? ". Low bits should look like noise; shapes or text here mean hidden data." : ""}`
      : { channel: `${s.channel} channel as greyscale`, inverted: `${s.channel} channel inverted`,
        random: `${s.channel} values mapped to random colours: reveals text drawn in nearly identical shades` }[s.mode];
  }
  chSel.addEventListener("change", () => { s.channel = chSel.value; update(); });
  modeSel.addEventListener("change", () => { s.mode = modeSel.value; update(); });
  const wrap = h("div", { class: "panel plane-panel", tabindex: "0",
    onkeydown: (e) => { if (e.key === "ArrowRight") { e.preventDefault(); step(1); } if (e.key === "ArrowLeft") { e.preventDefault(); step(-1); } } },
    h("h3", {}, "Plane viewer"),
    h("div", { class: "plane-controls" },
      h("button", { class: "btn btn-sm", type: "button", title: "Previous (←)", onclick: () => step(-1) }, "←"),
      chSel, modeSel,
      h("div", { class: "bit-buttons", role: "group", "aria-label": "Bit" }, h("span", { class: "muted" }, "bit"), bitBtns),
      h("button", { class: "btn btn-sm", type: "button", title: "Next (→)", onclick: () => step(1) }, "→"),
      sizeBtn, download),
    h("div", { class: "plane-stage" }, img),
    caption);
  wrap.select = (channel, bit) => { s.channel = channel; s.bit = bit; s.mode = "bit"; update(); wrap.scrollIntoView({ behavior: "smooth", block: "start" }); wrap.focus({ preventScroll: true }); };
  update();
  return wrap;
}

function planeGrid(r, viewer) {
  const rows = r.lsb.channels.filter((c) => r.lsb.planes.some((p) => p.channel === c));
  return h("div", { class: "panel" }, h("h3", {}, "All bit planes at a glance"),
    h("p", { class: "muted" }, "Each row is a colour channel, from the most significant bit (7) to the least (0). Click one to open it above."),
    h("div", { class: "plane-grid" }, rows.map((c) => [
      h("div", { class: "plane-row-label" }, c),
      [7, 6, 5, 4, 3, 2, 1, 0].map((b) => {
        const p = r.lsb.planes.find((x) => x.channel === c && x.bit === b);
        return h("button", { type: "button", class: "plane-thumb", title: `${c} bit ${b}`, onclick: () => viewer.select(c, b) },
          h("img", { src: `data:image/png;base64,${p.png}`, alt: `${c} bit ${b}` }), h("span", {}, b));
      }),
    ])));
}

function fileStego(r) {
  const parts = [];
  if (r.text_stego?.length) parts.push(textStegoPanel(r));
  if (r.lsb) {
    if (!r.lsb.lossless) {
      const tools = Object.entries(r.jpeg_tools || {}).filter(([, v]) => v).map(([k]) => k);
      parts.push(h("div", { class: "notice" },
        h("strong", {}, "JPEG: "), "compression destroys LSB data, so hidden data lives in the compressed coefficients instead (steghide, OutGuess, JSteg). Try ",
        h("code", {}, `stegseek ${r.name} rockyou.txt`), " or ", h("code", {}, `steghide extract -sf ${r.name}`),
        " with an empty password. ", tools.length ? `Installed here: ${tools.join(", ")}.` : "None of these tools are installed on this PC.",
        " The planes below can still show visible tricks."));
    }
    const viewer = planeViewer(r);
    parts.push(viewer, planeGrid(r, viewer));
    if (r.lsb.candidates) {
      parts.push(h("div", { class: "panel" }, h("h3", {}, "Automatic LSB extraction"),
        h("p", { class: "muted" }, "Reads the low bits in the orders CTF tools use (rows, columns, reversed; bits 0–2; both bit packings; palette indices) and ranks the results by readable text, file headers and flags."),
        lsbTable(r.lsb.candidates, null, r.lsb.tried)));
    }
  }
  return h("div", {}, parts);
}

function fileAudio(r) {
  const a = r.audio;
  const secs = a.duration;
  const spectro = (sp) => h("figure", { class: "spectro" },
    h("figcaption", {}, sp.label),
    h("div", { class: "spectro-frame" },
      h("div", { class: "spectro-y" }, h("span", {}, `${(a.max_freq / 1000).toFixed(1)} kHz`), h("span", {}, `${(a.max_freq / 2000).toFixed(1)} kHz`), h("span", {}, "0 Hz")),
      h("a", { href: `data:image/png;base64,${sp.png}`, target: "_blank", rel: "noopener", title: "Open full size" },
        h("img", { src: `data:image/png;base64,${sp.png}`, alt: `Spectrogram: ${sp.label}` }))),
    h("div", { class: "spectro-x" }, h("span", {}, "0 s"), h("span", {}, `${(secs / 2).toFixed(1)} s`), h("span", {}, `${secs} s`)));
  return h("div", {},
    h("div", { class: "tiles" },
      tile("Format", "neutral", `${a.bits}-bit`, `${a.channels === 2 ? "Stereo" : a.channels === 1 ? "Mono" : `${a.channels} channels`}, ${(a.rate / 1000).toFixed(1)} kHz`),
      tile("Duration", "neutral", `${secs} s`, secs >= 180 ? "Only the first 3 minutes are analysed." : "Whole file analysed."),
      tile("DTMF tones", a.dtmf ? "good" : "neutral", a.dtmf ? "found" : "none", a.dtmf ? `Keys pressed: ${a.dtmf}` : "No phone-keypad tones detected."),
      tile("Morse", a.morse ? "good" : "neutral", a.morse ? "found" : "none", a.morse ? `Decoded: ${a.morse}` : "No Morse code detected.")),
    h("div", { class: "panel" }, h("h3", {}, "Spectrogram"),
      h("p", { class: "muted" }, "Time runs left to right, pitch bottom to top. Text or pictures drawn here are a classic CTF hiding place. Click to open full size."),
      a.spectrograms.map(spectro)),
    h("div", { class: "panel" }, h("h3", {}, "Sample LSB extraction"),
      h("p", { class: "muted" }, "The lowest bits of the audio samples, which are inaudible, packed into bytes."),
      lsbTable(a.lsb)));
}

/* ---- hashes ---- */

async function showHashes() {
  const s = await labSettings();
  const input = h("textarea", { class: "lab-input mono", rows: "5", spellcheck: "false", "aria-label": "Hashes, one per line",
    placeholder: "Paste one or more hashes, one per line:\n5f4dcc3b5aa765d61d8327deb882cf99\n$2b$12$..." });
  input.value = store.get("ds.hash.input", "");
  const wordlist = h("input", { type: "text", class: "domain-input", placeholder: "Optional: path to a wordlist, e.g. C:\\wordlists\\rockyou.txt", spellcheck: "false", "aria-label": "Wordlist path" });
  wordlist.value = store.get("ds.hash.wordlist", "");
  const extra = h("textarea", { class: "lab-input mono", rows: "2", spellcheck: "false", "aria-label": "Extra words to try",
    placeholder: "Optional: extra candidate passwords, one per line" });
  const out = h("div", { class: "lab-results" });
  const err = h("div", { class: "form-error", role: "alert" });
  const run = h("button", { class: "btn btn-primary", type: "submit" }, icon("play"), "Identify & crack");

  async function go() {
    const list = input.value.split("\n").map((x) => x.trim()).filter(Boolean);
    if (!list.length) { err.textContent = "Paste at least one hash."; return; }
    err.textContent = "";
    store.set("ds.hash.input", input.value.slice(0, 20000));
    store.set("ds.hash.wordlist", wordlist.value);
    run.disabled = true;
    out.replaceChildren(h("div", { class: "empty" }, h("span", { class: "spinner", style: "display:inline-block" }), h("div", {}, "Cracking…")));
    try {
      const r = await api.post("/api/lab/hash", { hashes: list, wordlist: wordlist.value.trim() || null, extra_words: extra.value || null });
      out.replaceChildren(...r.results.map(hashCard));
    } catch (ex) { out.replaceChildren(); err.textContent = ex.message; }
    run.disabled = false;
  }

  function hashCard(e) {
    const res = e.result;
    const cracked = res && res.found;
    return h("article", { class: `lab-card ${cracked ? "has-flag" : ""}` },
      h("div", { class: "lab-card-head" }, h("code", { class: "mono", style: "word-break:break-all" }, e.hash),
        cracked ? h("span", { class: "score", style: "color:var(--ok);font-weight:700" }, "cracked") : null),
      h("div", {}, "Likely type: ", e.types.length
        ? e.types.map((t) => h("span", { class: `tag ${t.crackable ? "" : "note"}`, title: t.note || "" }, t.name))
        : h("span", { class: "muted" }, "unknown")),
      cracked
        ? h("div", { class: "flag-row" }, h("span", { class: "flag-value" }, res.found.password),
            h("span", { class: "muted" }, `${res.found.type}, ${res.tried.toLocaleString()} tried`),
            h("button", { class: "btn btn-sm btn-ghost", type: "button", onclick: () => copyText(res.found.password) }, icon("copy"), "Copy"))
        : res
          ? h("div", { class: "muted" }, res.exhausted ? `Not in the wordlist (${res.tried.toLocaleString()} tried). Try a bigger list like rockyou.txt.` : `Gave up after ${res.tried.toLocaleString()} words.`)
          : h("div", { class: "notice" }, "Salted or slow hash: can't be cracked by simple lookup. Use john or hashcat with this hash."));
  }

  input.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); go(); } });
  const form = h("form", { class: "panel", onsubmit: (e) => { e.preventDefault(); go(); } },
    input,
    h("details", { class: "options", style: "margin:12px 0" }, h("summary", {}, icon("sliders"), "Wordlist (optional)"),
      h("div", { class: "options-body" },
        h("div", { class: "toggle-text" }, h("strong", {}, "Wordlist file"), h("span", {}, "A big list finds more. rockyou.txt is the classic.")),
        wordlist,
        h("div", { class: "toggle-text", style: "margin-top:10px" }, h("strong", {}, "Extra words"), h("span", {}, "Words from the challenge itself often work.")),
        extra)),
    h("div", { class: "lab-controls" }, run,
      h("button", { class: "btn btn-ghost", type: "button", onclick: () => { input.value = "5f4dcc3b5aa765d61d8327deb882cf99"; go(); } }, "Try an example")),
    h("div", { class: "muted lab-tip" }, "Only weak/known passwords are found - the standard CTF hash-cracking workflow. Everything runs on this PC."),
    err);

  render(h("section", {},
    h("div", { class: "hero" }, h("h1", {}, "Hash cracker"),
      h("p", {}, "Identify what kind of hash you have and recover weak passwords from a wordlist.")),
    formatsLine(s), form, out));
  if (input.value.trim()) go(); else input.focus();
}

/* ---- jwt ---- */

async function showJwt() {
  const token = h("textarea", { class: "lab-input mono", rows: "4", spellcheck: "false", "aria-label": "JWT",
    placeholder: "Paste a JWT: eyJhbGci...  .  eyJ...  .  signature" });
  token.value = store.get("ds.jwt.input", "");
  const wordlist = h("input", { type: "text", class: "domain-input", placeholder: "Optional: wordlist path for the secret search", spellcheck: "false", "aria-label": "Wordlist path" });
  wordlist.value = store.get("ds.jwt.wordlist", "");
  const out = h("div", {});
  const err = h("div", { class: "form-error", role: "alert" });
  const run = h("button", { class: "btn btn-primary", type: "submit" }, icon("play"), "Decode");

  async function go() {
    if (!token.value.trim()) { err.textContent = "Paste a JWT first."; return; }
    err.textContent = "";
    store.set("ds.jwt.input", token.value.trim());
    store.set("ds.jwt.wordlist", wordlist.value);
    run.disabled = true;
    out.replaceChildren(h("div", { class: "empty" }, h("span", { class: "spinner", style: "display:inline-block" })));
    try {
      const r = await api.post("/api/lab/jwt", { token: token.value.trim(), wordlist: wordlist.value.trim() || null });
      out.replaceChildren(jwtReport(r, token.value.trim()));
    } catch (ex) { out.replaceChildren(); err.textContent = ex.message; }
    run.disabled = false;
  }

  function jwtReport(r, raw) {
    if (!r.valid) return h("div", { class: "notice danger" }, r.error);
    const sev = { high: "high", medium: "medium", info: "low" };
    const findings = h("div", { class: "findings" }, r.findings.map((f) => h("article", { class: `finding sev-${sev[f.severity]}` },
      h("span", { class: `pill ${sev[f.severity]}` }, f.severity), h("div", {}, h("div", { class: "finding-title" }, f.title), h("div", { class: "finding-detail" }, f.detail)))));
    const kv = (obj) => h("pre", { class: "lab-output" }, JSON.stringify(obj, null, 2));
    const parts = [
      h("div", { class: "tiles" },
        tile("Algorithm", r.alg.toLowerCase() === "none" ? "bad" : "neutral", r.alg || "—", r.alg.toLowerCase() === "none" ? "No signature required!" : "Signing algorithm"),
        tile("Signature", r.signature_b64 ? "neutral" : "warn", r.signature_b64 ? "present" : "none", r.signature_b64 ? `${r.signature_b64.length} chars` : "No signature segment")),
      h("div", { class: "panel" }, h("h3", {}, "Header"), kv(r.header), h("h3", {}, "Payload"), kv(r.payload),
        r.claims.length ? h("div", {}, r.claims.map((c) => h("div", { class: "row" }, h("span", { class: "muted" }, `${c.claim} (${c.label}): `), c.value, c.note ? h("span", { class: `tag ${c.note === "expired" ? "warn" : "good"}` }, c.note) : null))) : null),
    ];
    if (r.findings.length) parts.push(h("div", { class: "panel" }, h("h3", {}, "Findings"), findings));
    if (r.secret_search) {
      const ss = r.secret_search;
      parts.push(h("div", { class: `panel ${ss.secret ? "" : ""}` }, h("h3", {}, "HMAC secret search"),
        ss.secret
          ? h("div", { class: "flag-banner" }, h("div", { class: "flag-head" }, icon("flag"), "Secret found"),
              h("div", { class: "flag-row" }, h("span", { class: "flag-value" }, ss.secret), h("span", { class: "muted" }, `${ss.tried.toLocaleString()} tried`),
                h("button", { class: "btn btn-sm", type: "button", onclick: () => resign(raw, ss.secret) }, "Forge a token with this secret")))
          : h("div", { class: "muted" }, `Secret not in the wordlist (${ss.tried.toLocaleString()} tried). Add a wordlist path above for a bigger search.`)));
    }
    // alg:none forge helper
    const payloadBox = h("textarea", { class: "lab-input mono", rows: "3", spellcheck: "false" }, JSON.stringify(r.payload, null, 2));
    const forgeOut = h("div", {});
    parts.push(h("div", { class: "panel" }, h("h3", {}, "Forge an alg:none token"),
      h("p", { class: "muted" }, "Some servers accept a token with alg:none and no signature. Edit the payload, then generate one to try."),
      payloadBox,
      h("button", { class: "btn", type: "button", style: "margin-top:10px", onclick: async () => {
        try {
          const res = await api.post("/api/lab/jwt", { token: raw, forge_payload: payloadBox.value });
          forgeOut.replaceChildren(tokenOut(res.forged_none, "alg:none token"));
        } catch (ex) { forgeOut.replaceChildren(h("div", { class: "form-error" }, ex.message)); }
      } }, "Generate"), forgeOut));
    return h("div", {}, parts);
  }

  async function resign(raw, secret) {
    try {
      const res = await api.post("/api/lab/jwt", { token: raw, resign_secret: secret });
      out.prepend(tokenOut(res.resigned, `token re-signed with "${secret}"`));
    } catch (ex) { err.textContent = ex.message; }
  }

  function tokenOut(tok, label) {
    return h("div", { class: "flag-banner", style: "margin-top:10px" },
      h("div", { class: "flag-head" }, icon("flag"), label),
      h("pre", { class: "lab-output", style: "margin:0" }, tok),
      h("button", { class: "btn btn-sm", type: "button", onclick: () => copyText(tok) }, icon("copy"), "Copy token"));
  }

  token.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); go(); } });
  const form = h("form", { class: "panel", onsubmit: (e) => { e.preventDefault(); go(); } },
    token,
    h("details", { class: "options", style: "margin:12px 0" }, h("summary", {}, icon("sliders"), "Secret wordlist (optional)"),
      h("div", { class: "options-body" }, h("div", { class: "toggle-text" }, h("strong", {}, "Wordlist file"), h("span", {}, "For the HMAC secret search, beyond the built-in common secrets.")), wordlist)),
    h("div", { class: "lab-controls" }, run),
    h("div", { class: "muted lab-tip" }, "A JWT is only base64, not encrypted - anyone can read it. Check tokens from challenges or your own test apps."),
    err);

  render(h("section", {},
    h("div", { class: "hero" }, h("h1", {}, "JWT inspector"),
      h("p", {}, "Decode a JSON Web Token, flag its weaknesses, and recover a weak signing secret.")),
    form, out));
  if (token.value.trim()) go(); else token.focus();
}

/* ---- pcap / network tab in the file analyser ---- */

function fileNetwork(r) {
  const p = r.pcap;
  if (!p || p.error) return h("div", { class: "panel" }, h("div", { class: "empty" }, p?.error || "Not a readable capture."));
  const table = (title, head, rows, note) => h("div", { class: "panel" }, h("h3", {}, title),
    note ? h("p", { class: "muted" }, note) : null,
    rows.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, head.map((x) => h("th", {}, x)))), h("tbody", {}, rows)))
      : h("p", { class: "muted" }, "None."));
  const parts = [];
  if (p.credentials.length) {
    parts.push(h("div", { class: "panel" }, h("h3", {}, `Credentials sent in the clear (${p.credentials.length})`),
      h("p", { class: "muted" }, "These protocols don't encrypt, so usernames and passwords travelled in plaintext."),
      h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Protocol", "Server", "Data"].map((x) => h("th", {}, x)))),
        h("tbody", {}, p.credentials.map((c) => h("tr", { class: "flag-row-hit" },
          h("td", {}, h("span", { class: "tag warn" }, c.protocol)), h("td", { class: "mono" }, c.server),
          h("td", { class: "mono" }, highlightFlags(c.data, r.flags),
            " ", h("button", { class: "btn btn-sm btn-ghost", type: "button", onclick: () => copyText(c.data) }, icon("copy"))))))))));
  }
  parts.push(h("div", { class: "tiles" },
    tile("Packets", "neutral", p.packets.toLocaleString(), p.truncated ? "Truncated at the limit." : "Total in the capture."),
    tile("Credentials", p.credentials.length ? "bad" : "good", String(p.credentials.length), p.credentials.length ? "Plaintext logins found." : "None in the clear."),
    tile("DNS lookups", "neutral", String(p.dns.length), "Distinct names queried."),
    tile("HTTP requests", "neutral", String(p.http.length), "Captured plaintext HTTP.")));
  parts.push(table("Protocols", ["Protocol", "Packets"], p.protocols.map((x) => h("tr", {}, h("td", {}, x.name), h("td", {}, x.packets.toLocaleString())))));
  parts.push(table("Top talkers", ["Host", "Packets"], p.top_talkers.map((x) => h("tr", {}, h("td", { class: "mono" }, x.host), h("td", {}, x.packets.toLocaleString())))));
  if (p.dns.length) parts.push(table("DNS queries", ["Name", "Count"], p.dns.map((x) => h("tr", {},
    h("td", { class: "mono" }, highlightFlags(x.name, r.flags), " ",
      h("button", { class: "btn btn-sm btn-ghost send", type: "button", title: "Send to decoder", onclick: () => sendToDecoder(x.name) }, "decode")),
    h("td", {}, x.count)))));
  if (p.http.length) parts.push(table("HTTP requests", ["Method", "Host", "Path", "From → To"],
    p.http.map((x) => h("tr", {}, h("td", {}, x.method), h("td", { class: "mono" }, x.host),
      h("td", { class: "mono" }, highlightFlags(x.path, r.flags)), h("td", { class: "mono muted" }, `${x.src} → ${x.dst}`))),
    "URLs and paths often carry tokens or flags."));
  return h("div", {}, parts);
}

/* ================================================================== settings */

function flagFormatsPanel(s) {
  const box = h("textarea", { class: "lab-input mono", rows: "5", spellcheck: "false", "aria-label": "Flag formats, one per line" });
  box.value = (s.flag_formats || []).join("\n");
  const generic = h("input", { type: "checkbox", checked: s.flag_generic });
  const msg = h("div", { class: "form-error", role: "alert" });
  const save = async () => {
    msg.textContent = "";
    try {
      const fresh = await api.put("/api/settings", { flag_formats: box.value.split("\n"), flag_generic: generic.checked });
      state.settings = fresh;
      box.value = fresh.flag_formats.join("\n");
      toast("Flag formats saved");
    } catch (ex) { msg.textContent = ex.message; }
  };
  return h("div", { class: "panel" },
    h("h3", {}, "CTF flag formats"),
    h("p", { class: "muted" }, "The Lab highlights anything matching these. Write them the way the CTF announces them: ",
      h("code", {}, "picoCTF{...}"), ". Start a line with ", h("code", {}, "re:"), " for a regular expression."),
    box,
    h("label", { class: "toggle inline", style: "margin:10px 0" }, generic, h("span", { class: "switch" }),
      h("span", {}, "Also flag anything shaped like xyz{…} as a possible flag")),
    h("div", {}, h("button", { class: "btn btn-primary", type: "button", onclick: save }, "Save formats")),
    msg);
}

async function showSettings() {
  render(h("div", { class: "empty" }, h("span", { class: "spinner", style: "display:inline-block" })));
  let s;
  try { s = await api.get("/api/settings"); } catch (ex) { render(h("div", { class: "empty" }, ex.message)); return; }

  const status = h("div", {});
  const keyInput = h("input", { type: "password", class: "domain-input", placeholder: "Paste your HIBP API key", autocomplete: "off", spellcheck: "false", "aria-label": "HIBP API key" });
  const msg = h("div", { class: "form-error", role: "alert" });

  function drawStatus() {
    status.replaceChildren(s.hibp_key_set
      ? h("div", { class: "verdict good" }, `Using Have I Been Pwned (key ${s.hibp_key_masked}${s.hibp_key_source === "environment" ? ", from the HIBP_API_KEY environment variable" : ""}).`)
      : h("div", { class: "verdict warn" }, "No key set. Using XposedOrNot (free, about 25 email checks per hour)."));
  }
  async function save(value) {
    msg.textContent = "";
    try {
      s = await api.put("/api/settings", { hibp_api_key: value });
      keyInput.value = "";
      drawStatus();
      toast(value ? "API key saved" : "API key removed");
    } catch (ex) { msg.textContent = ex.message; }
  }
  drawStatus();

  render(h("section", { class: "settings" },
    h("div", { class: "hero" }, h("h1", {}, "Settings"), h("p", {}, "Optional extras. Everything works without changing anything here.")),
    h("div", { class: "panel" },
      h("h3", {}, "Have I Been Pwned API key"),
      h("p", { class: "muted" }, "Email checks use the free XposedOrNot service by default. If you have a ",
        h("a", { href: "https://haveibeenpwned.com/API/Key", target: "_blank", rel: "noopener noreferrer" }, "Have I Been Pwned API key"),
        ", add it here for HIBP's breach data and higher limits. The key is stored only on this computer."),
      status,
      h("form", { class: "domain-row", style: "margin-top:12px", onsubmit: (e) => { e.preventDefault(); if (keyInput.value.trim()) save(keyInput.value.trim()); } },
        keyInput,
        h("button", { class: "btn btn-primary", type: "submit" }, "Save key"),
        s.hibp_key_source === "settings" ? h("button", { class: "btn btn-danger", type: "button", onclick: () => save(null) }, "Remove") : null),
      msg),
    flagFormatsPanel(s),
    h("div", { class: "panel" },
      h("h3", {}, "Privacy"),
      h("ul", { class: "plain" },
        h("li", {}, "Everything runs on this computer. The app only listens on 127.0.0.1."),
        h("li", {}, "Password checks happen inside this page. Only the first 5 characters of the password's SHA-1 hash are sent (k-anonymity); the password is never sent or saved."),
        h("li", {}, "Scan history is stored in: ", h("code", {}, s.data_dir)))),
    h("div", { class: "panel" },
      h("h3", {}, "Use it responsibly"),
      h("p", { class: "muted", style: "margin:0" }, "Scan domains you own or have permission to test, and check email addresses that are yours or whose owner agreed. Breach data is shown at the level of which sites leaked what; actual leaked passwords are never retrieved."))));
}

/* ================================================================== boot */

(async function boot() {
  try {
    const info = await api.get("/api/info");
    document.getElementById("sideFoot").textContent = `v${info.version} · runs locally on your PC`;
  } catch { /* ignore */ }
  await loadHistory();
  route();
  refreshBadge();
  setInterval(() => { if (state.running.length) loadHistory(); }, 4000);
  setInterval(refreshBadge, 20000);
})();
