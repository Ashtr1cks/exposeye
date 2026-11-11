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

const DEFAULT_OPTS = { whois: true, email: true, subdomains: true, passive: false, probe_limit: 25 };

const TASKS = [
  { id: "full", kind: "domain", icon: "radar", title: "Full recon", badge: "Recommended",
    desc: "Everything: who owns it, DNS, email security, subdomains and website checks.", opts: {} },
  { id: "quiet", kind: "domain", icon: "eye", title: "Quiet look",
    desc: "Public sources only. Never connects to the domain's own servers.", opts: { passive: true } },
  { id: "emailsec", kind: "domain", icon: "mail", title: "Email spoofing check",
    desc: "Can someone send fake email as this domain? Checks SPF, DMARC and MTA-STS.",
    opts: { whois: false, subdomains: false, passive: true } },
  { id: "subs", kind: "domain", icon: "tree", title: "Find subdomains",
    desc: "Lists hostnames from public certificate logs and flags takeover risks.",
    opts: { whois: false, email: false, passive: true } },
  { id: "web", kind: "domain", icon: "lock", title: "Website security check",
    desc: "Security headers, TLS certificate and server versions for the main site.",
    opts: { whois: false, email: false, subdomains: false, probe_limit: 2 } },
  { id: "owner", kind: "domain", icon: "id", title: "Who owns it?",
    desc: "Registrar, creation and expiry dates, name servers and abuse contact.",
    opts: { email: false, subdomains: false, passive: true } },
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
const sameOpts = (a, b) => ["whois", "email", "subdomains", "passive"].every((k) => a[k] === b[k])
  && (a.passive || a.probe_limit === b.probe_limit);
const matchDomainTask = (opts) => TASKS.find((t) => t.kind === "domain" && sameOpts(taskOpts(t), opts));

function buildCommand(domain, o) {
  const parts = ["domainscope", domain || "<domain>"];
  if (o.passive) parts.push("--passive");
  if (!o.whois) parts.push("--no-whois");
  if (!o.email) parts.push("--no-email");
  if (!o.subdomains) parts.push("--no-subdomains");
  if (!o.passive && o.probe_limit !== 25) parts.push(`--probe-limit ${o.probe_limit}`);
  return parts.join(" ");
}

function expectedSteps(job) {
  if (job.kind === "email") return 3;
  const o = { ...DEFAULT_OPTS, ...(job.options || {}) };
  return (o.whois ? 1 : 0) + 1 + (o.email ? 1 : 0) + (o.subdomains ? 1 : 0) + 2 + (o.passive ? 1 : 2);
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
  [/^Wildcard DNS/, "Every subdomain resolves, even made-up ones. domainscope marks those hosts so they aren't mistaken for real systems."],
  [/^Recently registered/, "Newly registered domains are often used for phishing. Be careful if this isn't a domain you recognise."],
  [/^Domain registration expires soon/, "If the registration lapses, anyone could register the domain and take over its email and website."],
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

const state = { stream: null, tick: null, jobs: {}, history: [], running: [] };

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
  clearTimeout(state.monitorTimer);
  const [, view, id] = location.hash.split("/");
  if (view === "scan" && id) showResult(id);
  else if (view === "progress" && id) showProgress(id);
  else if (view === "compare" && id) showCompare(id);
  else if (view === "monitor") showMonitor();
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
      : kind === "email" ? `domainscope-email ${input.value.trim() || "<email>"}`
      : "domainscope-email --password";
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
      h("p", {}, "Pick what you want to know, fill in the blank, and press the button. domainscope does the rest.")),
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

async function showResult(id) {
  render(h("div", { class: "empty" }, h("span", { class: "spinner", style: "display:inline-block" })));
  let r;
  try { r = await api.get(`/api/scans/${id}`); }
  catch (ex) {
    render(h("div", { class: "empty" }, h("h2", {}, "Scan not found"), h("p", {}, ex.message), h("a", { class: "btn", href: "#/" }, "Start a new scan")));
    return;
  }
  const isEmail = r.meta.kind === "email";
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
    tabState[kind] = key;
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
    ["dns", "DNS", null],
    r.email ? ["email", "Email security", null] : null,
    http.length ? ["web", "Websites & TLS", http.length] : null,
    r.rdap || r.errors?.whois ? ["whois", "Registration", null] : null,
  ].filter(Boolean);
  let sevFilter = "all";
  const t = tabbed("domain", tabs, {
    findings: () => findingsView(r, sevFilter), hosts: () => hostsView(r), dns: () => dnsView(r),
    email: () => domainEmailView(r.email), web: () => webView(r), whois: () => whoisView(r),
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
      h("thead", {}, h("tr", {}, ["Host", "IP addresses", "Points to", "Network", "Website", "Notes"].map((x) => h("th", {}, x)))),
      body)));
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
    commandBox("Same check in terminal", `domainscope-email ${r.meta.email}`)));
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
      h("p", {}, "Watch domains you own and your own email addresses. domainscope re-checks them on a schedule and tells you what changed.")),
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

/* ================================================================== settings */

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
