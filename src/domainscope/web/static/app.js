"use strict";

/* ------------------------------------------------------------------ helpers */

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
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
  tree: '<circle cx="6" cy="6" r="2"/><circle cx="18" cy="12" r="2"/><circle cx="18" cy="19" r="2"/><path d="M6 8v9a2 2 0 002 2h8M6 12h10"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 018 0v4"/>',
  id: '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="12" r="2.5"/><path d="M14 10h4M14 14h4"/>',
  sliders: '<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
  play: '<path d="M7 5l12 7-12 7z"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 012-2h10"/>',
  download: '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
  external: '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 01-1 1H5a1 1 0 01-1-1V7a1 1 0 011-1h5"/>',
  refresh: '<path d="M20 11a8 8 0 10-2.3 5.7M20 4v7h-7"/>',
  trash: '<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>',
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
  main.scrollTop = 0;
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
  toastTimer = setTimeout(() => el.classList.remove("show"), 2200);
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
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
const safeUrl = (u) => (typeof u === "string" && /^https?:\/\//i.test(u) ? u : null);

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
  del: (p) => api.req("DELETE", p),
};

/* ------------------------------------------------------------------ tasks */

const DEFAULT_OPTS = { whois: true, email: true, subdomains: true, passive: false, probe_limit: 25 };

const TASKS = [
  { id: "full", icon: "radar", title: "Full recon", badge: "Recommended",
    desc: "Everything: who owns it, DNS, email security, subdomains and website checks.",
    opts: {} },
  { id: "quiet", icon: "eye", title: "Quiet look",
    desc: "Public sources only. Never connects to the domain's own servers.",
    opts: { passive: true } },
  { id: "email", icon: "mail", title: "Email spoofing check",
    desc: "Can someone send fake email as this domain? Checks SPF, DMARC and MTA-STS.",
    opts: { whois: false, subdomains: false, passive: true } },
  { id: "subs", icon: "tree", title: "Find subdomains",
    desc: "Lists hostnames from public certificate logs and flags takeover risks.",
    opts: { whois: false, email: false, passive: true } },
  { id: "web", icon: "lock", title: "Website security check",
    desc: "Security headers, TLS certificate and server versions for the main site.",
    opts: { whois: false, email: false, subdomains: false, probe_limit: 2 } },
  { id: "owner", icon: "id", title: "Who owns it?",
    desc: "Registrar, creation and expiry dates, name servers and abuse contact.",
    opts: { email: false, subdomains: false, passive: true } },
];

const taskOpts = (t) => ({ ...DEFAULT_OPTS, ...t.opts });
const sameOpts = (a, b) => ["whois", "email", "subdomains", "passive"].every((k) => a[k] === b[k])
  && (a.passive || a.probe_limit === b.probe_limit);

function buildCommand(domain, o) {
  const parts = ["domainscope", domain || "<domain>"];
  if (o.passive) parts.push("--passive");
  if (!o.whois) parts.push("--no-whois");
  if (!o.email) parts.push("--no-email");
  if (!o.subdomains) parts.push("--no-subdomains");
  if (!o.passive && o.probe_limit !== 25) parts.push(`--probe-limit ${o.probe_limit}`);
  return parts.join(" ");
}

function expectedSteps(o) {
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
];
const explain = (title) => EXPLAIN.find(([re]) => re.test(title))?.[1];

/* ------------------------------------------------------------------ state */

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
      h("div", { class: "h-domain" }, h("span", { class: "spinner", style: "width:12px;height:12px;border-width:2px" }), j.domain),
      h("div", { class: "h-meta" }, "scanning…"))));
  }
  for (const s of state.history) {
    const f = s.findings || {};
    items.push(h("li", {}, h("a", { href: `#/scan/${s.id}`, class: s.id === current ? "active" : null },
      h("div", { class: "h-domain" }, s.domain),
      h("div", { class: "h-meta" },
        h("span", {}, relTime(s.started)),
        f.high ? h("span", { class: "sev-dot high", title: "high" }, f.high) : null,
        f.medium ? h("span", { class: "sev-dot medium", title: "medium" }, f.medium) : null,
        s.passive ? h("span", {}, "passive") : null))));
  }
  ul.replaceChildren(...(items.length ? items : [h("li", { class: "history-empty" }, "No scans yet")]));
}

/* ------------------------------------------------------------------ routing */

function route() {
  closeStream();
  const [, view, id] = location.hash.split("/");
  if (view === "scan" && id) showResult(id);
  else if (view === "progress" && id) showProgress(id);
  else showNew();
  drawHistory();
}
window.addEventListener("hashchange", route);

async function startScan(domain, opts) {
  const res = await api.post("/api/scans", { domain, ...opts });
  state.jobs[res.id] = { domain: res.domain, options: opts };
  state.running.unshift({ id: res.id, domain: res.domain, options: opts });
  location.hash = `#/progress/${res.id}`;
}

/* ------------------------------------------------------------------ view: new scan */

function showNew() {
  let opts = { ...DEFAULT_OPTS, ...store.get("ds.opts", {}) };
  const input = h("input", {
    type: "text", class: "domain-input", placeholder: "example.com",
    autocomplete: "off", spellcheck: "false", "aria-label": "Domain to scan",
    value: store.get("ds.lastDomain", ""),
  });
  const err = h("div", { class: "form-error", role: "alert" });
  const runBtn = h("button", { type: "submit", class: "btn btn-primary btn-lg" }, icon("play"), "Run scan");
  const cmd = h("code", {});
  const tasksBox = h("div", { class: "tasks", role: "radiogroup", "aria-label": "What do you want to find out?" });
  const toggles = {};
  const probeOut = h("output", {});
  const probe = h("input", { type: "range", min: "1", max: "100", "aria-label": "Websites to check" });
  const probeRow = h("div", { class: "range-row" },
    h("div", { class: "toggle-text" }, h("strong", {}, "Websites to check"), h("span", {}, "Maximum number of hosts to visit")),
    probe, probeOut);

  function sync() {
    const match = TASKS.find((t) => sameOpts(taskOpts(t), opts));
    for (const card of tasksBox.children) {
      const sel = match && card.dataset.id === match.id;
      card.classList.toggle("selected", !!sel);
      card.querySelector("input").checked = !!sel;
    }
    for (const [k, el] of Object.entries(toggles)) el.checked = k === "web" ? !opts.passive : opts[k];
    probe.value = String(Math.max(1, opts.probe_limit));
    probeOut.textContent = probe.value;
    probeRow.hidden = opts.passive;
    cmd.textContent = buildCommand(input.value.trim(), opts);
    store.set("ds.opts", opts);
  }

  for (const t of TASKS) {
    tasksBox.append(h("label", { class: "task", "data-id": t.id },
      h("input", { type: "radio", name: "task", value: t.id, onchange: () => { opts = taskOpts(t); sync(); } }),
      t.badge ? h("span", { class: "task-badge" }, t.badge) : null,
      h("div", { class: "task-head" }, h("span", { class: "task-icon" }, icon(t.icon)), t.title),
      h("div", { class: "task-desc" }, t.desc)));
  }

  const toggle = (key, title, desc) => {
    const box = h("input", {
      type: "checkbox",
      onchange: () => {
        if (key === "web") opts.passive = !box.checked; else opts[key] = box.checked;
        sync();
      },
    });
    toggles[key] = box;
    return h("label", { class: "toggle" }, box, h("span", { class: "switch" }),
      h("span", { class: "toggle-text" }, h("strong", {}, title), h("span", {}, desc)));
  };

  probe.addEventListener("input", () => { opts.probe_limit = Number(probe.value); sync(); });
  input.addEventListener("input", () => { err.textContent = ""; sync(); });

  const form = h("form", {
    novalidate: true,
    onsubmit: async (e) => {
      e.preventDefault();
      const domain = input.value.trim();
      if (!domain) { err.textContent = "Type a domain first, e.g. example.com"; input.focus(); return; }
      runBtn.disabled = true;
      err.textContent = "";
      store.set("ds.lastDomain", domain);
      try { await startScan(domain, { ...opts }); }
      catch (ex) { err.textContent = ex.message; runBtn.disabled = false; }
    },
  },
    h("div", { class: "step-title" }, h("span", { class: "step-num" }, "1"), "What do you want to find out?"),
    tasksBox,
    h("div", { class: "step-title" }, h("span", { class: "step-num" }, "2"), "Which domain?"),
    h("div", { class: "domain-row" }, input),
    h("div", { class: "hint" }, "A domain or a full URL both work. Try: ",
      ["example.com", "github.com", "monash.edu"].map((d, i) => [i ? ", " : "",
        h("button", { type: "button", onclick: () => { input.value = d; sync(); input.focus(); } }, d)])),
    err,
    h("div", { class: "step-title" }, h("span", { class: "step-num" }, "3"), "Fine-tune ", h("span", { class: "opt" }, "(optional)")),
    h("details", { class: "options" },
      h("summary", {}, icon("sliders"), "Choose exactly what to check"),
      h("div", { class: "options-body" },
        toggle("whois", "Registration details", "Owner/registrar, creation and expiry dates (RDAP)"),
        toggle("email", "Email security", "SPF, DMARC, MTA-STS: can the domain be spoofed?"),
        toggle("subdomains", "Find subdomains", "Search public certificate logs (crt.sh, Cert Spotter)"),
        toggle("web", "Visit websites", "Check security headers and TLS certificates. Turn off for a passive scan."),
        probeRow)),
    h("div", { class: "command" }, h("span", { class: "label" }, "Command"), cmd,
      h("button", { type: "button", class: "btn btn-ghost", title: "Copy command", onclick: () => copyText(cmd.textContent) }, icon("copy"), "Copy")),
    h("div", { class: "run-row" }, runBtn,
      h("div", { class: "legal" }, "Only scan domains you own or have permission to test. 'Quiet look' uses public data only.")));

  render(h("section", {},
    h("div", { class: "hero" }, h("h1", {}, "New scan"),
      h("p", {}, "Pick what you want to know, type a domain, and press Run. domainscope does the rest.")),
    form));
  sync();
  input.focus();
}

/* ------------------------------------------------------------------ view: progress */

async function showProgress(id) {
  let job = state.jobs[id] || state.running.find((j) => j.id === id);
  if (!job) {
    await loadHistory();
    job = state.running.find((j) => j.id === id);
    if (!job) { location.hash = `#/scan/${id}`; return; }
  }
  const total = expectedSteps({ ...DEFAULT_OPTS, ...(job.options || {}) });
  let done = 0;

  const bar = h("div", {});
  const timer = h("span", { class: "muted" }, "0s");
  const working = h("li", { class: "step" }, h("span", { class: "spinner" }), h("span", { class: "step-name" }, "Working"),
    h("span", { class: "step-msg" }, "Querying public sources…"));
  const steps = h("ol", { class: "steps" }, working);

  render(h("section", {}, h("div", { class: "progress-card" },
    h("div", { class: "progress-head" }, h("h1", {}, job.domain), timer),
    h("div", { class: "bar" }, bar),
    h("div", { class: "muted" }, "Scanning… certificate-log searches can take up to a minute. You can start other scans meanwhile."),
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

/* ------------------------------------------------------------------ view: result */

let currentTab = "findings";

async function showResult(id) {
  render(h("div", { class: "empty" }, h("span", { class: "spinner", style: "display:inline-block" })));
  let r;
  try { r = await api.get(`/api/scans/${id}`); }
  catch (ex) {
    render(h("div", { class: "empty" }, h("h2", {}, "Scan not found"), h("p", {}, ex.message), h("a", { class: "btn", href: "#/" }, "Start a new scan")));
    return;
  }

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
  if (!tabs.some(([k]) => k === currentTab)) currentTab = "findings";

  const panel = h("div", {});
  const tabBar = h("div", { class: "tabs", role: "tablist" });
  let sevFilter = "all";
  function openTab(key) {
    currentTab = key;
    for (const b of tabBar.children) b.classList.toggle("active", b.dataset.key === key);
    const views = { findings: () => findingsView(r, sevFilter), hosts: () => hostsView(r), dns: () => dnsView(r),
      email: () => emailView(r), web: () => webView(r), whois: () => whoisView(r) };
    panel.replaceChildren(views[key]());
  }
  for (const [key, label, n] of tabs) {
    tabBar.append(h("button", { class: "tab", role: "tab", "data-key": key, onclick: () => openTab(key) },
      label, n != null ? h("span", { class: "count" }, n) : null));
  }

  const del = h("button", { class: "btn btn-danger", type: "button" }, icon("trash"), "Delete");
  let armed = false;
  del.addEventListener("click", async () => {
    if (!armed) {
      armed = true; del.classList.add("confirm"); del.lastChild.textContent = "Click again to delete";
      setTimeout(() => { armed = false; del.classList.remove("confirm"); del.lastChild.textContent = "Delete"; }, 3000);
      return;
    }
    await api.del(`/api/scans/${id}`);
    toast("Scan deleted");
    await loadHistory();
    location.hash = "#/";
  });

  const verdict = counts.high
    ? h("div", { class: "verdict bad" }, `${plural(counts.high, "serious issue")} found. Start with the red items below.`)
    : counts.medium
      ? h("div", { class: "verdict warn" }, `No serious issues, but ${plural(counts.medium, "medium-risk item")} worth fixing.`)
      : h("div", { class: "verdict good" }, "No serious issues found. Remaining items are hardening suggestions.");

  const sevCard = (s) => h("button", { class: `card ${s}`, type: "button", title: `Show ${s} findings`,
    onclick: () => { sevFilter = s; openTab("findings"); } },
    h("div", { class: "n" }, counts[s]), h("div", { class: "l" }, s));

  render(h("section", {},
    h("div", { class: "result-head" },
      h("div", {},
        h("h1", {}, r.meta.domain),
        h("div", { class: "result-meta" },
          h("span", {}, new Date(r.meta.started).toLocaleString()), "·", h("span", {}, `${r.meta.duration_s}s`),
          h("span", { class: `badge ${o.passive ? "" : "accent"}` }, o.passive ? "passive" : "active"))),
      h("div", { class: "actions" },
        h("a", { class: "btn", href: `/api/scans/${id}/report/html`, target: "_blank", rel: "noopener" }, icon("external"), "Open report"),
        h("a", { class: "btn", href: `/api/scans/${id}/report/html?download=true`, download: "" }, icon("download"), "HTML"),
        h("a", { class: "btn", href: `/api/scans/${id}/report/md?download=true`, download: "" }, icon("download"), "Markdown"),
        h("a", { class: "btn", href: `/api/scans/${id}/report/json?download=true`, download: "" }, icon("download"), "JSON"),
        h("button", { class: "btn", type: "button", onclick: async (e) => {
          const btn = e.currentTarget;
          btn.disabled = true;
          try { await startScan(r.meta.domain, o); } catch (ex) { toast(ex.message); btn.disabled = false; }
        } }, icon("refresh"), "Scan again"),
        del)),
    verdict,
    h("div", { class: "cards" }, SEVS.map(sevCard),
      h("div", { class: "card" }, h("div", { class: "n" }, r.summary.hosts_live, h("span", { class: "sub" }, ` / ${r.summary.hosts_total}`)), h("div", { class: "l" }, "hosts live")),
      h("div", { class: "card" }, h("div", { class: "n" }, r.summary.unique_ips), h("div", { class: "l" }, "unique IPs")),
      h("div", { class: "card" }, h("div", { class: "n" }, r.summary.networks), h("div", { class: "l" }, "networks"))),
    tabBar, panel,
    h("div", { class: "command", style: "margin-top:22px" }, h("span", { class: "label" }, "Same scan in terminal"),
      h("code", {}, buildCommand(r.meta.domain, o)),
      h("button", { type: "button", class: "btn btn-ghost", onclick: () => copyText(buildCommand(r.meta.domain, o)) }, icon("copy"), "Copy"))));
  openTab(currentTab);
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

  const errs = Object.entries(r.errors || {});
  return h("div", {},
    h("div", { class: "toolbar" }, chips, search),
    list,
    errs.length ? h("div", { class: "notice" }, h("strong", {}, "Some sources didn't respond: "),
      errs.map(([m, e], i) => [i ? "; " : "", `${m} (${e})`]), ". Results may be incomplete; try scanning again later.") : null);
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
      h("label", { class: "toggle", style: "border:none;padding:0;align-items:center" }, live, h("span", { class: "switch" }), h("span", {}, "Live hosts only")),
      counter),
    src ? h("p", { class: "muted", style: "margin:0 0 10px" }, "Sources: ",
      Object.entries(src.counts).map(([s, n]) => h("span", { class: "tag good" }, `${s}: ${n}`)),
      Object.keys(src.errors).map((s) => h("span", { class: "tag warn", title: src.errors[s] }, `${s}: failed`))) : null,
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Host", "IP addresses", "Points to", "Network", "Website", "Notes"].map((t) => h("th", {}, t)))),
      body)));
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
        h("tbody", {}, recs.map(([t, vals]) => h("tr", {}, h("td", {}, h("strong", {}, t)),
          h("td", {}, vals.map((v) => h("div", {}, h("code", {}, v))))))))) : h("p", { class: "muted" }, "No records found.")));
}

function tile(title, cls, status, text) {
  const tagCls = { good: "good", warn: "note", bad: "warn" }[cls];
  return h("div", { class: `tile ${cls}` },
    h("div", { class: "tile-head" }, title, h("span", { class: `tag ${tagCls}` }, status)),
    h("p", {}, text));
}

function emailView(r) {
  const e = r.email;
  const spf = e.spf;
  const dmarc = e.dmarc;
  const spfTile = !spf ? tile("SPF", "bad", "Missing", "No list of allowed mail senders.")
    : spf.all === "-" ? tile("SPF", "good", "Strict (-all)", "Unlisted senders are rejected.")
    : spf.all === "~" ? tile("SPF", "warn", "Soft (~all)", "Unlisted senders are flagged, not rejected.")
    : spf.all === "+" ? tile("SPF", "bad", "Open (+all)", "Anyone may send as this domain!")
    : tile("SPF", "warn", spf.all ? `${spf.all}all` : "No 'all'", "Unlisted senders are not rejected.");
  const dmarcTile = !dmarc ? tile("DMARC", "bad", "Missing", "Spoofed mail isn't blocked or reported.")
    : dmarc.policy === "reject" ? tile("DMARC", "good", "Reject", "Spoofed mail is rejected.")
    : dmarc.policy === "quarantine" ? tile("DMARC", "good", "Quarantine", "Spoofed mail goes to spam.")
    : tile("DMARC", "warn", `p=${dmarc.policy || "?"}`, "Monitoring only: spoofed mail is still delivered.");
  return h("div", {},
    h("div", { class: "tiles" }, spfTile, dmarcTile,
      tile("MTA-STS", e.mta_sts ? "good" : "warn", e.mta_sts ? "Enabled" : "Off", "Forces encrypted mail delivery."),
      tile("TLS-RPT", e.tls_rpt ? "good" : "warn", e.tls_rpt ? "Enabled" : "Off", "Reports mail-delivery TLS failures.")),
    h("div", { class: "panel" }, h("h3", {}, "Raw records"),
      h("dl", { class: "kv" },
        h("dt", {}, "Receives mail (MX)"), h("dd", {}, e.has_mx ? "Yes" : "No"),
        h("dt", {}, "SPF"), h("dd", {}, spf ? h("code", {}, spf.record) : "—"),
        spf ? [h("dt", {}, "SPF lookups"), h("dd", {}, `${spf.lookup_count} of 10 allowed (top level)`)] : null,
        h("dt", {}, "DMARC"), h("dd", {}, dmarc ? h("code", {}, dmarc.record) : "—"))));
}

function webView(r) {
  const tlsBy = Object.fromEntries((r.tls || []).map((t) => [t.host, t]));
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

/* ------------------------------------------------------------------ boot */

(async function boot() {
  try {
    const info = await api.get("/api/info");
    document.getElementById("sideFoot").textContent = `v${info.version} · runs locally on your PC`;
  } catch { /* ignore */ }
  await loadHistory();
  route();
  setInterval(() => { if (state.running.length) loadHistory(); }, 4000);
})();
