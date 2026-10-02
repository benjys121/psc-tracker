const view = document.getElementById("view");
const PW_KEY = "psc-tracker-pw";
const SEEN_KEY = "psc-tracker-seen";
const PENDING_KEY = "psc-tracker-pending";
const MARKER = "requested from the dashboard"; // the Slack bot looks for this (psc/slackbot.py)
let DATA = null; // decrypted bundle: { cases: [...], briefings: [...], webhook }
let BUILT_AT = null;
let PASSWORD = null;

/* ---------- helpers ---------- */

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const parseDay = (iso) => (iso ? new Date(iso.slice(0, 10) + "T12:00:00") : null);
const shortDate = (iso) => {
  const d = parseDay(iso);
  if (!d) return "—";
  const sameYear = d.getFullYear() === new Date().getFullYear();
  return `${MONTHS[d.getMonth()]} ${d.getDate()}${sameYear ? "" : ` ’${String(d.getFullYear()).slice(2)}`}`;
};
const longDate = (iso) =>
  parseDay(iso)?.toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric", year: "numeric" }) ?? "";
const relDay = (iso) => {
  const d = parseDay(iso);
  if (!d) return "";
  const today = new Date();
  today.setHours(12, 0, 0, 0);
  const days = Math.round((today - d) / 864e5);
  return days === 0 ? "Today" : days === 1 ? "Yesterday" : days < 7 ? `${days} days ago` : "";
};

// Browser storage can be missing or blocked (private windows); everything still works without it.
const storage = {
  get(key, fallback) {
    try {
      const v = localStorage.getItem(key);
      return v == null ? fallback : JSON.parse(v);
    } catch {
      return fallback;
    }
  },
  set(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch {}
  },
  remove(key) {
    try {
      localStorage.removeItem(key);
    } catch {}
  },
};

function setNav(which) {
  document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("on", a.dataset.nav === which));
}

/* ---------- unlocking ---------- */

const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function decrypt(blob, password) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64(blob.salt), iterations: blob.iter, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  const gz = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(blob.iv) }, key, b64(blob.ct)); // throws on a wrong password
  const text = await new Response(new Blob([gz]).stream().pipeThrough(new DecompressionStream("gzip"))).text();
  return JSON.parse(text);
}

async function fetchBlob() {
  const res = await fetch(`data.enc.json?t=${Date.now()}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Couldn't load the data (${res.status})`);
  return res.json();
}

function showLock(message = "") {
  document.body.classList.add("locked");
  view.innerHTML = `
    <form class="track lock" id="lock">
      <label for="pw">Password</label>
      <div class="track-row">
        <input id="pw" type="password" autocomplete="current-password" required autofocus>
        <button class="btn" type="submit">Unlock</button>
      </div>
      <label class="remember"><input type="checkbox" id="remember" checked> Remember me on this device</label>
      <div class="problems" id="problems">${esc(message)}</div>
    </form>`;
  document.getElementById("lock").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector("button");
    const pw = document.getElementById("pw").value;
    const remember = document.getElementById("remember").checked; // the form is gone once unlocked
    btn.disabled = true;
    btn.textContent = "Unlocking…";
    try {
      await unlock(pw);
      if (remember) storage.set(PW_KEY, pw);
    } catch (err) {
      showLock(err.name === "OperationError" ? "That password didn't work." : err.message);
    }
  });
}

async function unlock(pw) {
  const blob = await fetchBlob();
  DATA = await decrypt(blob, pw);
  PASSWORD = pw;
  BUILT_AT = blob.built_at;
  document.body.classList.remove("locked");
  document.getElementById("updated").textContent = BUILT_AT
    ? `Updated ${shortDate(BUILT_AT)}, ${new Date(BUILT_AT).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" })}`
    : "";
  route();
}

document.getElementById("lockbtn").addEventListener("click", () => {
  storage.remove(PW_KEY);
  DATA = null;
  showLock();
});

/* ---------- "new since your last visit" (per browser) ---------- */

const seenMap = () => storage.get(SEEN_KEY, {});
function lastSeen(c) {
  const seen = seenMap()[c.case];
  if (seen != null) return seen;
  // Never opened on this device: treat the last two days of filings as new.
  const cutoff = new Date(Date.now() - 2 * 864e5).toISOString().slice(0, 10);
  const older = c.filings.filter((f) => (f.date || "") < cutoff);
  return older.length ? Math.max(...older.map((f) => f.filing_seq)) : 0;
}
function markSeen(c) {
  const map = seenMap();
  map[c.case] = Math.max(0, ...c.filings.map((f) => f.filing_seq));
  storage.set(SEEN_KEY, map);
}

/* ---------- track / untrack (sent through Slack; the bot on the Mac applies them) ---------- */

function normalizeCase(raw) {
  const s = (raw || "").replace(/\s+/g, "").toUpperCase();
  let m = s.match(/^(\d{2})-([A-Z]{1,2})-(\d{1,4})$/);
  if (m) return `${m[1]}-${m[2]}-${m[3].padStart(4, "0")}`;
  m = s.match(/^(\d{2})-(\d{1,5})$/);
  return m ? `${m[1]}-${m[2].padStart(5, "0")}` : null;
}

const isTracked = (caseNo) => DATA.cases.some((c) => c.case === caseNo);

// Pending requests, dropped once the published data reflects them (or after an hour).
function pending() {
  const now = Date.now();
  const list = storage
    .get(PENDING_KEY, [])
    .filter((p) => now - p.at < 36e5 && (p.action === "track" ? !isTracked(p.case) : isTracked(p.case)));
  storage.set(PENDING_KEY, list);
  return list;
}
const pendingFor = (caseNo) => pending().find((p) => p.case === caseNo);

async function sendCommand(action, cases) {
  if (!DATA.webhook) throw new Error("Tracking from the dashboard isn't set up (no Slack webhook).");
  // Slack's webhook sends no CORS headers, so post a form-encoded payload in no-cors mode.
  // The response is unreadable; the bot confirms in the Slack thread.
  await fetch(DATA.webhook, {
    method: "POST",
    mode: "no-cors",
    body: new URLSearchParams({ payload: JSON.stringify({ text: `${action} ${cases.join(", ")} — ${MARKER}` }) }),
  });
  const list = storage.get(PENDING_KEY, []).filter((p) => !cases.includes(p.case));
  cases.forEach((c) => list.push({ action, case: c, at: Date.now() }));
  storage.set(PENDING_KEY, list);
  watchForUpdates();
}

// While requests are pending, re-download the published data and re-render when it changes.
let refreshTimer = null;
function watchForUpdates() {
  if (refreshTimer) return;
  refreshTimer = setInterval(async () => {
    if (!pending().length) {
      clearInterval(refreshTimer);
      refreshTimer = null;
      return;
    }
    try {
      const blob = await fetchBlob();
      if (blob.built_at === BUILT_AT) return;
      DATA = await decrypt(blob, PASSWORD);
      BUILT_AT = blob.built_at;
      route(false);
    } catch {}
  }, 45000);
}

async function onTrack(e) {
  e.preventDefault();
  const form = e.target;
  const problems = document.getElementById("problems");
  const tokens = form.cases.value.split(/[\s,]+/).filter(Boolean);
  const bad = tokens.filter((t) => !normalizeCase(t));
  const cases = [...new Set(tokens.map(normalizeCase).filter(Boolean))];
  const already = cases.filter(isTracked);
  const toAdd = cases.filter((c) => !isTracked(c));
  const notes = [
    ...bad.map((t) => `“${t}” doesn't look like a case number (try 25-E-0375).`),
    ...already.map((c) => `${c} is already tracked.`),
  ];
  if (!toAdd.length) {
    problems.innerHTML = notes.map(esc).join("<br>") || "Enter a case number.";
    return;
  }
  const btn = form.querySelector("button");
  btn.disabled = true;
  try {
    await sendCommand("track", toAdd);
    renderWatchlist();
    document.getElementById("problems").innerHTML = notes.map(esc).join("<br>");
  } catch (err) {
    problems.textContent = err.message;
    btn.disabled = false;
  }
}

async function onUntrack(caseNo) {
  if (!confirm(`Stop tracking ${caseNo}? This posts to the Slack channel for everyone.`)) return;
  try {
    await sendCommand("untrack", [caseNo]);
  } catch (err) {
    alert(err.message);
  }
  route(false);
}

/* ---------- watchlist ---------- */

function filingRow(f, seen) {
  const doc = f.documents[0] || {};
  const extra = f.documents.length > 1 ? ` <span class="meta">+${f.documents.length - 1} more</span>` : "";
  return `<li class="${f.filing_seq > seen ? "new" : ""}">
    <span class="when">${shortDate(f.date)}</span>
    <div>
      <div class="what"><span class="type">${esc(f.doc_type)}</span><a class="doc" href="${esc(doc.url)}" target="_blank" rel="noopener">${esc(doc.title)}</a>${extra}</div>
      <div class="meta">${esc(f.filer_short || f.filer)}</div>
    </div></li>`;
}

function watchCard(c) {
  const m = c.meta || {};
  const seen = lastSeen(c);
  const newCount = c.filings.filter((f) => f.filing_seq > seen).length;
  const kind = [m.industry, m.subtype || m.type].filter(Boolean).join(" · ");
  const latest = c.filings[0]?.date;
  const rel = relDay(latest);
  return `<article class="watch" data-case="${esc(c.case)}">
    <div class="watch-side">
      <a class="caseno" href="#/case/${esc(c.case)}">${esc(c.case)}</a>
      <div class="kicker">${esc(kind)}</div>
      ${
        pendingFor(c.case)
          ? `<span class="tag ink">Removing…</span>`
          : newCount
          ? `<span class="tag gold">${newCount} new</span>`
          : `<span class="tag">Up to date</span>`
      }
      <div class="count">${c.filings.length.toLocaleString()} filings${latest ? ` · last ${rel ? rel.toLowerCase() : shortDate(latest)}` : ""}</div>
    </div>
    <div class="watch-main">
      <h2><a href="#/case/${esc(c.case)}">${esc(m.title || c.case)}</a></h2>
      <div class="who">${esc(m.companies || "")}</div>
      <ul class="filings">${c.filings.slice(0, 6).map((f) => filingRow(f, seen)).join("")}</ul>
      <div class="actions">
        <a class="textbtn" href="#/case/${esc(c.case)}">All ${c.filings.length.toLocaleString()} filings</a>
        ${newCount ? `<button class="textbtn" data-act="seen">Mark as read</button>` : ""}
        <a class="textbtn quiet" href="${esc(m.url)}" target="_blank" rel="noopener">Open on DPS ↗</a>
        ${pendingFor(c.case) ? "" : `<button class="textbtn quiet" data-act="untrack">Stop tracking</button>`}
      </div>
    </div>
  </article>`;
}

function renderWatchlist() {
  setNav("watch");
  const cases = [...DATA.cases].sort((a, b) => (b.filings[0]?.date || "").localeCompare(a.filings[0]?.date || ""));
  const totalNew = cases.reduce((n, c) => n + c.filings.filter((f) => f.filing_seq > lastSeen(c)).length, 0);
  const adding = pending().filter((p) => p.action === "track");
  view.innerHTML = `
    <form class="track" id="track">
      <label for="cases">Track a proceeding</label>
      <div class="track-row">
        <input id="cases" name="cases" autocomplete="off" placeholder="25-E-0375" required>
        <button class="btn" type="submit">Track</button>
      </div>
      <p class="hint">One or more PSC case numbers, separated by commas. The request goes to the Slack channel, the bot confirms there, and the case appears here in a few minutes. You can also post <code>track 25-E-0375</code> in Slack.</p>
      <div class="problems" id="problems"></div>
    </form>
    <h2 class="section-head">Tracked cases</h2>
    ${adding
      .map(
        (p) => `<article class="watch pending"><div class="watch-side"><span class="caseno">${esc(p.case)}</span><span class="tag ink">Adding…</span></div>
        <div class="watch-main"><p class="who">Requested ${Math.max(1, Math.round((Date.now() - p.at) / 6e4))} min ago. The bot confirms in Slack (or says if the case doesn't exist), and the full history appears here once the dashboard rebuilds, usually within five minutes. This page checks automatically.</p></div></article>`
      )
      .join("")}
    ${
      !cases.length && !adding.length
        ? `<div class="empty"><p><strong>Nothing tracked yet.</strong> Add a case number above.</p></div>`
        : (totalNew
            ? `<p class="dek"><strong>${totalNew} new filing${totalNew === 1 ? "" : "s"}</strong> since your last visit.</p>`
            : `<p class="dek">No new filings in the ${cases.length} tracked case${cases.length === 1 ? "" : "s"} since your last visit.</p>`) +
          cases.map(watchCard).join("")
    }`;
  document.getElementById("track").addEventListener("submit", onTrack);
  view.querySelectorAll('[data-act="untrack"]').forEach((btn) =>
    btn.addEventListener("click", () => onUntrack(btn.closest(".watch").dataset.case))
  );
  view.querySelectorAll('[data-act="seen"]').forEach((btn) =>
    btn.addEventListener("click", () => {
      markSeen(DATA.cases.find((c) => c.case === btn.closest(".watch").dataset.case));
      renderWatchlist();
    })
  );
}

/* ---------- case page ---------- */

const PAGE = 60;

function renderCase(caseNo) {
  setNav("watch");
  const c = DATA.cases.find((x) => x.case === caseNo);
  if (!c) {
    view.innerHTML = `<a class="textbtn back" href="#/">← Tracked cases</a>
      <div class="empty"><p><strong>${esc(caseNo)} isn't tracked${pendingFor(caseNo) ? " yet. It's been requested and will appear here in a few minutes" : ""}.</strong>
      <a class="doc" href="https://documents.dps.ny.gov/public/MatterManagement/CaseMaster.aspx?MatterCaseNo=${encodeURIComponent(caseNo)}" target="_blank" rel="noopener">Open it on the DPS site</a>.</p>
      ${pendingFor(caseNo) ? "" : `<button class="btn" id="trackbtn">Track ${esc(caseNo)}</button>`}</div>`;
    document.getElementById("trackbtn")?.addEventListener("click", async () => {
      await sendCommand("track", [caseNo]).catch((err) => alert(err.message));
      renderCase(caseNo);
    });
    return;
  }
  const m = c.meta || {};
  const seen = lastSeen(c);
  const types = {};
  c.filings.forEach((f) => (types[f.doc_type] = (types[f.doc_type] || 0) + 1));
  const topTypes = Object.entries(types).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const state = { type: null, q: "", shown: PAGE };

  view.innerHTML = `
    <a class="textbtn back" href="#/">← Tracked cases</a>
    <header class="case-head">
      <div class="kicker">${esc([m.industry, m.type, m.subtype].filter(Boolean).join(" · "))}</div>
      <h1>${esc(m.title)}</h1>
      <dl class="facts">
        <div><dt>Case</dt><dd class="caseno">${esc(c.case)}</dd></div>
        <div><dt>Parties</dt><dd>${esc(m.companies || "—")}</dd></div>
        <div><dt>Opened</dt><dd>${esc(longDate(m.opened) || "—")}</dd></div>
        <div><dt>Filings</dt><dd>${c.filings.length.toLocaleString()} · latest ${esc(shortDate(c.filings[0]?.date))}</dd></div>
      </dl>
      <div class="case-actions">
        <a class="btn ghost" href="${esc(m.url)}" target="_blank" rel="noopener">Open on DPS ↗</a>
        <span class="kicker">Tracked since ${esc(shortDate(c.added_at))}</span>
        ${pendingFor(c.case) ? `<span class="tag ink">Removing…</span>` : `<button class="textbtn quiet" id="untrackbtn">Stop tracking</button>`}
      </div>
    </header>
    <div class="filters">
      <input id="q" type="search" placeholder="Search titles and filers" aria-label="Search filings">
      <button class="chip on" data-type="">All<span class="n">${c.filings.length}</span></button>
      ${topTypes.map(([t, n]) => `<button class="chip" data-type="${esc(t)}">${esc(t)}<span class="n">${n}</span></button>`).join("")}
    </div>
    <div id="timeline"></div>`;

  const timeline = document.getElementById("timeline");
  const draw = () => {
    const q = state.q.toLowerCase();
    const rows = c.filings.filter(
      (f) =>
        (!state.type || f.doc_type === state.type) &&
        (!q || f.filer.toLowerCase().includes(q) || f.documents.some((d) => d.title.toLowerCase().includes(q)))
    );
    const byDay = [];
    rows.slice(0, state.shown).forEach((f) => {
      const last = byDay[byDay.length - 1];
      if (last && last.date === f.date) last.items.push(f);
      else byDay.push({ date: f.date, items: [f] });
    });
    timeline.innerHTML =
      (rows.length ? "" : `<p class="empty">No filings match.</p>`) +
      byDay
        .map(
          (d) => `<section class="day">
        <div class="day-label">${shortDate(d.date)}<small>${esc(relDay(d.date) || parseDay(d.date)?.toLocaleDateString("en-US", { weekday: "long" }) || "")}</small></div>
        <div>${d.items
          .map((f) => {
            const isNew = f.filing_seq > seen;
            return `<div class="filing${isNew ? " new" : ""}">
              <div class="head">${isNew ? '<span class="tag gold">New</span> ' : ""}<span class="type">${esc(f.doc_type)}</span> · <b>${esc(f.filer_short || f.filer)}</b> · item ${esc(f.item_no)}</div>
              <ul>${f.documents
                .map(
                  (doc) =>
                    `<li><a class="doc" href="${esc(doc.url)}" target="_blank" rel="noopener">${esc(doc.title)}</a><span class="size">${esc(doc.ext)}${doc.size ? ` · ${esc(doc.size)}` : ""}</span></li>`
                )
                .join("")}</ul></div>`;
          })
          .join("")}</div></section>`
        )
        .join("") +
      (rows.length > state.shown
        ? `<div class="more"><button class="btn ghost" id="more">Show ${Math.min(PAGE, rows.length - state.shown)} more of ${(rows.length - state.shown).toLocaleString()}</button></div>`
        : "");
    document.getElementById("more")?.addEventListener("click", () => {
      state.shown += PAGE;
      draw();
    });
  };
  draw();
  markSeen(c); // opening the full case counts as reading it
  document.getElementById("untrackbtn")?.addEventListener("click", () => onUntrack(c.case));

  document.getElementById("q").addEventListener("input", (e) => {
    state.q = e.target.value;
    state.shown = PAGE;
    draw();
  });
  view.querySelectorAll(".chip").forEach((chip) =>
    chip.addEventListener("click", () => {
      view.querySelectorAll(".chip").forEach((x) => x.classList.toggle("on", x === chip));
      state.type = chip.dataset.type || null;
      state.shown = PAGE;
      draw();
    })
  );
}

/* ---------- briefing archive ---------- */

function renderBriefing(day) {
  setNav("briefing");
  const all = DATA.briefings.filter((b) => b.items.length || b.watchlist?.length);
  if (!all.length) {
    view.innerHTML = `<h2 class="section-head">Morning briefings</h2><div class="empty"><p><strong>No briefings yet.</strong> They appear here after each morning post.</p></div>`;
    return;
  }
  const b = all.find((x) => x.date === day) || all[0];
  view.innerHTML = `
    <h2 class="section-head">Morning briefings <span class="tools kicker">${esc(longDate(b.date))}</span></h2>
    <div class="brief-dates">${all
      .slice(0, 20)
      .map((x) => `<a class="chip${x === b ? " on" : ""}" href="#/briefing/${x.date}" style="text-decoration:none">${shortDate(x.date)}</a>`)
      .join("")}</div>
    ${b.items.length ? `<p class="topline">${esc(b.top_line)}</p>` : `<p class="topline">No major PSC news; new filings in tracked cases only.</p>`}
    <p class="kicker">${(b.filing_count || 0).toLocaleString()} filings reviewed</p>
    ${b.items
      .map(
        (it) => `<article class="item">
      <div class="side"><a class="caseno" href="${esc(it.url)}" target="_blank" rel="noopener">${esc(it.case)}</a></div>
      <div>
        <h2><a href="${esc(it.url)}" target="_blank" rel="noopener">${esc(it.headline)}</a></h2>
        <div class="who">${esc([it.companies, it.kind].filter(Boolean).join(" · "))}${it.comments ? ` · <strong>${it.comments.toLocaleString()} new public comments</strong>` : ""}</div>
        <p class="summary">${esc(it.summary)}</p>
        <ul>${it.filings.map((f) => `<li><a class="doc" href="${esc(f.url || it.url)}" target="_blank" rel="noopener">${esc(f.title)}</a> <span>— ${esc(f.doc_type)}</span></li>`).join("")}</ul>
      </div></article>`
      )
      .join("")}
    ${
      b.watchlist?.length
        ? `<h2 class="section-head">Tracked cases that day</h2>${b.watchlist
            .map(
              (w) => `<article class="item"><div class="side"><a class="caseno" href="#/case/${esc(w.case)}">${esc(w.case)}</a></div>
            <div><div class="who">${esc(w.title || "")}</div><ul>${w.filings
              .map((f) => `<li><a class="doc" href="${esc(f.url || w.url)}" target="_blank" rel="noopener">${esc(f.title)}</a> <span>— ${esc(f.doc_type)}</span></li>`)
              .join("")}</ul></div></article>`
            )
            .join("")}`
        : ""
    }`;
}

/* ---------- router ---------- */

function route(scroll = true) {
  if (!DATA) return;
  const [, page, arg] = location.hash.split("/");
  if (scroll) window.scrollTo(0, 0);
  if (pending().length) watchForUpdates();
  if (page === "case" && arg) renderCase(decodeURIComponent(arg));
  else if (page === "briefing") renderBriefing(arg);
  else renderWatchlist();
}
window.addEventListener("hashchange", () => route());

(async () => {
  const saved = storage.get(PW_KEY, null);
  if (!saved) return showLock();
  view.innerHTML = `<div class="loading"><div class="kicker">Unlocking</div><div class="bar"></div></div>`;
  try {
    await unlock(saved);
  } catch (err) {
    storage.remove(PW_KEY); // password changed since it was saved
    showLock(err.name === "OperationError" ? "The password has changed. Enter the new one." : err.message);
  }
})();
