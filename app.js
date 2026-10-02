const view = document.getElementById("view");
const PW_KEY = "psc-tracker-pw";
const SEEN_KEY = "psc-tracker-seen";
let DATA = null; // decrypted bundle: { cases: [...], briefings: [...] }
let BUILT_AT = null;

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
      ${newCount ? `<span class="tag gold">${newCount} new</span>` : `<span class="tag">Up to date</span>`}
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
      </div>
    </div>
  </article>`;
}

function renderWatchlist() {
  setNav("watch");
  const cases = [...DATA.cases].sort((a, b) => (b.filings[0]?.date || "").localeCompare(a.filings[0]?.date || ""));
  const totalNew = cases.reduce((n, c) => n + c.filings.filter((f) => f.filing_seq > lastSeen(c)).length, 0);
  view.innerHTML = `
    <div class="track howto">
      <label>Track a proceeding</label>
      <p>Post <code>track 25-E-0375</code> in the Slack channel. The bot confirms in a thread, and the case shows up here within a few minutes. <code>untrack 25-E-0375</code> removes it; <code>tracked</code> lists everything.</p>
    </div>
    <h2 class="section-head">Tracked cases</h2>
    ${
      !cases.length
        ? `<div class="empty"><p><strong>Nothing tracked yet.</strong> Post <code>track</code> and a case number in Slack to add one.</p></div>`
        : (totalNew
            ? `<p class="dek"><strong>${totalNew} new filing${totalNew === 1 ? "" : "s"}</strong> since your last visit.</p>`
            : `<p class="dek">No new filings in the ${cases.length} tracked case${cases.length === 1 ? "" : "s"} since your last visit.</p>`) +
          cases.map(watchCard).join("")
    }`;
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
      <div class="empty"><p><strong>${esc(caseNo)} isn't tracked.</strong> Post <code>track ${esc(caseNo)}</code> in Slack to add it, or
      <a class="doc" href="https://documents.dps.ny.gov/public/MatterManagement/CaseMaster.aspx?MatterCaseNo=${encodeURIComponent(caseNo)}" target="_blank" rel="noopener">open it on the DPS site</a>.</p></div>`;
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

function route() {
  if (!DATA) return;
  const [, page, arg] = location.hash.split("/");
  window.scrollTo(0, 0);
  if (page === "case" && arg) renderCase(decodeURIComponent(arg));
  else if (page === "briefing") renderBriefing(arg);
  else renderWatchlist();
}
window.addEventListener("hashchange", route);

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
