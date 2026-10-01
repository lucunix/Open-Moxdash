'use strict';
// Open Moxdash frontend: a dependency-free single-page UI. It polls /api/status every
// page.fast_refresh_seconds, rebuilds the panels from the JSON it gets back, and handles
// Proxmox login and UPnP port-mapping management against the routes in app.js.
//
// Layout: the Checks and Port mappings panels side by side, then one Proxmox panel per
// cluster node. Which panels appear depends on /api/config (what the server has
// configured; UPnP counts as configured only once you are logged in). Every
// server-supplied value goes through esc() before reaching innerHTML.

// Feature flags and page settings from /api/config. Loaded at startup and again whenever the
// login state changes, because the server reports UPnP as off until you are logged in.
let cfg = {};

// Same CIDR test as app.js; used to hide mappings outside network.subnet.
function ipInCidr(ip, cidr) {
  try {
    const [net, bits] = cidr.split('/');
    const mask = bits ? ~((1 << (32 - parseInt(bits))) - 1) >>> 0 : 0xffffffff;
    const toInt = s => s.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0) >>> 0;
    return (toInt(ip) & mask) === (toInt(net) & mask);
  } catch (_) { return false; }
}

let lastTs      = null;  // slow timestamp — "updated X ago"
let lastFastTs  = null;  // fast timestamp — render trigger
let lastTsEpoch = null;
let metaStatus  = 'loading';
let metaErr     = '';
// Login state mirrored from the server. The session itself is an HttpOnly cookie that
// this script can't read; the server's answers are the only source of truth.
let authState = { authenticated: false, username: null, canSeeAllMappings: false, allowedIps: [], ipLinks: {} };
// UPnP is invisible until login: no UPnP row in the Checks panel and no Port mappings panel,
// as if it were switched off. The server already withholds the data; this also keeps a
// stale config from showing it for a moment.
const upnpVisible = () => !!(cfg.upnp?.enabled && authState.authenticated);
// Not persisted anywhere on purpose — resets to locked on every page load.
let addMappingUnlocked = false;
let lastRenderData = null;

// Countdown target per mapping (key -> {leaseDuration, expiresAt}), kept
// across renders. The router's leaseDuration is a snapshot that only
// actually changes when the mapping list gets re-fetched (~30s, or right
// after an add/delete) — recomputing "now + leaseDuration" on every ~3s
// render would re-anchor the target to the current time using that same
// stale number each time, so "Left" would just track "Lease" forever and
// the countdown would never actually run. Only recompute when the source
// value genuinely changes; otherwise keep ticking from the cached target.
const mappingExpiryCache = new Map();

function getMappingExpiry(m) {
  const key = `${m.protocol}:${m.externalPort}`;
  const cached = mappingExpiryCache.get(key);
  if (cached && cached.leaseDuration === m.leaseDuration) return cached.expiresAt;
  const expiresAt = Date.now() + m.leaseDuration * 1000;
  mappingExpiryCache.set(key, { leaseDuration: m.leaseDuration, expiresAt });
  return expiresAt;
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// Wraps text in a coloured span. cls is one of ok, warn, bad, info, mute or dim (see style.css).
function v(cls, text) { return `<span class="v-${cls}">${esc(text)}</span>`; }

const DASH = '<span class="v-dim">—</span>';

// Threshold colouring — the colour IS the signal, so values need no badge chrome.
// Cut-offs: percentages warn at 70 and go bad at 90; latency 20 / 50 ms; temperature 60 / 75 °C.
function pctClass(p)  { return p >= 90 ? 'bad' : p >= 70 ? 'warn' : 'ok'; }
function msClass(ms)  { return ms >= 50 ? 'bad' : ms >= 20 ? 'warn' : 'ok'; }
function tempClass(t) { return t >= 75 ? 'bad' : t >= 60 ? 'warn' : 'ok'; }

function pctVal(p) {
  if (p == null) return DASH;
  return v(pctClass(p), `${p}%`);
}

// Fixed-width meter, used only where proportion genuinely aids a glance
// (host CPU/RAM). A full-width bar for a 0% idle disk is pure noise.
function meter(pct) {
  const w = Math.min(100, Math.max(0, pct ?? 0));
  return `<span class="meter"><i data-pct="${w}"></i></span>`;
}
function meterColor(pct) {
  return pct >= 90 ? 'var(--bad)' : pct >= 70 ? 'var(--warn)' : 'var(--ok)';
}

// Scales a bytes/s value to whichever unit reads best — B/s up through
// TB/s. Takes bytes/s specifically (not KB/s or MB/s) because that's the
// finest unit actually displayed — the backend measures in it directly
// (see checks/disk.js) rather than pre-rounding to some coarser unit, so
// there's no floor below B/s where precision could quietly vanish.
function formatRate(bytesPerSec) {
  let bytes = bytesPerSec;
  // KiB/MiB/GiB/TiB (IEC binary prefixes), not KB/MB/GB/TB — the latter
  // technically implies powers of 1000, but this divides by 1024.
  const units = ['B/s', 'KiB/s', 'MiB/s', 'GiB/s', 'TiB/s'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
  const decimals = bytes === 0 ? 0 : bytes < 10 ? 2 : bytes < 100 ? 1 : 0;
  return `${bytes.toFixed(decimals)} ${units[i]}`;
}

// Seconds to the two most significant units: "3d 4h", "2h 5m", "12m 5s", "45s".
function formatDuration(totalS) {
  const d = Math.floor(totalS / 86400);
  const h = Math.floor((totalS % 86400) / 3600);
  const m = Math.floor((totalS % 3600) / 60);
  const s = totalS % 60;
  return d ? `${d}d ${h}h`
       : h ? `${h}h ${m}m`
       : m ? `${m}m ${s}s`
       :     `${s}s`;
}

function uptime(secs) {
  if (!secs) return DASH;
  return esc(formatDuration(secs));
}

// Power-on hours to a compact age: "5h", "12d" or "3y 40d". Null stays null.
function formatPoh(h) {
  if (h == null) return null;
  const days = Math.floor(h / 24);
  if (days === 0) return `${h}h`;
  const years = Math.floor(days / 365);
  if (years === 0) return `${days}d`;
  return `${years}y ${days % 365}d`;
}

function fmtIface(s) {
  if (!s) return null;
  return s === 'nvme' ? 'NVMe' : s.toUpperCase();
}

// Lease field: bare number = seconds, "10m" = minutes, "1h" = hours.
// null for anything unparseable so it never silently becomes 0 (= permanent).
function parseLeaseInput(raw) {
  const s = raw.trim();
  if (s === '') return null;
  const m = s.match(/^(\d+)\s*(m|h)?$/i);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  const unit = (m[2] || '').toLowerCase();
  return unit === 'h' ? n * 3600 : unit === 'm' ? n * 60 : n;
}

function panel(title, bodyHtml, note) {
  return `<div class="panel">
    <div class="panel-head">
      <span class="panel-title">${esc(title)}</span>
      ${note ? `<span class="panel-note">${note}</span>` : ''}
    </div>
    ${bodyHtml}
  </div>`;
}

function kvItem(label, valHtml) {
  return `<div class="kv-item"><span class="kv-l">${esc(label)}</span><span class="kv-v">${valHtml}</span></div>`;
}

// Metered variant: grows to fill leftover width so the bar gets as long — and
// therefore as precise — as the layout allows.
function kvMeter(label, pct, numHtml) {
  return `<div class="kv-item grow"><span class="kv-l">${esc(label)}</span>` +
         `<span class="kv-v">${meter(pct)}<span class="kv-num">${numHtml}</span></span></div>`;
}

// Column-pruning table builder: a column whose every cell is empty across all
// rows is dropped entirely, so we never render a wall of "—" (SAS drives often
// report no SMART temperature or health, for instance).
// colDefs: [{ label, raw(item), cell(item, raw)?, num?, cls?, always? }]. `always` keeps
// a column even when empty. scrollKey identifies the table so render() can restore its
// horizontal scroll position after the DOM is rebuilt.
function dataTable(colDefs, items, scrollKey) {
  const cols = colDefs.filter(c =>
    c.always || items.some(it => {
      const raw = c.raw(it);
      return raw !== null && raw !== undefined && raw !== '';
    })
  );
  // Trailing filler column absorbs all slack, so real columns hug their
  // content and stay near each other instead of being stretched apart.
  const head = cols.map(c => `<th class="${c.num ? 'num' : ''}">${esc(c.label)}</th>`).join('') + '<th class="fill"></th>';
  const body = items.map(it =>
    `<tr>${cols.map(c => {
      const raw = c.raw(it);
      const html = (raw === null || raw === undefined || raw === '')
        ? DASH
        : (c.cell ? c.cell(it, raw) : esc(String(raw)));
      return `<td class="${c.num ? 'num' : ''}${c.cls ? ' ' + c.cls : ''}">${html}</td>`;
    }).join('')}<td class="fill"></td></tr>`
  ).join('');
  return `<div class="scroll-x" data-scroll-key="${esc(scrollKey)}"><table class="dt"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

// ── Checks panel ──────────────────────────────────────────────────────────────
// Reachability, DNS, DHCP and configured service checks were four separate
// floating cards, each half-empty. They are all the same shape of thing —
// "did X answer, how fast" — so they belong in one aligned table you can scan
// down in a single pass.

function lastOkText(res) {
  return (res && res.ok === false && res.lastOkAt)
    ? `${formatDuration(Math.floor((Date.now() - res.lastOkAt) / 1000))} ago`
    : null;
}

function cap(s) { s = String(s ?? ''); return s.charAt(0).toUpperCase() + s.slice(1); }

function pending() { return '<span class="ph">Checking…</span>'; }

function latencyCell(res) {
  if (!res) return pending();
  if (!res.ok) return v('bad', res.detail || 'FAIL');
  const ms = parseInt(res.detail);
  return isNaN(ms) ? v('ok', res.detail) : v(msClass(ms), res.detail);
}

// Builds the Checks panel: gateway, broadcast, internet, Proxmox UI, DNS, DHCP, UPnP and
// custom service checks in one table. `data` is the display cache from /api/status (null
// before the first cycle). Returns '' when there is nothing to show.
function renderChecks(data) {
  // Rows are collected as data first so the "last ok" column can be dropped
  // entirely when nothing is failing — same pruning rule as the other tables.
  const entries = [];   // {group} | {name, target, cell, lastOk}
  const push = (name, target, cell, res) =>
    entries.push({ name, target, cell, lastOk: lastOkText(res) });

  const netRows = [];
  const collectNet = (name, target, cell, res) => netRows.push({ name, target, cell, lastOk: lastOkText(res) });
  const gw = data?.network?.gateway;
  if (cfg.network?.gateway) collectNet('Gateway', gw?.host, latencyCell(gw), gw);
  const bc = data?.network?.broadcast;
  if (cfg.network?.broadcast) collectNet('Broadcast', bc?.host, latencyCell(bc), bc);
  const inet = data?.network?.internet;
  collectNet('Internet', '1.1.1.1', latencyCell(inet), inet);
  const pve = data?.services?.proxmox_ui;
  if (cfg.proxmox?.uiCheck) {
    collectNet('Proxmox UI', null, pve ? (pve.ok ? latencyCell(pve) : v('bad', 'Unreachable')) : pending(), pve);
  }
  if (netRows.length) { entries.push({ group: 'Network' }); entries.push(...netRows); }

  const dnsEntries = Object.entries(cfg.dns || {}).filter(([, s]) => s);
  if (dnsEntries.length) {
    entries.push({ group: 'DNS' });
    for (const [label] of dnsEntries) {
      const d = data?.dns?.[label];
      push(cap(label), d?.server, latencyCell(d), d);
    }
  }

  if (cfg.dhcp?.enabled) {
    const d = data?.services?.dhcp;
    entries.push({ group: 'DHCP' });
    push('Server', d?.offeredIp ? `Offered ${d.offeredIp}` : null,
      d ? v(d.ok ? 'ok' : 'bad', d.detail) : pending(), d);
  }

  // UPnP is the same shape of question — "did it answer, and did the probe
  // pass" — so it lives here rather than in a half-empty panel of its own.
  if (upnpVisible()) {
    const u = data?.services?.upnp;
    entries.push({ group: 'UPnP' });
    if (!u) {
      push('IGD', null, pending(), null);
    } else {
      push('IGD', null, v(u.igdDetected ? 'ok' : 'bad', u.igdDetected ? 'Detected' : 'Not found'), u);
      const pt = u.portTest || {};
      const parts = [];
      if (pt.added    !== undefined) parts.push(`Add ${pt.added ? 'OK' : 'failed'}`);
      if (pt.verified !== undefined) parts.push(`Verify ${pt.verified ? 'OK' : 'failed'}`);
      if (pt.expired  !== null && pt.expired !== undefined) parts.push(`Lease ${pt.expired ? 'honoured' : 'ignored'}`);
      push('Port map probe', parts.join(' · ') || null,
        (pt.added && pt.verified) ? v('ok', 'Passed') : v('bad', 'Failed'), null);
    }
  }

  const checkEntries = Object.entries(cfg.checks || {});
  if (checkEntries.length) {
    entries.push({ group: 'Services' });
    for (const [label, opts] of checkEntries) {
      const r = (data?.serviceChecks ?? []).find(x => x.label === label);
      let cell;
      if (!r) cell = pending();
      else if (opts.type === 'tls') cell = v(!r.ok ? 'bad' : r.warn ? 'warn' : 'ok', r.detail || 'FAIL');
      else cell = r.ok ? latencyCell(r) : v('bad', r.detail || 'FAIL');
      push(cap(label), cap(opts.type), cell, r);
    }
  }

  if (!entries.length) return '';

  const anyLastOk = entries.some(e => e.lastOk);
  const span = (anyLastOk ? 4 : 3) + 1;   // +1 for the filler column
  const body = entries.map(e => e.group
    ? `<tr class="grp"><td colspan="${span}">${esc(e.group)}</td></tr>`
    : `<tr>
        <td class="lbl">${esc(e.name)}</td>
        <td class="v-mute wide">${e.target ? `<span class="fit">${esc(e.target)}</span>` : ''}</td>
        <td class="res">${e.cell}</td>
        ${anyLastOk ? `<td class="num">${e.lastOk ? v('dim', e.lastOk) : ''}</td>` : ''}
        <td class="fill"></td>
      </tr>`
  ).join('');

  return panel('Checks', `<div class="scroll-x" data-scroll-key="checks"><table class="dt">
    <thead><tr><th>Check</th><th class="wide">Target</th><th class="res">Result</th>${anyLastOk ? '<th class="num">Last OK</th>' : ''}<th class="fill"></th></tr></thead>
    <tbody>${body}</tbody></table></div>`);
}

// The Checks table hugs its content so Result sits next to Target instead of at the far edge
// of a wide panel, with some extra space in front of Result (--res-pad, 52px by default).
// A panel too narrow for that would scroll sideways, so in that case the extra space shrinks
// by the overflow (never below the normal cell padding), and only if that is not enough does
// the table get `squeeze`, which lets the Target column wrap its text (see style.css).
// Runs after every render, and again when the window or the fonts change the available width.
function fitChecksTable() {
  const box   = document.querySelector('.scroll-x[data-scroll-key="checks"]');
  const table = box?.querySelector('table.dt');
  if (!table) return;
  table.classList.remove('squeeze');
  table.style.removeProperty('--res-pad');
  const over = () => box.scrollWidth - box.clientWidth;
  const o = over();
  if (o <= 0) return;
  const wanted = parseFloat(getComputedStyle(table.querySelector('th.res')).paddingLeft);
  const floor  = parseFloat(getComputedStyle(table.querySelector('th')).paddingLeft);
  table.style.setProperty('--res-pad', Math.max(floor, wanted - o - 1) + 'px');
  if (over() > 0) table.classList.add('squeeze');
}

// ── Host panel ────────────────────────────────────────────────────────────────

function renderCpuDetail(sockets, keyPrefix) {
  if (!sockets?.length) return '';
  const socketTable = dataTable([
    { label: 'Socket', always: true, raw: s => `#${s.id}` },
    { label: 'Model',  raw: s => s.model, cell: (s, m) => {
      const full  = m.replace(/\s*@.*$/, '');
      const short = full.replace(/\bIntel\(R\)\s*/gi, '').replace(/\bXeon\(R\)\s*/gi, '').replace(/\bCPU\s*/gi, '').trim();
      return `<span class="v-mute"><span class="cpu-model-full">${esc(full)}</span><span class="cpu-model-short">${esc(short)}</span></span>`;
    } },
    { label: 'Threads', num: true, raw: s => s.cores?.length ?? null },
    { label: 'Usage',  num: true, always: true, raw: s => s.usage, cell: (s) => pctVal(s.usage) },
    { label: 'Temp',   num: true, raw: s => s.temp, cell: (s, t) => v(tempClass(t), `${t}°C`) },
  ], sockets, `${keyPrefix}-cpu`);

  // The per-thread grid is the one payload big enough (dozens of logical CPUs on a
  // server) to warrant collapsing, so it sits behind a <details>.
  const totalCores = sockets.reduce((n, s) => n + (s.cores?.length || 0), 0);
  const coreBlocks = sockets.map(s => `
    <div class="core-grid">${(s.cores || []).map((c, i) => `
      <div class="core-row">
        <span class="ci">#${i}</span>
        ${c.mhz != null ? `<span class="cg">${(c.mhz / 1000).toFixed(2)} GHz</span>` : ''}
        <span class="cu">${pctVal(c.usage)}</span>
      </div>`).join('')}
    </div>`).join('');

  return socketTable + `<details class="more" data-key="${keyPrefix}-cores">
    <summary>Per-thread detail (${totalCores})</summary>${coreBlocks}</details>`;
}

function renderDisks(disks, keyPrefix) {
  if (!disks?.length) return '';
  return dataTable([
    { label: 'Model',  always: true, raw: d => d.model, cell: (d, m) => v('mute', m) },
    { label: 'Size',   num: true, raw: d => d.size },
    { label: 'Bus',    raw: d => fmtIface(d.iface) },
    { label: 'Temp',   num: true, raw: d => d.temp, cell: (d, t) => v(tempClass(t), `${t}°C`) },
    { label: 'Health', raw: d => d.health,
      cell: (d, h) => v(h === 'PASSED' ? 'ok' : h === 'FAILED' ? 'bad' : 'dim', h) },
    { label: 'Util',   num: true, always: true, raw: d => d.utilPct, cell: d => pctVal(d.utilPct) },
    { label: 'Read',   num: true, always: true, cls: 'rate-cell', raw: d => d.readBps,
      cell: d => d.readBps > 0 ? v('info', formatRate(d.readBps)) : v('dim', formatRate(0)) },
    { label: 'Write',  num: true, always: true, cls: 'rate-cell', raw: d => d.writeBps,
      cell: d => d.writeBps > 0 ? v('info', formatRate(d.writeBps)) : v('dim', formatRate(0)) },
    { label: 'Powered on', num: true, raw: d => formatPoh(d.powerOnHours) },
    { label: 'Wear',   num: true, raw: d => d.wearPct, cell: (d, w) => v(pctClass(w), `${w}%`) },
    { label: 'Spare',  num: true, raw: d => d.availableSpare, cell: (d, s) => v(s < 20 ? 'warn' : 'ok', `${s}%`) },
    { label: 'Realloc', num: true, raw: d => d.reallocated, cell: (d, n) => v(n > 0 ? 'warn' : 'dim', n) },
    { label: 'Pending', num: true, raw: d => d.pendingSectors, cell: (d, n) => v(n > 0 ? 'warn' : 'dim', n) },
    { label: 'Uncorr', num: true, raw: d => d.uncorrectable, cell: (d, n) => v(n > 0 ? 'bad' : 'dim', n) },
    { label: 'Media err', num: true, raw: d => d.mediaErrors, cell: (d, n) => v(n > 0 ? 'bad' : 'dim', n) },
  ], disks, `${keyPrefix}-disks`);
}

function renderGpus(gpus, keyPrefix) {
  if (!gpus?.length) return '';
  return dataTable([
    { label: '#',     always: true, raw: g => g.id, cell: (g, id) => v('dim', id + 1) },
    { label: 'GPU',   always: true, raw: g => g.name },
    { label: 'Util',  num: true, always: true, raw: g => g.util, cell: g => pctVal(g.util) },
    { label: 'Power', num: true, raw: g => (g.powerDraw != null && g.powerLimit != null) ? g.powerDraw : null,
      cell: g => `${g.powerDraw} <span class="v-dim">/ ${g.powerLimit} W</span>` },
    { label: 'VRAM',  num: true, raw: g => (g.memUsedMib != null && g.memTotalMib != null) ? g.memUsedMib : null,
      cell: g => `${(g.memUsedMib / 1024).toFixed(1)} <span class="v-dim">/ ${(g.memTotalMib / 1024).toFixed(1)} GB</span>` },
    { label: 'Fan',   num: true, raw: g => g.fanSpeed, cell: (g, f) => v(pctClass(f), `${f}%`) },
    { label: 'vGPU',  num: true, raw: g => g.vgpuMax != null ? g.vgpuActive : null,
      cell: g => `${g.vgpuActive} <span class="v-dim">/ ${g.vgpuMax}</span>` },
    { label: 'Alloc', raw: g => g.allocated === true ? 'Yes' : null, cell: () => v('warn', 'Yes') },
  ], gpus, `${keyPrefix}-gpus`);
}

// One node's panel body: a headline strip (CPU, RAM, swap, uptime, topology), then CPU,
// disk and GPU sub-sections, then a dim footer with model and version strings.
// keyPrefix keeps the ids/scroll keys of different nodes apart.
function renderNodeBody(nd, keyPrefix) {
  const h = nd?.host;
  if (!h)     return `<div class="empty">Checking…</div>`;
  if (!h.ok)  return `<div class="empty">${v('bad', `Node offline (${h.error || 'unknown'})`)}</div>`;

  // Headline numbers: one dense strip, no card-per-metric.
  const items = [];
  items.push(kvMeter('CPU', h.cpu, pctVal(h.cpu)));
  items.push(kvMeter('RAM', h.memPct, `<span class="v-mute">${h.memUsedGb} / ${h.memTotalGb} GB</span>`));
  if (h.swapTotalGb > 0) items.push(kvMeter('Swap', h.swapPct, `<span class="v-mute">${h.swapUsedGb} / ${h.swapTotalGb} GB</span>`));
  items.push(kvItem('Uptime', uptime(h.uptimeSeconds)));
  if (h.threads) items.push(kvItem('Topology', v('mute', `${h.sockets}p / ${h.cores}c / ${h.threads}t`)));

  // Long, low-priority strings collapse into one dim footer line instead of
  // eating a full table row each.
  const meta = [];
  if (h.cpuModel)      meta.push(esc(h.cpuModel));
  if (h.kernelVersion) meta.push(esc(h.kernelVersion));
  if (h.pveVersion)    meta.push(esc(h.pveVersion));

  const sub = (label, html) => html ? `<div class="subhead">${esc(label)}</div>${html}` : '';

  return `<div class="kv">${items.join('')}</div>`
    + sub('CPU',   renderCpuDetail(nd?.cpuCores, keyPrefix))
    + sub('Disks', renderDisks(nd?.disks, keyPrefix))
    + sub('GPUs',  renderGpus(nd?.gpus, keyPrefix))
    + (meta.length ? `<div class="meta-line">${meta.join('<span class="sep">·</span>')}</div>` : '');
}

// Node names in cluster order (nodeOrder), or whatever nodes have data.
function nodeNames(data) {
  return data?.nodeOrder?.length ? data.nodeOrder : Object.keys(data?.nodes || {});
}

// The Proxmox section: a single panel for a standalone host, one panel per node in a cluster.
function renderHost(data) {
  if (!cfg.proxmox?.enabled) return '';
  const nodes = data?.nodes || {};
  const names = nodeNames(data);
  if (names.length === 0) return panel('Proxmox host', '<div class="empty">Checking…</div>');

  // Single node — flat, nothing to collapse.
  if (names.length === 1) {
    const nd = nodes[names[0]];
    return panel('Proxmox host', renderNodeBody(nd, `host-${names[0]}`), esc(names[0]));
  }

  // Multiple nodes — one panel each, so no node's data is hidden behind a click.
  return names.map(name => {
    const nd = nodes[name];
    const h  = nd?.host;
    const note = h?.ok
      ? `CPU ${h.cpu}% · RAM ${h.memPct}% · up ${formatDuration(h.uptimeSeconds || 0)}`
      : (h ? 'Error' : '…');
    return panel(`Node ${name}`, renderNodeBody(nd, `host-${name}`), esc(note));
  }).join('');
}

// ── UPnP ──────────────────────────────────────────────────────────────────────

// The add-mapping form, shown only to logged-in users who own a VM/CT with a known IP (or
// are privileged). It is a convenience: the server re-validates every field and every
// permission.
function renderAddMappingForm() {
  // Requirement 1 (logged in) + requirement 2 (owns an IP-reporting VM/CT);
  // privileged accounts bypass requirement 2, same as delete.
  const eligible = authState.authenticated &&
    (authState.canSeeAllMappings || authState.allowedIps.length > 0);
  if (!eligible) return '';

  const lockHtml = authState.canSeeAllMappings
    ? `<span class="lock ${addMappingUnlocked ? 'unlocked' : 'locked'}" id="mapping-lock-btn"
         title="${addMappingUnlocked
           ? 'Unlocked — rules bypassed, click to lock'
           : 'Locked — normal rules apply, click to unlock'}"
       >${addMappingUnlocked ? 'UNLOCKED' : 'LOCKED'}</span>`
    : '';

  // Free-text IP only in the privileged+unlocked bypass state; otherwise you
  // pick from your own IPs. The server re-enforces this either way.
  const clientField = (addMappingUnlocked && authState.canSeeAllMappings)
    ? `<input id="mapping-client" type="text" placeholder="internal IP" autocomplete="off">`
    : `<select id="mapping-client">${authState.allowedIps.map(ip => `<option value="${esc(ip)}">${esc(ip)}</option>`).join('')}</select>`;

  return `<form id="add-mapping-form" class="addmap">
    <span class="addmap-l">Add</span>
    ${lockHtml}
    <input id="mapping-desc" type="text" placeholder="name" maxlength="64" autocomplete="off">
    <select id="mapping-proto"><option value="TCP">TCP</option><option value="UDP">UDP</option></select>
    <input id="mapping-iport" type="number" placeholder="int" min="1" max="65535">
    <input id="mapping-eport" type="number" placeholder="ext" min="1" max="65535">
    ${clientField}
    <input id="mapping-lease" type="text" placeholder="lease e.g. 1h" autocomplete="off">
    <button type="submit" class="add-mapping-btn">add</button>
    <span id="add-mapping-error" class="addmap-err"></span>
  </form>`;
}

// The Port mappings panel, shown only to logged-in users: the mappings the server sent
// (already filtered to this user), narrowed to network.subnet unless upnp.show_all_ports is
// set, each with a live lease countdown and a delete button.
function renderMappings(data) {
  if (!upnpVisible()) return '';
  const u = data?.services?.upnp;
  if (!u) return '';

  let body;
  const showAll = cfg.upnp?.show_all_ports;
  const subnet  = cfg.network?.subnet;
  const visible = (u.mappings ?? []).filter(m =>
    showAll || !subnet || !m.internalClient ? true : ipInCidr(m.internalClient, subnet));

  // Drop cache entries for mappings that no longer exist, so a deleted
  // mapping's slot doesn't linger forever and a re-added one with the
  // same protocol/port starts its countdown fresh rather than inheriting
  // a stale target.
  const liveKeys = new Set(visible.map(m => `${m.protocol}:${m.externalPort}`));
  for (const key of mappingExpiryCache.keys()) {
    if (!liveKeys.has(key)) mappingExpiryCache.delete(key);
  }

  if (!visible.length) {
    body = `<div class="empty">${u.igdDetected ? 'No active port mappings' : 'No IGD detected'}</div>`;
  } else {
    body = dataTable([
      { label: 'Name', always: true, raw: m => m.description, cls: 'name-cell',
        cell: (m, d) => `<span class="v-mute" title="${esc(d)}">${esc(d)}</span>` },
      { label: 'Proto',  always: true, raw: m => m.protocol },
      { label: 'Int',    always: true, num: true, raw: m => m.internalPort },
      { label: 'Ext',    always: true, num: true, raw: m => m.externalPort },
      { label: 'Client', always: true, raw: m => m.internalClient,
        // Links to the Proxmox UI for the VM/CT that owns this IP (server
        // resolves the vmid — the client never knew it), not the IP itself,
        // since a VM's LAN address usually isn't running its own web server.
        cell: (m, c) => authState.ipLinks[c]
          ? `<a class="v-info client-link" href="${esc(authState.ipLinks[c])}" target="_blank" rel="noopener noreferrer" title="Open in Proxmox">${esc(c)}</a>`
          : (authState.allowedIps.includes(c) ? v('info', c) : esc(c)) },
      { label: 'Lease',  always: true, num: true, raw: m => m.leaseDuration,
        cell: m => m.leaseDuration === 0 ? v('dim', 'Permanent') : esc(formatDuration(m.leaseDuration)) },
      { label: 'Left',   always: true, num: true, raw: m => m.leaseDuration,
        cell: m => {
          if (m.leaseDuration === 0) return DASH;
          const expiresAt  = getMappingExpiry(m);
          const remaining  = Math.max(0, Math.round((expiresAt - Date.now()) / 1000));
          return `<span class="lease-left" data-expires="${expiresAt}">${esc(formatDuration(remaining))}</span>`;
        } },
      { label: '', always: true, num: true, raw: () => 1,
        cell: m => `<button class="del-btn" title="Delete mapping (shift-click to skip confirmation)"
          data-protocol="${esc(m.protocol)}" data-port="${esc(String(m.externalPort))}">✕</button>` },
    ], visible, 'mappings');
  }

  let warns = '';
  for (const c of (u.compliance ?? [])) {
    warns += `<div class="warnbox"><b>${esc(c.issue)}</b> <span>${esc(c.detail)}</span></div>`;
  }

  const count = u.mappings?.length ?? 0;
  return panel('Port mappings', warns + renderAddMappingForm() + body,
    count ? esc(`${count} active`) : '');
}

// ── Render ───────────────────────────────────────────────────────────────────

const ADD_MAPPING_FIELD_IDS = ['mapping-desc', 'mapping-proto', 'mapping-iport', 'mapping-eport', 'mapping-client', 'mapping-lease'];

// Rebuilds the whole page from `data`, then restores UI state a rebuild would wipe: open
// <details>, add-mapping form input and focus, and horizontal table scroll.
function render(data) {
  lastRenderData = data;

  const openKeys = new Set();
  for (const el of document.querySelectorAll('details[data-key]')) {
    if (el.open) openKeys.add(el.dataset.key);
  }

  // The ~3s poll rebuilds #root wholesale — without this, typing into the
  // add-mapping form would be wiped mid-keystroke.
  const formValues = {};
  const focusedId  = document.activeElement?.id;
  for (const id of ADD_MAPPING_FIELD_IDS) {
    const el = document.getElementById(id);
    if (el) formValues[id] = el.value;
  }

  // Same problem for horizontal scroll on wide tables (mostly a mobile
  // thing) — every table gets a stable data-scroll-key precisely so this
  // can find the same logical table again after the DOM is rebuilt, even
  // though the actual elements are brand new each time.
  const scrollPos = new Map();
  for (const el of document.querySelectorAll('.scroll-x[data-scroll-key]')) {
    scrollPos.set(el.dataset.scrollKey, el.scrollLeft);
  }

  const checks   = renderChecks(data);
  const mappings = renderMappings(data);
  const host     = renderHost(data);

  let html = '';
  if (checks || mappings) html += `<div class="cols2">${checks}${mappings}</div>`;
  if (host) html += host;

  document.getElementById('root').innerHTML = html || '<div class="empty">No checks configured.</div>';
  fitChecksTable();

  // Meter fills applied via DOM API (inline style= is blocked by CSP)
  for (const el of document.querySelectorAll('.meter > i[data-pct]')) {
    const pct = parseFloat(el.dataset.pct);
    el.style.width      = pct + '%';
    el.style.background = meterColor(pct);
  }

  for (const el of document.querySelectorAll('details[data-key]')) {
    if (openKeys.has(el.dataset.key)) el.open = true;
  }
  for (const el of document.querySelectorAll('.scroll-x[data-scroll-key]')) {
    const saved = scrollPos.get(el.dataset.scrollKey);
    if (saved) el.scrollLeft = saved;
  }
  for (const id of ADD_MAPPING_FIELD_IDS) {
    const el = document.getElementById(id);
    if (el && formValues[id] !== undefined) el.value = formValues[id];
  }
  if (focusedId && ADD_MAPPING_FIELD_IDS.includes(focusedId)) {
    document.getElementById(focusedId)?.focus();
  }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

// Login form when logged out; username and logout button when logged in.
function renderAuthArea() {
  const el = document.getElementById('auth-area');
  if (authState.authenticated) {
    el.innerHTML = `<span id="auth-user">${esc(authState.username)}</span>
      <button id="logout-btn">logout</button>`;
    document.getElementById('logout-btn').onclick = doLogout;
  } else {
    el.innerHTML = `<form id="login-form">
        <input id="login-user" type="text" placeholder="username" autocomplete="username">
        <input id="login-pass" type="password" placeholder="password" autocomplete="current-password">
        <button type="submit" id="login-btn">login</button>
      </form>
      <span id="auth-error"></span>`;
    document.getElementById('login-form').onsubmit = doLogin;
  }
}

async function doLogin(e) {
  e.preventDefault();
  const raw      = document.getElementById('login-user').value.trim();
  const password = document.getElementById('login-pass').value;
  const errEl    = document.getElementById('auth-error');
  const btn      = document.getElementById('login-btn');

  // Realm resolution: `root` logs in against the pam realm, everyone else against the
  // built-in pve realm, so accounts in other realms (LDAP, AD...) can't sign in here.
  const username = raw === 'root' ? 'root@pam' : `${raw}@pve`;

  errEl.textContent = '';
  btn.textContent   = '…';
  btn.disabled      = true;

  try {
    const r = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const json = await r.json();
    if (json.ok) {
      authState = {
        authenticated: true, username: json.username,
        canSeeAllMappings: !!json.canSeeAllMappings, allowedIps: json.allowedIps || [], ipLinks: json.ipLinks || {},
      };
      addMappingUnlocked = false;
      await loadConfig();
      renderAuthArea();
      lastTs = null;
      await fetchStatus(true);
    } else {
      errEl.textContent = json.error || 'Login failed';
      btn.textContent   = 'login';
      btn.disabled      = false;
    }
  } catch (_) {
    errEl.textContent = 'Network error';
    btn.textContent   = 'login';
    btn.disabled      = false;
  }
}

async function doLogout() {
  await fetch('/api/auth/logout', { method: 'POST' });
  authState = { authenticated: false, username: null, canSeeAllMappings: false, allowedIps: [], ipLinks: {} };
  addMappingUnlocked = false;
  await loadConfig();
  renderAuthArea();
  lastTs = null;
  await fetchStatus(true);
}

// ── Mapping actions ───────────────────────────────────────────────────────────

async function onRootClick(e) {
  const lockBtn = e.target.closest('#mapping-lock-btn');
  if (lockBtn) {
    // Client-side UI state only — the server re-checks privilege on every
    // request and ignores a bypass flag from a non-privileged session.
    addMappingUnlocked = !addMappingUnlocked;
    render(lastRenderData);
    return;
  }

  const btn = e.target.closest('.del-btn');
  if (!btn) return;

  const protocol     = btn.dataset.protocol;
  const externalPort = Number(btn.dataset.port);
  if (!e.shiftKey && !confirm(`Delete port mapping ${protocol}/${externalPort}?`)) return;

  btn.disabled    = true;
  btn.textContent = '…';
  try {
    const r = await fetch('/api/upnp/delete-mapping', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ protocol, externalPort }),
    });
    const json = await r.json();
    if (!json.ok) {
      alert(json.error || 'Delete failed');
      btn.disabled    = false;
      btn.textContent = '✕';
      return;
    }
    lastTs = null;
    await fetchStatus(true);
  } catch (_) {
    alert('Network error');
    btn.disabled    = false;
    btn.textContent = '✕';
  }
}

async function onRootSubmit(e) {
  const form = e.target.closest('#add-mapping-form');
  if (!form) return;
  e.preventDefault();

  const errEl = document.getElementById('add-mapping-error');
  errEl.textContent = '';

  const description    = document.getElementById('mapping-desc').value.trim();
  const protocol       = document.getElementById('mapping-proto').value;
  const internalPort   = Number(document.getElementById('mapping-iport').value);
  const externalPort   = Number(document.getElementById('mapping-eport').value);
  const internalClient = document.getElementById('mapping-client').value.trim();
  const leaseRaw       = document.getElementById('mapping-lease').value;
  const leaseDuration  = parseLeaseInput(leaseRaw);

  // No silent default: an empty or unparseable lease is an error, since
  // guessing here would quietly create a mapping with a duration the user
  // never asked for.
  if (leaseDuration === null) {
    errEl.textContent = leaseRaw.trim() === ''
      ? 'Lease is required — a number of seconds, or a number + m/h (e.g. 10m, 1h)'
      : 'Lease must be a number, or a number + m/h (e.g. 10m, 1h)';
    return;
  }

  const btn = form.querySelector('.add-mapping-btn');
  btn.disabled    = true;
  btn.textContent = '…';

  try {
    const r = await fetch('/api/upnp/add-mapping', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        description, protocol, internalPort, externalPort, internalClient, leaseDuration,
        bypass: addMappingUnlocked,
      }),
    });
    const json = await r.json();
    if (!json.ok) {
      errEl.textContent = json.error || 'Add failed';
      btn.disabled    = false;
      btn.textContent = 'add';
      return;
    }
    document.getElementById('mapping-desc').value  = '';
    document.getElementById('mapping-iport').value = '';
    document.getElementById('mapping-eport').value = '';
    lastTs = null;
    await fetchStatus(true);
  } catch (_) {
    errEl.textContent = 'Network error';
    btn.disabled    = false;
    btn.textContent = 'add';
  }
}

// ── Meta timestamp ────────────────────────────────────────────────────────────

// The "updated X ago" text in the header. metaStatus is loading, pending (first server
// cycle still running), ok or error.
function renderMeta() {
  const el = document.getElementById('status-meta');
  if (!el) return;
  if (metaStatus === 'error')   { el.textContent = `error: ${metaErr}`; return; }
  if (metaStatus === 'pending') { el.textContent = 'first cycle in progress…'; return; }
  if (!lastTsEpoch)             { el.textContent = 'loading…'; return; }
  const diff = Math.floor((Date.now() - lastTsEpoch) / 1000);
  if (diff < 5)       el.textContent = 'updated just now';
  else if (diff < 60) el.textContent = `updated ${diff}s ago`;
  else                el.textContent = `updated ${Math.floor(diff / 60)}m ${diff % 60}s ago`;
}

// ── Fetch loop ───────────────────────────────────────────────────────────────

// Fetches /api/config and applies the page title. Runs at startup and on every login or
// logout, since UPnP only shows up in it once you are logged in.
async function loadConfig() {
  try {
    const r = await fetch('/api/config');
    cfg = await r.json();
    document.getElementById('page-title').textContent = cfg.page?.title || 'Open Moxdash';
    document.title = cfg.page?.title || 'Open Moxdash';
  } catch (e) {
    console.warn('config fetch failed:', e);
  }
}

// One poll of /api/status: syncs login state, re-renders when the data changed, and updates
// the timestamp and status dot. `force` re-renders even if nothing changed, for after a
// login, logout, add or delete.
async function fetchStatus(force) {
  const dot = document.getElementById('dot');
  try {
    const r    = await fetch('/api/status');
    const json = await r.json();

    if (!json.fastUpdated) {
      metaStatus = 'pending';
      renderMeta();
      dot.className = 'dot pending';
      render(null);
      return;
    }

    // Sync auth state (handles silent session expiry). A change re-renders at once, so UPnP
    // appears or disappears with the login instead of on the next data tick.
    let authFlipped = false;
    if (json.authenticated !== undefined && json.authenticated !== authState.authenticated) {
      authFlipped = true;
      authState.authenticated = json.authenticated;
      if (!json.authenticated) {
        authState.username = null;
        authState.allowedIps = [];
        authState.ipLinks = {};
        authState.canSeeAllMappings = false;
      }
      renderAuthArea();
      await loadConfig();
    }

    // Sync allowed-IP list every poll (e.g. a newly-created VM/CT's IP)
    // without needing to log out and back in — the add-mapping dropdown
    // reads authState.allowedIps on the next natural ~3s re-render below.
    if (json.authenticated) {
      authState.canSeeAllMappings = !!json.canSeeAllMappings;
      authState.allowedIps = json.allowedIps || [];
      authState.ipLinks = json.ipLinks || {};
    }

    // Re-render when fast data changes (~3s), when the login state just changed, or when
    // the caller knows the data changed (login/logout/add/delete) even if the timestamp
    // hasn't moved.
    if (force || authFlipped || json.fastUpdated !== lastFastTs) {
      lastFastTs = json.fastUpdated;
      dot.className = 'dot';
      render(json.data);
    }

    if (json.timestamp !== lastTs) {
      lastTs      = json.timestamp;
      lastTsEpoch = new Date(json.timestamp).getTime();
      metaStatus  = 'ok';
    }
    renderMeta();
  } catch (e) {
    metaStatus = 'error';
    metaErr    = e.message;
    renderMeta();
    dot.className = 'dot error';
  }
}

// Once a second, updates each mapping's "Left" cell from its data-expires timestamp.
function tickLeaseCountdowns() {
  const now = Date.now();
  for (const el of document.querySelectorAll('.lease-left[data-expires]')) {
    const remaining = Math.round((Number(el.dataset.expires) - now) / 1000);
    el.textContent = remaining <= 0 ? 'Expired' : formatDuration(remaining);
  }
}

// Startup: restore any existing login, load config (which depends on it), render, then start
// the poll and clock timers.
async function init() {
  try {
    const r = await fetch('/api/auth/me');
    const j = await r.json();
    if (j.ok) authState = {
      authenticated: true, username: j.username,
      canSeeAllMappings: !!j.canSeeAllMappings, allowedIps: j.allowedIps || [], ipLinks: j.ipLinks || {},
    };
  } catch (_) {}
  await loadConfig();
  renderAuthArea();
  document.getElementById('root').addEventListener('click', onRootClick);
  document.getElementById('root').addEventListener('submit', onRootSubmit);
  render(null);
  await fetchStatus();
  setInterval(fetchStatus, Math.max(1000, (cfg.page?.fast_refresh_seconds || 3) * 1000));
  setInterval(renderMeta, 1000);
  setInterval(tickLeaseCountdowns, 1000);
}

init();

// Widths change without a re-render when the window is resized or the web fonts arrive.
globalThis.addEventListener?.('resize', fitChecksTable);
document.fonts?.ready?.then(fitChecksTable);

// ── Hot-reload listener ───────────────────────────────────────────────────────
// The server sends 'reload' after a hot reload or a change to the frontend files. If the
// connection drops (e.g. the server restarted) and later comes back, reload as well.
let _sseHadError = false;
const _sse = new EventSource('/api/events');
_sse.addEventListener('reload', () => location.reload());
_sse.onerror = () => { _sseHadError = true; };
_sse.onopen  = () => { if (_sseHadError) location.reload(); };
