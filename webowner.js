'use strict';
// Open Moxdash entry point (start with `node webowner.js`, or `npm start`).
//
// This file owns everything that must survive a hot reload: the shared state, the
// check timers, the HTTP listener and the file watchers. The application code in
// app.js and checks/ is loaded around it and re-required whenever those files or
// config.json change, so most edits go live without restarting the process. Changes
// to webowner.js itself and to secrets.js need a restart.
//
// It listens on port 80, which needs root or CAP_NET_BIND_SERVICE. Put a
// TLS-terminating reverse proxy in front for HTTPS: session cookies are marked Secure,
// so login only works over https.
const http   = require('http');
const path   = require('path');
const fs     = require('fs');
const { cfg } = require('./config');

// ── Shared state (survives app.js reloads) ────────────────────────────────────

// Sets obj[a][b][c] = value for dotPath "a.b.c", creating intermediate objects.
function setPath(obj, dotPath, value) {
  const parts = dotPath.split('.');
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (!cur[parts[i]] || typeof cur[parts[i]] !== 'object') cur[parts[i]] = {};
    cur = cur[parts[i]];
  }
  cur[parts[parts.length - 1]] = value;
}

// Reads obj[a][b][c] for dotPath "a.b.c"; undefined if any step is missing.
function getPath(obj, dotPath) {
  const parts = dotPath.split('.');
  let cur = obj;
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object') return undefined;
    cur = cur[p];
  }
  return cur;
}

// Everything below lives here rather than in app.js so a hot reload keeps it.
const state = {
  displayCache:   {},  // latest check results, nested by dot path (see writeTo)
  lastUpdated:    null,  // slow cycle only — drives "updated X ago"
  fastUpdated:    null,  // fast cycle — drives re-render
  sessions:       new Map(),
  loginAttempts:  new Map(),
  sseClients:     new Set(),
  sseConnsPerIp:  new Map(),  // ip → active connection count
  allowedIpsCache: new Map(),  // username → { ips, ipLinks, fetchedAt } — per-user, never shared
};

// How the checks publish results. A result with an `ok` flag gets a lastOkAt time
// (kept from the previous result when this one is a failure), so the page can show
// how long ago a failing service was last up.
state.writeTo = (dotPath, value) => {
  if (value && typeof value === 'object' && !Array.isArray(value) && 'ok' in value) {
    const prev = getPath(state.displayCache, dotPath);
    if (value.ok === true) {
      value = { ...value, lastOkAt: Date.now() };
    } else if (prev?.lastOkAt) {
      value = { ...value, lastOkAt: prev.lastOkAt };
    }
  }
  setPath(state.displayCache, dotPath, value);
};

// ── Session / rate-limit purge (persistent — must not be in app.js) ───────────

setInterval(() => {
  const now = Date.now();
  for (const [sid, sess] of state.sessions) {
    if (now > sess.expiresAt) state.sessions.delete(sid);
  }
}, 15 * 60 * 1000);

setInterval(() => {
  const now    = Date.now();
  const cutoff = now - 30 * 60 * 1000;   // keep records for 30 min max
  for (const [ip, rec] of state.loginAttempts) {
    const ts          = typeof rec === 'object' ? (rec.ts          || 0) : rec;
    const lockedUntil = typeof rec === 'object' ? (rec.lockedUntil || 0) : 0;
    if (ts < cutoff && now > lockedUntil) state.loginAttempts.delete(ip);
  }
}, 5 * 60 * 1000);

// ── Check cycles ──────────────────────────────────────────────────────────────

let checks = require('./checks/index');

// Cycle lengths from config, clamped to at least 1s (fast) and 5s (slow).
const fastMs = Math.max(1000, cfg('page.fast_refresh_seconds', 3) * 1000);
const slowMs = Math.max(5000, cfg('page.refresh_seconds',      30) * 1000);

const secrets = require('./secrets');

// Where the Proxmox API token secret comes from: the systemd credential named
// proxmox-token-secret (LoadCredentialEncrypted= in the unit file) when present,
// otherwise proxmox.api_token_secret in config.json. The config fallback is for
// development only, since it leaves the secret in a plain file.
function readApiTokenSecret() {
  const credDir = process.env.CREDENTIALS_DIRECTORY;
  if (credDir) {
    try {
      const val = fs.readFileSync(path.join(credDir, 'proxmox-token-secret'), 'utf8').trim();
      if (val) return val;
    } catch (_) {}
  }
  return cfg('proxmox.api_token_secret');  // fallback for dev / non-systemd runs
}

// Encrypt token once at startup so the fast cycle has it immediately
secrets.setToken(readApiTokenSecret());

// Each cycle runs one pass at a time: if the previous pass is still going when the
// timer fires, that tick is skipped.
let fastRunning = false;
async function runFastCycle() {
  if (fastRunning) return;
  fastRunning = true;
  try { await checks.runFast(state.writeTo); state.fastUpdated = new Date().toISOString(); }
  catch (e) { console.error('[fast cycle]', e); }
  finally { fastRunning = false; }
}

let slowRunning = false;
async function runSlowCycle() {
  if (slowRunning) return;
  slowRunning = true;
  try {
    secrets.setToken(readApiTokenSecret());  // re-encrypt once per slow cycle
    await checks.runSlow(state.writeTo);
    state.lastUpdated = new Date().toISOString();
  }
  catch (e) { console.error('[slow cycle]', e); }
  finally { slowRunning = false; }
}

runFastCycle();
runSlowCycle();
setInterval(runFastCycle, fastMs);
setInterval(runSlowCycle, slowMs);
setInterval(() => notifySseClients('ping'), 30000);

// ── HTTP server ───────────────────────────────────────────────────────────────

let handler = require('./app')(state);

// `handler` is looked up on every request, so a hot reload swaps in the new app.js
// without touching this listener or dropping connections.
const server = http.createServer((req, res) => handler(req, res));
server.listen(80, '0.0.0.0', () => {
  console.log('[open-moxdash] listening on http://0.0.0.0:80');
  console.log(`[open-moxdash] fast cycle: ${fastMs}ms  slow cycle: ${slowMs}ms`);
});

// ── Hot reload ────────────────────────────────────────────────────────────────

const SELF    = __filename;
const SECRETS = require.resolve('./secrets');  // never cleared from cache: it holds the encrypted token

// Sends a server-sent event to every connected page. 'reload' tells browsers to
// reload; 'ping' is a keep-alive.
function notifySseClients(event = 'reload', data = {}) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of state.sseClients) {
    try { res.write(msg); }
    catch (_) { state.sseClients.delete(res); }
  }
}

// Drops every cached module except this file and secrets.js, re-requires the checks
// and the app, then tells open pages to reload. If the new code fails to load, the
// error is logged and the previous handler and checks keep running.
function reloadModules(trigger) {
  for (const key of Object.keys(require.cache)) {
    if (key.startsWith(__dirname) && key !== SELF && key !== SECRETS) {
      delete require.cache[key];
    }
  }
  try {
    checks  = require('./checks/index');
    handler = require('./app')(state);
    console.log(`[hot-reload] reloaded (trigger: ${trigger})`);
    notifySseClients('reload');
  } catch (e) {
    console.error(`[hot-reload] failed (trigger: ${trigger}): ${e.message}`);
  }
}

// Debounced by 200ms: editors often write a file in several steps.
let reloadTimer = null;
function scheduleReload(trigger) {
  clearTimeout(reloadTimer);
  reloadTimer = setTimeout(() => reloadModules(trigger), 200);
}

// What triggers what: a .js file in checks/, any .json file (config.json, the UPnP
// files) or a top-level .js file other than this one reloads the modules; a change
// under public/ only tells browsers to reload.
fs.watch(path.join(__dirname, 'checks'), (event, filename) => {
  if (filename?.endsWith('.js')) scheduleReload(`checks/${filename}`);
});
fs.watch(__dirname, (event, filename) => {
  if (!filename) return;
  if (filename.endsWith('.json')) scheduleReload(filename);
  else if (filename.endsWith('.js') && filename !== 'webowner.js') scheduleReload(filename);
});
// Debounced like scheduleReload() above — an atomic save (temp file + rename)
// fires several raw fs events for one edit. Without debouncing, each one sent
// its own 'reload' signal, so a single save could make a client's browser
// call location.reload() several times in quick succession. The new
// EventSource from one reload can open before the previous connection's
// server-side cleanup finishes (more so through a proxy), tripping
// sse.max_connections_per_ip and leaving that tab with no working connection
// until it's refreshed by hand.
let publicReloadTimer = null;
fs.watch(path.join(__dirname, 'public'), (event, filename) => {
  if (!filename) return;
  clearTimeout(publicReloadTimer);
  publicReloadTimer = setTimeout(() => {
    console.log(`[hot-reload] ${filename} changed — notifying clients`);
    notifySseClients('reload');
  }, 200);
});
