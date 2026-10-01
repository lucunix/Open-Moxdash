'use strict';
// SELF-SHA256: b340d8a789491dc0528163ffe3390b0b7354915322101f8db849e0f4b7343aa9
// Open Moxdash entry point (start with `node webowner.js`, or `npm start`).
//
// This file owns everything that must survive a hot reload: the shared state, the
// check timers, the HTTP listener and the file watchers. The application code in
// app.js and checks/ is loaded around it and re-required whenever those files or
// config.json change, so most edits go live without restarting the process. Changes
// to webowner.js, secrets.js and guard.js need a restart. Code is also integrity-checked
// (see below): after editing any .js file run `node webowner.js --update-hashes`, or
// start with `--no-hashing` while developing so edits go live without it.
//
// It listens on port 80, which needs root or CAP_NET_BIND_SERVICE. Put a
// TLS-terminating reverse proxy in front for HTTPS: session cookies are marked Secure,
// so login only works over https.

const crypto = require('crypto');
const http   = require('http');
const path   = require('path');
const fs     = require('fs');

// ── Integrity check ───────────────────────────────────────────────────────────
//
// Every .js file of the app (this one excepted) must match its SHA-256 in FILE_HASHES, no
// other .js file may exist, and this file must match the SELF-SHA256 on its second line
// (the hash of this whole file, table included, with that hash replaced by zeros). Any
// mismatch prints what differs and ends the process at once with exit status 99 (no
// secrets are shredded; that is only for the process guard, see Lockdown). The check runs
// at startup before any other app code is loaded, again before every hot reload, once
// after startup, and every 15 seconds.
//
// Status 99 is the "do not restart" status: deploy/open-moxdash.service lists it in
// RestartPreventExitStatus=, so after any defence trips (this check or the process guard)
// systemd leaves the service stopped instead of starting it again.
//
// This is a speed bump, not a lock: someone who can rewrite this file can rewrite the
// hashes too. It exists so that silent edits to the code fail loudly.
//
// After changing any .js file, run `node webowner.js --update-hashes` and restart. Hot
// reload still applies to config.json and to non-code files under public/, but no longer
// to code.
//
// `node webowner.js --no-hashing` turns all of this off: no hash is checked, no periodic
// timer runs, and code edits hot-reload as usual. The process guard and the lockdown stay
// active. It is meant for development; do not put it in the service unit.

// The service unit must list this same status in RestartPreventExitStatus=, and it must
// match NO_RESTART_EXIT in guard.js.
const NO_RESTART_EXIT = 99;
const NO_HASHING = process.argv.includes('--no-hashing');

// BEGIN FILE HASHES
const FILE_HASHES = Object.freeze({
  'app.js': '6ced8b3dee903cf31121b5a0ff895b1d5271124240a5e02435b6460bb8af7a0b',
  'checks/broadcast.js': '312b766efc65b354355ddc118775e441616a532e5812de14472f851eae136a0c',
  'checks/cpu.js': 'c6dd2ba1a2c47beeef5629a3425f01f6f7457b8e7408ce66fd130e424a3fe880',
  'checks/dhcp.js': 'ad401079ad3bb445d03d2484610e1ec8f1f6d281a9b5625df23a45f3f1ea380d',
  'checks/disk.js': 'c05e86514572ffe6c2190af3f12c3ef503da017390076cd515d49652ee59be45',
  'checks/dns.js': '7273311147cf5593fb56d08bfabd561824a9449b43b76707a3ac935bdbc5c360',
  'checks/gpu.js': 'a17ee2d6ff953dd074980bbb39aa2bd8ca79bb52517735583ff77635548084b1',
  'checks/index.js': 'abbcc59a54cb8f17a5de16deb892dc0b7ef129d6a0359d9830ed776c9c68035a',
  'checks/network.js': '7c8a3e96a591a023fc57e468dad77901112d8c68a68677fb996cd659249fa38f',
  'checks/proxmox.js': '06bbb8e86795a74618e9403064482294b7a0a57347fc8506bdd923c6970622b9',
  'checks/ram.js': 'ad78e2ec34bea518120bbb116ae74b4fc7dceb9abd989a7e1ad5ba86b59f69b0',
  'checks/services.js': 'e1f8926df1c821c97ae53cdecfee80b2e7a14618848b302319e7278542fcc9ba',
  'checks/ssh.js': 'b859e756f3c5c88c30a58dd73adb75b9bb5b01270a7f22bbc7a3c78f473b6eaf',
  'checks/upnp.js': '265ff3441a680bbaa3a22a336e4183efd69924d7c960ae70897bed5c379fb9d0',
  'config.js': 'f581fb721bbfcca78ffdbdc0f7985dfb26062e3b79fdb52f02fd48aac0d75dab',
  'guard.js': 'd085d47a8d89e61e2f4a3ee8d7a7562c80a05e31616df9ace522736ef2d0f56f',
  'public/main.js': 'e440add45dcf2c7c206b01d56bc3b2a85929fc2592dd6259d7521cc2d53bcbc8',
  'secrets.js': 'd271edd0bd431f76e5c497b84638daf47bb393be3b9919c163cd8a9688586e73',
});
// END FILE HASHES

const SELF_LINE_RE = /^(\/\/ SELF-SHA256: )([0-9a-f]{64})$/m;
const ZERO_HASH    = '0'.repeat(64);
const sha256       = data => crypto.createHash('sha256').update(data).digest('hex');

// Prints why, then ends the process with NO_RESTART_EXIT. `lines` are extra detail lines.
// Never returns. Deliberately no lockdown here: a hash mismatch also happens after an
// ordinary update of the files, so it only stops the process and leaves the secrets alone.
function integrityFailure(trigger, reason, lines = []) {
  try {
    fs.writeSync(2,
      `\n[open-moxdash] SECURITY: integrity check failed (${trigger}): possible tampering.\n` +
      '[open-moxdash] Terminating this process now (exit status 99, no automatic restart).\n' +
      `  reason:  ${reason}\n` +
      lines.map(l => `  ${l}\n`).join('') +
      `  pid:     ${process.pid}   time: ${new Date().toISOString()}\n\n`);
  } catch (_) {}
  // reallyExit is what process.exit() ends with, minus the 'exit' event, so no handler runs.
  // SIGKILL is only the last resort if both exits somehow fail (systemd would then restart).
  try { if (typeof process.reallyExit === 'function') process.reallyExit(NO_RESTART_EXIT); } catch (_) {}
  try { process.exit(NO_RESTART_EXIT); } catch (_) {}
  process.kill(process.pid, 'SIGKILL');
  for (;;) { /* the process is already gone; run nothing else */ }
}

// Every .js file under the app directory except this one, as forward-slash relative
// paths. node_modules is not covered.
function listJsFiles(dir = __dirname, rel = '') {
  const found = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const relPath = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) found.push(...listJsFiles(path.join(dir, entry.name), relPath));
    else if (entry.name.endsWith('.js') && relPath !== 'webowner.js') found.push(relPath);
  }
  return found.sort();
}

// Checks this file, the set of .js files, and every file's hash against what is on disk now.
// Does nothing under --no-hashing.
function verifyIntegrity(trigger) {
  if (NO_HASHING) return;
  let self;
  try { self = fs.readFileSync(__filename, 'utf8'); }
  catch (e) { integrityFailure(trigger, `cannot read webowner.js: ${e.message}`); }
  const m = SELF_LINE_RE.exec(self);
  if (!m) integrityFailure(trigger, 'the SELF-SHA256 line is missing from webowner.js');
  const selfActual = sha256(self.replace(SELF_LINE_RE, `$1${ZERO_HASH}`));
  if (selfActual !== m[2])
    integrityFailure(trigger, 'webowner.js does not match its own SELF-SHA256',
      ['file:     webowner.js', `expected: ${m[2]}`, `actual:   ${selfActual}`]);

  let onDisk;
  try { onDisk = listJsFiles(); }
  catch (e) { integrityFailure(trigger, `cannot list the app's .js files: ${e.message}`); }
  const expected = Object.keys(FILE_HASHES).sort();
  const extra   = onDisk.filter(f => !expected.includes(f));
  const missing = expected.filter(f => !onDisk.includes(f));
  if (extra.length || missing.length)
    integrityFailure(trigger, 'the set of .js files differs from FILE_HASHES',
      [`unexpected files: ${extra.join(', ') || 'none'}`, `missing files:    ${missing.join(', ') || 'none'}`]);

  for (const file of expected) {
    let actual;
    try { actual = sha256(fs.readFileSync(path.join(__dirname, file))); }
    catch (e) { integrityFailure(trigger, `cannot read ${file}: ${e.message}`); }
    if (actual !== FILE_HASHES[file])
      integrityFailure(trigger, `${file} does not match its SHA-256 in FILE_HASHES`,
        [`file:     ${file}`, `expected: ${FILE_HASHES[file]}`, `actual:   ${actual}`]);
  }
}

// `node webowner.js --update-hashes`: recomputes FILE_HASHES and SELF-SHA256 in this file
// for the .js files as they are now, then exits.
function updateHashes() {
  const hashes = {};
  for (const file of listJsFiles()) hashes[file] = sha256(fs.readFileSync(path.join(__dirname, file)));
  const table = 'const FILE_HASHES = Object.freeze({\n' +
    Object.entries(hashes).map(([f, h]) => `  '${f}': '${h}',`).join('\n') + '\n});';
  let self = fs.readFileSync(__filename, 'utf8');
  self = self.replace(/\/\/ BEGIN FILE HASHES\n[\s\S]*?\/\/ END FILE HASHES/,
    () => `// BEGIN FILE HASHES\n${table}\n// END FILE HASHES`);
  self = self.replace(SELF_LINE_RE, `$1${ZERO_HASH}`);
  self = self.replace(SELF_LINE_RE, `$1${sha256(self)}`);
  fs.writeFileSync(__filename, self);
  console.log(`[open-moxdash] updated hashes for ${Object.keys(hashes).length} files and SELF-SHA256 in webowner.js`);
  process.exit(0);
}

// ── Lockdown ──────────────────────────────────────────────────────────────────
//
// One strike: when the process guard trips (a malformed ssh command, or any other process
// launch the app never makes), the process first destroys what an attacker could reuse,
// then kills itself (see lockdown()). The integrity check above only kills the process;
// it does not shred, so updating files under a running instance costs a restart, not the
// secrets. Lockdown destroys:
//   - the in-memory token (secrets.js),
//   - proxmox.api_token_secret in config.json, if present,
//   - the credential files systemd gave this service ($CREDENTIALS_DIRECTORY),
//   - the extra files listed in config.json under lockdown.shred, for example an SSH
//     private key or an encrypted credential.
// Destroying local copies revokes nothing on the servers themselves: also revoke the
// Proxmox API token and remove the SSH key from the servers' authorized_keys.
//
// A mistake here would delete something the server needs, so shredding is fenced in. A
// file is overwritten and removed only if it is a regular file of at most 64 KiB, not a
// symlink, not inside the app directory, and under one of ALLOWED_ROOTS. Files in .ssh
// folders must also be private keys, never authorized_keys, known_hosts, config or .pub
// files. The shred list is read once at startup. `node webowner.js --lockdown-check`
// prints what would be shredded and what would be refused, without touching anything;
// run it after editing lockdown.shred.

const APP_DIR         = __dirname;
const CREDS_DIR       = process.env.CREDENTIALS_DIRECTORY || null;
const MAX_SHRED_BYTES = 64 * 1024;
const ALLOWED_ROOTS   = ['/etc/credstore.encrypted/', '/etc/credstore/', '/run/credentials/', '/root/.ssh/', '/tmp/'];
const HOME_SSH_RE     = /^\/home\/[^/]+\/\.ssh\/[^/]+$/;
const SSH_NEVER_SHRED = new Set(['authorized_keys', 'authorized_keys2', 'known_hosts', 'known_hosts.old', 'config']);

// lockdown.shred from config.json, read directly (no app code) and frozen at startup.
function readShredList() {
  try {
    const list = JSON.parse(fs.readFileSync(path.join(APP_DIR, 'config.json'), 'utf8')).lockdown?.shred;
    return Object.freeze(Array.isArray(list) ? list.filter(p => typeof p === 'string').slice(0, 20) : []);
  } catch (_) { return Object.freeze([]); }
}
const SHRED_LIST = readShredList();

// Decides whether one file may be shredded: { file, ok, note }.
function planShred(file) {
  const refuse = note => ({ file, ok: false, note });
  if (typeof file !== 'string' || !path.isAbsolute(file) || file.includes('\0') || path.normalize(file) !== file)
    return refuse('not a normalized absolute path');
  let st;
  try { st = fs.lstatSync(file); } catch (e) { return refuse(`cannot stat (${e.code})`); }
  if (st.isSymbolicLink()) return refuse('is a symlink');
  if (!st.isFile()) return refuse('not a regular file');
  if (st.size > MAX_SHRED_BYTES) return refuse(`larger than ${MAX_SHRED_BYTES} bytes`);
  if (file === APP_DIR || file.startsWith(APP_DIR + path.sep)) return refuse('inside the app directory');
  const isSsh = file.startsWith('/root/.ssh/') || HOME_SSH_RE.test(file);
  if (!isSsh && !ALLOWED_ROOTS.some(root => file.startsWith(root))) return refuse('outside the allowed locations');
  if (isSsh) {
    const base = path.basename(file);
    if (SSH_NEVER_SHRED.has(base) || base.endsWith('.pub')) return refuse('not a private key file');
    let head;
    try { head = fs.readFileSync(file, 'utf8').slice(0, 4096); } catch (e) { return refuse(`cannot read (${e.code})`); }
    if (!head.includes('PRIVATE KEY')) return refuse('does not look like a private key');
  }
  return { file, ok: true, note: `${st.size} bytes` };
}

// Every file lockdown() would consider: what systemd gave this service, then the list.
function lockdownTargets() {
  const targets = [];
  if (CREDS_DIR) { try { for (const n of fs.readdirSync(CREDS_DIR)) targets.push(path.join(CREDS_DIR, n)); } catch (_) {} }
  return targets.concat(SHRED_LIST);
}

// Overwrites the file with random bytes, flushes, then removes it. Best effort: on
// copy-on-write or journaling filesystems old blocks may survive until reused.
function shredFile(file) {
  const fd = fs.openSync(file, 'r+');
  try {
    const size = fs.fstatSync(fd).size;
    if (size > 0) { fs.writeSync(fd, crypto.randomBytes(size), 0, size, 0); fs.fsyncSync(fd); }
  } finally { fs.closeSync(fd); }
  fs.unlinkSync(file);
}

// Clears proxmox.api_token_secret in config.json, leaving every other setting as it was.
function scrubConfigSecret() {
  const file = path.join(APP_DIR, 'config.json');
  const conf = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!conf.proxmox || !conf.proxmox.api_token_secret) return 'no secret in config.json';
  conf.proxmox.api_token_secret = '';
  fs.writeFileSync(file, JSON.stringify(conf, null, 2) + '\n');
  return 'proxmox.api_token_secret cleared in config.json';
}

// Destroys the secrets described above. Prints each step, never throws, runs once.
let lockedDown = false;
function lockdown() {
  if (lockedDown) return;
  lockedDown = true;
  const say = line => { try { fs.writeSync(2, `[open-moxdash] LOCKDOWN: ${line}\n`); } catch (_) {} };
  say('destroying secrets before terminating');
  try {
    const loaded = require.cache[path.join(APP_DIR, 'secrets.js')];
    if (loaded && typeof loaded.exports.wipe === 'function') { loaded.exports.wipe(); say('in-memory token wiped'); }
    else say('in-memory token: not loaded');
  } catch (e) { say(`in-memory token: FAILED (${e.message})`); }
  try { say(scrubConfigSecret()); } catch (e) { say(`config.json secret: FAILED (${e.message})`); }
  for (const target of lockdownTargets()) {
    try {
      const plan = planShred(target);
      if (!plan.ok) { say(`refused ${target}: ${plan.note}`); continue; }
      shredFile(target);
      say(`shredded ${target} (${plan.note})`);
    } catch (e) { say(`FAILED ${target}: ${e.code || e.message}`); }
  }
  say('done');
}

// `node webowner.js --lockdown-check`: shows what lockdown() would shred and refuse.
function lockdownCheck() {
  console.log('[open-moxdash] lockdown check (nothing is modified)');
  console.log(`  CREDENTIALS_DIRECTORY: ${CREDS_DIR || '(not set)'}`);
  let hasSecret = false;
  try { hasSecret = !!JSON.parse(fs.readFileSync(path.join(APP_DIR, 'config.json'), 'utf8')).proxmox?.api_token_secret; } catch (_) {}
  console.log(`  config.json proxmox.api_token_secret: ${hasSecret ? 'present, would be cleared' : 'not present'}`);
  const targets = lockdownTargets();
  if (!targets.length) console.log('  no files to shred (no credentials directory, empty lockdown.shred)');
  for (const t of targets) {
    const plan = planShred(t);
    console.log(`  ${plan.ok ? 'WOULD SHRED' : 'REFUSED    '}  ${t}  (${plan.note})`);
  }
  process.exit(0);
}

if (process.argv.includes('--update-hashes')) updateHashes();
if (process.argv.includes('--lockdown-check')) lockdownCheck();
if (NO_HASHING) {
  console.warn('[open-moxdash] WARNING: --no-hashing: file hashes are NOT checked and code edits hot-reload.');
  console.warn('[open-moxdash] The process guard and lockdown are still active. Do not run production like this.');
} else {
  verifyIntegrity('startup');
  setInterval(() => verifyIntegrity('periodic'), 15000).unref();
}

// Guards everything this process can spawn (see guard.js). It is loaded only after the
// integrity check above, and is never hot-reloaded.
require('./guard').setLockdown(lockdown);

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
verifyIntegrity('post-load');  // closes the gap between the startup check and the loads above

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
const GUARD   = require.resolve('./guard');    // never cleared from cache: the allowlist must not be replaceable while running

// Sends a server-sent event to every connected page. 'reload' tells browsers to
// reload; 'ping' is a keep-alive.
function notifySseClients(event = 'reload', data = {}) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of state.sseClients) {
    try { res.write(msg); }
    catch (_) { state.sseClients.delete(res); }
  }
}

// Drops every cached module except this file, secrets.js and guard.js, re-requires the checks
// and the app, then tells open pages to reload. If the new code fails to load, the
// error is logged and the previous handler and checks keep running.
function reloadModules(trigger) {
  verifyIntegrity(`hot reload (${trigger})`);
  for (const key of Object.keys(require.cache)) {
    if (key.startsWith(__dirname) && key !== SELF && key !== SECRETS && key !== GUARD) {
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
