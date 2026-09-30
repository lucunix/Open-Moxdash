'use strict';
// Open Moxdash HTTP application: a factory that returns the Express app.
//
// webowner.js calls makeApp(state) at startup and again after every hot reload,
// handing it the long-lived shared state (cached check results, sessions, login
// attempts, SSE clients) so a reload never logs anyone out or empties the cache.
// This file provides:
//   - the read-only status API and the static frontend in public/
//   - Proxmox-backed login: users sign in with their Proxmox credentials and get a
//     server-side session (HttpOnly cookie); the Proxmox ticket stays on the server
//   - UPnP port-mapping management, limited to the guests the logged-in user can see
//   - Open Graph metadata so chat apps can unfurl a link to the page
//   - the server-sent-events stream that tells open pages to reload
//
// All behaviour is driven by config.json (see config.js and the README).
const express = require('express');
const path    = require('path');
const fs      = require('fs');
const https   = require('https');
const crypto  = require('crypto');
const { cfg, load } = require('./config');
const secrets = require('./secrets');
const { discoverNodes } = require('./checks/proxmox');
const { getMappingOwner, deletePortMapping, getCurrentMappings, addPortMapping, isBlacklisted, canRequestPermanentLease } = require('./checks/upnp');

// Parses a duration such as "30s", "5m", "2h" or "1d" into milliseconds; anything
// else (including undefined) yields defaultMs.
function parseTTL(str, defaultMs) {
  const m = String(str || '').match(/^(\d+)(s|m|h|d)$/i);
  if (!m) return defaultMs;
  return parseInt(m[1]) * ({ s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2].toLowerCase()]);
}

// True if the IPv4 address lies inside the CIDR range ("192.168.1.0/24"); a bare
// address without /bits matches only itself. Invalid input returns false. IPv4 only.
function ipInCidr(ip, cidr) {
  try {
    const [net, bits] = cidr.split('/');
    const mask = bits ? ~((1 << (32 - parseInt(bits))) - 1) >>> 0 : 0xffffffff;
    const toInt = s => s.split('.').reduce((a, b) => (a << 8) + parseInt(b), 0) >>> 0;
    return (toInt(ip) & mask) === (toInt(net) & mask);
  } catch (_) { return false; }
}

// Dotted-quad IPv4 with every octet in 0-255.
function isValidIPv4(ip) {
  const m = String(ip).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return !!m && m.slice(1).every(o => Number(o) >= 0 && Number(o) <= 255);
}

// Same escaping rule as the frontend's esc() — needed here too since the
// embed meta tags are values inserted into HTML attributes server-side.
function escAttr(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

module.exports = function makeApp(state) {

  // Sessions live on the server; the cookie carries only a random session id.
  // Two hours matches the lifetime of a Proxmox login ticket.
  const SESSION_COOKIE = 'openMoxdashSid';
  const SESSION_TTL_MS = 2 * 60 * 60 * 1000;

  // ── PVE helpers ───────────────────────────────────────────────────────────────

  // Proxmox uses a self-signed certificate by default, so verification is off for
  // these calls (same trade-off as checks/proxmox.js).
  const pveAgent = new https.Agent({ rejectUnauthorized: false });

  // POSTs a form-encoded body to the Proxmox API (used for login, /access/ticket).
  // Resolves { ok, status, data }; never rejects.
  function pvePost(urlPath, formBody) {
    return new Promise(resolve => {
      const host = cfg('proxmox.host');
      const port = cfg('proxmox.port', 8006);
      const body = new URLSearchParams(formBody).toString();
      const req = https.request({
        host, port, path: urlPath, method: 'POST', agent: pveAgent,
        headers: {
          'Content-Type':   'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(body),
        },
      }, res => {
        let data = '';
        res.on('data', d => { data += d; });
        res.on('end', () => {
          try { resolve({ ok: true, status: res.statusCode, data: JSON.parse(data) }); }
          catch (_) { resolve({ ok: false, status: res.statusCode, data: null }); }
        });
      });
      req.on('error', () => resolve({ ok: false, status: null, data: null }));
      req.write(body);
      req.end();
    });
  }

  // GETs a Proxmox API path as the logged-in user (PVEAuthCookie ticket), so results
  // cover only what that user is allowed to see. Resolves { ok, status, data }.
  function pveGet(urlPath, ticket) {
    return new Promise(resolve => {
      const host = cfg('proxmox.host');
      const port = cfg('proxmox.port', 8006);
      const req = https.request({
        host, port, path: urlPath, method: 'GET', agent: pveAgent,
        headers: { 'Cookie': `PVEAuthCookie=${ticket}` },
      }, res => {
        let data = '';
        res.on('data', d => { data += d; });
        res.on('end', () => {
          try { resolve({ ok: true, status: res.statusCode, data: JSON.parse(data) }); }
          catch (_) { resolve({ ok: false, status: res.statusCode, data: null }); }
        });
      });
      req.on('error', () => resolve({ ok: false, status: null, data: null }));
      req.end();
    });
  }

  // Resource-id formats (qemu/<vmid>, lxc/<vmid>) and the URL-fragment encoding
  // (#v1:<view>:<rid>:...:<kvmtab>::) are taken directly from the installed
  // pve-manager source (PVE.StateProvider in pvemanagerlib.js), not guessed —
  // view=0 is 'server', and position 7 (kvmtab) = 5 is 'summary', both from
  // that file's compDict. vmid === null links to the bare UI root instead
  // (used for the privileged host-IP entry, which isn't a guest).
  function proxmoxWebUrl(type, vmid) {
    const uiHost = cfg('proxmox.ui_host');
    const host   = uiHost || cfg('proxmox.host');
    // A configured ui_host is assumed to be a public/reverse-proxied hostname
    // (e.g. behind Cloudflare) that already maps to the right backend on the
    // default HTTPS port — an explicit :8006 there would target Cloudflare's
    // edge on a port it doesn't proxy and just fail to connect. The port is
    // only needed for the direct-LAN fallback, where nothing else is
    // listening on 443.
    const portSuffix = uiHost ? '' : `:${cfg('proxmox.port', 8006)}`;
    if (vmid == null) return `https://${host}${portSuffix}/`;
    return `https://${host}${portSuffix}/#v1:0:=${type}%2F${vmid}::::::5::`;
  }

  // Builds the set of guest IPs a user may see: walks every node's QEMU VMs and LXC
  // containers with the user's own ticket and collects their IPv4 addresses (limited
  // to network.subnet when set). Returns { allowedIps: Set, ipLinks: { ip -> Proxmox
  // UI URL for that guest } }.
  async function fetchAllowedIps(pveTicket) {
    const subnet = cfg('network.subnet', '');
    const allowedIps = new Set();
    const ipLinks = {};

    // Guests can live on any node in the cluster, not just the entry-point node.
    const nodes = await discoverNodes();

    await Promise.allSettled(
      nodes.map(async node => {
        // QEMU VMs — IP comes from the in-guest agent; stopped VMs or ones
        // without the agent running simply return nothing, no separate
        // "is it running" check needed.
        const vmsRes = await pveGet(`/api2/json/nodes/${node.name}/qemu`, pveTicket);
        if (vmsRes.ok && Array.isArray(vmsRes.data?.data)) {
          await Promise.allSettled(
            vmsRes.data.data.map(async vm => {
              const ifRes = await pveGet(
                `/api2/json/nodes/${node.name}/qemu/${vm.vmid}/agent/network-get-interfaces`,
                pveTicket
              );
              if (!ifRes.ok || !Array.isArray(ifRes.data?.data?.result)) return;
              for (const iface of ifRes.data.data.result) {
                for (const addr of (iface['ip-addresses'] || [])) {
                  const ip = addr['ip-address'];
                  if (ip && (!subnet || ipInCidr(ip, subnet))) {
                    allowedIps.add(ip);
                    ipLinks[ip] = proxmoxWebUrl('qemu', vm.vmid);
                  }
                }
              }
            })
          );
        }

        // LXC containers — no guest agent involved; Proxmox reports interfaces
        // directly for running containers, empty/failed for stopped ones.
        const ctsRes = await pveGet(`/api2/json/nodes/${node.name}/lxc`, pveTicket);
        if (ctsRes.ok && Array.isArray(ctsRes.data?.data)) {
          await Promise.allSettled(
            ctsRes.data.data.map(async ct => {
              const ifRes = await pveGet(`/api2/json/nodes/${node.name}/lxc/${ct.vmid}/interfaces`, pveTicket);
              if (!ifRes.ok || !Array.isArray(ifRes.data?.data)) return;
              for (const iface of ifRes.data.data) {
                const ip = (iface.inet || '').split('/')[0];
                if (ip && (!subnet || ipInCidr(ip, subnet))) {
                  allowedIps.add(ip);
                  ipLinks[ip] = proxmoxWebUrl('lxc', ct.vmid);
                }
              }
            })
          );
        }
      })
    );

    return { allowedIps, ipLinks };
  }

  // Like pveGet, but authenticates with the shared API token instead of a user
  // ticket, for lookups a normal user can't make (the ACL list).
  function pveGetApiToken(urlPath) {
    return new Promise(resolve => {
      const host     = cfg('proxmox.host');
      const port     = cfg('proxmox.port', 8006);
      const tokenId  = cfg('proxmox.api_token_id');
      const tokenSec = secrets.getToken();
      const req = https.request({
        host, port, path: urlPath, method: 'GET', agent: pveAgent,
        headers: { 'Authorization': `PVEAPIToken=${tokenId}=${tokenSec}` },
      }, res => {
        let data = '';
        res.on('data', d => { data += d; });
        res.on('end', () => {
          try { resolve({ ok: true, status: res.statusCode, data: JSON.parse(data) }); }
          catch (_) { resolve({ ok: false, status: res.statusCode, data: null }); }
        });
      });
      req.on('error', () => resolve({ ok: false, status: null, data: null }));
      req.end();
    });
  }

  // Off-schedule mapping-list refresh — the periodic slow cycle's checkUpnp()
  // also re-runs a ~12s self-test (add/verify/wait-for-expiry), so re-running
  // that in full after every add/delete/login would make those feel sluggish.
  // getCurrentMappings() only relists via the already-discovered IGD endpoint
  // (no self-test), so it's fast enough to await directly in the response
  // path — the caller's next status fetch sees genuinely fresh data instead
  // of waiting out the normal ~30s cadence. Only touches the mappings array;
  // igdDetected/portTest/compliance stay whatever the last full cycle found.
  async function refreshUpnpMappings() {
    if (!cfg('upnp.enabled', false)) return;
    try {
      const mappings = await getCurrentMappings();
      if (state.displayCache.services?.upnp) {
        state.displayCache.services.upnp.mappings = mappings;
      }
    } catch (e) {
      console.error('[upnp] off-schedule mapping refresh failed:', e.message);
    }
  }

  // The upnp.all_ports_role setting: 'root' (only root@pam) or the name of a Proxmox
  // role. Defaults to 'root' when missing or blank.
  function resolvedAllPortsRole() {
    const r = cfg('upnp.all_ports_role', '');
    return (typeof r === 'string' && r.trim()) ? r.trim() : 'root';
  }

  // Cache is keyed per-username — fetchAllowedIps() scopes results to
  // whatever the given pveTicket's own owner can see, so caching it in one
  // shared slot would let one user's VM/IP visibility leak into another
  // user's session. TTL-bounded per user so a freshly-created VM/CT shows up
  // without needing a full re-login, while not hammering the Proxmox API on
  // every poll.
  async function resolveAllowedIps(username, pveTicket) {
    const ttlMs = parseTTL(cfg('proxmox.allowed_ips_ttl'), 5 * 60 * 1000);
    const now   = Date.now();
    let cached = state.allowedIpsCache.get(username);
    if (!cached || (now - cached.fetchedAt) >= ttlMs) {
      const { allowedIps: ips, ipLinks } = await fetchAllowedIps(pveTicket);
      cached = { ips, ipLinks, fetchedAt: now };
      state.allowedIpsCache.set(username, cached);
    }
    return cached;
  }

  // Recomputes a live session's allowedIps/ipLinks from the (TTL-bounded)
  // per-user cache and writes the result back into the stored session, so a
  // newly-created VM/CT's IP appears on the next status poll instead of
  // requiring the user to log out and back in.
  async function refreshSessionAllowedIps(sid) {
    const raw = state.sessions.get(sid);
    if (!raw) return;
    const cached = await resolveAllowedIps(raw.username, raw.pveTicket);
    const proxmoxHost = cfg('proxmox.host');
    const allowedIps = raw.canSeeAllMappings
      ? new Set([...cached.ips, proxmoxHost].filter(Boolean))
      : cached.ips;
    const ipLinks = (raw.canSeeAllMappings && proxmoxHost)
      ? { ...cached.ipLinks, [proxmoxHost]: proxmoxWebUrl(null, null) }
      : cached.ipLinks;
    state.sessions.set(sid, { ...raw, allowedIps, ipLinks });
  }

  // Determines whether the logging-in user is "privileged": may see every UPnP mapping
  // and skip the per-user mapping restrictions.
  // 'root' → username must be root@pam.
  // Any other value → user must have that role assigned in the Proxmox ACL (read with
  // the API token, so the token needs permission to list ACLs).
  async function canSeeAllMappings(username) {
    const role = resolvedAllPortsRole();
    if (role === 'root') return username === 'root@pam';

    const tokenId  = cfg('proxmox.api_token_id');
    const tokenSec = secrets.getToken();
    if (!tokenId || !tokenSec) return false;

    const res = await pveGetApiToken('/api2/json/access/acl');
    if (!res.ok || !Array.isArray(res.data?.data)) return false;
    return res.data.data.some(e => e.ugid === username && e.type === 'user' && e.roleid === role);
  }

  // ── Session / auth helpers ────────────────────────────────────────────────────

  // Returns the configured trusted proxy IPs (trusted_proxies), or null if unrestricted
  // (empty / 0.0.0.0). When set, the middleware below rejects requests from any other
  // address, so the app can only be reached through those proxies.
  function getTrustedProxies() {
    const raw = cfg('trusted_proxies', null);
    if (!raw) return null;
    const ips = (Array.isArray(raw) ? raw : String(raw).split(','))
      .map(s => s.replace(/^::ffff:/, '').trim())
      .filter(s => s && s !== '0.0.0.0');
    return ips.length ? new Set(ips) : null;
  }

  // The caller's IP: the socket address, or the first X-Forwarded-For entry when the
  // request came from a trusted proxy. With no trusted_proxies configured that header
  // is believed from anyone, so the login rate limit can be evaded by spoofing it —
  // set trusted_proxies whenever the app is reachable other than through your proxy.
  function clientIp(req) {
    const remote  = (req.socket.remoteAddress || '').replace(/^::ffff:/, '').trim();
    const proxies = getTrustedProxies();
    const fwd     = req.headers['x-forwarded-for'];
    if (!fwd) return remote;
    // Only honour X-Forwarded-For when it arrives from a trusted proxy
    if (proxies === null || proxies.has(remote)) {
      return fwd.split(',')[0].replace(/^::ffff:/, '').trim();
    }
    return remote;
  }

  // Per-IP login throttle: at most one attempt per second, plus a 5-minute lockout
  // after 10 failed logins (see recordLoginFailure). Returns { ok, locked }.
  function checkRateLimit(req) {
    const ip  = clientIp(req);
    const now = Date.now();
    const rec = state.loginAttempts.get(ip);
    // Locked out?
    if (rec?.lockedUntil && now < rec.lockedUntil) return { ok: false, locked: true };
    // Per-second throttle (still applies outside lockout)
    const last = rec?.ts || 0;
    if (now - last < 1000) return { ok: false, locked: false };
    state.loginAttempts.set(ip, { ...(rec || {}), ts: now });
    return { ok: true };
  }

  function recordLoginFailure(req) {
    const ip       = clientIp(req);
    const now      = Date.now();
    const rec      = state.loginAttempts.get(ip) || { ts: now, failures: 0 };
    const failures = (rec.failures || 0) + 1;
    const lockedUntil = failures >= 10
      ? now + 5 * 60 * 1000               // 5-minute lockout
      : (rec.lockedUntil || 0);
    state.loginAttempts.set(ip, { ts: now, failures, lockedUntil });
    if (failures >= 10)
      console.warn(`[auth] ${ip} locked out for 5 min after ${failures} failed attempts`);
  }

  function parseCookies(req) {
    const header = req.headers.cookie || '';
    return Object.fromEntries(
      header.split(';')
        .map(p => { const [k, ...v] = p.trim().split('='); return [k.trim(), decodeURIComponent(v.join('='))]; })
        .filter(([k]) => k)
    );
  }

  // Returns the live session for this request's cookie ({ sid, ...session }), or null
  // if there is none or it has expired (expired sessions are deleted on sight).
  function getSession(req) {
    const sid = parseCookies(req)[SESSION_COOKIE];
    if (!sid) return null;
    const sess = state.sessions.get(sid);
    if (!sess) return null;
    if (Date.now() > sess.expiresAt) { state.sessions.delete(sid); return null; }
    return { sid, ...sess };
  }

  // ── Link-preview embed (Open Graph metadata for Discord/Slack/etc. unfurlers) ──
  // These bots fetch the page with a plain GET and parse Open Graph meta tags
  // straight out of the HTML response — they never run main.js, so the
  // summary has to be built and inlined server-side, from the same
  // displayCache the page itself renders from. Only uses data that's already
  // visible to anyone loading the page without logging in (port mappings,
  // the one section that needs auth, are deliberately left out).
  function buildEmbedDescription() {
    const d = state.displayCache || {};
    let total = 0;
    const failing = []; // { name, detail }

    const consider = (name, r) => {
      if (!r || typeof r.ok !== 'boolean') return;
      total++;
      if (!r.ok) failing.push({ name, detail: r.detail || 'FAIL' });
    };
    const cap = s => s.charAt(0).toUpperCase() + s.slice(1);

    consider('Gateway', d.network?.gateway);
    consider('Broadcast', d.network?.broadcast);
    consider('Internet', d.network?.internet);
    consider('Proxmox UI', d.services?.proxmox_ui);
    for (const [label, v] of Object.entries(d.dns || {})) consider(`DNS ${cap(label)}`, v);
    consider('DHCP', d.services?.dhcp);
    consider('UPnP', d.services?.upnp);
    for (const r of (d.serviceChecks || [])) consider(r.label, r);

    const lines = [];

    const nodeName = (d.nodeOrder || [])[0];
    const host = nodeName ? d.nodes?.[nodeName]?.host : null;
    if (host?.ok) lines.push(`CPU ${host.cpu}% · RAM ${host.memUsedGb}/${host.memTotalGb} GB`);

    if (total > 0) {
      lines.push(failing.length === 0 ? `All ${total} checks passing` : `${total - failing.length} checks passing`);
      // One failure per line — Discord and friends render \n in og:description
      // as real line breaks. Capped so a pile of failures can't blow past a
      // reasonable embed size.
      const shown = failing.slice(0, 10);
      for (const f of shown) lines.push(`${f.name}: ${f.detail}`);
      if (failing.length > shown.length) lines.push(`+${failing.length - shown.length} more`);
    }

    return lines.length ? lines.join('\n') : 'Live network & host status';
  }

  // ── Express app ───────────────────────────────────────────────────────────────

  const app = express();

  // ── Trusted proxy enforcement — block direct connections when proxies are configured ──
  app.use((req, res, next) => {
    const proxies = getTrustedProxies();
    if (!proxies) return next();
    const remote = (req.socket.remoteAddress || '').replace(/^::ffff:/, '').trim();
    if (!proxies.has(remote)) return res.status(403).end();
    next();
  });

  // ── Security headers ──────────────────────────────────────────────────────────

  // Content-Security-Policy: default-src 'self' plus one addition, the Cloudflare Web
  // Analytics beacon script and its reporting endpoint, so the page keeps working when it
  // is served through Cloudflare with analytics enabled. Remove those two hosts if you
  // don't use it.
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options',  'nosniff');
    res.setHeader('X-Frame-Options',         'DENY');
    res.setHeader('Referrer-Policy',         'same-origin');
    res.setHeader('Content-Security-Policy',
      "default-src 'self'; " +
      "script-src 'self' https://static.cloudflareinsights.com; " +
      "connect-src 'self' https://cloudflareinsights.com https://static.cloudflareinsights.com; " +
      "frame-ancestors 'none'"
    );
    next();
  });

  // Registered before express.static so it wins over that middleware's own
  // automatic index.html serving for the exact '/' path — every other file
  // (main.js, style.css, fonts, ...) still falls through untouched.
  app.get('/', (req, res) => {
    let html;
    try {
      html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
    } catch (e) {
      return res.status(500).end();
    }

    const title       = escAttr(cfg('page.title', 'Open Moxdash'));
    const description = escAttr(buildEmbedDescription());
    // Cloudflare (or any TLS-terminating proxy) always talks plain HTTP to
    // this origin, so req.protocol would report 'http' even though the
    // public URL is https — hardcode it rather than trust that.
    const host      = req.headers['x-forwarded-host'] || req.headers.host || 'localhost';
    const pageUrl   = escAttr(`https://${host}${req.originalUrl}`);

    const ogTags = `<meta property="og:type" content="website">
<meta property="og:site_name" content="${title}">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${description}">
<meta property="og:url" content="${pageUrl}">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="${title}">
<meta name="twitter:description" content="${description}">
<meta name="theme-color" content="#141619">`;

    // public/index.html contains an <!--OG--> marker and a placeholder <title>Open Moxdash</title>;
    // both are filled in per request so the configured page.title appears in the browser
    // tab and in link previews.
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html.replace('<!--OG-->', ogTags).replace('<title>Open Moxdash</title>', `<title>${title}</title>`));
  });

  // Static files come after the templated '/' above; JSON body parsing is only needed
  // by the POST routes below.
  app.use(express.static(path.join(__dirname, 'public')));
  app.use(express.json());

  // ── Auth routes ───────────────────────────────────────────────────────────────

  // Login: checks the credentials against Proxmox itself (POST /access/ticket), so any
  // realm your Proxmox accepts works. Failures feed the per-IP lockout. On success the
  // Proxmox ticket is kept in the server-side session and only a session cookie is
  // sent to the browser.
  app.post('/api/auth/login', async (req, res) => {
    const rl = checkRateLimit(req);
    if (!rl.ok) {
      if (rl.locked) {
        console.warn(`[auth] locked-out IP attempted login: ${clientIp(req)}`);
        return res.status(429).json({ ok: false, error: 'Too many failed attempts — try again in 5 minutes' });
      }
      console.warn(`[auth] rate limit hit from ${clientIp(req)}`);
      return res.status(429).json({ ok: false, error: 'Too many attempts — wait a moment' });
    }

    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ ok: false, error: 'Missing credentials' });

    const pveRes = await pvePost('/api2/json/access/ticket', { username, password });

    if (!pveRes.ok || pveRes.status !== 200 || !pveRes.data?.data?.ticket) {
      if (pveRes.status === 401) {
        recordLoginFailure(req);
        return res.status(401).json({ ok: false, error: 'Invalid credentials' });
      }
      return res.status(502).json({ ok: false, error: 'PVE auth unavailable' });
    }

    // Successful login — clear any recorded failures
    state.loginAttempts.delete(clientIp(req));

    const pveTicket = pveRes.data.data.ticket;
    const cached    = await resolveAllowedIps(username, pveTicket);
    const seeAll    = await canSeeAllMappings(username);
    // Privileged accounts also get Proxmox's own host IP added to their
    // personal IP set — this is per-session, not written back to the shared
    // cache, since it shouldn't apply to other users' sessions. It has no
    // vmid (it's the host, not a guest), so its link goes to the bare UI root.
    const proxmoxHost = cfg('proxmox.host');
    const allowedIps = seeAll
      ? new Set([...cached.ips, proxmoxHost].filter(Boolean))
      : cached.ips;
    const ipLinks = (seeAll && proxmoxHost)
      ? { ...cached.ipLinks, [proxmoxHost]: proxmoxWebUrl(null, null) }
      : cached.ipLinks;

    const sid = crypto.randomBytes(32).toString('hex');
    state.sessions.set(sid, { username, pveTicket, allowedIps, ipLinks, canSeeAllMappings: seeAll, expiresAt: Date.now() + SESSION_TTL_MS });

    if (cfg('upnp.refresh_on_login', true)) await refreshUpnpMappings();

    res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${sid}; HttpOnly; Secure; SameSite=Strict; Max-Age=7200; Path=/`);
    res.json({ ok: true, username, canSeeAllMappings: seeAll, allowedIps: Array.from(allowedIps), ipLinks });
  });

  app.post('/api/auth/logout', (req, res) => {
    const sess = getSession(req);
    if (sess) state.sessions.delete(sess.sid);
    res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/`);
    res.json({ ok: true });
  });

  // Lets the frontend restore its logged-in state after a page load.
  app.get('/api/auth/me', async (req, res) => {
    let sess = getSession(req);
    if (sess) {
      await refreshSessionAllowedIps(sess.sid);
      sess = getSession(req);
    }
    if (sess) res.json({ ok: true, username: sess.username, canSeeAllMappings: !!sess.canSeeAllMappings, allowedIps: Array.from(sess.allowedIps || []), ipLinks: sess.ipLinks || {} });
    else      res.json({ ok: false });
  });

  // ── Status route ──────────────────────────────────────────────────────────────

  // The frontend's polling endpoint. Everything is public except UPnP port mappings,
  // which are personalised: none when logged out, all for privileged users, otherwise
  // only mappings whose internal client is one of the user's own IPs.
  app.get('/api/status', async (req, res) => {
    let sess = getSession(req);
    // Piggybacks on the poll the frontend is already doing every ~3s — keeps
    // a logged-in session's IP list current (e.g. a just-created VM/CT)
    // without requiring the user to log out and back in. resolveAllowedIps()
    // TTL-bounds the actual Proxmox lookup, so this is a cheap no-op most polls.
    if (sess) {
      await refreshSessionAllowedIps(sess.sid);
      sess = getSession(req);
    }
    let data = state.displayCache;

    if (state.displayCache?.services?.upnp?.mappings) {
      const mappings = sess
        ? (sess.canSeeAllMappings
            ? state.displayCache.services.upnp.mappings
            : state.displayCache.services.upnp.mappings.filter(m => sess.allowedIps.has(m.internalClient)))
        : [];
      data = {
        ...state.displayCache,
        services: {
          ...state.displayCache.services,
          upnp: { ...state.displayCache.services.upnp, mappings },
        },
      };
    }

    res.json({
      timestamp:    state.lastUpdated,
      fastUpdated:  state.fastUpdated,
      serverTime:   new Date().toISOString(),
      authenticated: !!sess,
      canSeeAllMappings: sess ? !!sess.canSeeAllMappings : false,
      allowedIps:   sess ? Array.from(sess.allowedIps) : [],
      ipLinks:      sess ? sess.ipLinks : {},
      data,
    });
  });

  // ── UPnP mapping deletion ────────────────────────────────────────────────────
  // Requirement 1: must be logged in. Requirement 2: can only delete your own
  // VMs' mappings, UNLESS you're at the configured all_ports_role level (or
  // above), in which case ownership doesn't apply and any mapping can be
  // deleted. The client's request is never trusted for ownership — even the
  // internalClient value the browser is currently displaying — we re-derive
  // the mapping's real owner from a live query against the router itself.
  app.post('/api/upnp/delete-mapping', async (req, res) => {
    const sess = getSession(req);
    if (!sess) return res.status(401).json({ ok: false, error: 'Not logged in' });

    const { protocol, externalPort } = req.body || {};
    const proto = typeof protocol === 'string' ? protocol.toUpperCase() : '';
    const port  = Number(externalPort);
    if ((proto !== 'TCP' && proto !== 'UDP') || !Number.isInteger(port) || port < 1 || port > 65535) {
      return res.status(400).json({ ok: false, error: 'Invalid protocol or port' });
    }

    if (!sess.canSeeAllMappings) {
      const owner = await getMappingOwner(proto, port);
      if (!owner.found) {
        return res.status(404).json({ ok: false, error: 'Mapping not found' });
      }
      if (!owner.internalClient || !sess.allowedIps.has(owner.internalClient)) {
        console.warn(`[upnp] ${sess.username} tried to delete ${proto}/${port} (owned by ${owner.internalClient || '?'}) — denied`);
        return res.status(403).json({ ok: false, error: 'Not your mapping' });
      }
    }

    const result = await deletePortMapping(proto, port);
    if (!result.ok) return res.status(502).json({ ok: false, error: result.error || 'Delete failed' });

    console.log(`[upnp] ${sess.username} deleted mapping ${proto}/${port}`);
    if (cfg('upnp.refresh_on_delete', true)) await refreshUpnpMappings();
    res.json({ ok: true });
  });

  // ── UPnP mapping creation ────────────────────────────────────────────────────
  // Requirement 1: must be logged in. Requirement 2: your account needs at
  // least one running VM/CT reporting a LAN IP (sess.allowedIps non-empty) —
  // unless you're at the all_ports_role level, which skips that gate entirely.
  //
  // "Locked" mode (the default, and the ONLY mode for non-privileged users)
  // enforces: the internalClient must be one of your own IPs, it can't match
  // an upnp-blacklist.json rule, the internal port can't already be mapped for
  // that same IP, and the external port can't already be in use by anyone.
  // "Unlocked" bypass mode skips all of that — but the bypass flag from the
  // client is only ever honored when the session itself is already privileged;
  // a non-privileged session sending bypass:true is silently ignored, since
  // the lock UI is a convenience, not a permission grant — that lives here.
  app.post('/api/upnp/add-mapping', async (req, res) => {
    const sess = getSession(req);
    if (!sess) return res.status(401).json({ ok: false, error: 'Not logged in' });

    const privileged = !!sess.canSeeAllMappings;
    if (!privileged && sess.allowedIps.size === 0) {
      return res.status(403).json({ ok: false, error: 'No eligible VM/CT with a reported LAN IP' });
    }

    const b = req.body || {};
    const proto          = typeof b.protocol === 'string' ? b.protocol.toUpperCase() : '';
    const internalPort   = Number(b.internalPort);
    const externalPort   = Number(b.externalPort);
    const internalClient = typeof b.internalClient === 'string' ? b.internalClient.trim() : '';
    // No silent default here either — a missing/unparseable lease is rejected
    // rather than quietly becoming an hour.
    const leaseDuration  = (b.leaseDuration === '' || b.leaseDuration === null || b.leaseDuration === undefined
                            || !Number.isFinite(Number(b.leaseDuration)))
                             ? null
                             : Math.trunc(Number(b.leaseDuration));
    const description    = (typeof b.description === 'string' ? b.description : '').trim().slice(0, 64);

    if (proto !== 'TCP' && proto !== 'UDP')
      return res.status(400).json({ ok: false, error: 'Invalid protocol' });
    if (!Number.isInteger(internalPort) || internalPort < 1 || internalPort > 65535)
      return res.status(400).json({ ok: false, error: 'Invalid internal port' });
    if (!Number.isInteger(externalPort) || externalPort < 1 || externalPort > 65535)
      return res.status(400).json({ ok: false, error: 'Invalid external port' });
    if (!isValidIPv4(internalClient))
      return res.status(400).json({ ok: false, error: 'Invalid internal client IP' });
    if (!Number.isInteger(leaseDuration) || leaseDuration < 0 || leaseDuration > 2592000)
      return res.status(400).json({ ok: false, error: 'Invalid lease duration' });
    // 0 is UPnP's own "no expiry" value — gated separately from the general
    // duration check above since it means something different (permanent,
    // not just a long lease) and needs its own permission check. Deliberately
    // checked as === 0, not falsy, so an unparsed/empty lease (already turned
    // into `null` above and rejected by the Number.isInteger check) can never
    // accidentally be treated as a permanent-lease request.
    if (leaseDuration === 0 && !canRequestPermanentLease(sess.username, privileged)) {
      return res.status(403).json({ ok: false, error: 'Permanent leases are not permitted for this account' });
    }

    const bypass = privileged && !!b.bypass;

    if (!bypass) {
      if (!sess.allowedIps.has(internalClient)) {
        return res.status(403).json({ ok: false, error: 'Not your IP' });
      }
      if (isBlacklisted(internalClient, externalPort, internalPort)) {
        return res.status(403).json({ ok: false, error: 'Blocked by blacklist rule' });
      }
      const current = await getCurrentMappings();
      if (current.some(m => m.internalClient === internalClient && m.internalPort === internalPort)) {
        return res.status(409).json({ ok: false, error: 'Internal port already mapped for this IP' });
      }
      if (current.some(m => m.externalPort === externalPort)) {
        return res.status(409).json({ ok: false, error: 'External port already in use' });
      }
    }

    const result = await addPortMapping(
      proto, externalPort, internalPort, internalClient, leaseDuration,
      description || `open-moxdash:${sess.username}`
    );
    if (!result.ok) return res.status(502).json({ ok: false, error: result.error || 'Add failed' });

    console.log(`[upnp] ${sess.username} added mapping ${proto}/${externalPort} -> ${internalClient}:${internalPort}${bypass ? ' (bypass)' : ''}`);
    if (cfg('upnp.refresh_on_add', true)) await refreshUpnpMappings();
    res.json({ ok: true });
  });

  // Liveness probe for proxies and monitoring: answers 200 without running any checks.
  app.get('/health', (_req, res) => res.json({ ok: true }));

  // Server-sent events stream. The server pushes 'reload' (after a hot reload or a change
  // under public/) and 30-second 'ping' keep-alives; the bundled frontend acts only on
  // 'reload'. Open connections per client IP are capped at sse.max_connections_per_ip,
  // with addresses in sse.exceptions exempt.
  app.get('/api/events', (req, res) => {
    const ip      = clientIp(req);
    const maxConn = cfg('sse.max_connections_per_ip', 1);
    const rawExc  = cfg('sse.exceptions', []);
    const excepts = new Set(Array.isArray(rawExc)
      ? rawExc
      : String(rawExc).split(',').map(s => s.trim()).filter(Boolean));

    if (!excepts.has(ip)) {
      const current = state.sseConnsPerIp.get(ip) || 0;
      if (current >= maxConn) {
        console.warn(`[sse] connection limit (${maxConn}) reached for ${ip}`);
        return res.status(429).end();
      }
    }

    state.sseConnsPerIp.set(ip, (state.sseConnsPerIp.get(ip) || 0) + 1);

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();
    state.sseClients.add(res);
    req.on('close', () => {
      state.sseClients.delete(res);
      const n = state.sseConnsPerIp.get(ip) || 1;
      if (n <= 1) state.sseConnsPerIp.delete(ip);
      else        state.sseConnsPerIp.set(ip, n - 1);
    });
  });

  // Tells the frontend which panels to render. Public (no login): it exposes feature
  // flags and page settings, plus the LAN subnet and the labels and types of custom
  // checks, but never host addresses or credentials.
  app.get('/api/config', (req, res) => {
    const raw = load();
    res.json({
      network: {
        gateway:   !!raw.network?.gateway,
        broadcast: !!raw.network?.broadcast,
        subnet:    raw.network?.subnet || null,
      },
      dns: Object.fromEntries(
        Object.entries(raw.dns || {}).map(([label, server]) => [label, !!server])
      ),
      proxmox: {
        enabled: !!(raw.proxmox?.host && raw.proxmox?.api_token_id && secrets.getToken()),
        uiCheck: !!raw.proxmox?.host,
      },
      upnp: {
        enabled:        !!(raw.upnp?.enabled),
        show_all_ports: !!(raw.upnp?.show_all_ports),
        all_ports_role: resolvedAllPortsRole(),
      },
      dhcp: {
        enabled: !!raw.dhcp?.server,
      },
      page: {
        title:                raw.page?.title                || 'Open Moxdash',
        refresh_seconds:      raw.page?.refresh_seconds      || 30,
        fast_refresh_seconds: raw.page?.fast_refresh_seconds || 3,
      },
      checks: Object.fromEntries(
        Object.entries(raw.checks || {}).map(([label, opts]) => [label, { type: opts.type }])
      ),
    });
  });

  return app;
};
