'use strict';
// Custom service checks, configured in the `checks` block of config.json. Each key
// is the label shown on the page and each value selects a check by `type`:
//
//   "Router":   { "type": "ping", "host": "192.168.1.1" }
//   "Wiki":     { "type": "http", "url": "https://wiki.example.com", "verify": true }
//   "Mail TLS": { "type": "tls",  "host": "mail.example.com", "port": 443, "verify": true }
//
// ping  — one ICMP echo
// http  — GET; a 2xx or 3xx status counts as up (redirects are not followed)
// tls   — connects and reports days left on the certificate (warns under 14)
//
// `verify: false` accepts self-signed certificates for http/tls checks.
const http  = require('http');
const https = require('https');
const tls   = require('tls');
const { run } = require('./network');
const { cfg } = require('../config');

// label → timestamp (ms) of the last successful check, kept in memory so a failing
// service can show how long ago it was last up.
const lastOkTimes = {};

// Allow only characters valid in hostnames and IPv4 addresses — no shell metacharacters
function validateHost(host) {
  if (!host || !/^[a-zA-Z0-9.\-]+$/.test(String(host)))
    throw new Error(`Invalid host value in config: "${host}"`);
  return host;
}

// One ICMP echo (2s wait); reports the round-trip time in ms.
async function checkPing(host) {
  validateHost(host);
  const res = await run(`ping -c 1 -W 2 ${host}`, 5000);
  if (!res.ok) return { ok: false, detail: 'unreachable' };
  const m = res.stdout?.match(/time=([\d.]+)\s*ms/);
  if (!m) return { ok: false, detail: 'no reply' };
  return { ok: true, detail: `${Math.round(parseFloat(m[1]))}ms` };
}

// GETs the URL with an 8s timeout. Status 200-399 is up; the body is discarded.
// Redirects are not followed, so a 3xx is reported as up without visiting the target.
async function checkHttp(url, verify = true) {
  return new Promise(resolve => {
    const start = Date.now();
    const mod   = url.startsWith('https') ? https : http;
    const req   = mod.get(url, { timeout: 8000, rejectUnauthorized: verify }, res => {
      res.resume();
      const ms = Date.now() - start;
      const ok = res.statusCode >= 200 && res.statusCode < 400;
      resolve({ ok, detail: ok ? `${ms}ms` : `HTTP ${res.statusCode}` });
    });
    req.on('error',   ()  => resolve({ ok: false, detail: 'unreachable' }));
    req.on('timeout', ()  => { req.destroy(); resolve({ ok: false, detail: 'timeout' }); });
  });
}

// Opens a TLS connection and reports certificate expiry. An expired certificate is
// a failure; under 14 days left is still up but flagged with warn: true.
async function checkTls(host, port = 443, verify = true) {
  return new Promise(resolve => {
    const sock = tls.connect(
      { host, port: Number(port), servername: host, rejectUnauthorized: verify },
      () => {
        const cert = sock.getPeerCertificate();
        sock.destroy();
        if (!cert?.valid_to) return resolve({ ok: false, detail: 'no cert' });
        const daysLeft = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000);
        if (daysLeft  <  0) return resolve({ ok: false, detail: 'expired',                daysLeft });
        if (daysLeft  < 14) return resolve({ ok: true,  detail: `expires in ${daysLeft}d`, daysLeft, warn: true });
        resolve({ ok: true, detail: `${daysLeft}d left`, daysLeft });
      }
    );
    sock.setTimeout(8000);
    sock.on('timeout', () => { sock.destroy(); resolve({ ok: false, detail: 'timeout' }); });
    sock.on('error',   e  => resolve({ ok: false, detail: e.code || 'error' }));
  });
}

// Runs every configured check in parallel and returns [{ label, type, ok, detail,
// lastOkAt, ... }], or null when no checks are configured. A misconfigured entry
// (unknown type, invalid host) is reported as a failed result instead of throwing.
async function checkServices() {
  const checks = cfg('checks');
  if (!checks || typeof checks !== 'object') return null;
  const entries = Object.entries(checks);
  if (!entries.length) return null;

  const settled = await Promise.allSettled(
    entries.map(async ([label, opts]) => {
      let r;
      try {
        switch (opts.type) {
          case 'ping': r = await checkPing(opts.host);                                       break;
          case 'http': r = await checkHttp(opts.url,  opts.verify !== false);               break;
          case 'tls':  r = await checkTls(opts.host, opts.port ?? 443, opts.verify !== false); break;
          default:     r = { ok: false, detail: `unknown type: ${opts.type}` };
        }
      } catch (e) {
        r = { ok: false, detail: e.message };
      }
      if (r.ok) lastOkTimes[label] = Date.now();
      return { label, type: opts.type, ...r, lastOkAt: lastOkTimes[label] ?? null };
    })
  );

  return settled.filter(s => s.status === 'fulfilled').map(s => s.value);
}

module.exports = { checkServices };
