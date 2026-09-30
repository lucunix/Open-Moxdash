'use strict';
// Proxmox VE checks: web UI reachability (TCP), cluster node discovery, and
// per-node host statistics, all via the Proxmox REST API at
// https://<proxmox.host>:<proxmox.port>/api2/json, authenticated with an API token
// (proxmox.api_token_id plus the secret held by secrets.js). Every request in this
// file is a read-only GET.
const https   = require('https');
const net     = require('net');
const { cfg } = require('../config');
const secrets = require('../secrets');

// Proxmox ships with a self-signed certificate, so certificate verification is
// off for API calls. Point proxmox.host only at a host on a network you trust.
// keepAlive reuses connections across the frequent fast-cycle requests.
const agent = new https.Agent({ rejectUnauthorized: false, keepAlive: true });

// GET a URL (sending the API token header when both parts are given) and resolve
// { ok, status, data, ms }; never rejects. ok means an HTTP response arrived (not
// that the status was 2xx); data is the parsed JSON body or null.
function httpsGet(url, tokenId, tokenSecret, timeoutMs = 6000) {
  return new Promise(resolve => {
    const headers = {};
    if (tokenId && tokenSecret) headers['Authorization'] = `PVEAPIToken=${tokenId}=${tokenSecret}`;

    const start = Date.now();
    const req = https.get(url, { agent, headers, timeout: timeoutMs }, res => {
      let body = '';
      res.on('data', d => { body += d; });
      res.on('end', () => {
        let data = null;
        try { data = JSON.parse(body); } catch (_) {}
        resolve({ ok: true, status: res.statusCode, data, ms: Date.now() - start });
      });
    });
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, status: null, data: null, ms: timeoutMs }); });
    req.on('error',   () => resolve({ ok: false, status: null, data: null, ms: Date.now() - start }));
  });
}

// Web UI reachability: a plain TCP connect to proxmox.host:proxmox.port (default
// 8006), reported as connect time. Needs no API token. Returns null if no host is set.
async function checkProxmoxUI() {
  const host = cfg('proxmox.host');
  const port = cfg('proxmox.port', 8006);
  if (!host) return null;

  // TCP connect — gives true LAN latency without TLS handshake overhead
  const result = await new Promise(resolve => {
    const start = Date.now();
    const sock = net.createConnection({ host, port }, () => {
      const ms = Date.now() - start;
      sock.destroy();
      resolve({ ok: true, ms });
    });
    sock.setTimeout(3000, () => { sock.destroy(); resolve({ ok: false, ms: null }); });
    sock.on('error', () => resolve({ ok: false, ms: null }));
  });

  if (!result.ok) {
    console.warn(`[proxmox] UI unreachable — host=${host}:${port} TCP connect failed`);
  }
  return { ok: result.ok, detail: result.ok ? `${result.ms}ms` : 'unreachable' };
}

// Discover every node in the cluster via the entry-point host's API.
// Works for standalone hosts too — Proxmox always reports itself as a
// single-node "cluster" of one, so this is safe to call unconditionally.
async function discoverNodes() {
  const host       = cfg('proxmox.host');
  const port       = cfg('proxmox.port', 8006);
  const tokenId    = cfg('proxmox.api_token_id');
  const secretBuf  = secrets.getToken();
  const fallback   = host ? [{ name: cfg('proxmox.node', 'pve'), ip: host }] : [];
  if (!host || !tokenId || !secretBuf) return fallback;

  // The token exists in plaintext only briefly: getToken() returns a Buffer that is
  // zeroed as soon as it has been copied into the request string.
  const secret = secretBuf.toString('utf8');
  secretBuf.fill(0);

  const res = await httpsGet(`https://${host}:${port}/api2/json/cluster/status`, tokenId, secret);
  if (!res.ok || !Array.isArray(res.data?.data)) {
    console.warn(`[proxmox] cluster/status unavailable — falling back to single node "${fallback[0]?.name}"`);
    return fallback;
  }

  // The corosync-reported `ip` field is a cluster link address, which may not
  // be the same reachable address configured for the entry-point host — e.g.
  // it can be a WAN/public IP while proxmox.host is the LAN management IP.
  // For the local node (the one we're already talking to), trust the
  // configured host instead of the self-reported cluster IP. Only use the
  // cluster-reported IP for genuinely remote nodes, where it's the only
  // address we have.
  const nodes = res.data.data
    .filter(e => e.type === 'node' && e.name)
    .map(e => ({ name: e.name, ip: e.local ? host : (e.ip || host) }))
    .sort((a, b) => a.name.localeCompare(b.name));

  return nodes.length ? nodes : fallback;
}

// Fetches /nodes/<node>/status and returns CPU/memory/swap usage, load averages,
// uptime and version strings for the dashboard's host panel, or { ok: false } if
// the API call fails. Returns null when the host or API token isn't configured.
async function checkProxmoxStats(node) {
  const host      = cfg('proxmox.host');
  const port      = cfg('proxmox.port', 8006);
  const tokenId   = cfg('proxmox.api_token_id');
  const secretBuf = secrets.getToken();
  if (!host || !tokenId || !secretBuf) return null;
  const secret = secretBuf.toString('utf8');
  secretBuf.fill(0);

  const base = `https://${host}:${port}/api2/json/nodes/${node}`;
  const statusRes = await httpsGet(`${base}/status`, tokenId, secret);

  if (!statusRes.ok || !statusRes.data?.data) {
    console.warn(`[proxmox] stats API error — status=${statusRes.status} ok=${statusRes.ok}`);
    return { ok: false, error: statusRes.status || 'timeout' };
  }

  const s = statusRes.data.data;

  const memUsed  = s.memory?.used  || 0;
  const memTotal = s.memory?.total || 1;
  const swapUsed  = s.swap?.used  || 0;
  const swapTotal = s.swap?.total || 0;

  const cpuPct     = Math.round((s.cpu || 0) * 100 * 10) / 10;
  const memPct     = Math.round((memUsed / memTotal) * 100 * 10) / 10;
  const swapPct    = swapTotal > 0 ? Math.round((swapUsed / swapTotal) * 100 * 10) / 10 : 0;
  const memUsedGb  = Math.round(memUsed  / 1073741824 * 100) / 100;
  const memTotalGb = Math.round(memTotal / 1073741824 * 100) / 100;
  const swapUsedGb  = Math.round(swapUsed  / 1073741824 * 100) / 100;
  const swapTotalGb = Math.round(swapTotal / 1073741824 * 100) / 100;

  // 1/5/15-minute load averages, straight from the node status `loadavg` array
  let loadAvg = null;
  if (s.loadavg) {
    loadAvg = s.loadavg.map(v => Math.round(parseFloat(v) * 100) / 100);
  }

  return {
    ok:           true,
    cpu:          cpuPct,
    cpuModel:     s.cpuinfo?.model_name || null,
    sockets:      s.cpuinfo?.sockets    || null,
    cores:        s.cpuinfo?.cores      || null,
    threads:      s.cpuinfo?.cpus       || null,
    memUsedGb,    memTotalGb,  memPct,
    swapUsedGb,   swapTotalGb, swapPct,
    loadAvg,
    uptimeSeconds: s.uptime     || null,
    kernelVersion: s.kversion   || null,
    pveVersion:    s.pveversion || null,
  };
}

module.exports = { checkProxmoxUI, checkProxmoxStats, discoverNodes };
