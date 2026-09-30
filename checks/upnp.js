'use strict';
// UPnP / IGD health check and router port-mapping helpers.
//
// checkUpnp() exercises the router's UPnP Internet Gateway Device end to end. It
// belongs in the slow cycle because it deliberately waits for a lease to expire:
//   1  SSDP discovery (multicast, plus a unicast probe to network.gateway)
//   2  fetch the IGD description and locate its WAN connection service
//   3  read the external IP (a private one means double NAT)
//   4  list the router's existing port mappings
//   5  add a short-lived UDP test mapping on upnp.test_port pointing at this host
//   6  read the mapping back and check the router honoured the 10s lease
//   7  wait 12s and check the mapping expired on its own
// Anything the router does that deviates from the UPnP spec is collected in
// result.compliance and shown on the page.
//
// The other exports back the mapping-management API routes in app.js and reuse the
// IGD endpoint cached by the most recent discovery. The blocklist
// (upnp-blacklist.json) and the permanent-lease user list
// (upnp-permanent-users.txt) are optional files next to config.json and are
// re-read on every use, so edits apply without a restart.
const dgram = require('dgram');
const http  = require('http');
const https = require('https');
const os    = require('os');
const fs    = require('fs');
const path  = require('path');
const { cfg } = require('../config');

const BLACKLIST_PATH        = path.join(__dirname, '..', 'upnp-blacklist.json');
const PERMANENT_USERS_PATH  = path.join(__dirname, '..', 'upnp-permanent-users.txt');

// SSDP is UPnP's discovery protocol: an M-SEARCH sent to multicast 239.255.255.250:1900.
const SSDP_ADDR          = '239.255.255.250';
const SSDP_PORT          = 1900;
const SSDP_TIMEOUT_MS    = 4000;
const SOAP_TIMEOUT_MS    = 5000;
// Test mapping: default port (override with upnp.test_port), a deliberately short
// lease, and how long to wait for it to lapse (slightly longer than the lease, to
// allow for coarse router timers).
const UPNP_DEFAULT_PORT  = 62108;
const UPNP_LEASE_SECS    = 10;
const UPNP_EXPIRY_WAIT   = 12000;

// Search targets to try, most-preferred first. Routers vary — some only
// implement IGDv2 (WANIPConnection:2), older ones only IGDv1, and some use
// PPP-style WAN connections instead of a plain IP connection.
const IGD_SEARCH_TARGETS = [
  'urn:schemas-upnp-org:device:InternetGatewayDevice:2',
  'urn:schemas-upnp-org:device:InternetGatewayDevice:1',
];
const WAN_SERVICE_CANDIDATES = [
  'urn:schemas-upnp-org:service:WANIPConnection:2',
  'urn:schemas-upnp-org:service:WANIPConnection:1',
  'urn:schemas-upnp-org:service:WANPPPConnection:2',
  'urn:schemas-upnp-org:service:WANPPPConnection:1',
];

// Last successfully-resolved IGD control endpoint, kept for on-demand
// actions (e.g. deleting a mapping) between the periodic discovery cycles.
let lastIgd = null;

// ── Helpers ──────────────────────────────────────────────────────────────────

// Returns the trimmed text of the first <tag> element (any namespace prefix), or null.
// A regex is enough for the small, flat XML that routers return.
function parseXmlValue(xml, tag) {
  const m = xml.match(new RegExp(`<(?:[^:>]+:)?${tag}[^>]*>([^<]*)<`));
  return m ? m[1].trim() : null;
}

// Finds the <controlURL> belonging to the given <serviceType> in an IGD description.
function extractControlUrl(xml, serviceType) {
  const svcRe = new RegExp(`<serviceType>\\s*${serviceType}\\s*<\\/serviceType>[\\s\\S]*?<controlURL>([^<]+)<\\/controlURL>`);
  const m = xml.match(svcRe);
  return m ? m[1].trim() : null;
}

// Find whichever WAN connection service the device actually exposes, trying
// candidates in preference order. Returns the exact serviceType URN that
// matched (version and all) so SOAP calls use the namespace the device
// itself advertised, plus its controlURL.
function findWanService(xml) {
  for (const serviceType of WAN_SERVICE_CANDIDATES) {
    const controlPath = extractControlUrl(xml, serviceType);
    if (controlPath) return { serviceType, controlPath };
  }
  return null;
}

// True for RFC 1918 private addresses (10/8, 172.16/12, 192.168/16).
function isPrivateIp(ip) {
  return /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}

// Accept only http(s) URLs with a bare IPv4 host — prevents SSRF via DNS or other schemes
function isValidLocationUrl(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(u.hostname);
  } catch (_) { return false; }
}

// First non-loopback IPv4 address of this host, used as the internal client of the
// test mapping. On a host with several interfaces it may not be the one facing the router.
function getLocalIp() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) return iface.address;
    }
  }
  return '127.0.0.1';
}

// ── SSDP Discovery ───────────────────────────────────────────────────────────

// Sends an M-SEARCH for each IGD version and collects every reply that arrives within
// SSDP_TIMEOUT_MS. Resolves an array of raw response strings (empty if none).
function discoverUpnp(gatewayIp) {
  return new Promise(resolve => {
    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    const responses = [];

    const msearches = IGD_SEARCH_TARGETS.map(st => Buffer.from(
      'M-SEARCH * HTTP/1.1\r\n' +
      `HOST: ${SSDP_ADDR}:${SSDP_PORT}\r\n` +
      'MAN: "ssdp:discover"\r\n' +
      'MX: 3\r\n' +
      `ST: ${st}\r\n\r\n`
    ));

    sock.on('message', msg => responses.push(msg.toString()));
    sock.on('error', () => {});

    sock.bind(() => {
      for (const msearch of msearches) {
        sock.send(msearch, SSDP_PORT, SSDP_ADDR, () => {});
        // Some ISP-supplied gateways don't answer
        // the 239.255.255.250 multicast group from a routed subnet but do respond to
        // a unicast M-SEARCH sent straight to their IP — probe it directly as well.
        if (gatewayIp) sock.send(msearch, SSDP_PORT, gatewayIp, () => {});
      }
      setTimeout(() => {
        try { sock.close(); } catch (_) {}
        resolve(responses);
      }, SSDP_TIMEOUT_MS);
    });
  });
}

// ── HTTP(S) fetch ─────────────────────────────────────────────────────────────

// GET a URL and resolve { ok, status, body }; never rejects. HTTPS certificates are not
// verified because routers present self-signed ones.
function httpGet(url, timeoutMs = SOAP_TIMEOUT_MS) {
  return new Promise(resolve => {
    const lib = url.startsWith('https') ? https : http;
    const opts = url.startsWith('https') ? { rejectUnauthorized: false } : {};
    const req = lib.get(url, { ...opts, timeout: timeoutMs }, res => {
      let body = '';
      res.on('data', d => { body += d; });
      res.on('end', () => resolve({ ok: true, status: res.statusCode, body }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, status: null, body: '' }); });
    req.on('error',   () => resolve({ ok: false, status: null, body: '' }));
  });
}

// ── SOAP call ────────────────────────────────────────────────────────────────

// POSTs one SOAP action to the router's control URL and resolves { ok, status, body };
// never rejects. `bodyXml` is the action element itself; the SOAPAction header is built
// from serviceType and action. Port 443 switches to HTTPS (certificate not verified).
function upnpSoap(host, port, controlPath, action, serviceType, bodyXml) {
  const envelope =
    '<?xml version="1.0"?>' +
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' +
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
    '<s:Body>' + bodyXml + '</s:Body></s:Envelope>';

  const protocol = port === 443 ? https : http;
  const options = {
    host, port,
    path:   controlPath,
    method: 'POST',
    headers: {
      'Content-Type':   'text/xml; charset="utf-8"',
      'SOAPAction':     `"${serviceType}#${action}"`,
      'Content-Length': Buffer.byteLength(envelope),
    },
    timeout: SOAP_TIMEOUT_MS,
    ...(port === 443 ? { rejectUnauthorized: false } : {}),
  };

  return new Promise(resolve => {
    const req = protocol.request(options, res => {
      let body = '';
      res.on('data', d => { body += d; });
      res.on('end', () => resolve({ ok: true, status: res.statusCode, body }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, status: null, body: '' }); });
    req.on('error',   () => resolve({ ok: false, status: null, body: '' }));
    req.write(envelope);
    req.end();
  });
}

// ── Port mapping list ────────────────────────────────────────────────────────

// Lists the router's port mappings by walking GetGenericPortMappingEntry indexes until
// the router answers with an error, up to upnp.max_mappings (default 1024).
async function getMappings(host, port, controlPath, serviceType) {
  const mappings = [];
  const limit = Math.max(1, parseInt(cfg('upnp.max_mappings', 1024), 10) || 1024);
  for (let i = 0; i < limit; i++) {
    const r = await upnpSoap(host, port, controlPath, 'GetGenericPortMappingEntry', serviceType,
      `<u:GetGenericPortMappingEntry xmlns:u="${serviceType}"><NewPortMappingIndex>${i}</NewPortMappingIndex></u:GetGenericPortMappingEntry>`
    );
    if (!r.ok || r.status !== 200) break;
    mappings.push({
      protocol:       parseXmlValue(r.body, 'NewProtocol')        || '?',
      externalPort:   parseInt(parseXmlValue(r.body, 'NewExternalPort')   || '0', 10),
      internalPort:   parseInt(parseXmlValue(r.body, 'NewInternalPort')   || '0', 10),
      internalClient: parseXmlValue(r.body, 'NewInternalClient')  || null,
      leaseDuration:  parseInt(parseXmlValue(r.body, 'NewLeaseDuration')  || '0', 10),
      description:    parseXmlValue(r.body, 'NewPortMappingDescription') || null,
    });
  }
  return mappings;
}

// ── Main check ───────────────────────────────────────────────────────────────

// Runs the seven-stage check described at the top of this file. Resolves
// { ok, igdDetected, externalIp, mappings, portTest: { ok, added, verified, expired },
// compliance, detail }, or null when upnp.enabled is off or upnp.test_port is invalid.
// Takes at least UPNP_EXPIRY_WAIT ms once a test mapping has been added.
async function checkUpnp() {
  if (!cfg('upnp.enabled', false)) return null;

  const testPort = parseInt(cfg('upnp.test_port', UPNP_DEFAULT_PORT), 10);
  if (!(testPort > 0)) {
    console.error('[upnp] invalid upnp.test_port value — must be a positive integer. UPnP check disabled.');
    return null;
  }

  const gatewayIp = cfg('network.gateway');
  const compliance = [];
  const result = {
    ok: false, igdDetected: false, externalIp: null,
    mappings: [], portTest: { ok: false, added: false, verified: false, expired: null },
    compliance, detail: '',
  };

  // Stage 1: SSDP discovery
  const responses = await discoverUpnp(gatewayIp);
  if (responses.length === 0) {
    console.warn('[upnp] stage 1 — SSDP discovery returned no responses');
    result.detail = 'no IGD found';
    return result;
  }
  console.log(`[upnp] stage 1 — SSDP: ${responses.length} response(s)`);

  let chosen = responses[0];
  if (gatewayIp) {
    const match = responses.find(r => r.includes(gatewayIp));
    if (match) chosen = match;
  }

  const locMatch = chosen.match(/LOCATION:\s*(\S+)/i);
  if (!locMatch) {
    console.warn('[upnp] stage 1 — no LOCATION header in SSDP response');
    result.detail = 'no LOCATION in SSDP';
    return result;
  }
  const locationUrl = locMatch[1];
  if (!isValidLocationUrl(locationUrl)) {
    console.warn(`[upnp] stage 1 — rejected non-IPv4 LOCATION URL (possible SSRF): ${locationUrl}`);
    result.detail = 'invalid LOCATION URL';
    return result;
  }
  console.log(`[upnp] stage 2 — fetching IGD description: ${locationUrl}`);

  // Stage 2: Fetch IGD description
  const descRes = await httpGet(locationUrl);
  if (!descRes.ok) {
    console.warn(`[upnp] stage 2 — IGD description fetch failed: ${locationUrl} status=${descRes.status}`);
    result.detail = 'IGD description unreachable';
    return result;
  }

  result.igdDetected = true;

  const wanService = findWanService(descRes.body);
  if (!wanService) {
    console.warn('[upnp] stage 2 — no WANIPConnection/WANPPPConnection service (v1 or v2) found in IGD description');
    result.detail = 'WANIPConnection service not found';
    return result;
  }
  const { serviceType: usedServiceType, controlPath } = wanService;

  const urlMatch = locationUrl.match(/^https?:\/\/([^:/]+)(?::(\d+))?/);
  if (!urlMatch) {
    console.warn(`[upnp] stage 2 — could not parse host/port from LOCATION: ${locationUrl}`);
    result.detail = 'invalid LOCATION URL';
    return result;
  }
  const igdHost = urlMatch[1];
  const igdPort = parseInt(urlMatch[2] || (locationUrl.startsWith('https') ? '443' : '80'), 10);
  console.log(`[upnp] stage 2 — IGD at ${igdHost}:${igdPort} service=${usedServiceType} controlPath=${controlPath}`);

  // Cache the resolved control endpoint for on-demand actions (delete-mapping)
  // between discovery cycles, independent of whether the self-test below passes.
  lastIgd = { host: igdHost, port: igdPort, controlPath, serviceType: usedServiceType };

  // Stage 3: External IP
  const extIpRes = await upnpSoap(igdHost, igdPort, controlPath, 'GetExternalIPAddress', usedServiceType,
    `<u:GetExternalIPAddress xmlns:u="${usedServiceType}"></u:GetExternalIPAddress>`
  );
  if (extIpRes.ok && extIpRes.status === 200) {
    result.externalIp = parseXmlValue(extIpRes.body, 'NewExternalIPAddress');
    console.log(`[upnp] stage 3 — external IP: ${result.externalIp}`);
    if (result.externalIp && isPrivateIp(result.externalIp)) {
      console.warn(`[upnp] stage 3 — double NAT: external IP ${result.externalIp} is private (RFC1918)`);
      compliance.push({ issue: 'Double NAT detected', detail: `External IP ${result.externalIp} is private (RFC1918)` });
    }
  } else {
    console.warn(`[upnp] stage 3 — GetExternalIPAddress failed: status=${extIpRes.status} body=${extIpRes.body?.slice(0,200)}`);
    compliance.push({ issue: 'GetExternalIPAddress failed', detail: `Status ${extIpRes.status || 'timeout'}` });
  }

  // Stage 4: List mappings
  result.mappings = await getMappings(igdHost, igdPort, controlPath, usedServiceType);
  console.log(`[upnp] stage 4 — found ${result.mappings.length} existing mapping(s)`);

  // Stage 5: Add test mapping — fixed port, always delete first to avoid leftover collision
  const localIp  = getLocalIp();

  // Pre-delete: silently remove any stale mapping on our test port before adding
  await upnpSoap(igdHost, igdPort, controlPath, 'DeletePortMapping', usedServiceType,
    `<u:DeletePortMapping xmlns:u="${usedServiceType}">` +
    `<NewRemoteHost></NewRemoteHost>` +
    `<NewExternalPort>${testPort}</NewExternalPort>` +
    `<NewProtocol>UDP</NewProtocol>` +
    `</u:DeletePortMapping>`
  );

  console.log(`[upnp] stage 5 — AddPortMapping test port=${testPort} localIp=${localIp}`);
  const addRes = await upnpSoap(igdHost, igdPort, controlPath, 'AddPortMapping', usedServiceType,
    `<u:AddPortMapping xmlns:u="${usedServiceType}">` +
    `<NewRemoteHost></NewRemoteHost>` +
    `<NewExternalPort>${testPort}</NewExternalPort>` +
    `<NewProtocol>UDP</NewProtocol>` +
    `<NewInternalPort>${testPort}</NewInternalPort>` +
    `<NewInternalClient>${localIp}</NewInternalClient>` +
    `<NewEnabled>1</NewEnabled>` +
    `<NewPortMappingDescription>open-moxdash-test</NewPortMappingDescription>` +
    `<NewLeaseDuration>${UPNP_LEASE_SECS}</NewLeaseDuration>` +
    `</u:AddPortMapping>`
  );

  result.portTest.added = addRes.ok && addRes.status === 200;
  if (!result.portTest.added) {
    console.warn(`[upnp] stage 5 — AddPortMapping failed: status=${addRes.status} body=${addRes.body?.slice(0,300)}`);
    compliance.push({ issue: 'AddPortMapping failed', detail: `Status ${addRes.status || 'timeout'}` });
  } else {
    console.log(`[upnp] stage 5 — AddPortMapping ok`);
  }

  // Stage 6: Verify mapping
  if (result.portTest.added) {
    const verifyRes = await upnpSoap(igdHost, igdPort, controlPath, 'GetSpecificPortMappingEntry', usedServiceType,
      `<u:GetSpecificPortMappingEntry xmlns:u="${usedServiceType}">` +
      `<NewRemoteHost></NewRemoteHost>` +
      `<NewExternalPort>${testPort}</NewExternalPort>` +
      `<NewProtocol>UDP</NewProtocol>` +
      `</u:GetSpecificPortMappingEntry>`
    );
    result.portTest.verified = verifyRes.ok && verifyRes.status === 200;
    if (!result.portTest.verified) {
      console.warn(`[upnp] stage 6 — GetSpecificPortMappingEntry failed: status=${verifyRes.status} body=${verifyRes.body?.slice(0,300)}`);
      compliance.push({ issue: 'Mapping not retrievable after add', detail: `GetSpecificPortMappingEntry status ${verifyRes.status}` });
    } else {
      const returnedLease = parseInt(parseXmlValue(verifyRes.body, 'NewLeaseDuration') || '0', 10);
      console.log(`[upnp] stage 6 — verified ok, returned lease=${returnedLease}s`);
      if (returnedLease === 0) {
        console.warn('[upnp] stage 6 — router ignored lease duration, returned permanent (0) instead of 10s');
        compliance.push({ issue: 'Lease duration ignored', detail: 'Router returned permanent lease (0) instead of 10s' });
      }
    }

    // Stage 7: Wait for expiry
    console.log(`[upnp] stage 7 — waiting ${UPNP_EXPIRY_WAIT / 1000}s for lease to expire…`);
    await new Promise(r => setTimeout(r, UPNP_EXPIRY_WAIT));

    const expiredRes = await upnpSoap(igdHost, igdPort, controlPath, 'GetSpecificPortMappingEntry', usedServiceType,
      `<u:GetSpecificPortMappingEntry xmlns:u="${usedServiceType}">` +
      `<NewRemoteHost></NewRemoteHost>` +
      `<NewExternalPort>${testPort}</NewExternalPort>` +
      `<NewProtocol>UDP</NewProtocol>` +
      `</u:GetSpecificPortMappingEntry>`
    );

    const gone = !expiredRes.ok || expiredRes.status === 500 || expiredRes.status === 404;
    result.portTest.expired = gone;
    console.log(`[upnp] stage 7 — lease expiry check: status=${expiredRes.status} gone=${gone}`);

    if (!gone) {
      console.warn(`[upnp] stage 7 — lease NOT expired after ${UPNP_EXPIRY_WAIT / 1000}s — cleaning up`);
      compliance.push({ issue: 'Lease expiry not honoured', detail: 'Mapping still exists after 10s lease should have expired' });
      await upnpSoap(igdHost, igdPort, controlPath, 'DeletePortMapping', usedServiceType,
        `<u:DeletePortMapping xmlns:u="${usedServiceType}">` +
        `<NewRemoteHost></NewRemoteHost>` +
        `<NewExternalPort>${testPort}</NewExternalPort>` +
        `<NewProtocol>UDP</NewProtocol>` +
        `</u:DeletePortMapping>`
      );
    }
  }

  result.portTest.ok = result.portTest.added && result.portTest.verified;
  result.ok = result.igdDetected && result.portTest.ok && compliance.length === 0;
  result.detail = result.ok ? 'IGD healthy' : compliance.length > 0 ? `${compliance.length} issue${compliance.length > 1 ? 's' : ''}` : 'check failed';

  return result;
}

// ── On-demand mapping actions (used by the delete-mapping API route) ───────────
//
// These use the IGD connection info cached by the most recent checkUpnp()
// discovery, rather than re-discovering per call.

// Ask the router directly who owns a mapping. This is the server's own,
// independent source of truth for ownership checks — callers must not
// substitute a client-supplied internalClient for this.
async function getMappingOwner(protocol, externalPort) {
  if (!lastIgd) return { found: false, internalClient: null };
  const { host, port, controlPath, serviceType } = lastIgd;
  const r = await upnpSoap(host, port, controlPath, 'GetSpecificPortMappingEntry', serviceType,
    `<u:GetSpecificPortMappingEntry xmlns:u="${serviceType}">` +
    `<NewRemoteHost></NewRemoteHost>` +
    `<NewExternalPort>${externalPort}</NewExternalPort>` +
    `<NewProtocol>${protocol}</NewProtocol>` +
    `</u:GetSpecificPortMappingEntry>`
  );
  if (!r.ok || r.status !== 200) return { found: false, internalClient: null };
  return { found: true, internalClient: parseXmlValue(r.body, 'NewInternalClient') };
}

// Removes a mapping by protocol and external port. Resolves { ok } or { ok: false, error }.
async function deletePortMapping(protocol, externalPort) {
  if (!lastIgd) return { ok: false, error: 'IGD not currently available' };
  const { host, port, controlPath, serviceType } = lastIgd;
  const r = await upnpSoap(host, port, controlPath, 'DeletePortMapping', serviceType,
    `<u:DeletePortMapping xmlns:u="${serviceType}">` +
    `<NewRemoteHost></NewRemoteHost>` +
    `<NewExternalPort>${externalPort}</NewExternalPort>` +
    `<NewProtocol>${protocol}</NewProtocol>` +
    `</u:DeletePortMapping>`
  );
  if (!r.ok || r.status !== 200) {
    console.warn(`[upnp] DeletePortMapping ${protocol}/${externalPort} failed: status=${r.status}`);
    return { ok: false, error: `Router returned status ${r.status || 'timeout'}` };
  }
  console.log(`[upnp] deleted mapping ${protocol}/${externalPort}`);
  return { ok: true };
}

// List every mapping currently on the router, using the cached IGD endpoint.
// Used by the add-mapping route for its duplicate-port checks — always a
// fresh live query, never trusts a client-supplied list.
async function getCurrentMappings() {
  if (!lastIgd) return [];
  const { host, port, controlPath, serviceType } = lastIgd;
  return getMappings(host, port, controlPath, serviceType);
}

// Escapes text for use inside an XML element. Applied to the mapping description, the
// only free-text value sent to the router; the port and address arguments are
// validated by the add-mapping route in app.js before they get here.
function escapeXml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));
}

// ── Blocklist and permanent-lease policy ──────────────────────────────────────
//
// upnp-blacklist.json is NOT actually JSON — despite the name, it's parsed
// line by line. Each line is one rule matching on any combination of ip,
// external port, and internal port; a field left out of a rule acts as a
// wildcard, and a rule blocks a request only when every field it DOES
// specify matches. Port fields (ext/int) accept a single port OR a
// START-END range, inclusive on both ends. Accepted forms:
//   PORT or PORT-PORT           — shorthand for ext=PORT / ext=PORT-PORT
//   IP:PORT or IP:PORT-PORT     — shorthand for ip=IP,ext=...
//   ip=IP,ext=PORT,int=PORT     — full form, any subset of the three keys,
//                                 any order, ports may be ranges, e.g.
//                                 "int=25" alone, "ip=192.168.1.50" alone,
//                                 "ext=40000-40010", "ext=80,int=8080-8090"
// Blank lines and lines starting with # are ignored.
// Parses "25" or "40000-40010" into { min, max }; null if malformed or reversed.
function parsePortValue(val) {
  const range = val.match(/^(\d{1,5})-(\d{1,5})$/);
  if (range) {
    const min = parseInt(range[1], 10), max = parseInt(range[2], 10);
    return min <= max ? { min, max } : null;
  }
  if (/^\d{1,5}$/.test(val)) {
    const p = parseInt(val, 10);
    return { min: p, max: p };
  }
  return null;
}

// Parses one blocklist line (see the format above) into { ip, ext, int }, where each
// field is null (wildcard) or an IP / { min, max } range. Returns null if malformed.
function parseRuleLine(line) {
  const portOnly = parsePortValue(line);
  if (portOnly) return { ip: null, ext: portOnly, int: null };

  const ipPort = line.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5}(?:-\d{1,5})?)$/);
  if (ipPort) {
    const ext = parsePortValue(ipPort[2]);
    return ext ? { ip: ipPort[1], ext, int: null } : null;
  }

  const rule = { ip: null, ext: null, int: null };
  let sawField = false;
  for (const rawPair of line.split(',')) {
    const pair = rawPair.trim();
    if (!pair) continue;
    const m = pair.match(/^(ip|ext|int)\s*=\s*(.+)$/i);
    if (!m) return null;
    const key = m[1].toLowerCase();
    const val = m[2].trim();
    if (key === 'ip') {
      if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(val)) return null;
      rule.ip = val;
    } else {
      const pv = parsePortValue(val);
      if (!pv) return null;
      rule[key] = pv;
    }
    sawField = true;
  }
  return sawField ? rule : null;
}

// Reads and parses the blocklist file; a missing file means no rules. Malformed lines
// are logged and skipped rather than failing the whole list.
function loadBlacklistRules() {
  let raw;
  try { raw = fs.readFileSync(BLACKLIST_PATH, 'utf8'); }
  catch (_) { return []; }

  const rules = [];
  for (const rawLine of raw.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    const rule = parseRuleLine(line);
    if (!rule) { console.warn(`[upnp] ignoring malformed upnp-blacklist.json line: "${line}"`); continue; }
    rules.push(rule);
  }
  return rules;
}

function portInRange(range, value) {
  return range === null || (value >= range.min && value <= range.max);
}

// True if any blocklist rule matches this internal client and port pair.
function isBlacklisted(internalClient, externalPort, internalPort) {
  return loadBlacklistRules().some(r =>
    (r.ip === null || r.ip === internalClient) &&
    portInRange(r.ext, externalPort) &&
    portInRange(r.int, internalPort)
  );
}

// upnp-permanent-users.txt: one username@realm per line (e.g. root@pam,
// alice@pve). Blank lines and lines starting with # are ignored. Read fresh
// on every check (no cache) so edits take effect without a restart, same as
// the blacklist file above.
function loadPermanentLeaseUsers() {
  let raw;
  try { raw = fs.readFileSync(PERMANENT_USERS_PATH, 'utf8'); }
  catch (_) { return new Set(); }

  const users = new Set();
  for (const rawLine of raw.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    users.add(line.toLowerCase());
  }
  return users;
}

// Whether `username` may request a permanent (leaseDuration: 0) mapping,
// per the upnp.permanent_lease_access config:
//   off      — nobody
//   admin    — only privileged (all_ports_role) accounts
//   list     — privileged accounts, plus anyone in upnp-permanent-users.txt
//   everyone — anyone who can add a mapping at all
function canRequestPermanentLease(username, privileged) {
  const mode = cfg('upnp.permanent_lease_access', 'off');
  switch (mode) {
    case 'everyone': return true;
    case 'list':     return privileged || loadPermanentLeaseUsers().has(String(username || '').toLowerCase());
    case 'admin':    return privileged;
    case 'off':
    default:         return false;
  }
}

// Adds a mapping on the router (leaseDuration 0 = permanent). Callers must already have
// validated every argument except `description`, which is escaped here. Resolves
// { ok } or { ok: false, error }.
async function addPortMapping(protocol, externalPort, internalPort, internalClient, leaseDuration, description) {
  if (!lastIgd) return { ok: false, error: 'IGD not currently available' };
  const { host, port, controlPath, serviceType } = lastIgd;
  const r = await upnpSoap(host, port, controlPath, 'AddPortMapping', serviceType,
    `<u:AddPortMapping xmlns:u="${serviceType}">` +
    `<NewRemoteHost></NewRemoteHost>` +
    `<NewExternalPort>${externalPort}</NewExternalPort>` +
    `<NewProtocol>${protocol}</NewProtocol>` +
    `<NewInternalPort>${internalPort}</NewInternalPort>` +
    `<NewInternalClient>${internalClient}</NewInternalClient>` +
    `<NewEnabled>1</NewEnabled>` +
    `<NewPortMappingDescription>${escapeXml(description)}</NewPortMappingDescription>` +
    `<NewLeaseDuration>${leaseDuration}</NewLeaseDuration>` +
    `</u:AddPortMapping>`
  );
  if (!r.ok || r.status !== 200) {
    console.warn(`[upnp] AddPortMapping ${protocol}/${externalPort} failed: status=${r.status} body=${r.body?.slice(0,300)}`);
    return { ok: false, error: `Router returned status ${r.status || 'timeout'}` };
  }
  console.log(`[upnp] added mapping ${protocol}/${externalPort} -> ${internalClient}:${internalPort}`);
  return { ok: true };
}

module.exports = { checkUpnp, getMappingOwner, deletePortMapping, getCurrentMappings, addPortMapping, isBlacklisted, canRequestPermanentLease };
