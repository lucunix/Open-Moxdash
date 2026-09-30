'use strict';
// DHCP server check: broadcasts a real DHCPDISCOVER and waits for an OFFER from
// the configured server. The request uses a fixed fake client MAC and is never
// followed by a REQUEST, so it does not take a lease.
const dgram = require('dgram');
const { cfg } = require('../config');

// Builds a minimal 300-byte BOOTP/DHCP DISCOVER packet (RFC 2131): broadcast flag
// set, random transaction id, no other options.
function buildDiscover() {
  const buf = Buffer.alloc(300);
  buf[0] = 0x01; // op: BOOTREQUEST
  buf[1] = 0x01; // htype: ethernet
  buf[2] = 0x06; // hlen: 6 bytes
  buf[3] = 0x00; // hops

  // XID: random 4 bytes
  const xid = Math.floor(Math.random() * 0xFFFFFFFF);
  buf.writeUInt32BE(xid, 4);

  // secs, flags
  buf.writeUInt16BE(0, 8);
  buf.writeUInt16BE(0x8000, 10); // broadcast flag

  // chaddr: fake MAC deadbeefcafe
  buf[28] = 0xde; buf[29] = 0xad; buf[30] = 0xbe;
  buf[31] = 0xef; buf[32] = 0xca; buf[33] = 0xfe;

  // magic cookie
  buf[236] = 0x63; buf[237] = 0x82; buf[238] = 0x53; buf[239] = 0x63;

  // option 53: DHCP message type = DISCOVER
  buf[240] = 53; buf[241] = 1; buf[242] = 1;
  // end
  buf[243] = 255;

  return buf;
}

// Returns the address the server offered ("your IP address", bytes 16-19 of the reply).
function parseOfferedIp(msg) {
  return `${msg[16]}.${msg[17]}.${msg[18]}.${msg[19]}`;
}

// Used when this process may not bind UDP 68 (needs root or CAP_NET_BIND_SERVICE):
// only checks that a datagram can be sent to the server's port 67, which says
// nothing about whether a DHCP server is actually answering.
async function checkDhcpPortFallback(server) {
  return new Promise(resolve => {
    const sock = dgram.createSocket('udp4');
    sock.bind(() => {
      sock.send(Buffer.alloc(0), 67, server, err => {
        sock.close();
        resolve({ ok: !err, detail: !err ? 'port reachable' : `port error: ${err.message}` });
      });
    });
    sock.on('error', () => resolve({ ok: false, detail: 'socket error' }));
    setTimeout(() => { try { sock.close(); } catch (_) {} resolve({ ok: false, detail: 'timeout' }); }, 2000);
  });
}

// Sends a DISCOVER to dhcp.server and resolves { ok, detail, offeredIp } within 5s.
// Returns null when no DHCP server is configured.
async function checkDhcp() {
  const server = cfg('dhcp.server');
  if (!server) return null;

  return new Promise(resolve => {
    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });

    sock.on('error', async err => {
      try { sock.close(); } catch (_) {}
      if (err.code === 'EACCES' || err.code === 'EPERM') {
        console.warn(`[dhcp] no permission to bind :68 (${err.code}) — falling back to port reachability test`);
        const r = await checkDhcpPortFallback(server);
        if (!r.ok) console.warn(`[dhcp] fallback port check failed — ${r.detail}`);
        resolve({ ok: r.ok, detail: r.detail, offeredIp: null });
      } else {
        console.warn(`[dhcp] socket error — ${err.message}`);
        resolve({ ok: false, detail: err.message, offeredIp: null });
      }
    });

    sock.on('message', (msg, rinfo) => {
      if (rinfo.address !== server) return;
      if (msg.length < 240) return;
      try { sock.close(); } catch (_) {}
      clearTimeout(timer);
      resolve({ ok: true, detail: 'OFFER received', offeredIp: parseOfferedIp(msg) });
    });

    const timer = setTimeout(() => {
      try { sock.close(); } catch (_) {}
      console.warn(`[dhcp] no OFFER received from ${server} within 5s`);
      resolve({ ok: false, detail: 'no OFFER received (timeout)', offeredIp: null });
    }, 5000);

    try {
      sock.bind(68, () => {
        sock.setBroadcast(true);
        sock.send(buildDiscover(), 67, server, err => {
          if (err) {
            clearTimeout(timer);
            try { sock.close(); } catch (_) {}
            console.warn(`[dhcp] failed to send DISCOVER to ${server}:67 — ${err.message}`);
            resolve({ ok: false, detail: err.message, offeredIp: null });
          }
        });
      });
    } catch (e) {
      clearTimeout(timer);
      resolve({ ok: false, detail: e.message, offeredIp: null });
    }
  });
}

module.exports = { checkDhcp };
