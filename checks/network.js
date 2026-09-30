'use strict';
// Network reachability checks (gateway ping, LAN broadcast round trip, internet
// ping) plus run(), the shell helper shared by the other checks (ssh.js uses it).
const dgram     = require('dgram');
const { cfg }   = require('../config');

// Runs a shell command and resolves { ok, stdout, stderr }; never rejects. ok is
// true only for exit code 0 (and false on timeout or spawn failure).
function run(cmd, timeoutMs = 6000) {
  return new Promise(resolve => {
    // detached: true puts the child in its own process group so we can kill
    // the entire group (shell + grandchildren like ssh) on timeout.
    // Important: we only kill on timeout — killing on normal exit would tear
    // down the SSH ControlMaster and disrupt other concurrent SSH calls that
    // share the same socket (e.g. lsblk + smartctl running in parallel).
    const { spawn } = require('child_process');
    const proc = spawn('/bin/sh', ['-c', cmd], { detached: true });
    let stdout = '', stderr = '', settled = false, timedOut = false;

    function done(ok) {
      if (settled) return;
      settled = true;
      if (timedOut) {
        try { process.kill(-proc.pid, 'SIGKILL'); } catch (_) {}
      }
      resolve({ ok, stdout, stderr });
    }

    proc.stdout.on('data', d => { stdout += d; });
    proc.stderr.on('data', d => { stderr += d; });
    proc.on('close', code => done(code === 0));
    proc.on('error', ()   => done(false));

    setTimeout(() => { timedOut = true; done(false); }, timeoutMs);
  });
}

// Extracts the average round-trip time, in whole milliseconds, from the summary
// line of iputils/busybox `ping` output. Returns null if it can't be found.
function parsePingMs(stdout) {
  const m = stdout.match(/min\/avg\/max[^=]*=\s*[\d.]+\/([\d.]+)/);
  return m ? Math.round(parseFloat(m[1])) : null;
}

// Pings the configured network.gateway (2 packets). The value is validated
// against a strict host alphabet because it is interpolated into a shell command.
// Returns null when no gateway is configured.
async function checkGateway() {
  const ip = cfg('network.gateway');
  if (!ip) return null;
  if (!/^[a-zA-Z0-9.\-]+$/.test(ip)) {
    console.error(`[network] invalid gateway value in config: "${ip}"`);
    return null;
  }
  const { ok, stdout, stderr } = await run(`ping -c 2 -W 1 ${ip}`);
  const ms = parsePingMs(stdout);
  if (!ok || ms === null) {
    console.warn(`[network] gateway ${ip} unreachable — stderr: ${stderr.trim() || '(none)'}`);
  }
  return { ok: ok && ms !== null, host: ip, detail: ok && ms !== null ? `${ms}ms` : 'unreachable' };
}

// LAN broadcast check: sends a probe datagram to network.broadcast (UDP 55399)
// and waits up to 3s for an ACK from a responder (tools/broadcast-responder.py).
// The detail string is the round-trip time. Returns null when no broadcast
// address is configured.
async function checkBroadcast() {
  const ip = cfg('network.broadcast');
  if (!ip) return null;

  // The port and both strings are a wire protocol shared with
  // tools/broadcast-responder.py: the responder answers exactly PAYLOAD with
  // ACK_PREFIX + its hostname. Change them in both places or not at all.
  const PORT       = 55399;
  const PAYLOAD     = 'open-moxdash-broadcast-probe';
  const ACK_PREFIX  = 'open-moxdash-broadcast-ack:';
  const TIMEOUT     = 3000;

  // A same-host kernel loopback (the sender receiving its own outbound
  // broadcast datagram) proves nothing about the network — it happens
  // whenever `ip` matches this host's own interface, with no packet ever
  // reaching another device. Only an ACK from an external responder
  // (tools/broadcast-responder.py) proves the probe was answered by another
  // process. For a true LAN test, run the responder on a different physical
  // machine: if it shares a hypervisor with this app, the probe only crosses
  // the host's virtual bridge and never touches the physical network.
  return new Promise(resolve => {
    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    let done = false;

    const finish = (ok, detail) => {
      if (done) return;
      done = true;
      try { sock.close(); } catch (_) {}
      resolve({ ok, host: ip, detail });
    };

    const timer = setTimeout(() => {
      console.warn(`[network] broadcast ${ip} — no ACK from an external responder within ${TIMEOUT}ms`);
      finish(false, 'no ack');
    }, TIMEOUT);

    sock.on('error', err => {
      clearTimeout(timer);
      console.warn(`[network] broadcast socket error: ${err.message}`);
      finish(false, 'socket error');
    });

    sock.on('message', msg => {
      const text = msg.toString();
      if (text.startsWith(ACK_PREFIX)) {
        clearTimeout(timer);
        finish(true, `${Date.now() - start}ms`);
      }
      // Any other message (e.g. the same-host loopback of our own PAYLOAD)
      // is ignored — it isn't proof of anything and we keep waiting.
    });

    let start;
    sock.bind(PORT, () => {
      sock.setBroadcast(true);
      start = Date.now();
      sock.send(PAYLOAD, PORT, ip, err => {
        if (err) {
          clearTimeout(timer);
          console.warn(`[network] broadcast send error: ${err.message}`);
          finish(false, 'send failed');
        }
      });
    });
  });
}

// Internet reachability: pings 1.1.1.1 (Cloudflare's public resolver). The
// target is fixed in code, not configurable.
async function checkInternet() {
  const ip = '1.1.1.1';
  const { ok, stdout, stderr } = await run(`ping -c 2 -W 1 ${ip}`);
  const ms = parsePingMs(stdout);
  if (!ok || ms === null) {
    console.warn(`[network] internet (${ip}) unreachable — stderr: ${stderr.trim() || '(none)'}`);
  }
  return { ok: ok && ms !== null, detail: ok && ms !== null ? `${ms}ms` : 'unreachable' };
}

module.exports = { run, checkGateway, checkBroadcast, checkInternet };
