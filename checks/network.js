'use strict';
// Network reachability checks (gateway ping, internet ping) plus run(), the shell helper
// shared by the other checks (ssh.js uses it). The LAN broadcast check is in broadcast.js.
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

module.exports = { run, checkGateway, checkInternet };
