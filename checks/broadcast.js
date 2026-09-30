'use strict';
// LAN broadcast check: sends a UDP broadcast and confirms that another machine
// received it and answered.
//
// Nothing has to be installed for this. Each time the check runs, it starts a tiny
// listener on the machine named in network.broadcast_listener by sending a short Perl
// program over SSH (same user and key as the other SSH checks), waits for the listener
// to report READY, broadcasts a probe to network.broadcast, waits for the reply, then
// kills the SSH session, which stops the listener. The listener also ends itself after
// LISTENER_LIFETIME_S seconds, so nothing is left running even if the connection drops.
//
// For this to test the physical network, the listener machine must be a different
// physical machine from the one running this app. If it shares a hypervisor with the
// app, the probe only crosses the host's virtual bridge and never touches the wire.
// The listener machine also has to allow inbound UDP on PORT from this host (for
// example in the Proxmox firewall).
const dgram = require('dgram');
const { cfg } = require('../config');
const { spawnSSH } = require('./ssh');

// The port and both strings are a small wire protocol between this file and the
// listener program below: the listener answers exactly PAYLOAD with ACK_PREFIX plus its
// hostname.
const PORT       = 55399;
const PAYLOAD    = 'open-moxdash-broadcast-probe';
const ACK_PREFIX = 'open-moxdash-broadcast-ack:';

const READY_TIMEOUT_MS    = 8000;  // SSH connect plus starting the listener
const ACK_TIMEOUT_MS      = 3000;  // waiting for the reply once the probe is sent
const LISTENER_LIFETIME_S = 12;    // the listener's own time limit, a safety net

// The listener, run by Perl on the remote machine (Perl ships with Debian and Proxmox).
// It binds the port, prints READY, and answers each probe with an ACK sent back to
// whoever sent it. `alarm` ends the process after LISTENER_LIFETIME_S seconds.
const LISTENER = [
  'use strict;',
  'use IO::Socket::INET;',
  'use Sys::Hostname;',
  '$| = 1;',
  `alarm ${LISTENER_LIFETIME_S};`,
  `my $sock = IO::Socket::INET->new(LocalPort => ${PORT}, Proto => 'udp', ReuseAddr => 1)`,
  '  or die "bind failed: $!\\n";',
  'print "READY\\n";',
  'while (1) {',
  '  my $buf;',
  '  my $peer = $sock->recv($buf, 1024) or next;',
  `  $sock->send("${ACK_PREFIX}" . hostname(), 0, $peer) if $buf eq "${PAYLOAD}";`,
  '}',
].join('\n');

// The program is passed base64-encoded and decoded on the remote side, so no character
// in it can be mangled by shell quoting.
const REMOTE_COMMAND = `perl -e "$(echo ${Buffer.from(LISTENER).toString('base64')} | base64 -d)"`;

// Resolves { ok, host, detail }, where detail is the probe round-trip time or the
// reason for failure. Returns null unless both network.broadcast (the address to
// broadcast to) and network.broadcast_listener (the machine to run the listener on)
// are set.
async function checkBroadcast() {
  const ip           = cfg('network.broadcast');
  const listenerHost = cfg('network.broadcast_listener');
  if (!ip || !listenerHost) return null;

  return new Promise(resolve => {
    let done     = false;
    let ready    = false;
    let listener = null;
    let sock     = null;
    let start    = null;
    let out      = '';
    let errOut   = '';
    let readyTimer = null;
    let ackTimer   = null;

    // Stops the listener: SIGTERM to the local ssh process ends the session, which hangs
    // up the remote terminal and stops the listener with it. SIGKILL follows if ssh
    // ignores that.
    const stopListener = () => {
      if (!listener) return;
      const l = listener;
      listener = null;
      try { l.kill('SIGTERM'); } catch (_) {}
      setTimeout(() => { try { l.kill('SIGKILL'); } catch (_) {} }, 1000).unref();
    };

    const finish = (ok, detail) => {
      if (done) return;
      done = true;
      clearTimeout(readyTimer);
      clearTimeout(ackTimer);
      stopListener();
      try { sock?.close(); } catch (_) {}
      resolve({ ok, host: ip, detail });
    };

    // Runs once the listener is up: broadcasts the probe and waits for an ACK.
    const sendProbe = () => {
      sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });

      sock.on('error', err => {
        console.warn(`[broadcast] socket error: ${err.message}`);
        finish(false, 'socket error');
      });

      sock.on('message', msg => {
        // Anything else, such as the same-host loopback of our own PAYLOAD, proves
        // nothing about the network and is ignored while we keep waiting.
        if (msg.toString().startsWith(ACK_PREFIX)) finish(true, `${Date.now() - start}ms`);
      });

      sock.bind(PORT, () => {
        sock.setBroadcast(true);
        ackTimer = setTimeout(() => {
          console.warn(`[broadcast] ${ip} — no ACK from the listener on ${listenerHost} within ${ACK_TIMEOUT_MS}ms`);
          finish(false, 'no ack');
        }, ACK_TIMEOUT_MS);
        start = Date.now();
        sock.send(PAYLOAD, PORT, ip, err => {
          if (err) {
            console.warn(`[broadcast] send error: ${err.message}`);
            finish(false, 'send failed');
          }
        });
      });
    };

    try {
      listener = spawnSSH(listenerHost, REMOTE_COMMAND);
    } catch (e) {
      console.warn(`[broadcast] ${e.message}`);
      return resolve({ ok: false, host: ip, detail: 'bad listener host' });
    }

    readyTimer = setTimeout(() => {
      console.warn(`[broadcast] listener on ${listenerHost} not ready within ${READY_TIMEOUT_MS}ms`);
      finish(false, 'listener failed');
    }, READY_TIMEOUT_MS);

    listener.stdout.on('data', chunk => {
      if (ready) return;
      out += chunk;
      if (out.includes('READY')) {
        ready = true;
        clearTimeout(readyTimer);
        sendProbe();
      }
    });
    listener.stderr.on('data', chunk => { if (errOut.length < 500) errOut += chunk; });

    listener.on('error', err => {
      console.warn(`[broadcast] could not run ssh: ${err.message}`);
      finish(false, 'ssh failed');
    });

    // The listener normally only ends because we killed it; ending earlier than that
    // means SSH or the listener itself failed.
    listener.on('close', code => {
      if (done) return;
      console.warn(`[broadcast] listener on ${listenerHost} exited early (code ${code}): ${(errOut || out).trim().slice(0, 200)}`);
      if (!ready) finish(false, 'listener failed');
    });
  });
}

module.exports = { checkBroadcast };
