'use strict';
const { spawn } = require('child_process');
const { run } = require('./network');
const { cfg } = require('../config');

// Validates the host and the configured SSH user (both end up in a command line) and
// returns the user plus the path of the shared ControlMaster socket for that host.
function sshTarget(host) {
  if (!/^[a-zA-Z0-9.\-]+$/.test(host))
    throw new Error(`[ssh] invalid host value: "${host}"`);
  const sshUser = cfg('proxmox.ssh_user', 'root');
  if (!/^[a-zA-Z0-9._-]+$/.test(sshUser))
    throw new Error(`[ssh] invalid proxmox.ssh_user value in config: "${sshUser}"`);
  const socket = `/tmp/ssh_open-moxdash_${host.replace(/[^a-zA-Z0-9]/g, '_')}`;
  return { sshUser, socket };
}

// Returns an ssh(cmd, timeout) function that reuses a persistent ControlMaster
// socket for the given host — all parallel callers share one TCP connection.
// Every command sent through here is checked by guard.js before it starts: a new or
// changed remote command must be added to the allowlist there.
function makeSSH(host) {
  const { sshUser, socket } = sshTarget(host);
  return (cmd, timeout) => {
    const connectTimeout = Math.ceil((timeout || 8000) / 1000);
    return run(
      `ssh -o BatchMode=yes -o StrictHostKeyChecking=no` +
      ` -o ConnectTimeout=${connectTimeout}` +
      ` -o ControlMaster=auto -o ControlPath=${socket} -o ControlPersist=120s` +
      ` ${sshUser}@${host} '${cmd}'`,
      timeout
    );
  };
}

// Starts cmd on the host and returns the ChildProcess right away, for commands that keep
// running until the caller stops them (makeSSH, by contrast, waits for the command to
// exit). -tt gives the remote command a terminal, so killing this local process hangs
// the terminal up and the remote command is stopped with it. Uses the same ControlMaster
// socket as makeSSH. stdin is closed; stdout and stderr are piped to the caller.
function spawnSSH(host, cmd) {
  const { sshUser, socket } = sshTarget(host);
  return spawn('ssh', [
    '-tt', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
    '-o', 'ConnectTimeout=5',
    '-o', 'ControlMaster=auto', '-o', `ControlPath=${socket}`, '-o', 'ControlPersist=120s',
    `${sshUser}@${host}`, cmd,
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
}

module.exports = { makeSSH, spawnSSH };
