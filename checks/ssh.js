'use strict';
const { run } = require('./network');
const { cfg } = require('../config');

// Returns an ssh(cmd, timeout) function that reuses a persistent ControlMaster
// socket for the given host — all parallel callers share one TCP connection.
function makeSSH(host) {
  if (!/^[a-zA-Z0-9.\-]+$/.test(host))
    throw new Error(`[ssh] invalid proxmox.host value in config: "${host}"`);
  const sshUser = cfg('proxmox.ssh_user', 'root');
  if (!/^[a-zA-Z0-9._-]+$/.test(sshUser))
    throw new Error(`[ssh] invalid proxmox.ssh_user value in config: "${sshUser}"`);
  const socket = `/tmp/ssh_open-moxdash_${host.replace(/[^a-zA-Z0-9]/g, '_')}`;
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

module.exports = { makeSSH };
