'use strict';
// Process guard: a tripwire on everything this app can run.
//
// The app starts processes in exactly two ways and for exactly two purposes: `ping`, and
// `ssh` to run a fixed set of commands on your servers. This module wraps child_process
// so that every attempt to start a process is checked against that exact list. If
// anything does not match (an unexpected program, an extra ssh option, a remote command
// that is not on the list, an unexpected spawn option) the process treats it as possible
// corruption or a code hijack: it prints the reason, where the call came from and the
// exact command, runs the lockdown registered by webowner.js (which destroys secrets), then
// exits at once with status 99 without running any exit handlers. The service unit lists
// 99 in RestartPreventExitStatus= (see deploy/open-moxdash.service), so systemd leaves
// the service stopped instead of starting it again; start it by hand once you know why it
// tripped.
//
// Why it lives here: this file is loaded first and is never hot-reloaded (like
// secrets.js), so the check cannot be swapped out by editing files in checks/ while the
// app runs, and the allowlist is private to this closure. The wrapped functions are
// frozen and cannot be reassigned, the built-ins the checks rely on are captured before
// any other code runs, arguments are copied once before they are checked so they cannot
// change between the check and the call, and a watchdog confirms once a second that the
// wrappers are still installed.
//
// What it is not: a sandbox. Code that already runs inside this process with full
// privileges can still reach the operating system by other routes (native bindings,
// worker threads, and so on). This catches the realistic failures, such as a malformed
// value or bug that builds a bad command, injected input, or edited code that starts
// something new, and makes them loud and fatal instead of silent.
//
// Changing what the app runs: when you add or change a command in checks/, update
// REMOTE_COMMANDS below (or the ping/ssh rules) and restart the app. Until you do, the
// process will terminate the first time the changed command is run.
const fs = require('fs');
const cp = require('child_process');

// Built-ins captured before any other code runs, so later tampering with prototypes
// cannot change how the checks below behave.
const apply          = Reflect.apply;
const ownKeys        = Reflect.ownKeys;
const getProto       = Object.getPrototypeOf;
const getDescriptor  = Object.getOwnPropertyDescriptor;
const defineProp     = Object.defineProperty;
const freeze         = Object.freeze;
const isArray        = Array.isArray;
const reExec         = RegExp.prototype.exec;
const setHas         = Set.prototype.has;
const charCodeAt     = String.prototype.charCodeAt;
const charAt         = String.prototype.charAt;
const jsonStringify  = JSON.stringify;
const ErrorCtor      = Error;
const writeSync      = fs.writeSync;
const killProcess    = process.kill;
const exitProcess    = process.exit;
const exitNow        = typeof process.reallyExit === 'function' ? process.reallyExit : null;
const selfPid        = process.pid;
const originalSpawn  = cp.spawn;
const objectProto    = Object.prototype;

// The only remote commands the app may run over ssh, exactly as they are sent.
const REMOTE_COMMANDS = freeze({
  // checks/cpu.js: per-core usage, clock speeds, package temperatures
  cpu: "cat /proc/stat; printf \"\\n===CPUINFO===\\n\"; cat /proc/cpuinfo; printf \"\\n===TEMPS===\\n\"; for f in /sys/class/hwmon/hwmon*/temp*_label; do [ -f \"$f\" ] || continue; l=$(cat \"$f\" 2>/dev/null); case \"$l\" in Package*) t=$(cat \"${f%_label}_input\" 2>/dev/null); echo \"$l:$t\";; esac; done",
  // checks/ram.js: installed memory summary
  ram: "dmidecode -t memory 2>/dev/null",
  // checks/disk.js checkDisks: disk throughput and utilisation
  diskStats: "cat /proc/diskstats",
  // checks/disk.js checkDiskTemps: model, size and transport
  diskInventory: "lsblk -d --pairs -o NAME,MODEL,SIZE,TRAN 2>/dev/null",
  // checks/disk.js checkDiskTemps: SMART data for every disk
  diskSmart: "D=$(mktemp -d); for d in $(lsblk -dno NAME 2>/dev/null | grep -v ^zd); do { echo \"DISK_START $d\"; smartctl -a /dev/$d 2>/dev/null; } > $D/$d & done; wait; cat $D/*; rm -rf $D",
  // checks/gpu.js: per-GPU utilisation, power, memory, fan
  gpuStats: "nvidia-smi --query-gpu=index,name,utilization.gpu,power.draw,power.limit,memory.used,memory.total,fan.speed --format=csv,noheader,nounits 2>/dev/null",
  // checks/gpu.js: running vGPU instances
  gpuVgpuActive: "nvidia-smi vgpu --query-vgpu=gpu_index,vgpu_type_name --format=csv,noheader,nounits 2>/dev/null || true",
  // checks/gpu.js: supported vGPU profiles
  gpuVgpuSupported: "nvidia-smi vgpu -s --query-supported-vgpus=gpu_index,vgpu_type_name,vgpu_type_max_instances --format=csv,noheader,nounits 2>/dev/null || true",
  // checks/broadcast.js: short-lived UDP listener (Perl program, base64-encoded)
  broadcastListener: "perl -e \"$(echo dXNlIHN0cmljdDsKdXNlIElPOjpTb2NrZXQ6OklORVQ7CnVzZSBTeXM6Okhvc3RuYW1lOwokfCA9IDE7CmFsYXJtIDEyOwpteSAkc29jayA9IElPOjpTb2NrZXQ6OklORVQtPm5ldyhMb2NhbFBvcnQgPT4gNTUzOTksIFByb3RvID0+ICd1ZHAnLCBSZXVzZUFkZHIgPT4gMSkKICBvciBkaWUgImJpbmQgZmFpbGVkOiAkIVxuIjsKcHJpbnQgIlJFQURZXG4iOwp3aGlsZSAoMSkgewogIG15ICRidWY7CiAgbXkgJHBlZXIgPSAkc29jay0+cmVjdigkYnVmLCAxMDI0KSBvciBuZXh0OwogICRzb2NrLT5zZW5kKCJvcGVuLW1veGRhc2gtYnJvYWRjYXN0LWFjazoiIC4gaG9zdG5hbWUoKSwgMCwgJHBlZXIpIGlmICRidWYgZXEgIm9wZW4tbW94ZGFzaC1icm9hZGNhc3QtcHJvYmUiOwp9 | base64 -d)\"",
});

const remoteSet = new Set();
for (const key of ownKeys(REMOTE_COMMANDS)) remoteSet.add(REMOTE_COMMANDS[key]);

const PING_RE     = /^ping -c [1-9] -W [1-9] [A-Za-z0-9.-]+$/;
const SSH_LINE_RE = /^ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=([0-9]{1,2}) -o ControlMaster=auto -o ControlPath=(\/tmp\/ssh_open-moxdash_[A-Za-z0-9_]+) -o ControlPersist=120s ([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+) '([^']*)'$/;
const TARGET_RE   = /^([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+)$/;
const SOCKET_PREFIX = '/tmp/ssh_open-moxdash_';

const matches = (re, s) => apply(reExec, re, [s]);

// ── Termination ──────────────────────────────────────────────────────────────

// Exit status of every defence termination. Must match RestartPreventExitStatus= in
// deploy/open-moxdash.service and NO_RESTART_EXIT in webowner.js.
const NO_RESTART_EXIT = 99;

// Ends the process with NO_RESTART_EXIT without emitting 'exit', so no handler can run.
// process.reallyExit is the internal call that process.exit() ends with; if a future Node
// drops it, process.exit() is used instead, and SIGKILL only if that somehow returns.
function terminate() {
  if (exitNow !== null) { try { apply(exitNow, process, [NO_RESTART_EXIT]); } catch (_) {} }
  try { apply(exitProcess, process, [NO_RESTART_EXIT]); } catch (_) {}
  apply(killProcess, process, [selfPid, 'SIGKILL']);
  for (;;) { /* the process is already gone; run nothing else */ }
}

// The lockdown function from webowner.js, registered once right after this module loads.
let lockdownFn = null;
function setLockdown(fn) {
  if (lockdownFn === null && typeof fn === 'function') lockdownFn = fn;
}

// Prints why, where and what, runs the lockdown, then ends the process. Never returns.
function selfDestruct(reason, api, file, args, options) {
  try {
    let source = '(unavailable)';
    try {
      const frames = String(new ErrorCtor().stack).split('\n').slice(1)
        .filter(line => line.indexOf('guard.js') === -1).slice(0, 8);
      source = frames.map(line => '\n    ' + line.trim()).join('');
    } catch (_) {}
    let command;
    try { command = jsonStringify({ file, args, options }); } catch (_) { command = '(could not serialise)'; }
    writeSync(2,
      '\n[open-moxdash] SECURITY: process guard tripped: possible corruption or code hijack.\n' +
      '[open-moxdash] Terminating this process now.\n' +
      `  reason:  ${reason}\n` +
      `  api:     ${api}\n` +
      `  source:${source}\n` +
      `  command: ${command}\n` +
      `  pid:     ${selfPid}   time: ${new Date().toISOString()}\n\n`);
  } catch (_) {
    try { writeSync(2, '\n[open-moxdash] SECURITY: process guard tripped. Terminating.\n'); } catch (__) {}
  }
  if (lockdownFn !== null) { try { apply(lockdownFn, undefined, []); } catch (_) {} }
  terminate();
}

// ── Checks ───────────────────────────────────────────────────────────────────

const fail = reason => ({ reason });

// The control-socket path ssh_open-moxdash_<host with every non-alphanumeric as "_">
// that checks/ssh.js derives from the host; recomputed here to catch mismatches.
function socketFor(host) {
  let out = SOCKET_PREFIX;
  for (let i = 0; i < host.length; i++) {
    const code = apply(charCodeAt, host, [i]);
    const alnum = (code >= 48 && code <= 57) || (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
    out += alnum ? apply(charAt, host, [i]) : '_';
  }
  return out;
}

// Common ssh rules once the line or argument list has been taken apart.
function sshProblem(socket, user, host, remote) {
  if (socket !== socketFor(host)) return `ssh control socket "${socket}" does not match host "${host}"`;
  if (!apply(setHas, remoteSet, [remote])) return 'remote command is not on the allowlist';
  return null;
}

// Vets a spawn() call. Returns { reason } when it is not permitted, otherwise
// { argv, opts }: private copies of the arguments and options that were actually checked.
function vet(file, args, options) {
  if (typeof file !== 'string') return fail('executable is not a string');
  if (!isArray(args)) return fail('arguments are not an array');

  const argv = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (typeof a !== 'string') return fail(`argument ${i} is not a string`);
    argv[i] = a;
  }

  const opts = {};
  if (options !== undefined) {
    if (options === null || typeof options !== 'object' || isArray(options) || getProto(options) !== objectProto)
      return fail('spawn options must be a plain object');
    for (const key of ownKeys(options)) {
      if (key === 'detached') {
        if (typeof options.detached !== 'boolean') return fail('option "detached" must be a boolean');
        opts.detached = options.detached;
      } else if (key === 'stdio') {
        const s = options.stdio;
        if (!isArray(s) || s.length !== 3) return fail('option "stdio" must be an array of three entries');
        const copy = [];
        for (let i = 0; i < 3; i++) {
          if (s[i] !== 'ignore' && s[i] !== 'pipe') return fail(`stdio entry ${i} must be "ignore" or "pipe"`);
          copy[i] = s[i];
        }
        opts.stdio = copy;
      } else {
        return fail(`unexpected spawn option "${String(key)}"`);
      }
    }
  }

  if (file === '/bin/sh') {
    if (argv.length !== 2 || argv[0] !== '-c') return fail('/bin/sh may only be run as: /bin/sh -c "<command>"');
    const line = argv[1];
    if (matches(PING_RE, line)) return { argv, opts };
    const m = matches(SSH_LINE_RE, line);
    if (!m) return fail('shell command is neither a permitted ping nor a permitted ssh command line');
    const problem = sshProblem(m[2], m[3], m[4], m[5]);
    return problem ? fail(problem) : { argv, opts };
  }

  if (file === 'ssh') {
    // -tt -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5
    // -o ControlMaster=auto -o ControlPath=<socket> -o ControlPersist=120s user@host <command>
    const fixed = ['-tt', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=5',
                   '-o', 'ControlMaster=auto', '-o', null, '-o', 'ControlPersist=120s'];
    if (argv.length !== 15) return fail('ssh was given an unexpected number of arguments');
    for (let i = 0; i < fixed.length; i++) {
      if (fixed[i] !== null && argv[i] !== fixed[i]) return fail(`ssh argument ${i} is not the expected "${fixed[i]}"`);
    }
    const controlPath = argv[10];
    if (controlPath.slice(0, 12) !== 'ControlPath=') return fail('ssh argument 10 is not a ControlPath option');
    const t = matches(TARGET_RE, argv[13]);
    if (!t) return fail('ssh target is not user@host');
    const problem = sshProblem(controlPath.slice(12), t[1], t[2], argv[14]);
    return problem ? fail(problem) : { argv, opts };
  }

  return fail(`executable "${file}" is not permitted (allowed: ping via /bin/sh -c, and ssh)`);
}

// ── Installation ─────────────────────────────────────────────────────────────

const wrappers = {};

// spawn: the only process API the app uses. It runs only what vet() approved, using the
// private copies vet() made.
wrappers.spawn = function spawn(file, args, options) {
  const v = vet(file, args, options);
  if (v.reason) selfDestruct(v.reason, 'child_process.spawn', file, args, options);
  return apply(originalSpawn, cp, [file, v.argv, v.opts]);
};

// Everything else that can start a process is never used by the app, so any call is
// treated as a violation.
for (const name of ['spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
  wrappers[name] = function (...callArgs) {
    selfDestruct('this process API is never used by the app', `child_process.${name}`, callArgs[0], callArgs.slice(1));
  };
}

for (const name of ownKeys(wrappers)) {
  freeze(wrappers[name]);
  defineProp(cp, name, { value: wrappers[name], writable: false, configurable: false, enumerable: true });
}

// Watchdog: the wrappers must still be the ones installed above.
setInterval(() => {
  for (const name of ownKeys(wrappers)) {
    const d = getDescriptor(cp, name);
    if (!d || d.value !== wrappers[name] || d.writable || d.configurable)
      selfDestruct(`child_process.${name} is no longer the guarded function`, 'watchdog', undefined, undefined);
  }
}, 1000).unref();

module.exports = freeze({ installed: true, setLockdown });
