'use strict';
// Per-socket, per-core CPU usage, clock speed and package temperature for one
// cluster node, collected over SSH in a single round trip.
const { makeSSH } = require('./ssh');

// Parses the per-CPU lines of /proc/stat into { cpuN: { idle, total } } tick
// counters. Idle time includes iowait; total includes every counted state.
function parseStat(text) {
  const cpus = {};
  for (const line of text.split('\n')) {
    const m = line.match(/^(cpu\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/);
    if (!m) continue;
    const [, name, user, nice, system, idle, iowait, irq, softirq] = m;
    const idleVal = parseInt(idle) + parseInt(iowait);
    const total   = idleVal + parseInt(user) + parseInt(nice) + parseInt(system) + parseInt(irq) + parseInt(softirq);
    cpus[name] = { idle: idleVal, total };
  }
  return cpus;
}

// Parses /proc/cpuinfo into one entry per logical processor with its socket
// (physical id), core id, model name and current MHz.
function parseTopology(text) {
  const procs = [];
  for (const block of text.split('\n\n')) {
    const get = key => { const m = block.match(new RegExp(`^${key}\\s*:\\s*(.+)$`, 'm')); return m ? m[1].trim() : null; };
    const processor = get('processor');
    if (processor === null) continue;
    const mhzRaw = get('cpu MHz');
    procs.push({
      processor:  parseInt(processor),
      physicalId: parseInt(get('physical id') ?? '0'),
      coreId:     parseInt(get('core id')     ?? processor),
      modelName:  get('model name'),
      mhz:        mhzRaw ? (parseFloat(mhzRaw) || null) : null,
    });
  }
  return procs;
}

// Usage is the difference between two consecutive /proc/stat samples, so the
// previous sample is kept between calls (same approach as disk.js), which avoids
// sleeping inside the check. Keyed by node name so nodes don't clobber each other.
const prevStatByNode = new Map();

// Returns one entry per socket: { id, model, usage %, temp °C, cores: [{ logicalId,
// coreId, usage %, mhz }] }. Returns null on the first call for a node (there is no
// previous sample to diff against yet) or when the SSH call fails. The remote
// command prints /proc/stat, /proc/cpuinfo and the package temperature sensors
// separated by marker lines so all of it arrives in one SSH round trip.
async function checkCpuCores(node) {
  const host = node?.ip;
  if (!host) return null;

  const ssh = makeSSH(host);
  const { ok, stdout } = await ssh(
    `cat /proc/stat; printf "\\n===CPUINFO===\\n"; cat /proc/cpuinfo; printf "\\n===TEMPS===\\n"; for f in /sys/class/hwmon/hwmon*/temp*_label; do [ -f "$f" ] || continue; l=$(cat "$f" 2>/dev/null); case "$l" in Package*) t=$(cat "\${f%_label}_input" 2>/dev/null); echo "$l:$t";; esac; done`,
    8000
  );
  if (!ok || !stdout) { console.warn(`[cpu] SSH to ${host} failed or returned no data`); return null; }

  const cpuinfoSep = stdout.indexOf('\n===CPUINFO===\n');
  const tempSep    = stdout.indexOf('\n===TEMPS===\n');
  if (cpuinfoSep === -1 || tempSep === -1) { console.warn('[cpu] unexpected output format'); return null; }

  const statPart    = stdout.slice(0, cpuinfoSep);
  const cpuinfoPart = stdout.slice(cpuinfoSep + '\n===CPUINFO===\n'.length, tempSep);
  const tempsPart   = stdout.slice(tempSep    + '\n===TEMPS===\n'.length);

  const currentStat = parseStat(statPart);

  // First call for this node — store baseline, return null (no delta yet)
  const prevStat = prevStatByNode.get(node.name);
  if (!prevStat) {
    prevStatByNode.set(node.name, currentStat);
    return null;
  }

  const usage = {};
  for (const key of Object.keys(currentStat)) {
    const a = prevStat[key], b = currentStat[key];
    if (!a || !b) continue;
    const dt = b.total - a.total;
    usage[key] = dt > 0 ? Math.round((1 - (b.idle - a.idle) / dt) * 1000) / 10 : 0;
  }
  prevStatByNode.set(node.name, currentStat);

  // Parse package temperatures (millidegrees → °C)
  const temps = {};
  for (const line of tempsPart.split('\n')) {
    const m = line.match(/^Package id (\d+):(\d+)/);
    if (m) temps[parseInt(m[1])] = Math.round(parseInt(m[2]) / 1000);
  }

  const topology = parseTopology(cpuinfoPart);

  // Group logical processors by socket
  const sockets = {};
  for (const proc of topology) {
    const sid = proc.physicalId;
    if (!sockets[sid]) sockets[sid] = { id: sid, model: proc.modelName, cores: [] };
    if (!sockets[sid].model && proc.modelName) sockets[sid].model = proc.modelName;
    sockets[sid].cores.push({
      logicalId: proc.processor,
      coreId:    proc.coreId,
      usage:     usage[`cpu${proc.processor}`] ?? null,
      mhz:       proc.mhz ?? null,
    });
  }

  // If cpuinfo gave no topology, fall back to flat list from stat
  if (Object.keys(sockets).length === 0) {
    sockets[0] = {
      id: 0,
      cores: Object.keys(usage).map((key, i) => ({
        logicalId: i,
        coreId:    i,
        usage:     usage[key],
      })),
    };
  }

  return Object.values(sockets).sort((a, b) => a.id - b.id).map(s => {
    const cores = s.cores.sort((a, b) => a.coreId - b.coreId || a.logicalId - b.logicalId);
    const socketUsage = cores.length
      ? Math.round(cores.reduce((sum, c) => sum + (c.usage ?? 0), 0) / cores.length * 10) / 10
      : null;
    return { id: s.id, model: s.model ?? null, usage: socketUsage, temp: temps[s.id] ?? null, cores };
  });
}

module.exports = { checkCpuCores };
