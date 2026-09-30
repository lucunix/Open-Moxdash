'use strict';
// Per-node disk activity and health, collected over SSH in two tiers:
//   checkDisks()     fast  — read/write throughput and utilisation from /proc/diskstats
//   checkDiskTemps() slow  — model, size, transport and SMART health from lsblk/smartctl
// The slow tier caches into per-node state that the fast tier reads, so the panel
// updates every few seconds without running smartctl each time (smartmontools must
// be installed on the node, and SSH must be root, for SMART data).
const fs   = require('fs');
const path = require('path');
const { makeSSH } = require('./ssh');

// Optional disk_names.json maps a drive's raw model string (as lsblk reports it) to a
// friendlier display name. A missing or invalid file just means no renaming.
function loadDiskNames() {
  try {
    return JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'disk_names.json'), 'utf8'));
  } catch (_) {
    return {};
  }
}

// Match physical disks and software RAID — exclude partitions and device-mapper
const DISK_RE = /^(sd[a-z]+|hd[a-z]+|nvme\d+n\d+|vd[a-z]+|xvd[a-z]+|md\d+)$/;

// Persistent inter-call state, keyed by node name — each node's disks get
// their own delta baseline and slow-cycle metadata cache.
const stateByNode = new Map();  // name → { prevStats, prevTime, modelMap, diskSmart, diskSize, diskTran, lastResult }
const diskNames   = loadDiskNames();  // read once when this module loads; shared across nodes

function nodeState(name) {
  let s = stateByNode.get(name);
  if (!s) {
    s = { prevStats: null, prevTime: null, modelMap: {}, diskSmart: {}, diskSize: {}, diskTran: {}, lastResult: null };
    stateByNode.set(name, s);
  }
  return s;
}

// Parses /proc/diskstats into { device: { sectorsRead, sectorsWritten, ioMs } } for
// whole disks only (DISK_RE). Sector counts are always 512-byte units in this file.
function parseDiskStats(text) {
  const disks = {};
  for (const line of text.trim().split('\n')) {
    const p = line.trim().split(/\s+/);
    if (p.length < 14) continue;
    const name = p[2];
    if (!DISK_RE.test(name)) continue;
    disks[name] = {
      sectorsRead:    parseInt(p[5],  10),
      sectorsWritten: parseInt(p[9],  10),
      ioMs:           parseInt(p[12], 10),
    };
  }
  return disks;
}

// Splits the combined `smartctl -a` output (one "DISK_START <name>" marker per disk)
// and extracts health, temperature, power-on hours, wear and error counters for each.
// NVMe drives are parsed from their labelled fields, SATA drives from the numbered
// attribute table.
function parseSmartBlocks(text) {
  const result = {};
  for (const block of text.split(/^DISK_START /m)) {
    if (!block.trim()) continue;
    const nl = block.indexOf('\n');
    if (nl === -1) continue;
    const name = block.slice(0, nl).trim();
    const body = block.slice(nl + 1);
    const s = {};

    // Overall health (SATA and NVMe)
    const hm = body.match(/SMART overall-health self-assessment test result:\s*(\S+)/i);
    if (hm) s.health = hm[1];

    // NVMe-specific fields
    const nvmeTemp  = body.match(/^Temperature:\s+(\d+)\s+Celsius/im);
    if (nvmeTemp)  s.temp           = parseInt(nvmeTemp[1]);

    const nvmePoh   = body.match(/^Power On Hours:\s+([\d,]+)/im);
    if (nvmePoh)   s.powerOnHours  = parseInt(nvmePoh[1].replace(/,/g, ''));

    const nvmeWear  = body.match(/^Percentage Used:\s+(\d+)%/im);
    if (nvmeWear)  s.wearPct       = parseInt(nvmeWear[1]);

    const nvmeSpare = body.match(/^Available Spare:\s+(\d+)%/im);
    if (nvmeSpare) s.availableSpare = parseInt(nvmeSpare[1]);

    const nvmeErr   = body.match(/^Media and Data Integrity Errors:\s+(\d+)/im);
    if (nvmeErr)   s.mediaErrors   = parseInt(nvmeErr[1]);

    // SATA/SAS attribute table: ID NAME FLAG VALUE WORST THRESH TYPE UPDATED WHEN_FAILED RAW_VALUE
    for (const line of body.split('\n')) {
      const p = line.trim().split(/\s+/);
      if (p.length < 10 || !p[2]?.startsWith('0x')) continue;
      const id  = parseInt(p[0]);
      const raw = parseInt(p[9]);
      if (isNaN(id) || isNaN(raw)) continue;
      switch (id) {
        case 190:
        case 194: if (s.temp         == null) s.temp           = raw; break;
        case   9:                             s.powerOnHours   = raw; break;
        case   5:                             s.reallocated    = raw; break;
        case 197:                             s.pendingSectors = raw; break;
        case 198:                             s.uncorrectable  = raw; break;
        case 231:
        case 233:                             s.wearPct        = 100 - raw; break;
      }
    }

    result[name] = s;
  }
  return result;
}

// ── Fast: diskstats delta only ────────────────────────────────────────────────

// Returns one entry per disk: throughput (B/s), utilisation %, and the cached model,
// size, interface and SMART fields. The first call for a node only records a baseline
// and returns the last known result (null at first). If SSH fails, the last result is
// returned so the panel keeps showing stale data instead of blanking.
async function checkDisks(node) {
  const host = node?.ip;
  if (!host) return null;

  const st  = nodeState(node.name);
  const ssh = makeSSH(host);

  // Capture timestamp before SSH so dtMs reflects the actual diskstats interval
  const now = Date.now();

  const statsRes = await ssh('cat /proc/diskstats', 5000);

  if (!statsRes.ok || !statsRes.stdout) {
    console.warn(`[disk] diskstats SSH to ${node.name} failed or returned no data`);
    return st.lastResult;
  }

  const current = parseDiskStats(statsRes.stdout);

  // First call for this node — store baseline and return last known result (or null)
  if (!st.prevStats) {
    st.prevStats = current;
    st.prevTime  = now;
    return st.lastResult;
  }

  const dtMs = now - st.prevTime;
  if (dtMs < 100) return st.lastResult;

  const results = [];

  for (const name of Object.keys(current).sort()) {
    const a = st.prevStats[name];
    const b = current[name];
    if (!a) continue;

    const readBytes  = (b.sectorsRead    - a.sectorsRead)    * 512;
    const writeBytes = (b.sectorsWritten - a.sectorsWritten) * 512;
    const ioMsDelta  = b.ioMs - a.ioMs;

    // Bytes per second rather than KB/s or MB/s: the frontend does the unit
    // formatting, and rounding to a coarser unit here would set a floor under the
    // smallest rate it could ever show.
    const readBps  = Math.round(readBytes  / (dtMs / 1000));
    const writeBps = Math.round(writeBytes / (dtMs / 1000));
    const utilPct  = Math.min(100, Math.round(ioMsDelta / dtMs * 100));

    const rawModel = st.modelMap[name] || null;
    const model    = (rawModel && diskNames[rawModel]) ? diskNames[rawModel] : rawModel;
    const s        = st.diskSmart[name] || {};

    results.push({
      name, model, readBps, writeBps, utilPct,
      size:           st.diskSize[name] ?? null,
      iface:          st.diskTran[name] ?? null,
      temp:           s.temp           ?? null,
      health:         s.health         ?? null,
      powerOnHours:   s.powerOnHours   ?? null,
      reallocated:    s.reallocated    ?? null,
      pendingSectors: s.pendingSectors ?? null,
      uncorrectable:  s.uncorrectable  ?? null,
      wearPct:        s.wearPct        ?? null,
      availableSpare: s.availableSpare ?? null,
      mediaErrors:    s.mediaErrors    ?? null,
    });
  }

  st.prevStats = current;
  st.prevTime  = now;

  if (results.length) {
    st.lastResult = results;
    return results;
  }

  console.warn(`[disk] no matching disks found in /proc/diskstats on ${node.name}`);
  return st.lastResult;
}

// ── Slow: lsblk model map + smartctl (run in parallel) ────────────────────────

// Refreshes the cached model/size/transport map and SMART data for a node. Writes
// into the node's state and returns nothing; checkDisks() picks the data up on its
// next pass. ZFS zvols (zdN) are skipped.
async function checkDiskTemps(node) {
  const host = node?.ip;
  if (!host) return;

  const st  = nodeState(node.name);
  const ssh = makeSSH(host);

  // lsblk and smartctl run at the same time; on the node, smartctl runs once per disk
  // in parallel into a temp directory whose files are then concatenated.
  const [lsblkRes, smartRes] = await Promise.all([
    ssh('lsblk -d --pairs -o NAME,MODEL,SIZE,TRAN 2>/dev/null', 5000),
    ssh(
      'D=$(mktemp -d); ' +
      'for d in $(lsblk -dno NAME 2>/dev/null | grep -v ^zd); do ' +
      '{ echo "DISK_START $d"; smartctl -a /dev/$d 2>/dev/null; } > $D/$d & ' +
      'done; wait; cat $D/*; rm -rf $D',
      30000
    ),
  ]);

  if (lsblkRes.ok && lsblkRes.stdout.trim()) {
    st.modelMap = {};
    st.diskSize = {};
    st.diskTran = {};
    for (const line of lsblkRes.stdout.trim().split('\n')) {
      const get  = k => { const m = line.match(new RegExp(`${k}="([^"]*)"`)); return m ? m[1] : ''; };
      const name = get('NAME');
      if (!name || name.startsWith('zd')) continue;
      const model = get('MODEL').trim();
      const size  = get('SIZE').trim();
      const tran  = get('TRAN').trim().toLowerCase();
      if (model) st.modelMap[name] = model;
      if (size)  st.diskSize[name] = size;
      if (tran)  st.diskTran[name] = tran;
    }
  }

  if (smartRes.ok && smartRes.stdout) {
    st.diskSmart = parseSmartBlocks(smartRes.stdout);
  }
}

module.exports = { checkDisks, checkDiskTemps };
