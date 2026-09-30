'use strict';
// Installed-memory summary (type, speed, form factor, ECC, channel count) for one
// cluster node, parsed from `dmidecode -t memory` run over SSH. dmidecode needs
// root on the target, so the SSH user must be root (proxmox.ssh_user).
const { makeSSH } = require('./ssh');

// Use Type Detail to get a precise form factor when Form Factor just says "DIMM".
// Check LRDIMM before RDIMM — LRDIMM Type Detail also contains "Registered (Buffered)".
function resolveFormFactor(formFactor, typeDetail) {
  const ff = (formFactor && formFactor !== 'Unknown') ? formFactor : null;
  if (ff && ff !== 'DIMM') return ff;
  if (typeDetail) {
    if (/lrdimm|load.?reduced/i.test(typeDetail))    return 'LRDIMM';
    if (/registered|buffered/i.test(typeDetail))     return 'RDIMM';
    if (/unbuffered|unregistered/i.test(typeDetail)) return 'UDIMM';
  }
  return ff;
}

// Leading letters of a locator identify the socket: "A1"→"A", "B8"→"B", "P1-DIMMA1"→"P1"
function extractSocket(locator) {
  if (!locator) return null;
  const m = locator.match(/^([A-Z]+\d*(?=-)|[A-Z]+)(?=\d)/i);
  return m ? m[1].toUpperCase() : null;
}

// Parses dmidecode's "Memory Device" records into populated DIMMs (empty slots are
// skipped). ECC is inferred from Total Width > Data Width, and is null when the
// widths are unknown.
function parseDmidecodeMemory(text) {
  const devices = [];

  for (const record of text.split(/\n\n+/)) {
    if (!record.includes('Memory Device\n') && !record.includes('Memory Device\r\n')) continue;

    const get = key => {
      const m = record.match(new RegExp(`^\\s*${key}:\\s*(.+)$`, 'm'));
      return m ? m[1].trim() : null;
    };

    const size = get('Size');
    if (!size || size === 'No Module Installed' || size === 'Not Installed' ||
        size === 'Unknown' || size.startsWith('0 ')) continue;

    const type        = get('Type');
    const speed       = get('Speed');
    const cfgSpeed    = get('Configured Memory Speed') || get('Configured Clock Speed');
    const formFactor  = get('Form Factor');
    const typeDetail  = get('Type Detail');
    const locator     = get('Locator');
    const totalWidthS = get('Total Width');
    const dataWidthS  = get('Data Width');
    const setS        = get('Set');

    const totalWidth = (totalWidthS && totalWidthS !== 'Unknown') ? parseInt(totalWidthS) : 0;
    const dataWidth  = (dataWidthS  && dataWidthS  !== 'Unknown') ? parseInt(dataWidthS)  : 0;

    const ecc = (totalWidth > 0 && dataWidth > 0) ? totalWidth > dataWidth : null;

    const speedRaw = cfgSpeed || speed || '';
    const speedNum = (speedRaw && speedRaw !== 'Unknown')
      ? (parseInt(speedRaw.replace(/\D.*/, '')) || null)
      : null;

    const ff     = resolveFormFactor(formFactor, typeDetail);
    const type_  = (type && type !== 'Unknown' && type !== 'Other') ? type : null;
    const setNum = (setS && setS !== 'None' && setS !== 'Unknown') ? parseInt(setS) : null;
    const socket = extractSocket(locator);

    devices.push({ size, type: type_, speedMhz: speedNum, formFactor: ff, ecc, setNum, socket });
  }

  return devices;
}

// Channel count: each dmidecode Set contains one DIMM per memory channel of its socket.
// So channels-per-socket = max populated DIMMs sharing the same (socket, set).
// Total channels = channels-per-socket × number of populated sockets.
function countChannels(devices) {
  const socketSetCounts = new Map();
  for (const d of devices) {
    if (d.setNum === null || !d.socket) continue;
    const k = `${d.socket}:${d.setNum}`;
    socketSetCounts.set(k, (socketSetCounts.get(k) || 0) + 1);
  }
  if (!socketSetCounts.size) return null;
  const channelsPerSocket = Math.max(...socketSetCounts.values());
  const sockets = new Set([...socketSetCounts.keys()].map(k => k.split(':')[0])).size;
  return channelsPerSocket * sockets;
}

// Returns the node's memory summary { type, speedMhz, formFactor, ecc, channels },
// taking the first value seen when DIMMs differ, or null if dmidecode fails or
// reports no populated slots.
async function checkRam(node) {
  const host = node?.ip;
  if (!host) return null;

  const ssh = makeSSH(host);
  const { ok, stdout } = await ssh('dmidecode -t memory 2>/dev/null', 12000);

  if (!ok || !stdout) {
    console.warn('[ram] dmidecode SSH failed or returned no data');
    return null;
  }

  const devices = parseDmidecodeMemory(stdout);
  if (!devices.length) return null;

  const types       = [...new Set(devices.map(d => d.type).filter(Boolean))];
  const speeds      = [...new Set(devices.map(d => d.speedMhz).filter(Boolean))];
  const formFactors = [...new Set(devices.map(d => d.formFactor).filter(Boolean))];

  const eccKnown = devices.filter(d => d.ecc !== null);
  const hasEcc   = eccKnown.length > 0 ? eccKnown.some(d => d.ecc) : null;

  return {
    type:       types[0]       || null,
    speedMhz:   speeds[0]      || null,
    formFactor: formFactors[0] || null,
    ecc:        hasEcc,
    channels:   countChannels(devices),
  };
}

module.exports = { checkRam };
