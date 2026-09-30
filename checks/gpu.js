'use strict';
// NVIDIA GPU statistics (utilisation, power, memory, fan) and vGPU allocation for
// one cluster node, read by running nvidia-smi on the node over SSH.
const { makeSSH } = require('./ssh');

// Returns one entry per GPU: { id, name, util %, powerDraw W, powerLimit W,
// memUsedMib, memTotalMib, fanSpeed %, allocated, vgpuActive, vgpuMax }, or null
// when nvidia-smi is missing, fails, or finds no GPUs (a node without NVIDIA
// hardware simply gets no GPU panel).
async function checkGpu(node) {
  const host = node?.ip;
  if (!host) return null;

  const ssh = makeSSH(host);

  // Basic per-GPU stats, one CSV line per GPU (needs the NVIDIA driver on the node)
  const { ok: basicOk, stdout: basicOut } = await ssh(
    `nvidia-smi --query-gpu=index,name,utilization.gpu,power.draw,power.limit,memory.used,memory.total,fan.speed --format=csv,noheader,nounits 2>/dev/null`,
    10000
  );
  if (!basicOk || !basicOut.trim()) {
    console.warn('[gpu] nvidia-smi basic query failed or no GPUs found');
    return null;
  }

  // vGPU queries (NVIDIA vGPU host driver): running instances, and the profiles each
  // GPU supports. Both end in `|| true` so a GPU without vGPU support still works.
  const [activeRes, supportedRes] = await Promise.all([
    ssh(`nvidia-smi vgpu --query-vgpu=gpu_index,vgpu_type_name --format=csv,noheader,nounits 2>/dev/null || true`, 10000),
    ssh(`nvidia-smi vgpu -s --query-supported-vgpus=gpu_index,vgpu_type_name,vgpu_type_max_instances --format=csv,noheader,nounits 2>/dev/null || true`, 10000),
  ]);

  // Parse active vGPU instances: count per gpu_index
  // { gpuIndex -> { typeName -> count } }
  const activeByGpu = {};
  if (activeRes.ok && activeRes.stdout.trim()) {
    for (const line of activeRes.stdout.trim().split('\n')) {
      const parts = line.split(',').map(s => s.trim());
      if (parts.length < 2) continue;
      const [idxStr, typeName] = parts;
      const idx = parseInt(idxStr, 10);
      if (isNaN(idx)) continue;
      if (!activeByGpu[idx]) activeByGpu[idx] = {};
      activeByGpu[idx][typeName] = (activeByGpu[idx][typeName] || 0) + 1;
    }
  }

  // Parse supported vGPU types: max instances per gpu_index per type
  // { gpuIndex -> { typeName -> maxInstances } }
  const supportedByGpu = {};
  if (supportedRes.ok && supportedRes.stdout.trim()) {
    for (const line of supportedRes.stdout.trim().split('\n')) {
      const parts = line.split(',').map(s => s.trim());
      if (parts.length < 3) continue;
      const [idxStr, typeName, maxStr] = parts;
      const idx = parseInt(idxStr, 10);
      const max = parseInt(maxStr, 10);
      if (isNaN(idx) || isNaN(max)) continue;
      if (!supportedByGpu[idx]) supportedByGpu[idx] = {};
      supportedByGpu[idx][typeName] = max;
    }
  }

  const gpus = [];
  for (const line of basicOut.trim().split('\n')) {
    const parts = line.split(',').map(s => s.trim());
    if (parts.length < 8) continue;
    const [idxStr, name, utilStr, powerDrawStr, powerLimitStr, memUsedStr, memTotalStr, fanStr] = parts;
    const idx       = parseInt(idxStr, 10);
    const util      = parseFloat(utilStr);
    const powerDraw = parseFloat(powerDrawStr);
    const powerLimit = parseFloat(powerLimitStr);
    const memUsed   = parseFloat(memUsedStr);   // MiB
    const memTotal  = parseFloat(memTotalStr);   // MiB
    const fanSpeed  = parseFloat(fanStr);

    // Determine vGPU allocation (x/y) for the dominant active type on this GPU
    // x = total active vGPU instances on this GPU, y = max instances for that type
    let vgpuActive = 0;
    let vgpuMax = null;
    let vgpuTypeName = null;

    const activeTypes = activeByGpu[idx] || {};
    for (const [type, count] of Object.entries(activeTypes)) {
      vgpuActive += count;
      if (vgpuTypeName === null) vgpuTypeName = type;
    }

    // Find max for the first active type; fall back to first supported type's max
    if (vgpuTypeName && supportedByGpu[idx]?.[vgpuTypeName] !== undefined) {
      vgpuMax = supportedByGpu[idx][vgpuTypeName];
    } else if (supportedByGpu[idx]) {
      const firstType = Object.keys(supportedByGpu[idx])[0];
      if (firstType) {
        vgpuMax = supportedByGpu[idx][firstType];
        if (!vgpuTypeName) vgpuTypeName = firstType;
      }
    }

    // Allocated = active vGPU instances OR memory usage well above idle baseline (~100 MiB)
    const allocated = vgpuActive > 0 || memUsed > 100;

    gpus.push({
      id:          idx,
      name:        name ? `NVIDIA ${name}` : `GPU ${idx}`,
      util:        isNaN(util)       ? null : Math.round(util),
      powerDraw:   isNaN(powerDraw)  ? null : Math.round(powerDraw),
      powerLimit:  isNaN(powerLimit) ? null : Math.round(powerLimit),
      memUsedMib:  isNaN(memUsed)    ? null : Math.round(memUsed),
      memTotalMib: isNaN(memTotal)   ? null : Math.round(memTotal),
      fanSpeed:    isNaN(fanSpeed)   ? null : Math.round(fanSpeed),
      allocated,
      vgpuActive,
      vgpuMax,
    });
  }

  if (!gpus.length) {
    console.warn('[gpu] parsed zero GPUs from nvidia-smi output');
    return null;
  }

  console.log(`[gpu] found ${gpus.length} GPU(s)`);
  return gpus;
}

module.exports = { checkGpu };
