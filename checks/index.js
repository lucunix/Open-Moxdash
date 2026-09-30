'use strict';
// Check orchestration for Open Moxdash.
//
// runFast() and runSlow() are driven by timers in webowner.js, at
// page.fast_refresh_seconds and page.refresh_seconds. Every check publishes its
// result into the shared page state through writeTo(dotPath, value) the moment
// it finishes, and one failing or slow check never holds up the others
// (Promise.allSettled). Checks whose settings are missing from config.json are
// skipped rather than reported as failures.
const { cfg }   = require('../config');
const secrets   = require('../secrets');
const { checkGateway, checkInternet } = require('./network');
const { checkBroadcast }    = require('./broadcast');
const { checkDns }          = require('./dns');
const { checkProxmoxUI, checkProxmoxStats, discoverNodes } = require('./proxmox');
const { checkDhcp }         = require('./dhcp');
const { checkUpnp }         = require('./upnp');
const { checkCpuCores }     = require('./cpu');
const { checkGpu }          = require('./gpu');
const { checkDisks, checkDiskTemps } = require('./disk');
const { checkRam }          = require('./ram');
const { checkServices }     = require('./services');

// Cluster membership rarely changes, so it is cached: the fast cycle reuses the
// cache for up to NODES_TTL_MS, and the slow cycle force-refreshes it once per pass.
const NODES_TTL_MS = 30000;
let nodesCache   = null;
let nodesFetched = 0;

// Returns the cluster's node list (as reported by checks/proxmox.js discoverNodes()).
async function getNodes(force) {
  if (force || !nodesCache || (Date.now() - nodesFetched) > NODES_TTL_MS) {
    nodesCache   = await discoverNodes();
    nodesFetched = Date.now();
  }
  return nodesCache;
}

// Fast checks (default every 3s): the per-node Proxmox host, CPU, GPU and disk panels.
// Nothing is scheduled unless the Proxmox host, API token id and token secret are all set.
async function runFast(writeTo) {
  const tasks = [];
  if (cfg('proxmox.host')) {
    if (cfg('proxmox.api_token_id') && secrets.getToken()) {
      const nodes = await getNodes();
      writeTo('nodeOrder', nodes.map(n => n.name));
      for (const node of nodes) {
        tasks.push(checkProxmoxStats(node.name).then(r => writeTo(`nodes.${node.name}.host`, r)));
        tasks.push(checkCpuCores(node).then(r => r && writeTo(`nodes.${node.name}.cpuCores`, r)));
        tasks.push(checkGpu(node).then(r => r && writeTo(`nodes.${node.name}.gpus`, r)));
        tasks.push(checkDisks(node).then(r => r && writeTo(`nodes.${node.name}.disks`, r)));
      }
    }
  }
  await Promise.allSettled(tasks);
}

// Slow checks (default every 30s): network reachability, DNS, Proxmox web UI,
// per-node RAM spec and disk temperatures, DHCP, UPnP, and any custom service
// checks from the `checks` block in config.json.
async function runSlow(writeTo) {
  const tasks = [];
  if (cfg('network.gateway'))   tasks.push(checkGateway().then(r  => writeTo('network.gateway',   r)));
  if (cfg('network.broadcast') && cfg('network.broadcast_listener'))
    tasks.push(checkBroadcast().then(r => writeTo('network.broadcast', r)));
  tasks.push(checkInternet().then(r => writeTo('network.internet', r)));

  const dnsServers   = cfg('dns') || {};
  const dnsTestDomain = cfg('dns_test_domain', 'google.com');
  for (const [label, server] of Object.entries(dnsServers)) {
    if (!server) continue;
    tasks.push(checkDns(server, label, dnsTestDomain).then(r => writeTo(`dns.${label}`, r)));
  }

  if (cfg('proxmox.host')) {
    tasks.push(checkProxmoxUI().then(r => writeTo('services.proxmox_ui', r)));

    if (cfg('proxmox.api_token_id') && secrets.getToken()) {
      const nodes = await getNodes(true);  // force-refresh cluster membership once per slow cycle
      writeTo('nodeOrder', nodes.map(n => n.name));
      for (const node of nodes) {
        tasks.push(checkDiskTemps(node));
        tasks.push(checkRam(node).then(r => r && writeTo(`nodes.${node.name}.ramSpec`, r)));
      }
    }
  }

  if (cfg('dhcp.server'))         tasks.push(checkDhcp().then(r => writeTo('services.dhcp', r)));
  if (cfg('upnp.enabled', false)) tasks.push(checkUpnp().then(r => writeTo('services.upnp', r)));

  const svcChecks = cfg('checks');
  if (svcChecks && Object.keys(svcChecks).length)
    tasks.push(checkServices().then(r => r && writeTo('serviceChecks', r)));

  await Promise.allSettled(tasks);
}

module.exports = { runFast, runSlow };
