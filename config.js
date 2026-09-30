'use strict';
// Configuration for Open Moxdash, read from config.json next to this file.
//
// config.json is re-read on every cfg() call (no cache), so edits apply immediately, and
// webowner.js also reloads the modules when the file changes. If it doesn't exist, the
// defaults below are written out as a starting point on first run.
const fs   = require('fs');
const path = require('path');

const CONFIG_PATH = path.join(__dirname, 'config.json');

// Defaults, written to config.json when it doesn't exist yet. A blank address switches
// its check off, so a fresh install starts with just the DNS and internet checks; see
// config.example.json for a fully populated example. What each setting does:
//
//   network.gateway            router address, pinged by the Gateway check
//   network.broadcast          LAN broadcast address for the broadcast probe
//   network.broadcast_listener machine that runs the probe's listener during each check,
//                              reached over SSH; ideally a different physical machine.
//                              The check runs only when both broadcast settings are set
//   network.subnet             CIDR; guest IPs and UPnP mappings outside it are ignored
//   dns_test_domain            name resolved to test each DNS server
//   dns                        { label: resolver IP }, each checked and shown separately
//   proxmox.host, .port        API endpoint of any node in the cluster
//   proxmox.node               node name to assume if cluster discovery fails
//   proxmox.api_token_id       e.g. "root@pam!open-moxdash"; the secret is supplied
//                              separately (see readApiTokenSecret in webowner.js)
//   proxmox.ui_host            public hostname for links into the Proxmox UI; blank
//                              means host:port
//   proxmox.ssh_user           user for the SSH-based checks (CPU, RAM, disks, GPU)
//   upnp.enabled               run the UPnP health check and show port mappings
//   upnp.test_port             port used by the self-test mapping
//   upnp.permanent_lease_access  who may create permanent mappings: off, admin, list, everyone
//   upnp.refresh_on_add/_delete/_login  re-list mappings straight after that action
//   dhcp.server                DHCP server to probe; blank disables the check
//   sse.max_connections_per_ip, sse.exceptions  cap on live-update connections, and the
//                              IPs exempt from it
//   trusted_proxies            reverse-proxy IPs allowed to connect and to set
//                              X-Forwarded-For; blank means anyone
//   page.title, .refresh_seconds, .fast_refresh_seconds  page title and cycle lengths
//
// More optional settings are documented in the README: upnp.show_all_ports,
// upnp.max_mappings, upnp.all_ports_role, proxmox.allowed_ips_ttl, and checks (custom
// service checks).
const DEFAULT_CONFIG = {
  network: {
    gateway:   '',
    broadcast: '',
    broadcast_listener: '',
    subnet:    '',
  },
  dns_test_domain: 'example.com',
  dns: {
    primary:   '1.1.1.1',
    secondary: '8.8.8.8',
    tertiary:  '8.8.4.4',
  },
  proxmox: {
    host:         '',
    port:         8006,
    node:         'pve',
    api_token_id: '',
    ui_host:      '',
    ssh_user:     'root',
  },
  upnp: {
    enabled:           false,
    test_port:         62108,
    permanent_lease_access: 'off',
    refresh_on_add:    true,
    refresh_on_delete: true,
    refresh_on_login:  true,
  },
  dhcp: {
    server: '',
  },
  sse: {
    max_connections_per_ip: 1,
    exceptions: [],
  },
  trusted_proxies: '',
  page: {
    title:                'Open Moxdash',
    refresh_seconds:      30,
    fast_refresh_seconds: 3,
  },
};

// Reads and parses config.json. A missing file is created from DEFAULT_CONFIG; an
// unreadable or invalid file is logged and the defaults are used, so a typo in the
// config never takes the page down.
function load() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') {
      console.warn('[config] config.json not found — writing defaults');
      try {
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(DEFAULT_CONFIG, null, 2) + '\n', 'utf8');
        console.log('[config] config.json created with default values');
      } catch (we) {
        console.error('[config] could not write default config.json:', we.message);
      }
    } else {
      console.error('[config] Failed to load config.json:', e.message);
    }
    return { ...DEFAULT_CONFIG };
  }
}

// Reads one setting by dot path, e.g. cfg('proxmox.host'). Missing, null and empty-string
// values all count as unset and return defaultValue.
function cfg(dotPath, defaultValue = null) {
  const parts = dotPath.split('.');
  let cur = load();
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object') return defaultValue;
    cur = cur[p];
  }
  return (cur == null || cur === '') ? defaultValue : cur;
}

module.exports = { cfg, load };
