# Open Moxdash

A self-hosted health dashboard built around Proxmox VE. One page shows whether your network is up and how it's performing, how each
Proxmox node is doing, and, optionally, lets your Proxmox users manage their own UPnP port mappings.

## What it shows

**Network and services** (one table)
- Gateway ping, internet ping, and reachability of the Proxmox web UI
- LAN broadcast round trip
- DNS: lookup time against each resolver you list
- DHCP: sends a real DISCOVER and waits for an OFFER
- UPnP: an end-to-end test of your router's UPnP gateway (discovery, add, verify, lease expiry)
- Your own checks: ping, HTTP, and TLS certificate expiry

**Proxmox** (one panel per cluster node)
- CPU, RAM, swap, uptime, kernel and Proxmox versions (from the API)
- Per-socket and per-thread CPU usage, clock speed and package temperature
- Disks: throughput, utilisation, and SMART health, temperature and wear
- NVIDIA GPU utilisation, power, memory and fan, plus vGPU allocation

**Port mappings**
- Log in with your Proxmox credentials to see, add and delete UPnP mappings for the
  VMs and containers you can see. Privileged accounts can manage every mapping.

The page updates itself, reloads when the config changes, and serves Open Graph
tags so a link to it unfurls with a live summary in chat apps.

## Requirements

- Node.js 18 or newer (developed on Node 20)
- Linux with `ping` and `ssh` available to the user that runs the app
- For the Proxmox panels: a Proxmox VE API token, and key-based SSH from the
  app's host to each Proxmox node

## Quick start

```sh
git clone https://github.com/lucunix/Open-Moxdash.git
cd Open-Moxdash
npm install
node webowner.js
```

The app listens on port 80, which needs root or the `cap_net_bind_service` capability.
Optionally, put a TLS-terminating reverse proxy in front of it as the app itself doesn't support TLS (see [HTTPS](#https-and-reverse-proxies)).

Upon first start it will generate `config.json` with default values. A fresh install runs only the DNS and
internet checks; every other check switches on when you give it an address. Edit
`config.json` (see `config.example.json` for a fully populated example).

**Changes to `config.json` apply without a restart, except `page.refresh_seconds`, `page.fast_refresh_seconds` and `lockdown.shred`, which are read at startup.**

## Configuration

Everything lives in `config.json`. A blank value switches that feature off.

| Setting | Default | What it does |
|---|---|---|
| `network.gateway` | blank | Router address, pinged by the Gateway check |
| `network.broadcast` | blank | Broadcast address for the [broadcast check](#broadcast-check) |
| `network.subnet` | blank | CIDR such as `192.168.1.0/24`. Guest IPs and port mappings outside it are ignored |
| `dns_test_domain` | `example.com` | Name resolved to test each DNS server |
| `dns` | Cloudflare and Google | `{ "label": "resolver IP" }`, each checked and shown separately |
| `proxmox.host`, `.port` | blank, `8006` | Address of any node in the cluster |
| `proxmox.node` | `pve` | Node name to assume if cluster discovery fails |
| `proxmox.api_token_id` | blank | e.g. `root@pam!open-moxdash`. See [Proxmox access](#proxmox-access) |
| `proxmox.ui_host` | blank | Public hostname for links into the Proxmox UI. Blank means `host:port` |
| `proxmox.ssh_user` | `root` | User for the SSH-based checks |
| `proxmox.allowed_ips_ttl` | `5m` | How long a user's list of VM/CT IPs is cached (`30s`, `5m`, `2h`, `1d`) |
| `dhcp.server` | blank | DHCP server to probe |
| `upnp.enabled` | `false` | Run the UPnP test and show port mappings |
| `upnp.test_port` | `62108` | Port used by the self-test mapping |
| `upnp.show_all_ports` | `false` | Show mappings for clients outside `network.subnet` too |
| `upnp.max_mappings` | `1024` | Upper bound when listing the router's mappings |
| `upnp.all_ports_role` | `root` | Who counts as privileged: `root` (only `root@pam`) or a Proxmox role name |
| `upnp.permanent_lease_access` | `off` | Who may create permanent mappings: `off`, `admin`, `list`, `everyone` |
| `upnp.refresh_on_add`, `_delete`, `_login` | `true` | Re-list mappings straight after that action |
| `sse.max_connections_per_ip` | `1` | Live-update connections allowed per client IP |
| `sse.exceptions` | `[]` | IPs exempt from that limit |
| `trusted_proxies` | blank | Reverse-proxy IPs allowed to connect and set `X-Forwarded-For`. See [HTTPS](#https-and-reverse-proxies) |
| `lockdown.shred` | `[]` | Extra files to overwrite if the process guard trips, such as an SSH private key. See [Tamper protection](#tamper-protection) |
| `page.title` | `Open Moxdash` | Page title |
| `page.refresh_seconds`, `.fast_refresh_seconds` | `30`, `3` | Slow (network, DNS, UPnP) and fast (Proxmox) check intervals |
| `checks` | none | Your own service checks, below |

### Your own checks

```json
"checks": {
  "Router":   { "type": "ping", "host": "192.168.1.1" },
  "Wiki":     { "type": "http", "url": "https://wiki.example.com", "verify": true },
  "Mail TLS": { "type": "tls",  "host": "mail.example.com", "port": 443, "verify": true }
}
```

- `ping`: one ICMP echo
- `http`: a GET; 2xx and 3xx count as up (redirects are not followed)
- `tls`: connects and shows the days left on the certificate, warning under 14

Set `"verify": false` to accept self-signed certificates.

## Proxmox access

**API token.** Create one in Proxmox under Datacenter, Permissions, API Tokens, and give it
read access to the cluster and its nodes. If you set `upnp.all_ports_role` to a role name, the
token must also be able to read the ACL list. Put its id in `proxmox.api_token_id`. Every
request made with the token is a read-only GET.

**Token secret.** Supply it as a systemd credential named `proxmox-token-secret` (see
`deploy/open-moxdash.service`). For development you can instead set `proxmox.api_token_secret`
in `config.json`, but that leaves the secret in a plain file.

**SSH checks.** CPU, RAM, disk and GPU details come from running commands on each node:

```
ssh -o BatchMode=yes -o StrictHostKeyChecking=no <proxmox.ssh_user>@<node> ...
```
That way you don't need to install an agent/satellite service on every node, nor does there need to be any permanent software installed anywhere outside the app itself

Set up key-based login for the user that runs Open Moxdash. The commands used are
`/proc/stat`, `/proc/cpuinfo`, `/proc/diskstats`, `lsblk`, `smartctl`, `dmidecode` and
`nvidia-smi`;
`smartctl` and `dmidecode` need root on the node.

**Login.** The login form signs users in against Proxmox. `root` uses the `pam` realm and
every other name uses the `pve` realm.

## Broadcast check

The check sends a UDP probe to `network.broadcast` on port 55399 and waits for a reply.

Run the responder on a **different physical machine**. If it runs on the same hypervisor as
Open Moxdash, the probe only crosses the host's virtual bridge and never touches your real
network, so the check will pass even when the LAN is broken.

## UPnP

With `upnp.enabled`, each slow cycle Open Moxdash finds your router's gateway device, reads the
external IP (a private one means double NAT), lists the mappings, then adds a 10-second UDP
test mapping, reads it back, waits 12 seconds and confirms it expired. Anything the router
does wrong is listed under the Port mappings panel.

Logged-in users can add and delete mappings for their own VMs and containers. Two optional
files sit next to `config.json`; copy the examples to activate them:

- `upnp-blacklist.json` (from `upnp-blacklist.example.json`): ports and clients nobody may map.
  Despite the name it is a plain text file, one rule per line.
- `upnp-permanent-users.txt` (from `upnp-permanent-users.example.txt`): accounts allowed to
  create permanent mappings when `upnp.permanent_lease_access` is `list`.

`disk_names.json` (from `disk_names.example.json`) is another optional file. It maps the raw
model string a drive reports to a friendlier name.

## HTTPS and reverse proxies

The session cookie is marked `Secure`, so **login only works over HTTPS**. Terminate TLS at a
reverse proxy in front of the app, and have it pass `X-Forwarded-For` and `X-Forwarded-Host`.

Set `trusted_proxies` to the proxy's IP address. The app then refuses connections from anywhere
else and only trusts `X-Forwarded-For` from those addresses. With it blank, the header is
believed from anyone, which lets a client dodge the login rate limit by spoofing it.

## Running as a service

Copy the project to `/opt/open-moxdash`, run `npm install`, then:

```sh
cp deploy/open-moxdash.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now open-moxdash
```

The unit restarts the app if it crashes, but not when a [tamper defence](#tamper-protection)
ends it: that exits with status 99, which the unit lists in `RestartPreventExitStatus=`.
Check `journalctl -u open-moxdash` for the reason, then `systemctl start open-moxdash`.

## Hot reload

The app reloads itself without dropping the process when you change a `.json` file such as
`config.json`. Changes under `public/` just tell open browsers to reload.

Code is the exception. Every `.js` file is hash-checked (see [Tamper protection](#tamper-protection)),
so editing one stops the app. After editing code, run `node webowner.js --update-hashes` and
restart. While developing, start the app with `node webowner.js --no-hashing` instead: `.js` files
in `checks/`, and top-level `.js` files other than `webowner.js`, `secrets.js` and `guard.js`,
then reload live as before. Those three always need a restart.

## Tamper protection

Open Moxdash runs commands on your servers, so it guards itself against corrupted or injected code.

**Process guard** (`guard.js`). The app may start exactly two kinds of process: `ping`, and `ssh`
running one of a fixed list of commands (the ones under [Proxmox access](#proxmox-access)).
Anything else, such as another program, an extra ssh option or a changed remote command, is treated
as a possible hijack. The app prints the reason, the calling code and the exact command, runs the
lockdown, and exits. If you add or change a command in `checks/`, update `REMOTE_COMMANDS` in
`guard.js` and restart, or the app ends the first time it runs that command.

**Lockdown.** Before exiting, the app destroys what an attacker could use next: the token held in
memory, `proxmox.api_token_secret` in `config.json`, the files in the systemd credentials
directory, and every file listed in `lockdown.shred` (up to 20 absolute paths). Files are
overwritten with random bytes and deleted. Only regular files up to 64 KiB are touched, under
`/etc/credstore.encrypted/`, `/etc/credstore/`, `/run/credentials/`, `/tmp/` or an `.ssh`
directory (private keys only, never `known_hosts` or `authorized_keys`). Symlinks and the app's own
files are never touched. The encrypted credential in `/etc/credstore.encrypted/` is destroyed only
if you list it in `lockdown.shred`; if you do, recreate it before starting the service again.
`node webowner.js --lockdown-check` shows what would be shredded or refused and changes nothing.

**Integrity check.** `webowner.js` holds a SHA-256 for every other `.js` file, and its own hash on
line 2. A changed, missing or unexpected `.js` file ends the app. It is checked at startup, before
each reload and every 15 seconds. This one does not shred anything, because a mismatch also
follows an ordinary update. `node webowner.js --update-hashes` rewrites the hashes after you edit
code.

**Exit status 99.** Both defences exit with status 99, so systemd leaves the service stopped
instead of restarting it (see [Running as a service](#running-as-a-service)).

**Development.** `node webowner.js --no-hashing` ignores all hashes so code edits go live. The
process guard and the lockdown stay on. Don't use it in the service unit.

**Limits.** This is a tripwire, not a lock. Someone who can rewrite `webowner.js` can rewrite the
hashes too, `node_modules` is not hash-checked, and the guard does not stop code that already runs
inside the process from reaching the operating system by other routes. Shredding removes local
copies only, and is best effort on ZFS and other copy-on-write storage. After a trip, also revoke
the Proxmox API token and the SSH keys on the servers.

## Security notes

- Anyone who can reach the page can read the check results, the LAN subnet and the names of
  your custom checks. Port mapping details and management need a login.
- Login is checked against Proxmox itself. After 10 failed attempts an IP is locked out for
  5 minutes.
- Certificate verification is off for the Proxmox API and for router UPnP endpoints, because
  both normally use self-signed certificates. Only point the app at hosts on a network you trust.
- The SSH checks use `StrictHostKeyChecking=no`, so node host keys are not verified.
- The token secret is held encrypted in memory under a per-process key. That limits casual
  exposure but is not a vault; protect the process itself.
- The Content-Security-Policy is `default-src 'self'` plus an allowance for Cloudflare Web
  Analytics (`static.cloudflareinsights.com`). If you don't use it, remove those hosts in `app.js`.

## Known limitations

- The "Internet" check always pings `1.1.1.1`; the target is not configurable.
- Login covers the `pam` and `pve` realms only.

## Project layout

```
webowner.js         entry point: shared state, timers, HTTP listener, hot reload, integrity check, lockdown
app.js              Express app: API, login, UPnP routes, link previews
config.js           reads config.json
secrets.js          in-memory holder for the Proxmox token secret
guard.js            process guard: only the app's own ping and ssh commands may run
checks/             one module per check; index.js schedules them
public/             the frontend (index.html, main.js, style.css, fonts)
deploy/             systemd unit
```
