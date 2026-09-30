'use strict';
// DNS resolver check: times an A-record lookup against one specific server.
const { Resolver } = require('dns').promises;

// Resolves testDomain (A record) using only `server` and reports the lookup time.
// `label` is the key from the `dns` block in config.json (e.g. "primary"); it is
// passed through so the page can name the result. Returns null for an empty server.
async function checkDns(server, label, testDomain = 'google.com') {
  if (!server) return null;
  const resolver = new Resolver();
  resolver.setServers([server]);
  const start = Date.now();
  try {
    await resolver.resolve4(testDomain);
    const ms = Date.now() - start;
    return { ok: true, server, label, detail: `${ms}ms` };
  } catch (e) {
    const ms = Date.now() - start;
    console.warn(`[dns] ${label} (${server}) failed — ${e.message} ms=${ms}`);
    return { ok: false, server, label, detail: 'FAIL' };
  }
}

module.exports = { checkDns };
