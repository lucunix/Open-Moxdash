'use strict';
// In-memory holder for the Proxmox API token secret. The secret is kept encrypted
// (AES-256-GCM) under a random key generated when the process starts, and is decrypted
// only for the moment an API call needs it. This limits casual exposure (memory dumps of
// idle state, accidental logging); it is not a vault, because the key lives in the same
// process. Keep the process itself locked down.
const crypto = require('crypto');

// One-time key generated at process start — never leaves this module.
// This module is deliberately excluded from hot-reload so the key and
// ciphertext survive app.js / checks reloads.
const KEY = crypto.randomBytes(32);

let enc = null;  // { iv, ct, tag } — all Buffers

// Stores (or, given an empty value, clears) the secret. Called at startup and once per
// slow cycle, so a rotated systemd credential is picked up without a restart.
function setToken(plaintext) {
  if (!plaintext) { enc = null; return; }
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct     = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  enc = { iv, ct, tag: cipher.getAuthTag() };
}

// Returns a Buffer — caller must fill(0) after use to minimise plaintext lifetime.
function getToken() {
  if (!enc) return null;
  const { iv, ct, tag } = enc;
  const d = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

// Destroys the stored secret and the key that protects it. Called by the lockdown in
// webowner.js just before the process is killed.
function wipe() {
  if (enc) { enc.iv.fill(0); enc.ct.fill(0); enc.tag.fill(0); }
  enc = null;
  KEY.fill(0);
}

module.exports = { setToken, getToken, wipe };
