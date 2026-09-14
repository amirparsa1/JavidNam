/* ============================================================
 * JavidNam Panel — BUILT ARTIFACT (do not edit; edit src/ + build)
 * جاویدنام — به یاد جان‌بافتگان ۱۸ و ۱۹ دی ۱۴۰۴
 * License: GPL-3.0 | QR: qrcode-generator 1.4.4 (MIT, Kazuhiko Arase)
 * Build time: 2026-09-14T15:03:00.352Z
 * ============================================================ */


/**
 * ============================================================================
 *  JavidNam Panel — جاویدنام
 *  A fully original VLESS/Trojan management panel for Cloudflare Workers.
 *  به یاد جان‌باختگان ۱۸ و ۱۹ دی ۱۴۰۴ — نامشان جاوید.
 *
 *  Copyright (C) 2026 amirparsa1 (JavidNam)
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 * ============================================================================
 */

import { connect } from 'cloudflare:sockets';

const VERSION = '1.0.0';
const BRAND = {
  fa: 'جاویدنام',
  en: 'JavidNam',
  memorial: 'به یاد جان‌باختگان ۱۸ و ۱۹ دی ۱۴۰۴',
  eternal: 'نامشان جاوید',
};

/* ------------------------------------------------------------------ */
/* Encoding & crypto helpers (WebCrypto — all original implementations) */
/* ------------------------------------------------------------------ */

const TE = new TextEncoder();
const TD = new TextDecoder();

function hex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256hex(str) {
  return hex(await crypto.subtle.digest('SHA-256', TE.encode(str)));
}

async function hmacSign(secret, message) {
  const key = await crypto.subtle.importKey('raw', TE.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, TE.encode(message)));
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function rndHex(nBytes) {
  const b = new Uint8Array(nBytes);
  crypto.getRandomValues(b);
  return hex(b);
}

function randomPassword(len = 16) {
  const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return [...b].map(x => chars[x % chars.length]).join('');
}

function isUuid(s) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
}

function b64encode(str) {
  return btoa(String.fromCharCode(...TE.encode(str)));
}

/* ------------------------------------------------------------------ */
/* HTTP response helpers                                                */
/* ------------------------------------------------------------------ */

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'SAMEORIGIN',
};

function jsonResponse(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...SECURITY_HEADERS, ...extra },
  });
}

function htmlResponse(body, status = 200, extra = {}) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...SECURITY_HEADERS, ...extra },
  });
}

function notFound() {
  return new Response('404', { status: 404, headers: SECURITY_HEADERS });
}

/* ------------------------------------------------------------------ */
/* D1 helpers (all queries throw-safe; D1 binding is named DB)          */
/* Auto-creates schema on first use so manual deploys just work.        */
/* Module syntax: bindings arrive via env — captured here once.         */
/* ------------------------------------------------------------------ */

let DB = null;
let ADMIN_PASS_HASH = null;
let SESSION_SECRET = null;

function initEnv(env) {
  if (env) {
    if (env.DB) DB = env.DB;
    if (env.ADMIN_PASS_HASH) ADMIN_PASS_HASH = env.ADMIN_PASS_HASH;
    if (env.SESSION_SECRET) SESSION_SECRET = env.SESSION_SECRET;
  }
}

let _schemaEnsured = false;
async function ensureSchema() {
  if (_schemaEnsured) return;
  await DB.batch([
    DB.prepare(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, uuid TEXT UNIQUE NOT NULL, trojan_hash TEXT, name TEXT,
      sub_token TEXT UNIQUE NOT NULL, quota_bytes INTEGER DEFAULT 0, used_bytes INTEGER DEFAULT 0,
      reset_hours INTEGER DEFAULT 0, last_reset_at INTEGER, days INTEGER DEFAULT 0, expiry_at INTEGER,
      start_on_first INTEGER DEFAULT 0, first_connect_at INTEGER, ip_limit INTEGER DEFAULT 0,
      active INTEGER DEFAULT 1, note TEXT, created_at INTEGER)`),
    DB.prepare(`CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid)`),
    DB.prepare(`CREATE INDEX IF NOT EXISTS idx_users_trojan ON users(trojan_hash)`),
    DB.prepare(`CREATE INDEX IF NOT EXISTS idx_users_token ON users(sub_token)`),
    DB.prepare(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`),
    DB.prepare(`CREATE TABLE IF NOT EXISTS login_attempts (ip TEXT PRIMARY KEY, fails INTEGER DEFAULT 0, banned_until INTEGER)`),
  ]);
  _schemaEnsured = true;
}

async function dbAll(sql, params = []) {
  try {
    const { results } = await DB.prepare(sql).bind(...params).all();
    return results || [];
  } catch (e) {
    if (String(e.message || e).includes('no such table')) { await ensureSchema(); }
    else throw e;
    const { results } = await DB.prepare(sql).bind(...params).all();
    return results || [];
  }
}

async function dbGet(sql, params = []) {
  try {
    return await DB.prepare(sql).bind(...params).first();
  } catch (e) {
    if (String(e.message || e).includes('no such table')) { await ensureSchema(); }
    else throw e;
    return await DB.prepare(sql).bind(...params).first();
  }
}

async function dbRun(sql, params = []) {
  try {
    return await DB.prepare(sql).bind(...params).run();
  } catch (e) {
    if (String(e.message || e).includes('no such table')) { await ensureSchema(); }
    else throw e;
    return await DB.prepare(sql).bind(...params).run();
  }
}

/* ------------------------------------------------------------------ */
/* Settings: JSON rows in `settings` table, isolate-cached (fast paths) */
/* ------------------------------------------------------------------ */

const SETTING_DEFAULTS = {
  /* NOTE: proxy_path is seeded with a random value into D1 on first read
     (getSettings) — the placeholder below must stay deterministic because
     Workers forbid randomness at global scope. */
  proxy_path: '/jvn-setup',
  title: 'جاویدنام | JavidNam',
  welcome: 'سلام! این اشتراک اختصاصی توئه. لذت ببر 🌷',
  contact: '',
  locations: [
    { name: 'اصلی', host: '__PANEL_HOST__', port: 443, tls: true },
  ],
  sub_branding: true,
};

const DEFAULT_LOCATIONS = [
  { name: 'اصلی', host: '__PANEL_HOST__', port: 443, tls: true },
];

let _settingsCache = null;
let _settingsCacheAt = 0;
const SETTINGS_TTL = 30_000;

async function getSettings(force = false) {
  const now = Date.now();
  if (!force && _settingsCache && now - _settingsCacheAt < SETTINGS_TTL) return _settingsCache;
  let rows = [];
  try { rows = await dbAll('SELECT key, value FROM settings'); } catch (e) { /* fresh DB */ }
  /* proxy_path MUST be stable across isolates — seed a random one into D1 once */
  if (!rows.find(r => r.key === 'proxy_path')) {
    const candidate = '/jvn-' + rndHex(5);
    try {
      await dbRun("INSERT INTO settings (key, value) VALUES ('proxy_path', ?) ON CONFLICT(key) DO NOTHING", [candidate]);
      rows = await dbAll('SELECT key, value FROM settings');
    } catch (e) { rows = []; }
  }
  const s = { ...SETTING_DEFAULTS, locations: null };
  for (const r of rows) {
    if (r.key === 'locations') continue;
    s[r.key] = r.value;
  }
  let locs = null;
  try { locs = JSON.parse((rows.find(r => r.key === 'locations') || {}).value || 'null'); } catch (e) {}
  if (!Array.isArray(locs) || !locs.length) locs = DEFAULT_LOCATIONS.map(x => ({ ...x }));
  s.locations = locs;
  s.sub_branding = s.sub_branding !== 'false' && s.sub_branding !== false;
  _settingsCache = s;
  _settingsCacheAt = now;
  return s;
}

async function saveSettings(patch) {
  const allowed = ['proxy_path', 'title', 'welcome', 'contact', 'locations', 'sub_branding'];
  for (const k of allowed) {
    if (!(k in patch)) continue;
    let v = patch[k];
    if (k === 'proxy_path') {
      v = String(v || '').trim();
      if (!/^\/[A-Za-z0-9_-]{3,64}$/.test(v)) throw new Error('مسیر پروکسی نامعتبره (مثال: /jvn-myPath)');
    }
    if (k === 'locations') {
      if (!Array.isArray(v) || !v.length || v.length > 12) throw new Error('لیست لوکیشن‌ها باید بین ۱ تا ۱۲ آیتم باشه');
      v = v.map(l => ({
        name: String(l.name || 'لوکیشن').slice(0, 40),
        host: String(l.host || '').trim().slice(0, 200),
        port: Number(l.port) || 443,
        tls: l.tls !== false,
      })).filter(l => l.host);
      v = JSON.stringify(v);
    }
    if (typeof v !== 'string') v = String(v);
    await dbRun('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', [k, v]);
  }
  _settingsCache = null;
  return await getSettings(true);
}

/* Resolve __PANEL_HOST__ placeholder to the request host */
function resolveLocations(settings, requestHost) {
  return settings.locations.map(l => ({
    ...l,
    host: l.host === '__PANEL_HOST__' ? requestHost : l.host,
  }));
}

/* ------------------------------------------------------------------ */
/* User cache + traffic accounting (throttled flushes, isolate-local)   */
/* ------------------------------------------------------------------ */

const USER_TTL = 60_000;              // auth cache lifetime
const FLUSH_INTERVAL = 60_000;        // traffic flush throttle per user
const IP_WINDOW = 3 * 60_000;         // soft concurrent-IP window

const _userCache = new Map();         // uuid -> { user, at }
const _dirty = new Map();             // uuid -> { bytes, at }
const _ipMap = new Map();             // uuid -> Map(ip -> lastSeen)

async function getUserByUuid(uuid, force = false) {
  const now = Date.now();
  const c = _userCache.get(uuid);
  if (!force && c && now - c.at < USER_TTL) return c.user;
  const user = await dbGet('SELECT * FROM users WHERE uuid = ?', [uuid]);
  if (user) _userCache.set(uuid, { user, at: now });
  return user;
}

function cacheUser(user) {
  _userCache.set(user.uuid, { user, at: Date.now() });
}

function addUsage(uuid, bytes) {
  if (bytes <= 0) return;
  const d = _dirty.get(uuid) || { bytes: 0, at: 0 };
  d.bytes += bytes;
  _dirty.set(uuid, d);
}

async function flushUsage(uuid, force = false) {
  const d = _dirty.get(uuid);
  if (!d || d.bytes <= 0) return;
  const now = Date.now();
  if (!force && now - d.at < FLUSH_INTERVAL) return;
  d.at = now;
  const chunk = d.bytes;
  try {
    await dbRun('UPDATE users SET used_bytes = used_bytes + ? WHERE uuid = ?', [chunk, uuid]);
    d.bytes -= chunk;
  } catch (e) { /* retried on next flush */ }
}

function flushAllUsage() {
  return Promise.all([..._dirty.keys()].map(u => flushUsage(u, true)));
}

/* Soft concurrent-IP limit */
function ipAllowed(uuid, ip, limit) {
  if (!limit || limit <= 0) return true;
  let m = _ipMap.get(uuid);
  if (!m) { m = new Map(); _ipMap.set(uuid, m); }
  const now = Date.now();
  for (const [k, t] of m) if (now - t > IP_WINDOW) m.delete(k);
  m.set(ip, now);
  return m.size <= limit;
}

/* ------------------------------------------------------------------ */
/* User state checks shared by proxy + sub endpoints                    */
/* ------------------------------------------------------------------ */

function userState(user) {
  const now = Date.now();
  const quota = user.quota_bytes > 0 ? user.quota_bytes : null;
  const used = user.used_bytes || 0;
  const overQuota = quota !== null && used >= quota;
  const expired = !!user.expiry_at && now > user.expiry_at;
  const pending = !!user.start_on_first && !user.first_connect_at;
  return {
    ok: !!user.active && !overQuota && !expired,
    overQuota,
    expired,
    pending,
    expiryAt: user.expiry_at || null,
    quota,
    used,
    remainingBytes: quota === null ? null : Math.max(0, quota - used),
  };
}

/* Parse proxy path match (exact path, any query string) */
function pathMatches(urlPath, proxyPath) {
  return urlPath === proxyPath || urlPath === proxyPath + '/';
}

/* ------------------------------------------------------------------ */
/* PROXY CORE — VLESS & Trojan over WebSocket (original implementation)  */
/* Protocol references: public XTLS/VLESS spec & Trojan-Go spec.        */
/* ------------------------------------------------------------------ */

const VLESS_VER = 0x00;

/**
 * Parse a VLESS request header from the start of `buf`.
 * Layout: [ver(1)][uuid(16)][addonLen(1)][addon][cmd(1)][port(2)][atyp(1)][addr][payload]
 * Returns null when more bytes are needed; throws on invalid input.
 */
function parseVlessHeader(buf) {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (u8.length < 24) return null; // need at least ver+uuid+addonLen+cmd+port+atyp
  if (u8[0] !== VLESS_VER) throw new Error('bad-version');
  let i = 1;
  const uuidBytes = u8.subarray(i, i + 16); i += 16;
  const uuid = [...uuidBytes].map(b => b.toString(16).padStart(2, '0')).join('').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
  const addonLen = u8[i]; i += 1 + addonLen;
  if (u8.length < i + 4) return null;
  const cmd = u8[i]; i += 1;
  const port = (u8[i] << 8) | u8[i + 1]; i += 2;
  const atyp = u8[i]; i += 1;
  let host = '';
  if (atyp === 0x01) {           // IPv4
    if (u8.length < i + 4) return null;
    host = `${u8[i]}.${u8[i + 1]}.${u8[i + 2]}.${u8[i + 3]}`; i += 4;
  } else if (atyp === 0x02) {    // Domain
    if (u8.length < i + 1) return null;
    const len = u8[i]; i += 1;
    if (u8.length < i + len) return null;
    host = TD.decode(u8.subarray(i, i + len)); i += len;
  } else if (atyp === 0x03) {    // IPv6
    if (u8.length < i + 16) return null;
    const p = [];
    for (let j = 0; j < 16; j += 2) p.push(((u8[i + j] << 8) | u8[i + j + 1]).toString(16));
    host = p.join(':'); i += 16;
  } else {
    throw new Error('bad-atyp');
  }
  return { proto: 'vless', uuid, cmd, host, port, rest: u8.subarray(i) };
}

/* --- Trojan: 56-char hex SHA-224 of password, then SOCKS5-ish target --- */

/* Compact SHA-224 (FIPS 180-4) — original implementation for the panel. */
const SHA224_K = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
];

function sha224hex(bytes) {
  /* SHA-224 = SHA-256 core with distinct IV; output is the first 7 words */
  const H = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
  const ml = bytes.length;
  const withPad = new Uint8Array((((ml + 9) >> 6) + 1) << 6);
  withPad.set(bytes);
  withPad[ml] = 0x80;
  const dv = new DataView(withPad.buffer);
  dv.setUint32(withPad.length - 4, ml << 3);
  dv.setUint32(withPad.length - 8, Math.floor((ml * 8) / 0x100000000));
  const w = new Int32Array(64);
  const rr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < withPad.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getInt32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA224_K[i] + w[i]) | 0;
      const S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22);
      const mj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + mj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0;
  }
  return H.slice(0, 7).map(x => (x >>> 0).toString(16).padStart(8, '0')).join('');
}

async function trojanHashOf(uuidStr) {
  return sha224hex(TE.encode(uuidStr));
}

/**
 * Parse a Trojan request: "HEX(SHA224(pass))\r\n[cmd][atyp][addr][port]\r\n[payload]"
 * Returns null when more bytes are needed; throws on invalid input.
 */
function parseTrojanHeader(buf) {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  const nl = u8.indexOf(0x0d);
  if (nl < 0 || u8[nl + 1] !== 0x0a) return null;
  const hash = TD.decode(u8.subarray(0, nl)).toLowerCase();
  if (!/^[0-9a-f]{56}$/.test(hash)) throw new Error('bad-trojan-hash');
  let i = nl + 2;
  if (u8.length < i + 4) return null;
  const cmd = u8[i]; i += 1;
  if (cmd !== 0x01) throw new Error('bad-trojan-cmd');
  const atyp = u8[i]; i += 1;
  let host = '';
  if (atyp === 0x01) {
    if (u8.length < i + 4) return null;
    host = `${u8[i]}.${u8[i + 1]}.${u8[i + 2]}.${u8[i + 3]}`; i += 4;
  } else if (atyp === 0x03) {
    if (u8.length < i + 1) return null;
    const len = u8[i]; i += 1;
    if (u8.length < i + len) return null;
    host = TD.decode(u8.subarray(i, i + len)); i += len;
  } else if (atyp === 0x04) {
    if (u8.length < i + 16) return null;
    const p = [];
    for (let j = 0; j < 16; j += 2) p.push(((u8[i + j] << 8) | u8[i + j + 1]).toString(16));
    host = p.join(':'); i += 16;
  } else throw new Error('bad-trojan-atyp');
  const port = (u8[i] << 8) | u8[i + 1]; i += 2;
  if (u8[i] === 0x0d && u8[i + 1] === 0x0a) i += 2;
  return { proto: 'trojan', hash, cmd, host, port, rest: u8.subarray(i) };
}

/* --- VLESS UDP framing: [atyp][addr][port][len:2][data] per datagram --- */

function parseUdpDatagram(u8, offset = 0) {
  let i = offset;
  if (u8.length < i + 4) return null;
  const atyp = u8[i]; i += 1;
  let host = '';
  if (atyp === 0x01) {
    host = `${u8[i]}.${u8[i + 1]}.${u8[i + 2]}.${u8[i + 3]}`; i += 4;
  } else if (atyp === 0x02) {
    const len = u8[i]; i += 1;
    host = TD.decode(u8.subarray(i, i + len)); i += len;
  } else if (atyp === 0x03) {
    const p = [];
    for (let j = 0; j < 16; j += 2) p.push(((u8[i + j] << 8) | u8[i + j + 1]).toString(16));
    host = p.join(':'); i += 16;
  } else return null;
  const port = (u8[i] << 8) | u8[i + 1]; i += 2;
  if (u8.length < i + 2) return null;
  const dl = (u8[i] << 8) | u8[i + 1]; i += 2;
  if (u8.length < i + dl) return null;
  const data = u8.subarray(i, i + dl); i += dl;
  return { host, port, data, next: i };
}

function frameUdpDatagram(host, port, data) {
  const hb = TE.encode(host);
  const parts = [];
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    parts.push(new Uint8Array([0x01, ...host.split('.').map(Number)]));
  } else {
    parts.push(new Uint8Array([0x02, hb.length, ...hb]));
  }
  parts.push(new Uint8Array([(port >> 8) & 0xff, port & 0xff, (data.length >> 8) & 0xff, data.length & 0xff]));
  parts.push(data);
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/* DNS over UDP(53) relayed through DoH wireformat — keeps clients happy */
async function relayDns(datagram) {
  try {
    const resp = await fetch('https://1.1.1.1/dns-query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/dns-udpwireformat' },
      body: datagram.data,
    });
    if (!resp.ok) return null;
    const answer = new Uint8Array(await resp.arrayBuffer());
    if (!answer.length) return null;
    return frameUdpDatagram(datagram.host, datagram.port, answer);
  } catch (e) { return null; }
}

const BLOCKED_HOSTS = new Set([
  'speed.cloudflare.com', 'cp.cloudflare.com', 'dash.cloudflare.com',
  'www.cloudflare.com', 'api.cloudflare.com', 'developer.cloudflare.com',
]);

/* ------------------------------------------------------------------ */
/* WebSocket proxy entrypoint                                           */
/* ------------------------------------------------------------------ */

async function handleProxy(request, ctx) {
  const settings = await getSettings();
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();

  const handle = async () => {
    let headerParsed = false;
    let user = null;
    let uploadWriter = null;
    let target = null;
    let closed = false;
    let udpMode = false;
    let dnsHost = '';
    let dnsPort = 0;

    const closeAll = async () => {
      if (closed) return;
      closed = true;
      try { server.close(); } catch (e) {}
      try { if (uploadWriter) await uploadWriter.releaseLock(); } catch (e) {}
      try { if (target) await target.close(); } catch (e) {}
      if (user) ctx.waitUntil(flushUsage(user.uuid, true).catch(() => {}));
    };

    server.addEventListener('message', async (ev) => {
      try {
        let u8 = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data)
          : typeof ev.data === 'string' ? TE.encode(ev.data)
          : new Uint8Array(ev.data.buffer || ev.data);

        if (!headerParsed) {
          /* Detect protocol: VLESS starts with 0x00, Trojan with ASCII hex */
          let parsed = null;
          if (u8.length > 0 && u8[0] === VLESS_VER) {
            parsed = parseVlessHeader(u8);
          } else {
            parsed = parseTrojanHeader(u8);
          }
          if (parsed === null) return; // wait for more bytes
          headerParsed = true;

          /* ---- authenticate ---- */
          if (parsed.proto === 'vless') {
            user = await getUserByUuid(parsed.uuid);
          } else {
            const row = await dbGet('SELECT * FROM users WHERE trojan_hash = ?', [parsed.hash]);
            user = row || null;
          }
          if (!user) { closeAll(); return; }

          const st = userState(user);
          if (!st.ok) { closeAll(); return; }

          const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
          if (!ipAllowed(user.uuid, ip, user.ip_limit)) { closeAll(); return; }

          /* first-connect trigger: start countdown on first use, auto-reset window */
          if (user.start_on_first && !user.first_connect_at) {
            const exp = user.days > 0 ? Date.now() + user.days * 86400000 : null;
            try {
              await dbRun(
                'UPDATE users SET first_connect_at = ?, expiry_at = COALESCE(?, expiry_at) WHERE id = ? AND first_connect_at IS NULL',
                [Date.now(), exp, user.id]
              );
            } catch (e) {}
          }
          if (user.reset_hours > 0 && (!user.last_reset_at || (Date.now() - user.last_reset_at) > user.reset_hours * 3600000)) {
            try {
              await dbRun('UPDATE users SET used_bytes = 0, last_reset_at = ? WHERE id = ?', [Date.now(), user.id]);
              user.used_bytes = 0;
              cacheUser({ ...user });
            } catch (e) {}
          }

          /* ---- UDP ---- */
          if (parsed.cmd === 0x02) {
            udpMode = true;
            const dg = parseUdpDatagram(parsed.rest);
            if (dg && dg.port === 53) {
              dnsHost = dg.host; dnsPort = dg.port;
              const reply = await relayDns(dg);
              if (parsed.proto === 'vless' && reply) {
                const r = new Uint8Array(reply.length + 2);
                r[0] = 0; r[1] = 0; r.set(reply, 2);
                server.send(r);
              } else if (reply) {
                server.send(reply);
              }
            }
            return;
          }
          if (parsed.cmd !== 0x01) { closeAll(); return; }

          /* ---- TCP ---- */
          if (BLOCKED_HOSTS.has(parsed.host.toLowerCase())) { closeAll(); return; }
          try {
            target = connect({ hostname: parsed.host, port: parsed.port });
            uploadWriter = target.writable.getWriter();
          } catch (e) { closeAll(); return; }

          if (parsed.proto === 'vless') server.send(new Uint8Array([0, 0])); // response header

          /* pump target -> client */
          (async () => {
            const reader = target.readable.getReader();
            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                if (!value || closed) break;
                addUsage(user.uuid, value.length);
                server.send(value);
              }
            } catch (e) {}
            closeAll();
          })();

          if (parsed.rest && parsed.rest.length) {
            addUsage(user.uuid, parsed.rest.length);
            await uploadWriter.write(parsed.rest);
          }
          return;
        }

        /* ---- subsequent payloads ---- */
        if (closed) return;
        if (udpMode) {
          let off = 0;
          while (off < u8.length) {
            const dg = parseUdpDatagram(u8, off);
            if (!dg) break;
            off = dg.next;
            if (dg.port === 53) {
              const reply = await relayDns(dg);
              if (reply) server.send(reply);
            }
          }
          return;
        }
        if (uploadWriter) {
          addUsage(user.uuid, u8.length);
          await uploadWriter.write(u8);
        }
      } catch (e) {
        closeAll();
      }
    });

    server.addEventListener('close', () => { closed = true; closeAll(); });
    server.addEventListener('error', () => { closed = true; closeAll(); });
  };

  ctx.waitUntil(handle());
  return new Response(null, { status: 101, webSocket: client });
}

/* ------------------------------------------------------------------ */
/* ADMIN AUTH — session cookies (HMAC), lockout, first-run setup        */
/* ------------------------------------------------------------------ */

const SESSION_COOKIE = 'jn_session';
const SESSION_TTL = 12 * 3600 * 1000;
const MAX_FAILS = 5;
const BAN_MS = 15 * 60 * 1000;

async function getAdminCreds() {
  /* Priority: env ADMIN_PASS_HASH (set by deployer) → settings row (setup flow) */
  const envHash = typeof ADMIN_PASS_HASH !== 'undefined' ? ADMIN_PASS_HASH : null;
  if (envHash) return { source: 'env', salt: envHash.split('$')[0], hash: envHash.split('$')[1] };
  const row = await dbGet('SELECT value FROM settings WHERE key = ?', ['admin_hash']);
  if (row) {
    const [salt, hash] = row.value.split('$');
    return { source: 'db', salt, hash };
  }
  return null;
}

async function verifyAdminPassword(password) {
  const creds = await getAdminCreds();
  if (!creds) return { ok: false, noCreds: true };
  const calc = await sha256hex(creds.salt + ':' + password);
  return { ok: safeEqual(calc, creds.hash) };
}

async function getSessionSecret() {
  if (SESSION_SECRET) return SESSION_SECRET;
  let row = await dbGet('SELECT value FROM settings WHERE key = ?', ['session_secret']);
  if (!row) {
    const s = rndHex(32);
    await dbRun('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', ['session_secret', s]);
    return s;
  }
  return row.value;
}

async function makeSession() {
  const exp = Date.now() + SESSION_TTL;
  const secret = await getSessionSecret();
  const sig = await hmacSign(secret, String(exp));
  return `${exp}.${sig}`;
}

async function checkSession(request) {
  const cookies = (request.headers.get('Cookie') || '').split(/;\s*/);
  const raw = cookies.map(c => c.split('=')).find(p => p[0] === SESSION_COOKIE);
  if (!raw) return false;
  const [exp, sig] = decodeURIComponent(raw.slice(1).join('=')).split('.');
  if (!exp || !sig) return false;
  if (Date.now() > Number(exp)) return false;
  const secret = await getSessionSecret();
  return safeEqual(await hmacSign(secret, exp), sig);
}

/* NOTE: returns the cookie VALUE STRING (used as the Set-Cookie header value) */
function sessionCookieHeader(value, maxAge = SESSION_TTL / 1000) {
  return `${SESSION_COOKIE}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Strict; Secure`;
}

function clearSessionHeader() {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Secure`;
}

async function loginBanned(ip) {
  const row = await dbGet('SELECT * FROM login_attempts WHERE ip = ?', [ip]);
  return !!(row && row.banned_until && Date.now() < row.banned_until);
}

async function recordFail(ip) {
  const row = await dbGet('SELECT * FROM login_attempts WHERE ip = ?', [ip]);
  const fails = (row ? row.fails : 0) + 1;
  const bannedUntil = fails >= MAX_FAILS ? Date.now() + BAN_MS : null;
  await dbRun(
    'INSERT INTO login_attempts (ip, fails, banned_until) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET fails = excluded.fails, banned_until = excluded.banned_until',
    [ip, fails, bannedUntil]
  );
  return { fails, banned: !!bannedUntil, remaining: Math.max(0, MAX_FAILS - fails) };
}

async function clearFails(ip) {
  await dbRun('DELETE FROM login_attempts WHERE ip = ?', [ip]);
}

/* ------------------------------------------------------------------ */
/* ADMIN JSON API                                                       */
/* ------------------------------------------------------------------ */

function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

function userPublic(user, requestHost, settings) {
  const st = userState(user);
  return {
    id: user.id,
    name: user.name,
    uuid: user.uuid,
    sub_token: user.sub_token,
    quota_bytes: user.quota_bytes,
    used_bytes: user.used_bytes,
    reset_hours: user.reset_hours,
    days: user.days,
    expiry_at: user.expiry_at,
    start_on_first: !!user.start_on_first,
    first_connect_at: user.first_connect_at,
    ip_limit: user.ip_limit,
    active: !!user.active,
    note: user.note,
    created_at: user.created_at,
    state: st,
    sub_url: `https://${requestHost}/sub/${user.sub_token}`,
  };
}

async function handleAdminApi(request, url, ctx) {
  const path = url.pathname;
  const method = request.method;
  const ip = clientIp(request);

  /* ---------- public endpoints ---------- */
  if (path === '/api/setup' && method === 'POST') {
    const creds = await getAdminCreds();
    if (creds && creds.source === 'env') return jsonResponse({ error: 'رمز از قبل توسط دیپلویر تنظیم شده' }, 400);
    if (creds) return jsonResponse({ error: 'رمز مدیریت قبلاً تنظیم شده است' }, 400);
    const body = await request.json().catch(() => ({}));
    const pass = String(body.password || '');
    if (pass.length < 8) return jsonResponse({ error: 'رمز باید حداقل ۸ کاراکتر باشد' }, 400);
    const salt = rndHex(8);
    const hash = await sha256hex(salt + ':' + pass);
    await dbRun('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', ['admin_hash', `${salt}$${hash}`]);
    return jsonResponse({ ok: true });
  }

  if (path === '/api/login' && method === 'POST') {
    if (await loginBanned(ip)) return jsonResponse({ error: 'تلاش زیاد؛ ۱۵ دقیقه صبر کنید' }, 429);
    const creds = await getAdminCreds();
    const body = await request.json().catch(() => ({}));
    const v = await verifyAdminPassword(String(body.password || ''));
    if (!v.ok) {
      if (v.noCreds) return jsonResponse({ error: 'نصب نشده', setup: true }, 400);
      const r = await recordFail(ip);
      return jsonResponse({ error: `رمز اشتباه است (${r.remaining} تلاش باقی مانده)` }, 401);
    }
    await clearFails(ip);
    const token = await makeSession();
    return jsonResponse({ ok: true }, 200, { 'Set-Cookie': sessionCookieHeader(token) });
  }

  if (path === '/api/logout' && method === 'POST') {
    return jsonResponse({ ok: true }, 200, { 'Set-Cookie': clearSessionHeader() });
  }

  /* ---------- authenticated endpoints ---------- */
  if (!(await checkSession(request))) return jsonResponse({ error: 'unauthorized' }, 401);
  const isMutation = method !== 'GET' && method !== 'HEAD';
  if (isMutation && request.headers.get('X-JN') !== '1') return jsonResponse({ error: 'csrf' }, 403);

  if (path === '/api/me' && method === 'GET') {
    return jsonResponse({ ok: true, version: VERSION, brand: BRAND });
  }

  if (path === '/api/stats' && method === 'GET') {
    const [t] = await dbAll(
      'SELECT COUNT(*) AS total, SUM(active) AS active, SUM(used_bytes) AS used, SUM(quota_bytes) AS quota FROM users'
    );
    const soon = await dbAll(
      'SELECT COUNT(*) AS n FROM users WHERE expiry_at IS NOT NULL AND expiry_at > ? AND expiry_at < ?',
      [Date.now(), Date.now() + 7 * 86400000]
    );
    return jsonResponse({
      users: { total: t?.total || 0, active: t?.active || 0 },
      traffic: { used: t?.used || 0, quota: t?.quota || 0 },
      expiring_soon: soon[0]?.n || 0,
      version: VERSION,
    });
  }

  if (path === '/api/users' && method === 'GET') {
    const settings = await getSettings();
    const q = (url.searchParams.get('q') || '').trim().toLowerCase();
    let rows = await dbAll('SELECT * FROM users ORDER BY created_at DESC');
    if (q) rows = rows.filter(u => (u.name || '').toLowerCase().includes(q) || u.uuid.includes(q));
    return jsonResponse({ users: rows.map(u => userPublic(u, url.host, settings)) });
  }

  if (path === '/api/users' && method === 'POST') {
    const b = await request.json().catch(() => ({}));
    const name = String(b.name || '').trim().slice(0, 60);
    if (!name) return jsonResponse({ error: 'نام الزامی است' }, 400);
    const quotaGb = Math.max(0, Number(b.quota_gb) || 0);
    const days = Math.max(0, Number(b.days) || 0);
    const ipLimit = Math.min(10, Math.max(0, Number(b.ip_limit) || 0));
    const resetHours = Math.max(0, Number(b.reset_hours) || 0);
    const startOnFirst = !!b.start_on_first;
    const uuid = isUuid(b.uuid) ? b.uuid : crypto.randomUUID();
    const id = rndHex(8);
    const subToken = rndHex(16);
    const expiryAt = startOnFirst || days === 0 ? null : Date.now() + days * 86400000;
    await dbRun(
      `INSERT INTO users (id, uuid, trojan_hash, name, sub_token, quota_bytes, used_bytes, reset_hours, days, expiry_at, start_on_first, ip_limit, active, note, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, 1, ?, ?)`,
      [id, uuid, sha224hex(TE.encode(uuid)), name, subToken, quotaGb * 1073741824, resetHours, days, expiryAt, startOnFirst ? 1 : 0, ipLimit, String(b.note || '').slice(0, 200), Date.now()]
    );
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [id]);
    return jsonResponse({ ok: true, user: userPublic(user, url.host, await getSettings()) });
  }

  const userMatch = path.match(/^\/api\/users\/([0-9a-f]+)$/);
  if (userMatch) {
    const uid = userMatch[1];
    if (method === 'PATCH') {
      const b = await request.json().catch(() => ({}));
      const user = await dbGet('SELECT * FROM users WHERE id = ?', [uid]);
      if (!user) return jsonResponse({ error: 'کاربر پیدا نشد' }, 404);
      const sets = [];
      const vals = [];
      if ('name' in b) { sets.push('name = ?'); vals.push(String(b.name).slice(0, 60)); }
      if ('note' in b) { sets.push('note = ?'); vals.push(String(b.note).slice(0, 200)); }
      if ('active' in b) { sets.push('active = ?'); vals.push(b.active ? 1 : 0); }
      if ('quota_gb' in b) { sets.push('quota_bytes = ?'); vals.push(Math.max(0, Number(b.quota_gb) || 0) * 1073741824); }
      if ('ip_limit' in b) { sets.push('ip_limit = ?'); vals.push(Math.min(10, Math.max(0, Number(b.ip_limit) || 0))); }
      if ('reset_hours' in b) { sets.push('reset_hours = ?'); vals.push(Math.max(0, Number(b.reset_hours) || 0)); }
      if ('days' in b) {
        const days = Math.max(0, Number(b.days) || 0);
        sets.push('days = ?'); vals.push(days);
        if (days > 0 && !b.start_on_first) { sets.push('expiry_at = ?'); vals.push(Date.now() + days * 86400000); }
        if (days === 0) { sets.push('expiry_at = ?'); vals.push(null); }
      }
      if ('start_on_first' in b) { sets.push('start_on_first = ?'); vals.push(b.start_on_first ? 1 : 0); }
      if ('extend_days' in b && Number(b.extend_days) > 0) {
        const cur = user.expiry_at && user.expiry_at > Date.now() ? user.expiry_at : Date.now();
        sets.push('expiry_at = ?'); vals.push(cur + Number(b.extend_days) * 86400000);
      }
      if (!sets.length) return jsonResponse({ error: 'چیزی برای تغییر نیست' }, 400);
      vals.push(uid);
      await dbRun(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`, vals);
      _userCache.delete(user.uuid);
      const updated = await dbGet('SELECT * FROM users WHERE id = ?', [uid]);
      return jsonResponse({ ok: true, user: userPublic(updated, url.host, await getSettings()) });
    }

    if (method === 'DELETE') {
      const user = await dbGet('SELECT * FROM users WHERE id = ?', [uid]);
      if (!user) return jsonResponse({ error: 'کاربر پیدا نشد' }, 404);
      await dbRun('DELETE FROM users WHERE id = ?', [uid]);
      _userCache.delete(user.uuid);
      return jsonResponse({ ok: true });
    }
  }

  const resetMatch = path.match(/^\/api\/users\/([0-9a-f]+)\/reset$/);
  if (resetMatch && method === 'POST') {
    const uid = resetMatch[1];
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [uid]);
    if (!user) return jsonResponse({ error: 'کاربر پیدا نشد' }, 404);
    const b = await request.json().catch(() => ({}));
    if (b.traffic) await dbRun('UPDATE users SET used_bytes = 0, last_reset_at = ? WHERE id = ?', [Date.now(), uid]);
    if (b.expiry) {
      const exp = user.days > 0 ? Date.now() + user.days * 86400000 : null;
      await dbRun('UPDATE users SET expiry_at = ?, first_connect_at = NULL WHERE id = ?', [exp, uid]);
    }
    _userCache.delete(user.uuid);
    const updated = await dbGet('SELECT * FROM users WHERE id = ?', [uid]);
    return jsonResponse({ ok: true, user: userPublic(updated, url.host, await getSettings()) });
  }

  if (path === '/api/bulk' && method === 'POST') {
    const b = await request.json().catch(() => ({}));
    const ids = Array.isArray(b.ids) ? b.ids.filter(x => /^[0-9a-f]+$/.test(x)) : [];
    if (!ids.length) return jsonResponse({ error: 'شناسه نامعتبر' }, 400);
    const ph = ids.map(() => '?').join(',');
    if (b.action === 'activate') await dbRun(`UPDATE users SET active = 1 WHERE id IN (${ph})`, ids);
    else if (b.action === 'deactivate') await dbRun(`UPDATE users SET active = 0 WHERE id IN (${ph})`, ids);
    else if (b.action === 'delete') await dbRun(`DELETE FROM users WHERE id IN (${ph})`, ids);
    else if (b.action === 'reset_traffic') await dbRun(`UPDATE users SET used_bytes = 0, last_reset_at = ? WHERE id IN (${ph})`, [Date.now(), ...ids]);
    else return jsonResponse({ error: 'عملیات نامعتبر' }, 400);
    return jsonResponse({ ok: true });
  }

  if (path === '/api/settings' && method === 'GET') {
    const s = await getSettings(true);
    return jsonResponse({ settings: { ...s, locations: resolveLocations(s, url.host) } });
  }

  if (path === '/api/settings' && method === 'PUT') {
    const b = await request.json().catch(() => ({}));
    try {
      const s = await saveSettings(b);
      return jsonResponse({ ok: true, settings: { ...s, locations: resolveLocations(s, url.host) } });
    } catch (e) {
      return jsonResponse({ error: e.message || 'خطای ذخیره' }, 400);
    }
  }

  if (path === '/api/backup' && method === 'GET') {
    const users = await dbAll('SELECT * FROM users');
    const settingsRows = await dbAll("SELECT key, value FROM settings WHERE key NOT IN ('admin_hash', 'session_secret')");
    return jsonResponse({
      app: 'javidnam', version: VERSION, exported_at: new Date().toISOString(),
      users: users.map(u => ({ ...u, trojan_hash: undefined })),
      settings: Object.fromEntries(settingsRows.map(r => { try { return [r.key, JSON.parse(r.value)]; } catch (e) { return [r.key, r.value]; } })),
    });
  }

  if (path === '/api/restore' && method === 'POST') {
    const b = await request.json().catch(() => ({}));
    if (b.app !== 'javidnam' || !Array.isArray(b.users)) return jsonResponse({ error: 'فایل پشتیبان نامعتبر است' }, 400);
    let n = 0;
    for (const u of b.users) {
      if (!isUuid(u.uuid)) continue;
      await dbRun(
        `INSERT INTO users (id, uuid, trojan_hash, name, sub_token, quota_bytes, used_bytes, reset_hours, days, expiry_at, start_on_first, first_connect_at, ip_limit, active, note, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(uuid) DO UPDATE SET used_bytes = excluded.used_bytes, active = excluded.active`,
        [
          u.id || rndHex(8), u.uuid, sha224hex(TE.encode(u.uuid)), u.name || 'بدون نام', u.sub_token || rndHex(16),
          u.quota_bytes || 0, u.used_bytes || 0, u.reset_hours || 0, u.days || 0, u.expiry_at || null,
          u.start_on_first ? 1 : 0, u.first_connect_at || null, u.ip_limit || 0, u.active === 0 ? 0 : 1,
          u.note || '', u.created_at || Date.now(),
        ]
      );
      n++;
    }
    return jsonResponse({ ok: true, restored: n });
  }

  return jsonResponse({ error: 'not-found' }, 404);
}

/* ------------------------------------------------------------------ */
/* SUBSCRIPTION — config links, ISP presets, sub page data              */
/* ------------------------------------------------------------------ */

const ISP_PRESETS = [
  { id: 'all',      label: 'همه',            fp: 'chrome',  frag: null,          mux: false, note: 'حالت پیش‌فرض و پیشنهادی برای شروع' },
  { id: 'mci',      label: 'همراه اول',       fp: 'chrome',  frag: [10, 20, 10, 20], mux: false, note: 'fragment فعال؛ برای قطعی‌های شدید MCI' },
  { id: 'irancell', label: 'ایرانسل',         fp: 'safari',  frag: [40, 50, 10, 20], mux: false, note: 'fragment با بازه بلندتر؛ مناسب اینترنت‌های ضعیف' },
  { id: 'rightel',  label: 'رایتل',           fp: 'chrome',  frag: [10, 30, 10, 20], mux: false, note: 'حالت متعادل' },
  { id: 'tci',      label: 'تلکام (خانگی)',   fp: 'chrome',  frag: [5, 10, 5, 10],   mux: false, note: 'fragment ریز برای خطوط ثابت' },
  { id: 'gaming',   label: 'گیمینگ',          fp: 'chrome',  frag: null,          mux: false, note: 'کم‌ترین تأخیر؛ fragment خاموش' },
];

const CLIENT_UA_HINTS = [
  'v2ray', 'hiddify', 'sing-box', 'singbox', 'clash', 'shadowrocket', 'streisand',
  'loon', 'stash', 'surge', 'sfa', 'karing', 'husi', 'v2box', 'napsternetv', 'shadowsocks',
];

function buildConfigLinks(user, locations, proxyPath, panelHost) {
  const links = [];
  for (const loc of locations) {
    const tag = encodeURIComponent(`${BRAND.en} | ${loc.name}`);
    const vp = new URLSearchParams({
      encryption: 'none',
      security: loc.tls ? 'tls' : 'none',
      type: 'ws',
      host: panelHost,
      path: `${proxyPath}?ed=2048`,
    });
    if (loc.tls) { vp.set('sni', loc.host); vp.set('fp', 'chrome'); }
    links.push({
      name: loc.name,
      proto: 'vless',
      link: `vless://${user.uuid}@${loc.host}:${loc.port}?${vp.toString()}#${tag}`,
    });
    const tp = new URLSearchParams({
      security: loc.tls ? 'tls' : 'none',
      type: 'ws',
      host: panelHost,
      path: `${proxyPath}?ed=2048`,
    });
    if (loc.tls) tp.set('sni', loc.host);
    links.push({
      name: loc.name,
      proto: 'trojan',
      link: `trojan://${user.uuid}@${loc.host}:${loc.port}?${tp.toString()}#${encodeURIComponent(`${BRAND.en} TRJ | ${loc.name}`)}`,
    });
  }
  return links;
}

/* Apply an ISP preset to a link (client-side tunables) */
function applyPresetToLink(link, preset) {
  try {
    const u = new URL(link);
    u.searchParams.set('fp', preset.fp);
    if (preset.frag) {
      u.searchParams.set('frag', `${preset.frag[0]}-${preset.frag[1]}-${preset.frag[2]}-${preset.frag[3]}`);
    } else {
      u.searchParams.delete('frag');
    }
    return u.toString();
  } catch (e) { return link; }
}

async function handleSub(request, url, ctx) {
  const m = url.pathname.match(/^\/sub\/([0-9a-f]{8,64})$/);
  if (!m) return notFound();
  const token = m[1];
  const user = await dbGet('SELECT * FROM users WHERE sub_token = ?', [token]);
  if (!user) return new Response('<h1 dir="rtl">اشتراک یافت نشد</h1>', { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' } });

  const settings = await getSettings();
  const locations = resolveLocations(settings, url.host);
  const links = buildConfigLinks(user, locations, settings.proxy_path, url.host);
  const state = userState(user);
  const subUrl = `https://${url.host}/sub/${token}`;

  const fmt = url.searchParams.get('format') || url.searchParams.get('fmt');
  const ua = (request.headers.get('User-Agent') || '').toLowerCase();
  const isClient = CLIENT_UA_HINTS.some(h => ua.includes(h));

  if (url.searchParams.get('json') === '1') {
    return jsonResponse({
      name: user.name, state, sub_url: subUrl, version: VERSION,
      updated_at: Date.now(),
    });
  }

  if (fmt === 'b64' || fmt === 'base64') {
    return new Response(b64encode(links.map(l => l.link).join('\n')), {
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Profile-Update-Interval': '6', 'Subscription-Userinfo': subInfoHeader(state) },
    });
  }

  if (isClient || fmt === 'raw' || fmt === 'txt') {
    return new Response(links.map(l => l.link).join('\n'), {
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Profile-Update-Interval': '6', 'Subscription-Userinfo': subInfoHeader(state) },
    });
  }

  /* Pretty HTML page (humans) */
  const data = {
    brand: BRAND,
    version: VERSION,
    name: user.name,
    state,
    sub_url: subUrl,
    links,
    presets: ISP_PRESETS,
    welcome: settings.welcome || '',
    contact: settings.contact || '',
    proxy_path: settings.proxy_path,
    show_branding: !!settings.sub_branding,
  };
  const html = renderSubPage(data);
  return htmlResponse(html, 200, { 'Cache-Control': 'no-store' });
}

function subInfoHeader(state) {
  const parts = [];
  if (state.quota !== null) parts.push(`upload=0; download=${state.used}; total=${state.quota}`);
  else parts.push(`upload=0; download=${state.used}; total=0`);
  if (state.expiryAt) parts.push(`expire=${Math.floor(state.expiryAt / 1000)}`);
  return parts.join('; ');
}

/* Render the sub page: template + runtime data injection (template comes
   from assets/sub.html at build time as SUB_PAGE_TEMPLATE) */
function renderSubPage(data) {
  const payload = JSON.stringify(data).replace(/</g, '\\u003c');
  return SUB_PAGE_TEMPLATE
    .replace('__SUB_DATA_JSON__', payload)
    .replace('__TITLE__', escapeHtml(data.brand.fa + ' | اشتراک ' + data.name));
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ------------------------------------------------------------------ */
/* ROUTER — main fetch handler + PWA assets                             */
/* ------------------------------------------------------------------ */

const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
<stop offset="0" stop-color="#f43f5e"/><stop offset="1" stop-color="#881337"/></linearGradient>
<radialGradient id="c" cx="0.5" cy="0.35" r="0.5">
<stop offset="0" stop-color="#fbbf24"/><stop offset="1" stop-color="#f43f5e" stop-opacity="0"/></radialGradient></defs>
<rect width="64" height="64" rx="14" fill="#0a0a10"/>
<path d="M32 10c-1.8 5-6 7.2-6 12.6 0 3.4 1.9 6.3 4.2 8.4C29.6 39 27.4 44.6 22 50c7-1.6 11.2-5 13.4-9.6 2.2 4.6 6.4 8 13.4 9.6-5.4-5.4-7.6-11-8.2-19 2.3-2.1 4.2-5 4.2-8.4C44.8 17.2 40.6 15 38.8 10c-1.6 3.4-4.2 5-6.8 5s-5.2-1.6-6.8-5z" fill="url(#g)"/>
<ellipse cx="32" cy="24" rx="3.6" ry="6.5" fill="url(#c)" opacity="0.9"/>
</svg>`;

const MANIFEST_JSON = JSON.stringify({
  name: 'JavidNam | جاویدنام',
  short_name: 'JavidNam',
  description: 'پنل اشتراک جاویدنام — به یاد ۱۸ و ۱۹ دی ۱۴۰۴',
  start_url: '/',
  display: 'standalone',
  background_color: '#0a0a10',
  theme_color: '#0a0a10',
  icons: [
    { src: '/favicon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' },
  ],
});

const SW_JS = `const C='javidnam-v${'%VERSION%'}';
self.addEventListener('install',e=>{self.skipWaiting()});
self.addEventListener('activate',e=>{e.waitUntil(clients.claim())});
self.addEventListener('fetch',e=>{e.respondWith(
  fetch(e.request).then(r=>{const cp=r.clone();caches.open(C).then(c=>c.put(e.request,cp)).catch(()=>{});return r;})
  .catch(()=>caches.match(e.request))
)});`;

export default {
  async fetch(request, env, ctx) {
    initEnv(env);
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      /* --- WebSocket proxy (VLESS/Trojan) --- */
      if (request.headers.get('Upgrade') === 'websocket') {
        const settings = await getSettings();
        if (pathMatches(path, settings.proxy_path)) {
          return await handleProxy(request, ctx);
        }
        return notFound();
      }

      /* --- health & robots --- */
      if (path === '/healthz') return jsonResponse({ ok: true, app: 'javidnam', version: VERSION });
      if (path === '/robots.txt') return new Response('User-agent: *\nDisallow: /\n', { headers: { 'Content-Type': 'text/plain' } });
      if (path === '/favicon.svg') return new Response(FAVICON_SVG, { headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' } });
      if (path === '/manifest.webmanifest') return new Response(MANIFEST_JSON, { headers: { 'Content-Type': 'application/manifest+json' } });
      if (path === '/sw.js') return new Response(SW_JS.replace('%VERSION%', VERSION), { headers: { 'Content-Type': 'application/javascript', 'Cache-Control': 'public, max-age=3600' } });

      /* --- subscription --- */
      if (path.startsWith('/sub/')) return await handleSub(request, url, ctx);
      if (/^\/status\/[0-9a-f]+$/.test(path)) {
        return Response.redirect(url.origin + '/sub/' + path.split('/')[2], 302);
      }

      /* --- admin --- */
      if (path.startsWith('/api/')) return await handleAdminApi(request, url, ctx);
      if (path === '/' || path === '/index.html' || path === '/panel') {
        return htmlResponse(renderAdminPage(url.origin), 200, { 'Cache-Control': 'no-store' });
      }

      return notFound();
    } catch (e) {
      return jsonResponse({ error: 'internal', message: String(e && e.message || e) }, 500);
    }
  },
};

/* Render admin SPA shell (template from assets/admin.html at build time) */
function renderAdminPage(origin) {
  return ADMIN_PAGE_TEMPLATE.replace('__ORIGIN__', origin);
}

/* periodic safety: flush traffic counters on isolate eviction */
addEventListener('waituntilflush', () => {});


/* ---------- embedded assets ---------- */

const ADMIN_PAGE_TEMPLATE = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="robots" content="noindex">
<meta name="theme-color" content="#07070c">
<title>جاویدنام | پنل مدیریت</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>
:root{
  --bg:#07070c; --bg2:#0c0c14; --card:#11111c; --card2:#161622;
  --line:rgba(255,255,255,.07); --line2:rgba(255,255,255,.12);
  --txt:#f2f2f7; --mut:#8e8ea3; --mut2:#5d5d72;
  --red:#f43f5e; --red2:#e11d48; --dark:#881337;
  --amber:#fbbf24; --green:#34d399; --blue:#60a5fa;
  --r:16px; --sh:0 8px 32px rgba(0,0,0,.45);
}
*{box-sizing:border-box;margin:0;padding:0}
html{scrollbar-color:#2a2a3a transparent}
body{
  background:var(--bg); color:var(--txt);
  font-family:Vazirmatn,-apple-system,"Segoe UI",Tahoma,"Iranian Sans",sans-serif;
  font-size:15px; line-height:1.7; min-height:100vh;
  background-image:radial-gradient(ellipse 80% 50% at 50% -10%,rgba(244,63,94,.08),transparent);
}
::selection{background:rgba(244,63,94,.35)}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-thumb{background:#26263a;border-radius:9px}
::-webkit-scrollbar-track{background:transparent}
a{color:var(--red);text-decoration:none}
button{font-family:inherit}
input,select,textarea{font-family:inherit}
.hidden{display:none!important}

/* ---------- login ---------- */
#login{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.login-card{width:100%;max-width:400px;background:var(--card);border:1px solid var(--line);
  border-radius:var(--r);padding:36px 30px;box-shadow:var(--sh);text-align:center;position:relative;overflow:hidden}
.login-card::before{content:"";position:absolute;inset:0 0 auto 0;height:3px;
  background:linear-gradient(90deg,transparent,var(--red),var(--amber),var(--red),transparent)}
.brand-mark{width:74px;height:74px;margin:0 auto 14px;display:block}
.login-card h1{font-size:22px;font-weight:800;margin-bottom:4px}
.login-card .mem{font-size:12px;color:var(--mut);margin-bottom:24px}
.field{position:relative;margin-bottom:14px;text-align:right}
.field input{width:100%;background:var(--bg2);border:1px solid var(--line2);border-radius:12px;
  padding:13px 16px;color:var(--txt);font-size:15px;outline:none;transition:.2s}
.field input:focus{border-color:var(--red);box-shadow:0 0 0 3px rgba(244,63,94,.15)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:none;cursor:pointer;
  border-radius:12px;padding:12px 22px;font-size:15px;font-weight:700;transition:.2s}
.btn-main{width:100%;background:linear-gradient(135deg,var(--red2),var(--dark));color:#fff}
.btn-main:hover{filter:brightness(1.15);transform:translateY(-1px)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.login-err{color:var(--red);font-size:13px;min-height:22px;margin-bottom:8px}
.setup-note{background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.25);color:var(--amber);
  border-radius:12px;padding:10px 14px;font-size:13px;margin-bottom:14px;text-align:right}

/* ---------- app layout ---------- */
#app{display:none;min-height:100vh}
.layout{display:flex;min-height:100vh}
aside{width:230px;background:var(--bg2);border-left:1px solid var(--line);
  padding:22px 14px;position:sticky;top:0;height:100vh;display:flex;flex-direction:column;flex-shrink:0}
.side-brand{display:flex;align-items:center;gap:10px;padding:0 8px 18px;border-bottom:1px solid var(--line);margin-bottom:14px}
.side-brand img{width:40px;height:40px}
.side-brand b{font-size:17px}
.side-brand small{display:block;font-size:10.5px;color:var(--mut);font-weight:400}
nav{display:flex;flex-direction:column;gap:4px;flex:1}
nav button{display:flex;align-items:center;gap:10px;background:none;border:none;color:var(--mut);
  padding:11px 14px;border-radius:12px;cursor:pointer;font-size:14.5px;font-weight:600;transition:.15s;text-align:right;width:100%}
nav button:hover{background:rgba(255,255,255,.04);color:var(--txt)}
nav button.active{background:linear-gradient(135deg,rgba(225,29,72,.18),rgba(136,19,55,.12));color:#ff8095;
  box-shadow:inset 0 0 0 1px rgba(244,63,94,.25)}
.side-foot{border-top:1px solid var(--line);padding-top:12px;font-size:11px;color:var(--mut2);text-align:center;line-height:1.9}
main{flex:1;padding:26px;max-width:1060px;margin:0 auto;width:100%}
.pagehead{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:22px;flex-wrap:wrap}
.pagehead h2{font-size:20px;font-weight:800}
.pagehead .sub{font-size:12.5px;color:var(--mut);margin-top:2px}

/* ---------- cards & stats ---------- */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:24px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:18px 20px;position:relative;overflow:hidden}
.stat::after{content:"";position:absolute;inset:auto 0 0 0;height:2px;background:linear-gradient(90deg,transparent,rgba(244,63,94,.5),transparent)}
.stat .k{font-size:12.5px;color:var(--mut);margin-bottom:6px}
.stat .v{font-size:26px;font-weight:800;font-variant-numeric:tabular-nums}
.stat .v small{font-size:13px;color:var(--mut);font-weight:400}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);padding:20px}

/* ---------- toolbar & table ---------- */
.toolbar{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.toolbar input[type=search]{flex:1;min-width:180px;background:var(--bg2);border:1px solid var(--line2);
  border-radius:12px;padding:11px 16px;color:var(--txt);outline:none}
.toolbar input[type=search]:focus{border-color:var(--red)}
.btn-ghost{background:var(--card2);border:1px solid var(--line2);color:var(--txt)}
.btn-ghost:hover{border-color:var(--red);color:#ff8095}
.btn-danger{background:rgba(225,29,72,.12);border:1px solid rgba(244,63,94,.35);color:#ff8095}
.btn-danger:hover{background:rgba(225,29,72,.22)}
.btn-sm{padding:8px 14px;font-size:13px;border-radius:10px}
.tblwrap{overflow-x:auto;border:1px solid var(--line);border-radius:var(--r);background:var(--card)}
table{width:100%;border-collapse:collapse;min-width:820px}
th{font-size:12px;color:var(--mut);font-weight:600;text-align:right;padding:13px 14px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:12px 14px;border-bottom:1px solid rgba(255,255,255,.04);font-size:13.5px;vertical-align:middle}
tr:last-child td{border-bottom:none}
tbody tr{transition:.12s}
tbody tr:hover{background:rgba(255,255,255,.025)}
.chip{display:inline-flex;align-items:center;gap:6px;padding:3px 11px;border-radius:99px;font-size:11.5px;font-weight:700;white-space:nowrap}
.chip-ok{background:rgba(52,211,153,.12);color:var(--green)}
.chip-off{background:rgba(255,255,255,.07);color:var(--mut)}
.chip-exp{background:rgba(251,191,36,.12);color:var(--amber)}
.chip-dead{background:rgba(244,63,94,.13);color:var(--red)}
.ubar{width:110px;height:6px;border-radius:99px;background:rgba(255,255,255,.08);overflow:hidden}
.ubar i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--red2),var(--amber))}
.rowact{display:flex;gap:6px;flex-wrap:wrap}
.iconb{width:32px;height:32px;display:inline-flex;align-items:center;justify-content:center;border-radius:9px;
  background:var(--card2);border:1px solid var(--line2);color:var(--mut);cursor:pointer;transition:.15s;font-size:14px}
.iconb:hover{color:#ff8095;border-color:var(--red)}
.bulkbar{display:flex;gap:8px;align-items:center;margin-top:12px;flex-wrap:wrap;font-size:13px;color:var(--mut)}

/* ---------- forms & modal ---------- */
.modal-bg{position:fixed;inset:0;background:rgba(3,3,8,.75);backdrop-filter:blur(6px);z-index:50;
  display:flex;align-items:center;justify-content:center;padding:18px}
.modal{width:100%;max-width:520px;max-height:92vh;overflow-y:auto;background:var(--card);
  border:1px solid var(--line2);border-radius:18px;padding:26px;box-shadow:var(--sh)}
.modal h3{font-size:17px;margin-bottom:18px;display:flex;align-items:center;justify-content:space-between}
.modal .x{background:none;border:none;color:var(--mut);font-size:20px;cursor:pointer}
.fgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.fgrid .full{grid-column:1/-1}
label.fl{display:block;font-size:12.5px;color:var(--mut);margin-bottom:6px}
.fgrid input,.fgrid textarea,.fgrid select{width:100%;background:var(--bg2);border:1px solid var(--line2);
  border-radius:11px;padding:11px 13px;color:var(--txt);outline:none;font-size:14px}
.fgrid input:focus,.fgrid textarea:focus{border-color:var(--red)}
.fgrid textarea{resize:vertical;min-height:64px}
.check{display:flex;align-items:center;gap:9px;background:var(--bg2);border:1px solid var(--line2);
  border-radius:11px;padding:11px 13px;cursor:pointer;font-size:13.5px}
.check input{accent-color:var(--red);width:16px;height:16px}
.mfoot{display:flex;gap:10px;margin-top:20px}
.mfoot .btn{flex:1}
.hint{font-size:11.5px;color:var(--mut2);margin-top:5px}
.err-inline{color:var(--red);font-size:13px;min-height:18px;margin-top:8px}

/* settings */
.set-grid{display:grid;gap:16px}
.loc-row{display:grid;grid-template-columns:1.1fr 1.6fr 90px 60px 40px;gap:10px;margin-bottom:10px;align-items:center}
.loc-row input{background:var(--bg2);border:1px solid var(--line2);border-radius:10px;padding:9px 12px;color:var(--txt);outline:none;width:100%;font-size:13.5px}
.loc-row .iconb{width:38px;height:38px}

/* toast */
#toasts{position:fixed;bottom:20px;right:20px;z-index:99;display:flex;flex-direction:column;gap:8px}
.toast{background:var(--card2);border:1px solid var(--line2);border-right:3px solid var(--red);
  border-radius:12px;padding:11px 18px;font-size:13.5px;box-shadow:var(--sh);animation:tin .25s}
.toast.ok{border-right-color:var(--green)}
@keyframes tin{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

/* empty */
.empty{padding:50px 20px;text-align:center;color:var(--mut)}
.empty .big{font-size:38px;margin-bottom:10px;opacity:.7}

@media(max-width:860px){
  .layout{flex-direction:column}
  aside{width:100%;height:auto;position:static;flex-direction:row;align-items:center;padding:10px 12px;border-left:none;border-bottom:1px solid var(--line);gap:8px;overflow-x:auto}
  .side-brand{border:none;padding:0 8px 0 0;margin:0;flex-shrink:0}
  .side-brand div small{display:none}
  nav{flex-direction:row;gap:2px}
  nav button{padding:9px 13px;white-space:nowrap;font-size:13px}
  .side-foot{display:none}
  main{padding:18px 14px}
  .fgrid{grid-template-columns:1fr}
  .loc-row{grid-template-columns:1fr 1fr;grid-auto-rows:auto}
}
</style>
</head>
<body>

<!-- ======================= LOGIN ======================= -->
<div id="login">
  <div class="login-card">
    <img class="brand-mark" src="/favicon.svg" alt="JavidNam">
    <h1>جاویدنام</h1>
    <div class="mem">JavidNam — پنل مدیریت اشتراک</div>
    <div id="setupBox" class="setup-note hidden">
      نصب اولیه: هنوز رمز مدیریتی تعیین نشده. یک رمز قوی (حداقل ۸ کاراکتر) انتخاب کن؛ همین رمز برای ورود استفاده می‌شود.
    </div>
    <div class="field"><input id="passInput" type="password" placeholder="رمز مدیریت" autocomplete="current-password"></div>
    <div class="field hidden" id="pass2Field"><input id="pass2Input" type="password" placeholder="تکرار رمز"></div>
    <div class="login-err" id="loginErr"></div>
    <button class="btn btn-main" id="loginBtn">ورود 🌷</button>
  </div>
</div>

<!-- ======================= APP ======================= -->
<div id="app"><div class="layout">
  <aside>
    <div class="side-brand">
      <img src="/favicon.svg" alt="">
      <div><b>جاویدنام</b><small>JavidNam Panel</small></div>
    </div>
    <nav id="nav">
      <button data-view="dash" class="active">📊 داشبورد</button>
      <button data-view="users">👥 کاربران</button>
      <button data-view="settings">⚙️ تنظیمات</button>
      <button data-view="backup">🗄 پشتیبان‌گیری</button>
    </nav>
    <div class="side-foot">
      به یاد جان‌باختگان ۱۸ و ۱۹ دی ۱۴۰۴<br>نامشان جاوید 🕯<br><span id="verChip"></span>
    </div>
  </aside>
  <main id="main"></main>
</div></div>

<div id="toasts"></div>

<script>
/* ===== JavidNam Admin — original code, GPL-3.0 ===== */
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

let VIEW = 'dash';
let USERS = [];

/* ---------- Jalali date (standard public algorithm) ---------- */
function div(a,b){return ~~(a/b)}
function toJalali(gy,gm,gd){
  const g_d_m=[0,31,59,90,120,151,181,212,243,273,304,334];
  const gy2=gy-1600,gm2=gm-1,gd2=gd-1;
  let g_day_no=365*gy2+div(gy2+3,4)-div(gy2+99,100)+div(gy2+399,400);
  g_day_no+=g_d_m[gm2]+gd2;
  if(gm2>1&&((gy%4===0&&gy%100!==0)||(gy%400===0)))g_day_no++;
  g_day_no-=79;
  let j_day_no=div(g_day_no,12053);g_day_no%=12053;
  let jy=979+33*j_day_no+4*div(g_day_no,1461);
  g_day_no%=1461;
  if(g_day_no>=366){jy+=div(g_day_no-1,365);g_day_no=(g_day_no-1)%365}
  const ml=[31,31,31,31,31,31,30,30,30,30,30,29];
  let i;
  for(i=0;i<11&&g_day_no>=ml[i];i++)g_day_no-=ml[i];
  return [jy,i+1,g_day_no+1];
}
function fa(n){return String(n).replace(/\\d/g,d=>'۰۱۲۳۴۵۶۷۸۹'[d])}
function jalali(ts){
  if(!ts)return '—';
  const d=new Date(ts);
  const [jy,jm,jd]=toJalali(d.getFullYear(),d.getMonth()+1,d.getDate());
  return fa(jd)+' '+['فروردین','اردیبهشت','خرداد','تیر','مرداد','شهریور','مهر','آبان','آذر','دی','بهمن','اسفند'][jm-1]+' '+fa(jy);
}
function gb(bytes){
  if(!bytes) return '۰';
  const u=['بایت','کیلوبایت','مگابایت','گیگابایت','ترابایت'];
  let i=0,v=bytes;
  while(v>=1024&&i<4){v/=1024;i++}
  return fa(v.toFixed(v<10&&i>1?2:0))+' '+u[i];
}
function daysLeft(ts){
  if(!ts)return null;
  return Math.max(0,Math.ceil((ts-Date.now())/86400000));
}

/* ---------- api ---------- */
async function api(path, opts={}){
  const o={headers:{'X-JN':'1'},...opts};
  if(o.body&&typeof o.body==='object'){o.headers['Content-Type']='application/json';o.body=JSON.stringify(o.body)}
  const r=await fetch(path,o);
  const j=await r.json().catch(()=>({error:'bad-response'}));
  if(r.status===401&&path!=='/api/login'){showLogin();throw new Error('unauthorized')}
  if(!r.ok)throw new Error(j.error||'خطا');
  return j;
}

/* ---------- toasts ---------- */
function toast(msg,ok=false){
  const t=document.createElement('div');
  t.className='toast'+(ok?' ok':'');
  t.textContent=msg;
  $('#toasts').appendChild(t);
  setTimeout(()=>{t.style.opacity='0';t.style.transition='.3s';setTimeout(()=>t.remove(),320)},2600);
}

/* ---------- login ---------- */
let SETUP_MODE=false;
function showLogin(){
  $('#app').style.display='none';
  $('#login').style.display='flex';
  document.cookie='jn_session=; Path=/; Max-Age=0';
}
async function tryLogin(){
  const p=$('#passInput').value;
  const err=$('#loginErr');
  err.textContent='';
  if(SETUP_MODE){
    if(p.length<8){err.textContent='رمز باید حداقل ۸ کاراکتر باشد';return}
    if(p!==$('#pass2Input').value){err.textContent='تکرار رمز یکسان نیست';return}
    try{
      await api('/api/setup',{method:'POST',body:{password:p}});
      toast('رمز تنظیم شد؛ وارد شوید',true);
      SETUP_MODE=false;$('#setupBox').classList.add('hidden');$('#pass2Field').classList.add('hidden');
      $('#passInput').value='';return;
    }catch(e){err.textContent=e.message;return}
  }
  $('#loginBtn').disabled=true;
  try{
    const r=await api('/api/login',{method:'POST',body:{password:p}});
    if(r.ok){enterApp()}
  }catch(e){
    err.textContent=e.message||'رمز اشتباه است';
  }finally{$('#loginBtn').disabled=false}
}
$('#loginBtn').onclick=tryLogin;
$('#passInput').addEventListener('keydown',e=>{if(e.key==='Enter')tryLogin()});

async function enterApp(){
  $('#login').style.display='none';
  $('#app').style.display='block';
  $$('#nav button').forEach(b=>b.onclick=()=>go(b.dataset.view));
  go('dash');
}

/* ---------- router ---------- */
function go(view){
  VIEW=view;
  $$('#nav button').forEach(b=>b.classList.toggle('active',b.dataset.view===view));
  if(view==='dash')renderDash();
  if(view==='users')renderUsers();
  if(view==='settings')renderSettings();
  if(view==='backup')renderBackup();
}

/* ---------- dashboard ---------- */
async function renderDash(){
  $('#main').innerHTML='<div class="empty">⏳ در حال بارگذاری…</div>';
  try{
    const s=await api('/api/stats');
    $('#verChip').textContent='v'+s.version;
    $('#main').innerHTML=\`
    <div class="pagehead"><div><h2>داشبورد</h2><div class="sub">نمای کلی پنل جاویدنام</div></div>
      <button class="btn btn-main btn-sm" onclick="openUserModal()">＋ کاربر جدید</button></div>
    <div class="stats">
      <div class="stat"><div class="k">کاربران</div><div class="v">\${fa(s.users.total)}</div></div>
      <div class="stat"><div class="k">فعال</div><div class="v" style="color:var(--green)">\${fa(s.users.active)}</div></div>
      <div class="stat"><div class="k">مصرف کل</div><div class="v">\${gb(s.traffic.used)}</div></div>
      <div class="stat"><div class="k">انقضا نزدیک (۷ روز)</div><div class="v" style="color:var(--amber)">\${fa(s.expiring_soon)}</div></div>
    </div>
    <div class="card">
      <b style="font-size:14px">🕯 جاویدنام</b>
      <p style="font-size:13px;color:var(--mut);margin-top:8px">
        این پنل به یاد جان‌بافتگان ۱۸ و ۱۹ دی ۱۴۰۴ ساخته شده است؛ نامشان جاوید.<br>
        پروتکل‌ها: VLESS و Trojan روی WebSocket — مبتنی بر Cloudflare Workers، بدون هیچ تبلیغی.
      </p>
    </div>\`;
  }catch(e){$('#main').innerHTML='<div class="empty">⚠️ '+e.message+'</div>'}
}

/* ---------- users ---------- */
async function renderUsers(){
  $('#main').innerHTML='<div class="empty">⏳ در حال بارگذاری…</div>';
  try{
    const r=await api('/api/users'+(location.search?'':''));
    USERS=r.users;
    paintUsers();
  }catch(e){$('#main').innerHTML='<div class="empty">⚠️ '+e.message+'</div>'}
}
function stateChip(u){
  if(!u.active)return '<span class="chip chip-off">غیرفعال</span>';
  if(u.state.overQuota)return '<span class="chip chip-dead">حجم تمام</span>';
  if(u.state.expired)return '<span class="chip chip-dead">منقضی</span>';
  if(u.state.pending)return '<span class="chip chip-exp">شروع با اتصال</span>';
  return '<span class="chip chip-ok">فعال</span>';
}
function paintUsers(){
  const q=($('#userSearch')?.value||'').trim().toLowerCase();
  const rows=USERS.filter(u=>!q||u.name.toLowerCase().includes(q)||u.uuid.includes(q));
  const html=\`
  <div class="pagehead"><div><h2>کاربران</h2><div class="sub">مدیریت اشتراک‌ها</div></div></div>
  <div class="toolbar">
    <input type="search" id="userSearch" placeholder="جستجو (نام یا UUID)…" value="\${q.replace(/"/g,'&quot;')}">
    <button class="btn btn-main btn-sm" onclick="openUserModal()">＋ کاربر جدید</button>
    <button class="btn btn-ghost btn-sm" onclick="renderUsers()">↻</button>
  </div>
  <div class="tblwrap"><table>
    <thead><tr><th style="width:34px"><input type="checkbox" id="selAll" style="accent-color:var(--red)"></th>
      <th>نام</th><th>وضعیت</th><th>مصرف / سهمیه</th><th>انقضا</th><th>لینک ساب</th><th></th></tr></thead>
    <tbody>
    \${rows.map(u=>\`
      <tr data-id="\${u.id}">
        <td><input type="checkbox" class="sel" value="\${u.id}" style="accent-color:var(--red)"></td>
        <td><b>\${esc(u.name)}</b>\${u.note?'<br><small style="color:var(--mut2)">'+esc(u.note)+'</small>':''}</td>
        <td>\${stateChip(u)}</td>
        <td><div style="display:flex;align-items:center;gap:8px">
          <div class="ubar"><i style="width:\${u.quota_bytes?Math.min(100,u.used_bytes/u.quota_bytes*100):0}%"></i></div>
          <span style="font-size:12px;color:var(--mut);white-space:nowrap">\${gb(u.used_bytes)}\${u.quota_bytes?' / '+gb(u.quota_bytes):''}</span></div></td>
        <td style="font-size:12.5px">\${u.expiry_at?jalali(u.expiry_at)+'<br><small style="color:'+(daysLeft(u.expiry_at)<=3?'var(--red)':'var(--mut)')+'">'+(daysLeft(u.expiry_at)!==null?fa(daysLeft(u.expiry_at))+' روز':'')+'</small>':(u.state.pending?'<small style="color:var(--amber)">شروع با اتصال</small>':'نامحدود')}</td>
        <td><button class="iconb" title="کپی لینک ساب" onclick="copySub('\${u.sub_token}')">🔗</button>
            <button class="iconb" title="باز کردن پنل کاربر" onclick="window.open('/sub/\${u.sub_token}','_blank')">👁</button></td>
        <td><div class="rowact">
          <button class="iconb" title="ویرایش" onclick="openUserModal('\${u.id}')">✏️</button>
          <button class="iconb" title="ریست مصرف" onclick="resetUser('\${u.id}')">♻️</button>
          <button class="iconb" title="\${u.active?'غیرفعال کن':'فعال کن'}" onclick="toggleUser('\${u.id}',\${u.active?0:1})">\${u.active?'⏸':'▶️'}</button>
          <button class="iconb" title="حذف" onclick="delUser('\${u.id}','\${esc(u.name).replace(/'/g,'')}')">🗑</button>
        </div></td>
      </tr>\`).join('')}
    </tbody></table></div>
  <div class="bulkbar" id="bulkbar">
    <span>عملیات گروهی:</span>
    <button class="btn btn-ghost btn-sm" onclick="bulk('activate')">فعال‌سازی</button>
    <button class="btn btn-ghost btn-sm" onclick="bulk('deactivate')">غیرفعال‌سازی</button>
    <button class="btn btn-ghost btn-sm" onclick="bulk('reset_traffic')">ریست مصرف</button>
    <button class="btn btn-danger btn-sm" onclick="bulk('delete')">حذف</button>
  </div>
  \${!rows.length?'<div class="empty"><div class="big">👥</div>هنوز کاربری اضافه نشده؛ «کاربر جدید» را بزن</div>':''}\`;
  $('#main').innerHTML=html;
  $('#userSearch').oninput=()=>paintUsers();
  $('#userSearch').onkeydown=e=>{if(e.key==='Enter')paintUsers()};
  $('#selAll').onchange=e=>$$('.sel').forEach(c=>c.checked=e.target.checked);
}
function esc(s){return String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}

async function copySub(tok){
  try{await navigator.clipboard.writeText(location.origin+'/sub/'+tok);toast('لینک ساب کپی شد ✅',true)}
  catch(e){prompt('این لینک را کپی کن:',location.origin+'/sub/'+tok)}
}
async function resetUser(id){
  if(!confirm('مصرف و انقضای این کاربر ریست شود؟'))return;
  try{await api('/api/users/'+id+'/reset',{method:'POST',body:{traffic:true,expiry:true}});toast('ریست شد ✅',true);renderUsers()}
  catch(e){toast(e.message)}
}
async function toggleUser(id,val){
  try{await api('/api/users/'+id,{method:'PATCH',body:{active:!!val}});renderUsers()}
  catch(e){toast(e.message)}
}
async function delUser(id,name){
  if(!confirm('کاربر «'+name+'» برای همیشه حذف شود؟'))return;
  try{await api('/api/users/'+id,{method:'DELETE'});toast('حذف شد',true);renderUsers()}
  catch(e){toast(e.message)}
}
async function bulk(action){
  const ids=$$('.sel:checked').map(c=>c.value);
  if(!ids.length){toast('اول کاربرها را انتخاب کن');return}
  if(action==='delete'&&!confirm(ids.length+' کاربر حذف شود؟'))return;
  try{await api('/api/bulk',{method:'POST',body:{ids,action}});toast('انجام شد ✅',true);renderUsers()}
  catch(e){toast(e.message)}
}

/* ---------- user modal ---------- */
function openUserModal(id){
  const u=id?USERS.find(x=>x.id===id):null;
  const modal=document.createElement('div');
  modal.className='modal-bg';
  modal.innerHTML=\`<div class="modal">
    <h3>\${u?'ویرایش کاربر':'کاربر جدید'} <button class="x">✕</button></h3>
    <div class="fgrid">
      <div class="full"><label class="fl">نام *</label><input id="f_name" value="\${u?esc(u.name):''}" placeholder="مثلاً: علی"></div>
      <div><label class="fl">حجم (گیگابایت)</label><input id="f_quota" type="number" min="0" value="\${u?(u.quota_bytes/1073741824).toFixed(2):''}" placeholder="0 = نامحدود"></div>
      <div><label class="fl">مدت (روز)</label><input id="f_days" type="number" min="0" value="\${u?u.days:30}" placeholder="0 = نامحدود"></div>
      <div><label class="fl">محدودیت IP همزمان</label><input id="f_ip" type="number" min="0" max="10" value="\${u?u.ip_limit:2}" placeholder="0 = نامحدود"></div>
      <div><label class="fl">ریست دوره‌ای مصرف (ساعت)</label><input id="f_reset" type="number" min="0" value="\${u?u.reset_hours:0}" placeholder="0 = هرگز"></div>
      <div><label class="fl">UUID (خالی = خودکار)</label><input id="f_uuid" value="\${u?u.uuid:''}" placeholder="uuid-v4"></div>
      <div><label class="fl">تمدید (روز)</label><input id="f_ext" type="number" min="0" placeholder="فقط هنگام ویرایش"></div>
      <div><label class="check"><input type="checkbox" id="f_sof" \${!u||u.start_on_first?'checked':''}> شروع شمارش با اولین اتصال</label></div>
      <div class="full"><label class="fl">یادداشت</label><textarea id="f_note">\${u?esc(u.note||''):''}</textarea></div>
    </div>
    <div class="err-inline" id="mErr"></div>
    <div class="mfoot">
      <button class="btn btn-ghost" id="mCancel">انصراف</button>
      <button class="btn btn-main" id="mSave">💾 ذخیره</button>
    </div></div>\`;
  document.body.appendChild(modal);
  modal.querySelector('.x').onclick=modal.querySelector('#mCancel').onclick=()=>modal.remove();
  modal.querySelector('#mSave').onclick=async()=>{
    const body={
      name:modal.querySelector('#f_name').value.trim(),
      quota_gb:parseFloat(modal.querySelector('#f_quota').value)||0,
      days:parseInt(modal.querySelector('#f_days').value)||0,
      ip_limit:parseInt(modal.querySelector('#f_ip').value)||0,
      reset_hours:parseFloat(modal.querySelector('#f_reset').value)||0,
      start_on_first:modal.querySelector('#f_sof').checked,
      note:modal.querySelector('#f_note').value.trim(),
    };
    if(u){
      body.active=u.active;
      const ext=parseInt(modal.querySelector('#f_ext').value)||0;
      if(ext>0)body.extend_days=ext;
      try{await api('/api/users/'+u.id,{method:'PATCH',body});modal.remove();toast('ذخیره شد ✅',true);renderUsers()}
      catch(e){modal.querySelector('#mErr').textContent=e.message}
    }else{
      const uuid=modal.querySelector('#f_uuid').value.trim();
      if(uuid)body.uuid=uuid;
      try{const r=await api('/api/users',{method:'POST',body});modal.remove();toast('کاربر اضافه شد ✅',true);renderUsers()}
      catch(e){modal.querySelector('#mErr').textContent=e.message}
    }
  };
}

/* ---------- settings ---------- */
let SETTINGS=null;
async function renderSettings(){
  $('#main').innerHTML='<div class="empty">⏳ در حال بارگذاری…</div>';
  try{
    const r=await api('/api/settings');
    SETTINGS=r.settings;
    const s=SETTINGS;
    $('#main').innerHTML=\`
    <div class="pagehead"><div><h2>تنظیمات</h2><div class="sub">پیکربندی پنل و کانفیگ‌ها</div></div></div>
    <div class="card set-grid">
      <div><label class="fl">عنوان پنل</label><input id="s_title" value="\${esc(s.title)}"></div>
      <div><label class="fl">متن خوش‌آمد پنل ساب</label><input id="s_welcome" value="\${esc(s.welcome||'')}"></div>
      <div><label class="fl">راه ارتباطی (نمایش در پنل ساب)</label><input id="s_contact" value="\${esc(s.contact||'')}" placeholder="مثلاً @yourTelegram"></div>
      <div><label class="fl">مسیر WebSocket پروکسی</label><input id="s_path" value="\${esc(s.proxy_path)}">
        <div class="hint">پس از تغییر، کانفیگ‌های قبلی کاربران باطل می‌شوند؛ لینک ساب خودش آپدیت می‌شود.</div></div>
      <label class="check"><input type="checkbox" id="s_brand" \${s.sub_branding!==false?'checked':''}> نمایش برندینگ یادبود در پنل ساب</label>
    </div>
    <div class="card" style="margin-top:16px">
      <b style="font-size:14px">🌍 لوکیشن‌ها (میزبان‌های کانفیگ)</b>
      <div class="hint" style="margin-bottom:12px">هر لوکیشن یک میزبان برای تولید کانفیگ است. می‌توانی دامنه/آی‌پی «تمیز» کلودفلر (Clean IP) یا دامنه اختصاصی خودت را وارد کنی. پورت‌های TLS: 443، 2053، 2083، 2087، 2096، 8443.</div>
      <div id="locList"></div>
      <button class="btn btn-ghost btn-sm" onclick="addLocRow()">＋ افزودن لوکیشن</button>
    </div>
    <div style="margin-top:16px;display:flex;gap:10px">
      <button class="btn btn-main" id="saveSettings">💾 ذخیره تنظیمات</button>
    </div>\`;
    const list=$('#locList');
    s.locations.forEach(l=>locRow(list,l.name,l.host,l.port,l.tls));
    $('#saveSettings').onclick=saveSettingsClick;
  }catch(e){$('#main').innerHTML='<div class="empty">⚠️ '+e.message+'</div>'}
}
function locRow(list,name,host,port,tls){
  const row=document.createElement('div');
  row.className='loc-row';
  row.innerHTML=\`<input class="l_name" value="\${esc(name)}" placeholder="نام (مثلاً آلمان)">
    <input class="l_host" value="\${esc(host)}" placeholder="دامنه یا آی‌پی">
    <input class="l_port" type="number" value="\${port}" placeholder="443">
    <label class="check" style="padding:8px"><input type="checkbox" class="l_tls" \${tls!==false?'checked':''}>TLS</label>
    <button class="iconb" title="حذف">🗑</button>\`;
  row.querySelector('.iconb').onclick=()=>row.remove();
  list.appendChild(row);
}
function addLocRow(){locRow($('#locList'),'لوکیشن جدید','',443,true)}
async function saveSettingsClick(){
  const locs=$$('#locList .loc-row').map(r=>({
    name:r.querySelector('.l_name').value.trim()||'لوکیشن',
    host:r.querySelector('.l_host').value.trim(),
    port:parseInt(r.querySelector('.l_port').value)||443,
    tls:r.querySelector('.l_tls').checked,
  })).filter(l=>l.host);
  const body={
    title:$('#s_title').value.trim()||'جاویدنام | JavidNam',
    welcome:$('#s_welcome').value.trim(),
    contact:$('#s_contact').value.trim(),
    proxy_path:$('#s_path').value.trim(),
    sub_branding:$('#s_brand').checked,
    locations:locs,
  };
  try{await api('/api/settings',{method:'PUT',body});toast('تنظیمات ذخیره شد ✅',true)}
  catch(e){toast(e.message)}
}

/* ---------- backup ---------- */
function renderBackup(){
  $('#main').innerHTML=\`
  <div class="pagehead"><div><h2>پشتیبان‌گیری</h2><div class="sub">خروجی و بازگردانی کامل داده‌ها</div></div></div>
  <div class="card">
    <p style="font-size:13.5px;color:var(--mut);margin-bottom:14px">پشتیبان شامل همه کاربران، مصرف‌ها و تنظیمات (بدون رمزها) به‌صورت JSON است.</p>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn btn-main" id="expBtn">⬇️ دانلود پشتیبان</button>
      <label class="btn btn-ghost" style="cursor:pointer">⬆️ انتخاب فایل<input type="file" id="impFile" accept=".json" style="display:none"></label>
    </div>
    <div class="hint" style="margin-top:14px">بازگردانی، کاربران موجود با UUID یکسان را به‌روز می‌کند.</div>
  </div>\`;
  $('#expBtn').onclick=async()=>{
    try{
      const b=await api('/api/backup');
      const blob=new Blob([JSON.stringify(b,null,2)],{type:'application/json'});
      const a=document.createElement('a');
      a.href=URL.createObjectURL(blob);
      a.download='javidnam-backup-'+new Date().toISOString().slice(0,10)+'.json';
      a.click();
      toast('پشتیبان دانلود شد ✅',true);
    }catch(e){toast(e.message)}
  };
  $('#impFile').onchange=async e=>{
    const f=e.target.files[0];
    if(!f)return;
    if(!confirm('فایل پشتیبان بازگردانی شود؟'))return;
    try{
      const data=JSON.parse(await f.text());
      const r=await api('/api/restore',{method:'POST',body:data});
      toast(r.restored+' کاربر بازگردانی شد ✅',true);
    }catch(err){toast('خطا: '+err.message)}
  };
}

/* ---------- boot ---------- */
(async()=>{
  try{
    await api('/api/me');
    enterApp();
  }catch(e){
    if(String(e.message).includes('unauthorized')){
      try{
        await api('/api/login',{method:'POST',body:{password:''}});
      }catch(e2){
        if(e2.setup){SETUP_MODE=true;$('#setupBox').classList.remove('hidden');$('#pass2Field').classList.remove('hidden');$('#loginBtn').textContent='ثبت رمز و ورود'}
      }
    }
  }
})();
</script>
</body>
</html>
`;

const SUB_PAGE_TEMPLATE = `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="robots" content="noindex">
<meta name="theme-color" content="#07070c">
<title>__TITLE__</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>
:root{
  --bg:#07070c; --bg2:#0c0c14; --card:#101019; --card2:#151522;
  --line:rgba(255,255,255,.07); --line2:rgba(255,255,255,.13);
  --txt:#f2f2f7; --mut:#9090a5; --mut2:#5c5c70;
  --red:#f43f5e; --red2:#e11d48; --dark:#881337;
  --amber:#fbbf24; --green:#34d399;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  background:var(--bg);color:var(--txt);
  font-family:Vazirmatn,-apple-system,"Segoe UI",Tahoma,"Iranian Sans",sans-serif;
  font-size:15px;line-height:1.8;min-height:100vh;overflow-x:hidden;
}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:-1;
  background:
    radial-gradient(ellipse 90% 40% at 50% -8%,rgba(244,63,94,.13),transparent),
    radial-gradient(ellipse 60% 30% at 85% 110%,rgba(251,191,36,.05),transparent);}
.wrap{max-width:680px;margin:0 auto;padding:26px 16px 40px}
a{color:var(--red);text-decoration:none}
::selection{background:rgba(244,63,94,.35)}
::-webkit-scrollbar{width:8px}::-webkit-scrollbar-thumb{background:#26263a;border-radius:8px}

/* header */
header{text-align:center;padding:10px 0 4px}
.logo-badge{width:92px;height:92px;margin:0 auto 12px;border-radius:26px;
  background:linear-gradient(160deg,#141420,#0a0a10);border:1px solid var(--line2);
  display:flex;align-items:center;justify-content:center;
  box-shadow:0 12px 40px rgba(244,63,94,.18),inset 0 1px 0 rgba(255,255,255,.06);
  animation:breath 5s ease-in-out infinite}
@keyframes breath{0%,100%{box-shadow:0 12px 40px rgba(244,63,94,.14),inset 0 1px 0 rgba(255,255,255,.06)}50%{box-shadow:0 12px 56px rgba(244,63,94,.3),inset 0 1px 0 rgba(255,255,255,.06)}}
h1{font-size:24px;font-weight:800;letter-spacing:.5px}
h1 .en{font-size:13px;color:var(--mut);font-weight:400;display:block;letter-spacing:3px;margin-top:2px}
.ribbon{margin:14px auto 0;display:inline-flex;align-items:center;gap:8px;
  background:linear-gradient(90deg,rgba(136,19,55,.25),rgba(244,63,94,.12),rgba(136,19,55,.25));
  border:1px solid rgba(244,63,94,.28);color:#ff9db0;border-radius:99px;
  padding:5px 18px;font-size:12px;font-weight:600}

/* hero */
.hero{margin-top:22px;background:var(--card);border:1px solid var(--line);border-radius:22px;
  padding:22px;position:relative;overflow:hidden}
.hero::before{content:"";position:absolute;inset:0 0 auto 0;height:2px;
  background:linear-gradient(90deg,transparent,var(--red),var(--amber),var(--red),transparent)}
.hero-top{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap}
.hello{font-size:17px;font-weight:700}
.hello small{display:block;font-weight:400;color:var(--mut);font-size:12.5px;margin-top:3px}
.status-chip{display:inline-flex;align-items:center;gap:7px;padding:5px 15px;border-radius:99px;font-size:12.5px;font-weight:700}
.status-chip .dot{width:8px;height:8px;border-radius:50%;background:currentColor;animation:pulse 1.6s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.st-ok{background:rgba(52,211,153,.12);color:var(--green)}
.st-quota,.st-exp{background:rgba(244,63,94,.13);color:var(--red)}
.st-pend{background:rgba(251,191,36,.12);color:var(--amber)}
.st-off{background:rgba(255,255,255,.07);color:var(--mut)}
.usage{display:flex;align-items:center;gap:20px;margin-top:18px;flex-wrap:wrap}
.ring{position:relative;width:118px;height:118px;flex-shrink:0}
.ring svg{transform:rotate(-90deg)}
.ring .track{stroke:rgba(255,255,255,.08)}
.ring .bar{stroke:url(#rg);stroke-linecap:round;transition:stroke-dashoffset .8s ease}
.ring .mid{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.ring .mid b{font-size:19px;font-variant-numeric:tabular-nums}
.ring .mid span{font-size:10.5px;color:var(--mut)}
.umeta{flex:1;min-width:200px;display:grid;grid-template-columns:1fr 1fr;gap:10px}
.umeta .cell{background:var(--bg2);border:1px solid var(--line);border-radius:14px;padding:10px 14px}
.umeta .cell .k{font-size:11px;color:var(--mut);margin-bottom:3px}
.umeta .cell .v{font-size:14.5px;font-weight:700;font-variant-numeric:tabular-nums}

/* actions */
.bigacts{display:flex;gap:10px;margin-top:18px;flex-wrap:wrap}
.bbtn{flex:1;min-width:150px;border:none;cursor:pointer;border-radius:14px;padding:13px 16px;
  font-family:inherit;font-size:14px;font-weight:700;transition:.18s;display:inline-flex;align-items:center;justify-content:center;gap:8px}
.bbtn:active{transform:scale(.98)}
.bbtn-red{background:linear-gradient(135deg,var(--red2),var(--dark));color:#fff}
.bbtn-red:hover{filter:brightness(1.15)}
.bbtn-ghost{background:var(--card2);border:1px solid var(--line2);color:var(--txt)}
.bbtn-ghost:hover{border-color:var(--red)}

/* sections */
section{margin-top:26px}
.sec-title{display:flex;align-items:center;gap:10px;font-size:15px;font-weight:800;margin-bottom:14px}
.sec-title::after{content:"";flex:1;height:1px;background:var(--line)}

/* isp tabs */
.tabs{display:flex;gap:8px;overflow-x:auto;padding-bottom:6px;-webkit-overflow-scrolling:touch}
.tab{flex-shrink:0;border:1px solid var(--line2);background:var(--card);color:var(--mut);
  border-radius:99px;padding:8px 18px;font-size:13px;font-weight:700;cursor:pointer;transition:.15s;font-family:inherit}
.tab.on{background:linear-gradient(135deg,rgba(225,29,72,.25),rgba(136,19,55,.15));color:#ff8095;border-color:rgba(244,63,94,.4)}
.tab:not(.on):hover{color:var(--txt)}
.preset-note{font-size:12px;color:var(--mut);margin:10px 2px 0;min-height:20px}

/* config cards */
.cfg{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:16px 18px;margin-bottom:12px;transition:.15s}
.cfg:hover{border-color:rgba(244,63,94,.3)}
.cfg-head{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.cfg-head .nm{display:flex;align-items:center;gap:9px;font-weight:700;font-size:14.5px}
.flag{font-size:19px}
.proto-tag{font-size:10px;font-weight:800;letter-spacing:1px;padding:2px 9px;border-radius:7px}
.proto-vless{background:rgba(96,165,250,.14);color:#7db6f9}
.proto-trojan{background:rgba(244,63,94,.14);color:#ff8095}
.cfg-link{margin-top:10px;background:var(--bg2);border:1px solid var(--line);border-radius:11px;
  padding:9px 13px;font-size:11.5px;color:var(--mut);direction:ltr;text-align:left;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-family:ui-monospace,Menlo,Consolas,monospace}
.cfg-acts{display:flex;gap:8px;margin-top:11px;flex-wrap:wrap}
.cbtn{border:1px solid var(--line2);background:var(--card2);color:var(--txt);border-radius:10px;
  padding:8px 15px;font-size:12.5px;font-weight:700;cursor:pointer;transition:.15s;font-family:inherit;display:inline-flex;align-items:center;gap:6px}
.cbtn:hover{border-color:var(--red);color:#ff8095}
.cbtn:active{transform:scale(.97)}

/* guide */
.guide-tabs{display:flex;gap:8px;overflow-x:auto;padding-bottom:6px}
.steps{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:18px 20px}
.steps ol{padding-right:20px;font-size:13.5px;color:#cfcfdd}
.steps li{margin-bottom:9px}
.steps li:last-child{margin-bottom:0}
.steps b{color:var(--txt)}
.kbd{background:var(--bg2);border:1px solid var(--line2);border-bottom-width:2px;border-radius:7px;
  padding:1px 8px;font-size:12px;direction:ltr;display:inline-block;font-family:ui-monospace,Menlo,monospace}

/* frag table */
.frag{width:100%;border-collapse:collapse;font-size:12.5px}
.frag th,.frag td{padding:9px 12px;border-bottom:1px solid rgba(255,255,255,.05);text-align:right}
.frag th{color:var(--mut);font-weight:600;font-size:11.5px}

/* qr modal */
.modal-bg{position:fixed;inset:0;background:rgba(3,3,8,.8);backdrop-filter:blur(8px);z-index:60;
  display:flex;align-items:center;justify-content:center;padding:18px}
.modal{background:var(--card);border:1px solid var(--line2);border-radius:22px;padding:24px;text-align:center;max-width:320px;width:100%}
.modal h4{font-size:15px;margin-bottom:14px}
#qrBox{background:#fff;border-radius:16px;padding:14px;display:inline-block}
#qrBox canvas,#qrBox img{display:block}
.modal .hint{font-size:11.5px;color:var(--mut);margin-top:12px;direction:ltr;word-break:break-all}

/* toast */
#toasts{position:fixed;bottom:18px;right:50%;transform:translateX(50%);z-index:99;display:flex;flex-direction:column;gap:8px;align-items:center}
.toast{background:#1b1b2a;border:1px solid var(--line2);border-right:3px solid var(--red);
  border-radius:12px;padding:10px 20px;font-size:13px;box-shadow:0 10px 30px rgba(0,0,0,.5);animation:tin .25s}
.toast.ok{border-right-color:var(--green)}
@keyframes tin{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

/* footer */
footer{margin-top:34px;text-align:center;padding:22px 10px 6px;border-top:1px solid var(--line)}
.memorial{font-size:13px;color:#ff9db0;line-height:2.1}
.candle{font-size:20px;display:block;margin-bottom:4px;animation:flicker 2.2s ease-in-out infinite}
@keyframes flicker{0%,100%{opacity:1}50%{opacity:.55}}
.meta{font-size:11px;color:var(--mut2);margin-top:8px;line-height:2}
</style>
</head>
<body>
<svg width="0" height="0" style="position:absolute"><defs>
<linearGradient id="rg" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="#e11d48"/><stop offset="1" stop-color="#fbbf24"/></linearGradient>
</defs></svg>

<div class="wrap">
  <header>
    <div class="logo-badge">
      <svg width="58" height="58" viewBox="0 0 64 64">
        <defs>
        <linearGradient id="lg" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stop-color="#f43f5e"/><stop offset="1" stop-color="#881337"/></linearGradient>
        <radialGradient id="lc" cx="0.5" cy="0.35" r="0.55">
        <stop offset="0" stop-color="#fbbf24"/><stop offset="1" stop-color="#f43f5e" stop-opacity="0"/></radialGradient>
        </defs>
        <rect width="64" height="64" rx="14" fill="#0a0a10" opacity="0"/>
        <path d="M32 8c-2 5.5-6.8 8-6.8 14 0 3.8 2.1 7 4.7 9.3C30.5 39.5 28 45.6 22 51.4c7.8-1.8 12.4-5.6 14.9-10.7 2.5 5.1 7.1 8.9 14.9 10.7-6-5.8-8.5-11.9-7.9-20.1 2.6-2.3 4.7-5.5 4.7-9.3 0-6-4.8-8.5-6.8-14-1.8 3.8-4.7 5.6-7.6 5.6s-4.2-1.8-6.2-5.6z" fill="url(#lg)"/>
        <ellipse cx="32" cy="23" rx="4" ry="7" fill="url(#lc)" opacity="0.95"/>
      </svg>
    </div>
    <h1>جاویدنام<span class="en">J A V I D N A M</span></h1>
    <div class="ribbon">🕯 به یاد جان‌باختگان ۱۸ و ۱۹ دی ۱۴۰۴ — نامشان جاوید</div>
  </header>

  <div id="content"></div>

  <footer id="foot"></footer>
</div>

<div id="toasts"></div>
<div id="modalHost"></div>

<script>var qrcode=function(){function i(t,r){function a(t,r){g=function(t){for(var r=new Array(t),e=0;e<t;e+=1){r[e]=new Array(t);for(var n=0;n<t;n+=1)r[e][n]=null}return r}(l=4*u+17),e(0,0),e(l-7,0),e(0,l-7),i(),o(),v(t,r),7<=u&&h(t),null==n&&(n=w(u,f,c)),d(n,r)}var u=t,f=y[r],g=null,l=0,n=null,c=[],s={},e=function(t,r){for(var e=-1;e<=7;e+=1)if(!(t+e<=-1||l<=t+e))for(var n=-1;n<=7;n+=1)r+n<=-1||l<=r+n||(g[t+e][r+n]=0<=e&&e<=6&&(0==n||6==n)||0<=n&&n<=6&&(0==e||6==e)||2<=e&&e<=4&&2<=n&&n<=4)},o=function(){for(var t=8;t<l-8;t+=1)null==g[t][6]&&(g[t][6]=t%2==0);for(var r=8;r<l-8;r+=1)null==g[6][r]&&(g[6][r]=r%2==0)},i=function(){for(var t=B.getPatternPosition(u),r=0;r<t.length;r+=1)for(var e=0;e<t.length;e+=1){var n=t[r],o=t[e];if(null==g[n][o])for(var i=-2;i<=2;i+=1)for(var a=-2;a<=2;a+=1)g[n+i][o+a]=-2==i||2==i||-2==a||2==a||0==i&&0==a}},h=function(t){for(var r=B.getBCHTypeNumber(u),e=0;e<18;e+=1){var n=!t&&1==(r>>e&1);g[Math.floor(e/3)][e%3+l-8-3]=n}for(e=0;e<18;e+=1){n=!t&&1==(r>>e&1);g[e%3+l-8-3][Math.floor(e/3)]=n}},v=function(t,r){for(var e=f<<3|r,n=B.getBCHTypeInfo(e),o=0;o<15;o+=1){var i=!t&&1==(n>>o&1);o<6?g[o][8]=i:o<8?g[o+1][8]=i:g[l-15+o][8]=i}for(o=0;o<15;o+=1){i=!t&&1==(n>>o&1);o<8?g[8][l-o-1]=i:o<9?g[8][15-o-1+1]=i:g[8][15-o-1]=i}g[l-8][8]=!t},d=function(t,r){for(var e=-1,n=l-1,o=7,i=0,a=B.getMaskFunction(r),u=l-1;0<u;u-=2)for(6==u&&(u-=1);;){for(var f=0;f<2;f+=1)if(null==g[n][u-f]){var c=!1;i<t.length&&(c=1==(t[i]>>>o&1)),a(n,u-f)&&(c=!c),g[n][u-f]=c,-1==(o-=1)&&(i+=1,o=7)}if((n+=e)<0||l<=n){n-=e,e=-e;break}}},w=function(t,r,e){for(var n=b.getRSBlocks(t,r),o=M(),i=0;i<e.length;i+=1){var a=e[i];o.put(a.getMode(),4),o.put(a.getLength(),B.getLengthInBits(a.getMode(),t)),a.write(o)}var u=0;for(i=0;i<n.length;i+=1)u+=n[i].dataCount;if(o.getLengthInBits()>8*u)throw"code length overflow. ("+o.getLengthInBits()+">"+8*u+")";for(o.getLengthInBits()+4<=8*u&&o.put(0,4);o.getLengthInBits()%8!=0;)o.putBit(!1);for(;!(o.getLengthInBits()>=8*u||(o.put(236,8),o.getLengthInBits()>=8*u));)o.put(17,8);return function(t,r){for(var e=0,n=0,o=0,i=new Array(r.length),a=new Array(r.length),u=0;u<r.length;u+=1){var f=r[u].dataCount,c=r[u].totalCount-f;n=Math.max(n,f),o=Math.max(o,c),i[u]=new Array(f);for(var g=0;g<i[u].length;g+=1)i[u][g]=255&t.getBuffer()[g+e];e+=f;var l=B.getErrorCorrectPolynomial(c),h=C(i[u],l.getLength()-1).mod(l);a[u]=new Array(l.getLength()-1);for(g=0;g<a[u].length;g+=1){var s=g+h.getLength()-a[u].length;a[u][g]=0<=s?h.getAt(s):0}}var v=0;for(g=0;g<r.length;g+=1)v+=r[g].totalCount;var d=new Array(v),w=0;for(g=0;g<n;g+=1)for(u=0;u<r.length;u+=1)g<i[u].length&&(d[w]=i[u][g],w+=1);for(g=0;g<o;g+=1)for(u=0;u<r.length;u+=1)g<a[u].length&&(d[w]=a[u][g],w+=1);return d}(o,n)};s.addData=function(t,r){var e=null;switch(r=r||"Byte"){case"Numeric":e=x(t);break;case"Alphanumeric":e=m(t);break;case"Byte":e=L(t);break;case"Kanji":e=D(t);break;default:throw"mode:"+r}c.push(e),n=null},s.isDark=function(t,r){if(t<0||l<=t||r<0||l<=r)throw t+","+r;return g[t][r]},s.getModuleCount=function(){return l},s.make=function(){if(u<1){for(var t=1;t<40;t++){for(var r=b.getRSBlocks(t,f),e=M(),n=0;n<c.length;n++){var o=c[n];e.put(o.getMode(),4),e.put(o.getLength(),B.getLengthInBits(o.getMode(),t)),o.write(e)}var i=0;for(n=0;n<r.length;n++)i+=r[n].dataCount;if(e.getLengthInBits()<=8*i)break}u=t}a(!1,function(){for(var t=0,r=0,e=0;e<8;e+=1){a(!0,e);var n=B.getLostPoint(s);(0==e||n<t)&&(t=n,r=e)}return r}())},s.createTableTag=function(t,r){t=t||2;var e="";e+='<table style="',e+=" border-width: 0px; border-style: none;",e+=" border-collapse: collapse;",e+=" padding: 0px; margin: "+(r=void 0===r?4*t:r)+"px;",e+='">',e+="<tbody>";for(var n=0;n<s.getModuleCount();n+=1){e+="<tr>";for(var o=0;o<s.getModuleCount();o+=1)e+='<td style="',e+=" border-width: 0px; border-style: none;",e+=" border-collapse: collapse;",e+=" padding: 0px; margin: 0px;",e+=" width: "+t+"px;",e+=" height: "+t+"px;",e+=" background-color: ",e+=s.isDark(n,o)?"#000000":"#ffffff",e+=";",e+='"/>';e+="</tr>"}return e+="</tbody>",e+="</table>"},s.createSvgTag=function(t,r,e,n){var o={};"object"==typeof t&&(t=(o=t).cellSize,r=o.margin,e=o.alt,n=o.title),t=t||2,r=void 0===r?4*t:r,(e="string"==typeof e?{text:e}:e||{}).text=e.text||null,e.id=e.text?e.id||"qrcode-description":null,(n="string"==typeof n?{text:n}:n||{}).text=n.text||null,n.id=n.text?n.id||"qrcode-title":null;var i,a,u,f,c=s.getModuleCount()*t+2*r,g="";for(f="l"+t+",0 0,"+t+" -"+t+",0 0,-"+t+"z ",g+='<svg version="1.1" xmlns="http://www.w3.org/2000/svg"',g+=o.scalable?"":' width="'+c+'px" height="'+c+'px"',g+=' viewBox="0 0 '+c+" "+c+'" ',g+=' preserveAspectRatio="xMinYMin meet"',g+=n.text||e.text?' role="img" aria-labelledby="'+p([n.id,e.id].join(" ").trim())+'"':"",g+=">",g+=n.text?'<title id="'+p(n.id)+'">'+p(n.text)+"</title>":"",g+=e.text?'<description id="'+p(e.id)+'">'+p(e.text)+"</description>":"",g+='<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>',g+='<path d="',a=0;a<s.getModuleCount();a+=1)for(u=a*t+r,i=0;i<s.getModuleCount();i+=1)s.isDark(a,i)&&(g+="M"+(i*t+r)+","+u+f);return g+='" stroke="transparent" fill="black"/>',g+="</svg>"},s.createDataURL=function(o,t){o=o||2,t=void 0===t?4*o:t;var r=s.getModuleCount()*o+2*t,i=t,a=r-t;return I(r,r,function(t,r){if(i<=t&&t<a&&i<=r&&r<a){var e=Math.floor((t-i)/o),n=Math.floor((r-i)/o);return s.isDark(n,e)?0:1}return 1})},s.createImgTag=function(t,r,e){t=t||2,r=void 0===r?4*t:r;var n=s.getModuleCount()*t+2*r,o="";return o+="<img",o+=' src="',o+=s.createDataURL(t,r),o+='"',o+=' width="',o+=n,o+='"',o+=' height="',o+=n,o+='"',e&&(o+=' alt="',o+=p(e),o+='"'),o+="/>"};var p=function(t){for(var r="",e=0;e<t.length;e+=1){var n=t.charAt(e);switch(n){case"<":r+="&lt;";break;case">":r+="&gt;";break;case"&":r+="&amp;";break;case'"':r+="&quot;";break;default:r+=n}}return r};return s.createASCII=function(t,r){if((t=t||1)<2)return function(t){t=void 0===t?2:t;var r,e,n,o,i,a=1*s.getModuleCount()+2*t,u=t,f=a-t,c={"██":"█","█ ":"▀"," █":"▄","  ":" "},g={"██":"▀","█ ":"▀"," █":" ","  ":" "},l="";for(r=0;r<a;r+=2){for(n=Math.floor((r-u)/1),o=Math.floor((r+1-u)/1),e=0;e<a;e+=1)i="█",u<=e&&e<f&&u<=r&&r<f&&s.isDark(n,Math.floor((e-u)/1))&&(i=" "),u<=e&&e<f&&u<=r+1&&r+1<f&&s.isDark(o,Math.floor((e-u)/1))?i+=" ":i+="█",l+=t<1&&f<=r+1?g[i]:c[i];l+="\\\\n"}return a%2&&0<t?l.substring(0,l.length-a-1)+Array(1+a).join("▀"):l.substring(0,l.length-1)}(r);t-=1,r=void 0===r?2*t:r;var e,n,o,i,a=s.getModuleCount()*t+2*r,u=r,f=a-r,c=Array(t+1).join("██"),g=Array(t+1).join("  "),l="",h="";for(e=0;e<a;e+=1){for(o=Math.floor((e-u)/t),h="",n=0;n<a;n+=1)i=1,u<=n&&n<f&&u<=e&&e<f&&s.isDark(o,Math.floor((n-u)/t))&&(i=0),h+=i?c:g;for(o=0;o<t;o+=1)l+=h+"\\\\n"}return l.substring(0,l.length-1)},s.renderTo2dContext=function(t,r){r=r||2;for(var e=s.getModuleCount(),n=0;n<e;n++)for(var o=0;o<e;o++)t.fillStyle=s.isDark(n,o)?"black":"white",t.fillRect(n*r,o*r,r,r)},s}i.stringToBytes=(i.stringToBytesFuncs={default:function(t){for(var r=[],e=0;e<t.length;e+=1){var n=t.charCodeAt(e);r.push(255&n)}return r}}).default,i.createStringToBytes=function(u,f){var i=function(){function t(){var t=r.read();if(-1==t)throw"eof";return t}for(var r=S(u),e=0,n={};;){var o=r.read();if(-1==o)break;var i=t(),a=t()<<8|t();n[String.fromCharCode(o<<8|i)]=a,e+=1}if(e!=f)throw e+" != "+f;return n}(),a="?".charCodeAt(0);return function(t){for(var r=[],e=0;e<t.length;e+=1){var n=t.charCodeAt(e);if(n<128)r.push(n);else{var o=i[t.charAt(e)];"number"==typeof o?(255&o)==o?r.push(o):(r.push(o>>>8),r.push(255&o)):r.push(a)}}return r}};var r,t,a=1,u=2,o=4,f=8,y={L:1,M:0,Q:3,H:2},e=0,n=1,c=2,g=3,l=4,h=5,s=6,v=7,B=(r=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],(t={}).getBCHTypeInfo=function(t){for(var r=t<<10;0<=d(r)-d(1335);)r^=1335<<d(r)-d(1335);return 21522^(t<<10|r)},t.getBCHTypeNumber=function(t){for(var r=t<<12;0<=d(r)-d(7973);)r^=7973<<d(r)-d(7973);return t<<12|r},t.getPatternPosition=function(t){return r[t-1]},t.getMaskFunction=function(t){switch(t){case e:return function(t,r){return(t+r)%2==0};case n:return function(t,r){return t%2==0};case c:return function(t,r){return r%3==0};case g:return function(t,r){return(t+r)%3==0};case l:return function(t,r){return(Math.floor(t/2)+Math.floor(r/3))%2==0};case h:return function(t,r){return t*r%2+t*r%3==0};case s:return function(t,r){return(t*r%2+t*r%3)%2==0};case v:return function(t,r){return(t*r%3+(t+r)%2)%2==0};default:throw"bad maskPattern:"+t}},t.getErrorCorrectPolynomial=function(t){for(var r=C([1],0),e=0;e<t;e+=1)r=r.multiply(C([1,w.gexp(e)],0));return r},t.getLengthInBits=function(t,r){if(1<=r&&r<10)switch(t){case a:return 10;case u:return 9;case o:case f:return 8;default:throw"mode:"+t}else if(r<27)switch(t){case a:return 12;case u:return 11;case o:return 16;case f:return 10;default:throw"mode:"+t}else{if(!(r<41))throw"type:"+r;switch(t){case a:return 14;case u:return 13;case o:return 16;case f:return 12;default:throw"mode:"+t}}},t.getLostPoint=function(t){for(var r=t.getModuleCount(),e=0,n=0;n<r;n+=1)for(var o=0;o<r;o+=1){for(var i=0,a=t.isDark(n,o),u=-1;u<=1;u+=1)if(!(n+u<0||r<=n+u))for(var f=-1;f<=1;f+=1)o+f<0||r<=o+f||0==u&&0==f||a==t.isDark(n+u,o+f)&&(i+=1);5<i&&(e+=3+i-5)}for(n=0;n<r-1;n+=1)for(o=0;o<r-1;o+=1){var c=0;t.isDark(n,o)&&(c+=1),t.isDark(n+1,o)&&(c+=1),t.isDark(n,o+1)&&(c+=1),t.isDark(n+1,o+1)&&(c+=1),0!=c&&4!=c||(e+=3)}for(n=0;n<r;n+=1)for(o=0;o<r-6;o+=1)t.isDark(n,o)&&!t.isDark(n,o+1)&&t.isDark(n,o+2)&&t.isDark(n,o+3)&&t.isDark(n,o+4)&&!t.isDark(n,o+5)&&t.isDark(n,o+6)&&(e+=40);for(o=0;o<r;o+=1)for(n=0;n<r-6;n+=1)t.isDark(n,o)&&!t.isDark(n+1,o)&&t.isDark(n+2,o)&&t.isDark(n+3,o)&&t.isDark(n+4,o)&&!t.isDark(n+5,o)&&t.isDark(n+6,o)&&(e+=40);var g=0;for(o=0;o<r;o+=1)for(n=0;n<r;n+=1)t.isDark(n,o)&&(g+=1);return e+=Math.abs(100*g/r/r-50)/5*10},t);function d(t){for(var r=0;0!=t;)r+=1,t>>>=1;return r}var w=function(){for(var r=new Array(256),e=new Array(256),t=0;t<8;t+=1)r[t]=1<<t;for(t=8;t<256;t+=1)r[t]=r[t-4]^r[t-5]^r[t-6]^r[t-8];for(t=0;t<255;t+=1)e[r[t]]=t;var n={glog:function(t){if(t<1)throw"glog("+t+")";return e[t]},gexp:function(t){for(;t<0;)t+=255;for(;256<=t;)t-=255;return r[t]}};return n}();function C(n,o){if(void 0===n.length)throw n.length+"/"+o;var r=function(){for(var t=0;t<n.length&&0==n[t];)t+=1;for(var r=new Array(n.length-t+o),e=0;e<n.length-t;e+=1)r[e]=n[e+t];return r}(),i={getAt:function(t){return r[t]},getLength:function(){return r.length},multiply:function(t){for(var r=new Array(i.getLength()+t.getLength()-1),e=0;e<i.getLength();e+=1)for(var n=0;n<t.getLength();n+=1)r[e+n]^=w.gexp(w.glog(i.getAt(e))+w.glog(t.getAt(n)));return C(r,0)},mod:function(t){if(i.getLength()-t.getLength()<0)return i;for(var r=w.glog(i.getAt(0))-w.glog(t.getAt(0)),e=new Array(i.getLength()),n=0;n<i.getLength();n+=1)e[n]=i.getAt(n);for(n=0;n<t.getLength();n+=1)e[n]^=w.gexp(w.glog(t.getAt(n))+r);return C(e,0).mod(t)}};return i}function p(){var e=[],o={writeByte:function(t){e.push(255&t)},writeShort:function(t){o.writeByte(t),o.writeByte(t>>>8)},writeBytes:function(t,r,e){r=r||0,e=e||t.length;for(var n=0;n<e;n+=1)o.writeByte(t[n+r])},writeString:function(t){for(var r=0;r<t.length;r+=1)o.writeByte(t.charCodeAt(r))},toByteArray:function(){return e},toString:function(){var t="";t+="[";for(var r=0;r<e.length;r+=1)0<r&&(t+=","),t+=e[r];return t+="]"}};return o}var k,A,b=(k=[[1,26,19],[1,26,16],[1,26,13],[1,26,9],[1,44,34],[1,44,28],[1,44,22],[1,44,16],[1,70,55],[1,70,44],[2,35,17],[2,35,13],[1,100,80],[2,50,32],[2,50,24],[4,25,9],[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],[2,86,68],[4,43,27],[4,43,19],[4,43,15],[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],[3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12,7,37,13],[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],[3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14],[3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,43,15,10,44,16],[4,144,116,4,145,117],[17,68,42],[17,50,22,6,51,23],[19,46,16,6,47,17],[2,139,111,7,140,112],[17,74,46],[7,54,24,16,55,25],[34,37,13],[4,151,121,5,152,122],[4,75,47,14,76,48],[11,54,24,14,55,25],[16,45,15,14,46,16],[6,147,117,4,148,118],[6,73,45,14,74,46],[11,54,24,16,55,25],[30,46,16,2,47,17],[8,132,106,4,133,107],[8,75,47,13,76,48],[7,54,24,22,55,25],[22,45,15,13,46,16],[10,142,114,2,143,115],[19,74,46,4,75,47],[28,50,22,6,51,23],[33,46,16,4,47,17],[8,152,122,4,153,123],[22,73,45,3,74,46],[8,53,23,26,54,24],[12,45,15,28,46,16],[3,147,117,10,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],[7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],[5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],[13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],[17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],[17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,55,25],[11,45,15,46,46,16],[13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],[12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],[6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],[17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],[4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],[20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,45,15,67,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16]],(A={}).getRSBlocks=function(t,r){var e=function(t,r){switch(r){case y.L:return k[4*(t-1)+0];case y.M:return k[4*(t-1)+1];case y.Q:return k[4*(t-1)+2];case y.H:return k[4*(t-1)+3];default:return}}(t,r);if(void 0===e)throw"bad rs block @ typeNumber:"+t+"/errorCorrectionLevel:"+r;for(var n,o,i=e.length/3,a=[],u=0;u<i;u+=1)for(var f=e[3*u+0],c=e[3*u+1],g=e[3*u+2],l=0;l<f;l+=1)a.push((n=g,o=void 0,(o={}).totalCount=c,o.dataCount=n,o));return a},A),M=function(){var e=[],n=0,o={getBuffer:function(){return e},getAt:function(t){var r=Math.floor(t/8);return 1==(e[r]>>>7-t%8&1)},put:function(t,r){for(var e=0;e<r;e+=1)o.putBit(1==(t>>>r-e-1&1))},getLengthInBits:function(){return n},putBit:function(t){var r=Math.floor(n/8);e.length<=r&&e.push(0),t&&(e[r]|=128>>>n%8),n+=1}};return o},x=function(t){var r=a,n=t,e={getMode:function(){return r},getLength:function(t){return n.length},write:function(t){for(var r=n,e=0;e+2<r.length;)t.put(o(r.substring(e,e+3)),10),e+=3;e<r.length&&(r.length-e==1?t.put(o(r.substring(e,e+1)),4):r.length-e==2&&t.put(o(r.substring(e,e+2)),7))}},o=function(t){for(var r=0,e=0;e<t.length;e+=1)r=10*r+i(t.charAt(e));return r},i=function(t){if("0"<=t&&t<="9")return t.charCodeAt(0)-"0".charCodeAt(0);throw"illegal char :"+t};return e},m=function(t){var r=u,n=t,e={getMode:function(){return r},getLength:function(t){return n.length},write:function(t){for(var r=n,e=0;e+1<r.length;)t.put(45*o(r.charAt(e))+o(r.charAt(e+1)),11),e+=2;e<r.length&&t.put(o(r.charAt(e)),6)}},o=function(t){if("0"<=t&&t<="9")return t.charCodeAt(0)-"0".charCodeAt(0);if("A"<=t&&t<="Z")return t.charCodeAt(0)-"A".charCodeAt(0)+10;switch(t){case" ":return 36;case"$":return 37;case"%":return 38;case"*":return 39;case"+":return 40;case"-":return 41;case".":return 42;case"/":return 43;case":":return 44;default:throw"illegal char :"+t}};return e},L=function(t){var r=o,e=i.stringToBytes(t),n={getMode:function(){return r},getLength:function(t){return e.length},write:function(t){for(var r=0;r<e.length;r+=1)t.put(e[r],8)}};return n},D=function(t){var r=f,e=i.stringToBytesFuncs.SJIS;if(!e)throw"sjis not supported.";!function(){var t=e("友");if(2!=t.length||38726!=(t[0]<<8|t[1]))throw"sjis not supported."}();var o=e(t),n={getMode:function(){return r},getLength:function(t){return~~(o.length/2)},write:function(t){for(var r=o,e=0;e+1<r.length;){var n=(255&r[e])<<8|255&r[e+1];if(33088<=n&&n<=40956)n-=33088;else{if(!(57408<=n&&n<=60351))throw"illegal char at "+(e+1)+"/"+n;n-=49472}n=192*(n>>>8&255)+(255&n),t.put(n,13),e+=2}if(e<r.length)throw"illegal char at "+(e+1)}};return n},S=function(t){var e=t,n=0,o=0,i=0,r={read:function(){for(;i<8;){if(n>=e.length){if(0==i)return-1;throw"unexpected end of file./"+i}var t=e.charAt(n);if(n+=1,"="==t)return i=0,-1;t.match(/^\\\\s$/)||(o=o<<6|a(t.charCodeAt(0)),i+=6)}var r=o>>>i-8&255;return i-=8,r}},a=function(t){if(65<=t&&t<=90)return t-65;if(97<=t&&t<=122)return t-97+26;if(48<=t&&t<=57)return t-48+52;if(43==t)return 62;if(47==t)return 63;throw"c:"+t};return r},I=function(t,r,e){for(var n=function(t,r){var n=t,o=r,l=new Array(t*r),e={setPixel:function(t,r,e){l[r*n+t]=e},write:function(t){t.writeString("GIF87a"),t.writeShort(n),t.writeShort(o),t.writeByte(128),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(255),t.writeByte(255),t.writeByte(255),t.writeString(","),t.writeShort(0),t.writeShort(0),t.writeShort(n),t.writeShort(o),t.writeByte(0);var r=i(2);t.writeByte(2);for(var e=0;255<r.length-e;)t.writeByte(255),t.writeBytes(r,e,255),e+=255;t.writeByte(r.length-e),t.writeBytes(r,e,r.length-e),t.writeByte(0),t.writeString(";")}},i=function(t){for(var r=1<<t,e=1+(1<<t),n=t+1,o=h(),i=0;i<r;i+=1)o.add(String.fromCharCode(i));o.add(String.fromCharCode(r)),o.add(String.fromCharCode(e));var a=p(),u=function(t){var e=t,n=0,o=0,r={write:function(t,r){if(t>>>r!=0)throw"length over";for(;8<=n+r;)e.writeByte(255&(t<<n|o)),r-=8-n,t>>>=8-n,n=o=0;o|=t<<n,n+=r},flush:function(){0<n&&e.writeByte(o)}};return r}(a);u.write(r,n);var f=0,c=String.fromCharCode(l[f]);for(f+=1;f<l.length;){var g=String.fromCharCode(l[f]);f+=1,o.contains(c+g)?c+=g:(u.write(o.indexOf(c),n),o.size()<4095&&(o.size()==1<<n&&(n+=1),o.add(c+g)),c=g)}return u.write(o.indexOf(c),n),u.write(e,n),u.flush(),a.toByteArray()},h=function(){var r={},e=0,n={add:function(t){if(n.contains(t))throw"dup key:"+t;r[t]=e,e+=1},size:function(){return e},indexOf:function(t){return r[t]},contains:function(t){return void 0!==r[t]}};return n};return e}(t,r),o=0;o<r;o+=1)for(var i=0;i<t;i+=1)n.setPixel(i,o,e(i,o));var a=p();n.write(a);for(var u=function(){function e(t){a+=String.fromCharCode(r(63&t))}var n=0,o=0,i=0,a="",t={},r=function(t){if(t<0);else{if(t<26)return 65+t;if(t<52)return t-26+97;if(t<62)return t-52+48;if(62==t)return 43;if(63==t)return 47}throw"n:"+t};return t.writeByte=function(t){for(n=n<<8|255&t,o+=8,i+=1;6<=o;)e(n>>>o-6),o-=6},t.flush=function(){if(0<o&&(e(n<<6-o),o=n=0),i%3!=0)for(var t=3-i%3,r=0;r<t;r+=1)a+="="},t.toString=function(){return a},t}(),f=a.toByteArray(),c=0;c<f.length;c+=1)u.writeByte(f[c]);return u.flush(),"data:image/gif;base64,"+u};return i}();qrcode.stringToBytesFuncs["UTF-8"]=function(t){return function(t){for(var r=[],e=0;e<t.length;e++){var n=t.charCodeAt(e);n<128?r.push(n):n<2048?r.push(192|n>>6,128|63&n):n<55296||57344<=n?r.push(224|n>>12,128|n>>6&63,128|63&n):(e++,n=65536+((1023&n)<<10|1023&t.charCodeAt(e)),r.push(240|n>>18,128|n>>12&63,128|n>>6&63,128|63&n))}return r}(t)},function(t){"function"==typeof define&&define.amd?define([],t):"object"==typeof exports&&(module.exports=t())}(function(){return qrcode});</script>
<script id="sub-data" type="application/json">__SUB_DATA_JSON__</script>
<script>
/* ===== JavidNam Sub Page — original code, GPL-3.0 ===== */
const D = JSON.parse(document.getElementById('sub-data').textContent);
const $ = s => document.querySelector(s);
let ACTIVE_PRESET = D.presets && D.presets.length ? D.presets[0] : {id:'all',label:'همه',fp:'chrome',frag:null};
let PROTO_FILTER = 'all';

function fa(n){return String(n).replace(/\\d/g,d=>'۰۱۲۳۴۵۶۷۸۹'[d])}
function div(a,b){return ~~(a/b)}
function toJalali(gy,gm,gd){
  const g_d_m=[0,31,59,90,120,151,181,212,243,273,304,334];
  let gy2=gy-1600,gm2=gm-1,gd2=gd-1;
  let g_day_no=365*gy2+div(gy2+3,4)-div(gy2+99,100)+div(gy2+399,400);
  g_day_no+=g_d_m[gm2]+gd2;
  if(gm2>1&&((gy%4===0&&gy%100!==0)||(gy%400===0)))g_day_no++;
  g_day_no-=79;
  let j_day_no=div(g_day_no,12053);g_day_no%=12053;
  let jy=979+33*j_day_no+4*div(g_day_no,1461);
  g_day_no%=1461;
  if(g_day_no>=366){jy+=div(g_day_no-1,365);g_day_no=(g_day_no-1)%365}
  let jm=0;
  const ml=[31,31,31,31,31,31,30,30,30,30,30,29];
  let i;
  for(i=0;i<11&&g_day_no>=ml[i];i++){g_day_no-=ml[i]}
  return [jy,i+1,g_day_no+1];
}
function jalali(ts){
  if(!ts)return '—';
  const d=new Date(ts);
  const [jy,jm,jd]=toJalali(d.getFullYear(),d.getMonth()+1,d.getDate());
  return fa(jd)+' '+['فروردین','اردیبهشت','خرداد','تیر','مرداد','شهریور','مهر','آبان','آذر','دی','بهمن','اسفند'][jm-1]+' '+fa(jy);
}
function gb(bytes){
  if(!bytes)return '۰';
  const u=['بایت','کیلوبایت','مگابایت','گیگابایت','ترابایت'];
  let i=0,v=bytes;
  while(v>=1024&&i<4){v/=1024;i++}
  return fa(v.toFixed(v<10&&i>1?2:0))+' '+u[i];
}
function daysLeft(ts){return ts?Math.max(0,Math.ceil((ts-Date.now())/86400000)):null}

function esc(s){return String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}

function toast(msg,ok){
  const t=document.createElement('div');
  t.className='toast'+(ok?' ok':'');
  t.textContent=msg;
  $('#toasts').appendChild(t);
  setTimeout(()=>{t.style.opacity='0';t.style.transition='.3s';setTimeout(()=>t.remove(),320)},2400);
}

/* apply ISP preset to a link (client-side tunables) */
function tunedLink(link){
  try{
    const u=new URL(link);
    u.searchParams.set('fp',ACTIVE_PRESET.fp||'chrome');
    if(ACTIVE_PRESET.frag){
      const f=ACTIVE_PRESET.frag;
      u.searchParams.set('frag',f[0]+'-'+f[1]+'-'+f[2]+'-'+f[3]);
    }else{
      u.searchParams.delete('frag');
    }
    return u.toString();
  }catch(e){return link}
}

function statusInfo(){
  const s=D.state;
  if(!s.ok){
    if(s.overQuota)return {cls:'st-quota',txt:'حجم تمام شده',icon:'⛔'};
    if(s.expired)return {cls:'st-exp',txt:'اشتراک منقضی شده',icon:'⏰'};
    return {cls:'st-off',txt:'غیرفعال',icon:'⏸'};
  }
  if(s.pending)return {cls:'st-pend',txt:'آماده — شروع با اولین اتصال',icon:'✨'};
  return {cls:'st-ok',txt:'اشتراک فعال',icon:'✅'};
}

function ringSvg(pct){
  const r=48,c=2*Math.PI*r;
  return \`<div class="ring">
    <svg width="118" height="118">
      <circle class="track" cx="59" cy="59" r="\${r}" fill="none" stroke-width="9"/>
      <circle class="bar" cx="59" cy="59" r="\${r}" fill="none" stroke-width="9"
        stroke-dasharray="\${c}" stroke-dashoffset="\${c*(1-pct)}"/>
    </svg>
    <div class="mid"><b>\${fa(Math.round(pct*100))}٪</b><span>مصرف حجم</span></div>
  </div>\`;
}

function render(){
  const s=D.state;
  const st=statusInfo();
  const pct=s.quota===null?(s.used>0?1:0):Math.min(1,s.used/s.quota);
  const dl=daysLeft(s.expiryAt);
  const myWelcome=esc(D.welcome||'سلام! این اشتراک اختصاصی توئه. 🌷');
  const name=esc(D.name||'کاربر');

  const links=D.links.filter(l=>PROTO_FILTER==='all'||l.proto===PROTO_FILTER);
  const presetNote=ACTIVE_PRESET.note?('💡 '+esc(ACTIVE_PRESET.note)):'';

  $('#content').innerHTML=\`
  <div class="hero">
    <div class="hero-top">
      <div class="hello">سلام، \${name} 👋<small>\${myWelcome}</small></div>
      <div class="status-chip \${st.cls}">\${st.icon}<span class="dot"></span>\${st.txt}</div>
    </div>
    <div class="usage">
      \${ringSvg(pct)}
      <div class="umeta">
        <div class="cell"><div class="k">مصرف شده</div><div class="v">\${gb(s.used)}</div></div>
        <div class="cell"><div class="k">\${s.quota===null?'سهمیه':'باقی‌مانده'}</div><div class="v">\${s.quota===null?'نامحدود ∞':gb(s.remainingBytes)}</div></div>
        <div class="cell"><div class="k">\${s.expiryAt===null?'اعتبار':'تاریخ انقضا'}</div><div class="v">\${s.expiryAt===null?'نامحدود ∞':jalali(s.expiryAt)}</div></div>
        <div class="cell"><div class="k">\${s.expiryAt===null?'وضعیت':'روز باقی‌مانده'}</div><div class="v">\${s.expiryAt===null?'همیشه':(dl+' روز')}</div></div>
      </div>
    </div>
    <div class="bigacts">
      <button class="bbtn bbtn-red" id="copyAll">📋 کپی همه کانفیگ‌ها</button>
      <button class="bbtn bbtn-ghost" id="copySub">🔗 کپی لینک ساب‌اسکریپشن</button>
    </div>
  </div>

  <section>
    <div class="sec-title">📡 کانفیگ‌های اختصاصی</div>
    <div class="tabs" id="ispTabs">
      \${D.presets.map(p=>\`<button class="tab\${p.id===ACTIVE_PRESET.id?' on':''}" data-p="\${p.id}">\${esc(p.label)}</button>\`).join('')}
    </div>
    <div class="preset-note">\${presetNote}</div>
    <div class="tabs" id="protoTabs" style="margin-top:10px">
      <button class="tab\${PROTO_FILTER==='all'?' on':''}" data-pt="all">همه پروتکل‌ها</button>
      <button class="tab\${PROTO_FILTER==='vless'?' on':''}" data-pt="vless">VLESS</button>
      <button class="tab\${PROTO_FILTER==='trojan'?' on':''}" data-pt="trojan">Trojan</button>
    </div>
    <div id="cfgList" style="margin-top:14px">
      \${links.map((l,i)=>\`
      <div class="cfg">
        <div class="cfg-head">
          <div class="nm"><span class="flag">\${l.proto==='vless'':'🛡'}</span>\${esc(l.name)} — \${esc(D.brand?.fa||'جاویدنام')}</div>
          <span class="proto-tag proto-\${l.proto}">\${l.proto.toUpperCase()}</span>
        </div>
        <div class="cfg-link" id="lnk\${i}">\${esc(tunedLink(l.link))}</div>
        <div class="cfg-acts">
          <button class="cbtn" onclick="copyLink(\${i})">📋 کپی لینک</button>
          <button class="cbtn" onclick="showQr(\${i})">📱 QR</button>
        </div>
      </div>\`).join('')}
      \${!links.length?'<div style="text-align:center;color:var(--mut);padding:24px">کانفیگی با این فیلتر نیست</div>':''}
    </div>
  </section>

  <section>
    <div class="sec-title">📖 راهنمای اتصال</div>
    <div class="guide-tabs" id="guideTabs">
      <button class="tab on" data-g="v2rayng">v2rayNG (اندروید)</button>
      <button class="tab" data-g="hiddify">Hiddify</button>
      <button class="tab" data-g="ios">iOS (Streisand/V2Box)</button>
    </div>
    <div class="steps" id="guideBody" style="margin-top:12px"></div>
  </section>

  <section>
    <div class="sec-title">🧩 تنظیم Fragment (ضد فیلترینگ)</div>
    <div class="steps">
      <table class="frag">
        <tr><th>اپراتور</th><th>Length</th><th>Interval</th><th>توضیح</th></tr>
        \${D.presets.filter(p=>p.frag).map(p=>\`
        <tr><td><b>\${esc(p.label)}</b></td>
        <td><span class="kbd">\${p.frag[0]}-\${p.frag[1]}</span></td>
        <td><span class="kbd">\${p.frag[2]}-\${p.frag[3]}</span></td>
        <td style="color:var(--mut)">\${esc(p.note||'')}</td></tr>\`).join('')}
      </table>
      <p style="font-size:12px;color:var(--mut2);margin-top:10px">
        در v2rayNG: تنظیمات ← Fragment را فعال کنید و مقادیر بالا را وارد کنید. کانفیگ‌های هر تب اپراتور همین بالا به‌صورت خودکار بهینه شده‌اند.
      </p>
    </div>
  </section>\`;

  $('#foot').innerHTML=\`
    \${D.show_branding!==false?\`
    <div class="memorial"><span class="candle">🕯</span>
      به یاد جان‌باختگان ۱۸ و ۱۹ دی ۱۴۰۴<br><b>نامشان جاوید</b></div>\`:''}
    <div class="meta">
      JavidNam v\${esc(D.version)} — بدون تبلیغ، بدون محدودیت مصنوعی<br>
      \${D.contact?('راه ارتباطی: '+esc(D.contact)+'<br>'):''}
      ساخته‌شده روی Cloudflare Workers
    </div>\`;

  /* wire events */
  $('#copyAll').onclick=async()=>{
    const txt=D.links.map(l=>tunedLink(l.link)).join('\\n');
    await copyText(txt,'همه کانفیگ‌ها کپی شد ✅');
  };
  $('#copySub').onclick=async()=>{ await copyText(D.sub_url,'لینک ساب کپی شد ✅'); };
  $$('#ispTabs .tab').forEach(b=>b.onclick=()=>{
    ACTIVE_PRESET=D.presets.find(p=>p.id===b.dataset.p)||ACTIVE_PRESET;
    render();
  });
  $$('#protoTabs .tab').forEach(b=>b.onclick=()=>{ PROTO_FILTER=b.dataset.pt; render(); });
  $$('#guideTabs .tab').forEach(b=>b.onclick=()=>{
    $$('#guideTabs .tab').forEach(x=>x.classList.toggle('on',x===b));
    renderGuide(b.dataset.g);
  });
  renderGuide('v2rayng');
}

const GUIDES={
  v2rayng:[
    'اپ <b>v2rayNG</b> را از گوگل‌پلی یا GitHub نصب کنید.',
    'روی صفحه اصلی، آیکون <b>＋</b> (بالای صفحه) را بزنید و <b>«دسترسی از حافظه/Import from clipboard»</b> را انتخاب کنید.',
    'یکی از کانفیگ‌های بالا را <b>کپی</b> کرده و در اپ Paste کنید؛ یا دکمه <b>QR</b> را بزنید و دوربین را به کد بگیرید.',
    'بهتر: از <b>لینک ساب‌اسکریپشن</b> استفاده کنید — در v2rayNG: ← «Subscription» ← افزودن؛ آدرس ساب را وارد کنید. با هر تغییر پنل، خودکار آپدیت می‌شود.',
    'بالای اپ را به <b>VPN</b> وصل کنید و اینترنت آزاد را تجربه کنید 🌷',
  ],
  hiddify:[
    'اپ <b>Hiddify Next</b> را نصب کنید (اندروید/iOS/ویندوز).',
    'در صفحه اصلی، <b>「+」</b> را بزنید و <b>«افزودن از کلیپ‌بورد»</b> را انتخاب کنید.',
    'لینک ساب‌اسکریپشن یا کانفیگ کپی‌شده را وارد کنید.',
    'دکمه اتصال بزرگ را بزنید — تمام!',
  ],
  ios:[
    'اپ <b>Streisand</b> یا <b>V2Box</b> یا <b>Shadowrocket</b> را از App Store نصب کنید.',
    'در <b>Streisand</b>: منو ← <b>Add Config</b> ← <b>Copy from clipboard</b>.',
    'یا دکمه <b>QR</b> این صفحه را با دوربین اپ اسکن کنید.',
    'باتصل، همه چیز آماده است.',
  ],
};
function renderGuide(k){
  $('#guideBody').innerHTML='<ol>'+GUIDES[k].map(s=>'<li>'+s+'</li>').join('')+'</ol>';
}

async function copyText(txt,msg){
  try{
    await navigator.clipboard.writeText(txt);
    toast(msg,true);
  }catch(e){
    const ta=document.createElement('textarea');
    ta.value=txt;document.body.appendChild(ta);ta.select();
    try{document.execCommand('copy');toast(msg,true)}catch(e2){toast('کپی نشد — دستی کپی کنید')}
    ta.remove();
  }
}
function copyLink(i){
  const l=D.links[i];
  copyText(tunedLink(l.link),'کانفیگ '+l.name+' کپی شد ✅');
}
function showQr(i){
  const l=D.links[i];
  const link=tunedLink(l.link);
  const host=$('#modalHost');
  host.innerHTML=\`<div class="modal-bg" id="mbg"><div class="modal">
    <h4>\${esc(l.name)} — \${esc(D.brand?.fa||'جاویدنام')}</h4>
    <div id="qrBox"></div>
    <div class="hint">\${esc(link.slice(0,90))}…</div>
    <div style="margin-top:14px"><button class="bbtn bbtn-ghost" style="width:100%" onclick="document.getElementById('mbg').remove()">بستن</button></div>
  </div></div>\`;
  const qr=qrcode(0,'M');
  qr.addData(link);
  qr.make();
  const n=qr.getModuleCount();
  const cell=Math.max(3,Math.floor(220/n));
  const cv=document.createElement('canvas');
  cv.width=cv.height=n*cell;
  const cx=cv.getContext('2d');
  cx.fillStyle='#ffffff';cx.fillRect(0,0,cv.width,cv.height);
  cx.fillStyle='#0a0a10';
  for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(qr.isDark(y,x))cx.fillRect(x*cell,y*cell,cell,cell);
  $('#qrBox').appendChild(cv);
  $('#mbg').onclick=e=>{if(e.target.id==='mbg')e.target.remove()};
}

/* live refresh every 60s */
setInterval(async()=>{
  try{
    const r=await fetch(location.pathname+'?json=1',{cache:'no-store'});
    if(!r.ok)return;
    const j=await r.json();
    D.state=j.state;D.name=j.name||D.name;
    render();
  }catch(e){}
},60000);

render();
</script>
</body>
</html>
`;
