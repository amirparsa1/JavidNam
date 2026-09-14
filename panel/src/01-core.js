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
