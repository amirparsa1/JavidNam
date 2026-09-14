/* ============================================================
 * JavidNam Panel — BUILT ARTIFACT (edit src/ + assets/, then run build.mjs)
 * جاویدنام — به یاد جان‌باختگان ۱۸ و ۱۹ دی ۱۴۰۴
 * License: GPL-3.0 | QR: qrcode-generator 1.4.4 (MIT, Kazuhiko Arase)
 * Build time: 2026-09-14T16:15:00.521Z
 * ============================================================ */

/**
 * ============================================================================
 *  JavidNam Panel v2 — جاویدنام
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

const VERSION = '2.0.0';
const BRAND = {
  fa: 'جاویدنام',
  en: 'JavidNam',
  memorial: 'به یاد جان‌باختگان ۱۸ و ۱۹ دی ۱۴۰۴',
  eternal: 'نامشان جاوید',
  repo: 'https://github.com/amirparsa1/JavidNam',
  raw: 'https://raw.githubusercontent.com/amirparsa1/JavidNam/main/panel/javidnam-worker.js',
};

/* ------------------------------------------------------------------ */
/* Encoding & crypto helpers                                            */
/* ------------------------------------------------------------------ */

const TE = new TextEncoder();
const TD = new TextDecoder();

function hex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function sha256hex(str) { return hex(await crypto.subtle.digest('SHA-256', TE.encode(str))); }
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
function rndHex(nBytes) { const b = new Uint8Array(nBytes); crypto.getRandomValues(b); return hex(b); }
function randomPassword(len = 16) {
  const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const b = new Uint8Array(len); crypto.getRandomValues(b);
  return [...b].map(x => chars[x % chars.length]).join('');
}
function isUuid(s) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s); }
function b64encode(str) { return btoa(String.fromCharCode(...TE.encode(str))); }
function strHash(s) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
function isIPv4(h) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(h); }
function isIPv6(h) { return h.includes(':'); }

/* ------------------------------------------------------------------ */
/* HTTP helpers                                                         */
/* ------------------------------------------------------------------ */

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'SAMEORIGIN',
};
function jsonResponse(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...SECURITY_HEADERS, ...extra } });
}
function htmlResponse(body, status = 200, extra = {}) {
  return new Response(body, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...SECURITY_HEADERS, ...extra } });
}
function textResponse(body, extra = {}) {
  return new Response(body, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', ...extra } });
}
function notFound() { return new Response('404', { status: 404, headers: SECURITY_HEADERS }); }

/* ------------------------------------------------------------------ */
/* Env / D1                                                             */
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

const USER_COLUMNS_V2 = [
  ['max_requests', 'INTEGER DEFAULT 0'],
  ['used_requests', 'INTEGER DEFAULT 0'],
  ['locations', 'TEXT'],
  ['block_ads', 'INTEGER DEFAULT 0'],
  ['block_nsfw', 'INTEGER DEFAULT 0'],
  ['last_seen_at', 'INTEGER'],
  ['last_ip', 'TEXT'],
  ['reset_requests', 'INTEGER DEFAULT 0'],
];

let _schemaEnsured = false;
async function ensureSchema() {
  if (_schemaEnsured) return;
  await DB.batch([
    DB.prepare(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, uuid TEXT UNIQUE NOT NULL, trojan_hash TEXT, name TEXT,
      sub_token TEXT UNIQUE NOT NULL, quota_bytes INTEGER DEFAULT 0, used_bytes INTEGER DEFAULT 0,
      reset_hours INTEGER DEFAULT 0, last_reset_at INTEGER, days INTEGER DEFAULT 0, expiry_at INTEGER,
      start_on_first INTEGER DEFAULT 0, first_connect_at INTEGER, ip_limit INTEGER DEFAULT 0,
      active INTEGER DEFAULT 1, note TEXT, created_at INTEGER,
      max_requests INTEGER DEFAULT 0, used_requests INTEGER DEFAULT 0, locations TEXT,
      block_ads INTEGER DEFAULT 0, block_nsfw INTEGER DEFAULT 0, last_seen_at INTEGER, last_ip TEXT,
      reset_requests INTEGER DEFAULT 0)`),
    DB.prepare(`CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid)`),
    DB.prepare(`CREATE INDEX IF NOT EXISTS idx_users_trojan ON users(trojan_hash)`),
    DB.prepare(`CREATE INDEX IF NOT EXISTS idx_users_token ON users(sub_token)`),
    DB.prepare(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`),
    DB.prepare(`CREATE TABLE IF NOT EXISTS login_attempts (ip TEXT PRIMARY KEY, fails INTEGER DEFAULT 0, banned_until INTEGER)`),
    DB.prepare(`CREATE TABLE IF NOT EXISTS metrics (day TEXT PRIMARY KEY, requests INTEGER DEFAULT 0, conns INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0)`),
  ]);
  /* v1 → v2 migration: add missing columns (ignore "duplicate column") */
  for (const [col, type] of USER_COLUMNS_V2) {
    try { await DB.prepare(`ALTER TABLE users ADD COLUMN ${col} ${type}`).run(); } catch (e) {}
  }
  _schemaEnsured = true;
}

function needsSchema(e) {
  const m = String(e && e.message || e);
  return m.includes('no such table') || m.includes('no such column') || m.includes('has no column');
}
async function dbAll(sql, params = []) {
  try { const { results } = await DB.prepare(sql).bind(...params).all(); return results || []; }
  catch (e) { if (!needsSchema(e)) throw e; _schemaEnsured = false; await ensureSchema(); const { results } = await DB.prepare(sql).bind(...params).all(); return results || []; }
}
async function dbGet(sql, params = []) {
  try { return await DB.prepare(sql).bind(...params).first(); }
  catch (e) { if (!needsSchema(e)) throw e; _schemaEnsured = false; await ensureSchema(); return await DB.prepare(sql).bind(...params).first(); }
}
async function dbRun(sql, params = []) {
  try { return await DB.prepare(sql).bind(...params).run(); }
  catch (e) { if (!needsSchema(e)) throw e; _schemaEnsured = false; await ensureSchema(); return await DB.prepare(sql).bind(...params).run(); }
}

/* ------------------------------------------------------------------ */
/* Settings                                                             */
/* ------------------------------------------------------------------ */

const FP_OPTIONS = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random', 'randomized', 'qq', '360'];

const AI_DOMAINS_DEFAULT = [
  'gemini.google.com', 'aistudio.google.com', 'generativelanguage.googleapis.com', 'bard.google.com', 'makersuite.google.com',
  'openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com', 'auth0.openai.com',
  'claude.ai', 'anthropic.com', 'copilot.microsoft.com', 'bing.com',
  'x.ai', 'grok.com', 'perplexity.ai', 'midjourney.com', 'huggingface.co', 'deepseek.com',
];

/* default clean anycast ranges (Cloudflare public ranges; scanner in panel finds better ones) */
const CLEAN_IPS_DEFAULT = ['104.16.0.0', '104.17.0.0', '104.18.0.0', '104.19.0.0', '162.159.128.0', '172.67.0.0', '188.114.96.0', '188.114.97.0'];

const SETTING_DEFAULTS = {
  proxy_path: '/jvn-setup',            // seeded random on first read
  title: 'جاویدنام | JavidNam',
  welcome: 'سلام! این اشتراک اختصاصی توئه. لذت ببر 🌷',
  contact: '',
  sub_branding: true,
  /* network */
  fp: 'chrome',
  alpn: 'h2,http/1.1',
  frag_enabled: true,
  frag_len: '10-20',
  frag_int: '10-20',
  frag_packets: 'tlshello',
  sni_mask: '',                        // custom SNI (TLS masking); empty = location host
  host_mask: '',                       // custom WS Host header; empty = panel host
  /* outbound */
  proxy_ip: '',                        // global fallback proxyIP host[:port] for CF-fronted targets
  proxy_ips: [],                       // VIP proxy pool (proxyip:.. or socks5://..) — round-robin + failover
  auto_proxy: false,                   // pull pool from BRAND.repo proxies list when empty
  ai_route: '',                        // '' | 'pool' | outbound spec — route AI domains via this
  ai_domains: AI_DOMAINS_DEFAULT,
  block_hosts: [],                     // extra blocked hosts (global)
  dns: 'https://1.1.1.1/dns-query',
  /* clean ip rotation */
  clean_ips: CLEAN_IPS_DEFAULT,
  clean_count: 2,
  rotate_minutes: 0,                   // 0 = static (hash by user), N = rotate every N minutes
  /* locations: id, name, host, port, tls, sni, out (outbound spec), enabled */
  locations: [
    { id: 'main', name: 'اصلی', host: '__PANEL_HOST__', port: 443, tls: true, sni: '', out: 'direct', enabled: true },
    { id: 'clean', name: 'IP تمیز', host: '__CLEAN_IP__', port: 443, tls: true, sni: '', out: 'direct', enabled: true },
  ],
  cf_token: '',                        // for in-panel OTA (optional)
};
const LIST_KEYS = ['locations', 'proxy_ips', 'ai_domains', 'block_hosts', 'clean_ips'];
const BOOL_KEYS = ['sub_branding', 'frag_enabled', 'auto_proxy'];
const NUM_KEYS = ['clean_count', 'rotate_minutes'];

let _settingsCache = null;
let _settingsCacheAt = 0;
const SETTINGS_TTL = 20_000;

function coerceSetting(k, v) {
  if (LIST_KEYS.includes(k)) { if (typeof v === 'string') { try { v = JSON.parse(v); } catch (e) { v = null; } } return Array.isArray(v) ? v : null; }
  if (BOOL_KEYS.includes(k)) return v === true || v === 'true' || v === 1 || v === '1';
  if (NUM_KEYS.includes(k)) return Number(v) || 0;
  return v == null ? '' : String(v);
}

async function getSettings(force = false) {
  const now = Date.now();
  if (!force && _settingsCache && now - _settingsCacheAt < SETTINGS_TTL) return _settingsCache;
  let rows = [];
  try { rows = await dbAll('SELECT key, value FROM settings'); } catch (e) {}
  if (!rows.find(r => r.key === 'proxy_path')) {
    const candidate = '/jvn-' + rndHex(5);
    try {
      await dbRun("INSERT INTO settings (key, value) VALUES ('proxy_path', ?) ON CONFLICT(key) DO NOTHING", [candidate]);
      rows = await dbAll('SELECT key, value FROM settings');
    } catch (e) { rows = []; }
  }
  const s = JSON.parse(JSON.stringify(SETTING_DEFAULTS));
  for (const r of rows) {
    if (!(r.key in SETTING_DEFAULTS)) { s[r.key] = r.value; continue; }
    const v = coerceSetting(r.key, r.value);
    if (v !== null) s[r.key] = v;
  }
  /* locations sanity + v1 compatibility (no id/out) */
  if (!Array.isArray(s.locations) || !s.locations.length) s.locations = JSON.parse(JSON.stringify(SETTING_DEFAULTS.locations));
  s.locations = s.locations.map((l, i) => ({
    id: String(l.id || ('loc' + i)).slice(0, 24), name: String(l.name || 'لوکیشن').slice(0, 40),
    host: String(l.host || '__PANEL_HOST__'), port: Number(l.port) || 443, tls: l.tls !== false,
    sni: String(l.sni || ''), out: String(l.out || 'direct'), enabled: l.enabled !== false,
  }));
  _settingsCache = s; _settingsCacheAt = now;
  return s;
}

async function saveSettings(patch) {
  for (const k of Object.keys(SETTING_DEFAULTS)) {
    if (!(k in patch)) continue;
    let v = patch[k];
    if (k === 'proxy_path') {
      v = String(v || '').trim();
      if (!/^\/[A-Za-z0-9_-]{3,64}$/.test(v)) throw new Error('مسیر پروکسی نامعتبره (مثال: /jvn-myPath)');
    }
    if (k === 'locations') {
      if (!Array.isArray(v) || !v.length || v.length > 16) throw new Error('لیست لوکیشن‌ها باید بین ۱ تا ۱۶ آیتم باشه');
      const seen = new Set();
      v = v.map((l, i) => {
        let id = String(l.id || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 24) || ('loc' + rndHex(2));
        while (seen.has(id)) id = id + rndHex(1);
        seen.add(id);
        return {
          id, name: String(l.name || 'لوکیشن').slice(0, 40), host: String(l.host || '').trim().slice(0, 200),
          port: Math.min(65535, Math.max(1, Number(l.port) || 443)), tls: l.tls !== false,
          sni: String(l.sni || '').trim().slice(0, 200), out: normalizeOutbound(l.out), enabled: l.enabled !== false,
        };
      }).filter(l => l.host);
    }
    if (k === 'proxy_ips') v = (Array.isArray(v) ? v : String(v).split(/[\n,]+/)).map(x => normalizeOutbound(String(x).trim())).filter(x => x && x !== 'direct').slice(0, 64);
    if (k === 'ai_domains' || k === 'block_hosts') v = (Array.isArray(v) ? v : String(v).split(/[\n,\s]+/)).map(x => String(x).trim().toLowerCase()).filter(Boolean).slice(0, 500);
    if (k === 'clean_ips') v = (Array.isArray(v) ? v : String(v).split(/[\n,\s]+/)).map(x => String(x).trim()).filter(x => isIPv4(x) || /^[0-9a-f:]+$/i.test(x) && x.includes(':') || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(x)).slice(0, 200);
    if (k === 'proxy_ip') { v = String(v || '').trim(); if (v && !/^[a-zA-Z0-9.\-:\[\]]+$/.test(v)) throw new Error('ProxyIP نامعتبره'); }
    if (k === 'ai_route') { v = String(v || '').trim(); if (v && v !== 'pool') v = normalizeOutbound(v); }
    if (k === 'fp') { v = String(v || 'chrome'); if (!FP_OPTIONS.includes(v)) v = 'chrome'; }
    if (k === 'dns') { v = String(v || '').trim(); if (v && !/^https:\/\//.test(v)) throw new Error('DNS باید آدرس DoH با https باشد'); }
    if (BOOL_KEYS.includes(k)) v = (v === true || v === 'true' || v === 1 || v === '1') ? 'true' : 'false';
    if (NUM_KEYS.includes(k)) v = String(Math.max(0, Number(v) || 0));
    if (typeof v !== 'string') v = JSON.stringify(v);
    await dbRun('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', [k, v]);
  }
  _settingsCache = null;
  return await getSettings(true);
}

/* Outbound spec: 'direct' | 'proxyip:host[:port]' | 'socks5://[user:pass@]host:port' | bare 'host[:port]' => proxyip */
function normalizeOutbound(spec) {
  spec = String(spec || '').trim();
  if (!spec || spec === 'direct') return 'direct';
  if (/^socks5?:\/\//i.test(spec)) return spec.replace(/^socks:\/\//i, 'socks5://');
  if (/^proxyip:/i.test(spec)) return 'proxyip:' + spec.slice(8).trim();
  return 'proxyip:' + spec;
}
function parseOutbound(spec) {
  spec = normalizeOutbound(spec);
  if (spec === 'direct') return { type: 'direct' };
  if (spec.startsWith('socks5://')) {
    try {
      const u = new URL(spec);
      return { type: 'socks5', host: u.hostname.replace(/^\[|\]$/g, ''), port: Number(u.port) || 1080, user: decodeURIComponent(u.username || ''), pass: decodeURIComponent(u.password || '') };
    } catch (e) { return { type: 'direct' }; }
  }
  const hp = spec.slice(8);
  const m = hp.match(/^\[?([^\]]+?)\]?(?::(\d+))?$/);
  return { type: 'proxyip', host: m ? m[1] : hp, port: m && m[2] ? Number(m[2]) : 0 };
}

/* Resolve placeholders: __PANEL_HOST__ and __CLEAN_IP__ (rotation-aware) */
function cleanIpsFor(settings, seed, count) {
  const ips = settings.clean_ips || [];
  if (!ips.length) return [];
  const slot = settings.rotate_minutes > 0 ? Math.floor(Date.now() / (settings.rotate_minutes * 60000)) : 0;
  const base = (strHash(String(seed)) + slot) % ips.length;
  const out = [];
  for (let i = 0; i < Math.min(count, ips.length); i++) out.push(ips[(base + i) % ips.length]);
  return out;
}
function resolveLocations(settings, requestHost, seed = 'x') {
  const out = [];
  for (const l of settings.locations) {
    if (!l.enabled) continue;
    if (l.host === '__CLEAN_IP__') {
      const ips = cleanIpsFor(settings, seed, Math.max(1, settings.clean_count || 1));
      ips.forEach((ip, i) => out.push({ ...l, id: ips.length > 1 ? `${l.id}${i + 1}` : l.id, baseId: l.id, name: ips.length > 1 ? `${l.name} ${i + 1}` : l.name, host: ip, sni: l.sni || requestHost, isClean: true }));
      continue;
    }
    out.push({ ...l, baseId: l.id, host: l.host === '__PANEL_HOST__' ? requestHost : l.host });
  }
  return out;
}
function findLocation(settings, id) {
  if (!id) return null;
  return settings.locations.find(l => l.id === id) || settings.locations.find(l => id.startsWith(l.id)) || null;
}

/* ------------------------------------------------------------------ */
/* Metrics (CF quota monitor) — isolate counters, throttled flush       */
/* ------------------------------------------------------------------ */

const _metrics = { requests: 0, conns: 0, bytes: 0, at: 0 };
function todayKey() { return new Date().toISOString().slice(0, 10); }
function countRequest() { _metrics.requests++; }
function countConn() { _metrics.conns++; }
function countBytes(n) { _metrics.bytes += n; }
async function flushMetrics(force = false) {
  const now = Date.now();
  if (!force && now - _metrics.at < 30_000) return;
  if (!_metrics.requests && !_metrics.conns && !_metrics.bytes) return;
  const r = _metrics.requests, c = _metrics.conns, b = _metrics.bytes;
  _metrics.requests = 0; _metrics.conns = 0; _metrics.bytes = 0; _metrics.at = now;
  try {
    await dbRun('INSERT INTO metrics (day, requests, conns, bytes) VALUES (?, ?, ?, ?) ON CONFLICT(day) DO UPDATE SET requests = requests + excluded.requests, conns = conns + excluded.conns, bytes = bytes + excluded.bytes', [todayKey(), r, c, b]);
  } catch (e) { _metrics.requests += r; _metrics.conns += c; _metrics.bytes += b; }
}

/* ------------------------------------------------------------------ */
/* User cache + traffic accounting                                      */
/* ------------------------------------------------------------------ */

const USER_TTL = 60_000;
const FLUSH_INTERVAL = 45_000;
const IP_WINDOW = 3 * 60_000;

const _userCache = new Map();      // uuid -> { user, at }
const _hashCache = new Map();      // trojan hash -> uuid
const _dirty = new Map();          // uuid -> { bytes, reqs, at, lastIp }
const _ipMap = new Map();          // uuid -> Map(ip -> lastSeen)

async function getUserByUuid(uuid, force = false) {
  const now = Date.now();
  const c = _userCache.get(uuid);
  if (!force && c && now - c.at < USER_TTL) return c.user;
  const user = await dbGet('SELECT * FROM users WHERE uuid = ?', [uuid]);
  if (user) _userCache.set(uuid, { user, at: now });
  return user;
}
async function getUserByTrojanHash(hash) {
  const uuid = _hashCache.get(hash);
  if (uuid) { const u = await getUserByUuid(uuid); if (u) return u; }
  const row = await dbGet('SELECT * FROM users WHERE trojan_hash = ?', [hash]);
  if (row) { _hashCache.set(hash, row.uuid); _userCache.set(row.uuid, { user: row, at: Date.now() }); }
  return row || null;
}
function cacheUser(user) { _userCache.set(user.uuid, { user, at: Date.now() }); }
function invalidateUser(uuid) { _userCache.delete(uuid); }

function addUsage(uuid, bytes) {
  if (bytes <= 0) return;
  const d = _dirty.get(uuid) || { bytes: 0, reqs: 0, at: 0, lastIp: null };
  d.bytes += bytes; _dirty.set(uuid, d);
  countBytes(bytes);
}
function addRequest(uuid, ip) {
  const d = _dirty.get(uuid) || { bytes: 0, reqs: 0, at: 0, lastIp: null };
  d.reqs += 1; d.lastIp = ip; _dirty.set(uuid, d);
  const c = _userCache.get(uuid); if (c) c.user.used_requests = (c.user.used_requests || 0) + 1;
}
async function flushUsage(uuid, force = false) {
  const d = _dirty.get(uuid);
  if (!d || (d.bytes <= 0 && d.reqs <= 0)) return;
  const now = Date.now();
  if (!force && now - d.at < FLUSH_INTERVAL) return;
  d.at = now;
  const b = d.bytes, r = d.reqs, ip = d.lastIp;
  try {
    await dbRun('UPDATE users SET used_bytes = used_bytes + ?, used_requests = used_requests + ?, last_seen_at = ?, last_ip = COALESCE(?, last_ip) WHERE uuid = ?', [b, r, now, ip, uuid]);
    d.bytes -= b; d.reqs -= r;
  } catch (e) {}
}
function flushAllUsage() { return Promise.all([..._dirty.keys()].map(u => flushUsage(u, true))); }

function ipAllowed(uuid, ip, limit) {
  if (!limit || limit <= 0) return true;
  let m = _ipMap.get(uuid);
  if (!m) { m = new Map(); _ipMap.set(uuid, m); }
  const now = Date.now();
  for (const [k, t] of m) if (now - t > IP_WINDOW) m.delete(k);
  m.set(ip, now);
  return m.size <= limit;
}
function activeIps(uuid) {
  const m = _ipMap.get(uuid); if (!m) return 0;
  const now = Date.now(); let n = 0;
  for (const [, t] of m) if (now - t <= IP_WINDOW) n++;
  return n;
}

/* ------------------------------------------------------------------ */
/* User state                                                           */
/* ------------------------------------------------------------------ */

function userState(user) {
  const now = Date.now();
  const quota = user.quota_bytes > 0 ? user.quota_bytes : null;
  const used = user.used_bytes || 0;
  const overQuota = quota !== null && used >= quota;
  const expired = !!user.expiry_at && now > user.expiry_at;
  const pending = !!user.start_on_first && !user.first_connect_at;
  const maxReq = user.max_requests > 0 ? user.max_requests : null;
  const usedReq = user.used_requests || 0;
  const overRequests = maxReq !== null && usedReq >= maxReq;
  return {
    ok: !!user.active && !overQuota && !expired && !overRequests,
    active: !!user.active, overQuota, expired, pending, overRequests,
    expiryAt: user.expiry_at || null, quota, used,
    remainingBytes: quota === null ? null : Math.max(0, quota - used),
    maxRequests: maxReq, usedRequests: usedReq,
    lastSeenAt: user.last_seen_at || null,
    daysLeft: user.expiry_at ? Math.max(0, Math.ceil((user.expiry_at - now) / 86400000)) : null,
  };
}
function userLocationIds(user) {
  if (!user.locations) return null;
  try { const a = JSON.parse(user.locations); return Array.isArray(a) && a.length ? a : null; } catch (e) { return null; }
}
function pathMatches(urlPath, proxyPath) { return urlPath === proxyPath || urlPath === proxyPath + '/'; }

/* ------------------------------------------------------------------ */
/* DNS wireformat + filtered DoH (content blocking engine)              */
/* ------------------------------------------------------------------ */

const DOH_ADS = 'https://dns.adguard-dns.com/dns-query';           // ads + trackers
const DOH_FAMILY = 'https://family.cloudflare-dns.com/dns-query';  // 1.1.1.3: malware + adult

function buildDnsQuery(name, qtype = 1) {
  const labels = name.split('.').filter(Boolean);
  const qname = [];
  for (const l of labels) { const b = TE.encode(l); qname.push(b.length, ...b); }
  qname.push(0);
  const id = Math.floor(Math.random() * 65535);
  return new Uint8Array([id >> 8, id & 255, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, ...qname, 0, qtype, 0, 1]);
}
function parseDnsAnswer(u8) {
  const rcode = u8[3] & 0x0f;
  const qd = (u8[4] << 8) | u8[5], an = (u8[6] << 8) | u8[7];
  let i = 12;
  const skipName = () => { while (i < u8.length) { const l = u8[i]; if (l === 0) { i++; return; } if ((l & 0xc0) === 0xc0) { i += 2; return; } i += l + 1; } };
  for (let q = 0; q < qd; q++) { skipName(); i += 4; }
  const ips = [];
  for (let a = 0; a < an && i < u8.length; a++) {
    skipName();
    const type = (u8[i] << 8) | u8[i + 1]; i += 8;
    const rdl = (u8[i] << 8) | u8[i + 1]; i += 2;
    if (type === 1 && rdl === 4) ips.push(`${u8[i]}.${u8[i + 1]}.${u8[i + 2]}.${u8[i + 3]}`);
    i += rdl;
  }
  return { rcode, ips };
}
const _filterCache = new Map(); // key -> { blocked, at }
async function hostBlockedByFilter(host, mode) {
  if (isIPv4(host) || isIPv6(host)) return false;
  const key = mode + ':' + host.toLowerCase();
  const c = _filterCache.get(key);
  if (c && Date.now() - c.at < 10 * 60_000) return c.blocked;
  let blocked = false;
  try {
    const resp = await fetch(mode === 'ads' ? DOH_ADS : DOH_FAMILY, {
      method: 'POST', headers: { 'Content-Type': 'application/dns-message', Accept: 'application/dns-message' }, body: buildDnsQuery(host),
    });
    if (resp.ok) {
      const ans = parseDnsAnswer(new Uint8Array(await resp.arrayBuffer()));
      blocked = ans.rcode === 3 || (ans.ips.length > 0 && ans.ips.every(ip => ip === '0.0.0.0' || ip === '127.0.0.1'));
    }
  } catch (e) {}
  if (_filterCache.size > 5000) _filterCache.clear();
  _filterCache.set(key, { blocked, at: Date.now() });
  return blocked;
}
function matchesDomainList(host, list) {
  host = host.toLowerCase();
  for (const d of list) { if (!d) continue; if (host === d || host.endsWith('.' + d)) return true; }
  return false;
}

/* Jalali date (for UI / status) */
function toJalali(ts) {
  const d = new Date(ts);
  let gy = d.getUTCFullYear(), gm = d.getUTCMonth() + 1, gd = d.getUTCDate();
  const g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
  let jy = gy <= 1600 ? 0 : 979; gy -= gy <= 1600 ? 621 : 1600;
  const gy2 = gm > 2 ? gy + 1 : gy;
  let days = 365 * gy + Math.floor((gy2 + 3) / 4) - Math.floor((gy2 + 99) / 100) + Math.floor((gy2 + 399) / 400) - 80 + gd + g_d_m[gm - 1];
  jy += 33 * Math.floor(days / 12053); days %= 12053;
  jy += 4 * Math.floor(days / 1461); days %= 1461;
  if (days > 365) { jy += Math.floor((days - 1) / 365); days = (days - 1) % 365; }
  const jm = days < 186 ? 1 + Math.floor(days / 31) : 7 + Math.floor((days - 186) / 30);
  const jd = 1 + (days < 186 ? days % 31 : (days - 186) % 30);
  return `${jy}/${String(jm).padStart(2, '0')}/${String(jd).padStart(2, '0')}`;
}

/* ------------------------------------------------------------------ */
/* PROXY CORE — VLESS & Trojan over WebSocket                           */
/* Outbound engine: direct → location outbound → ProxyIP → VIP pool     */
/* (auto-failover), SOCKS5 support, AI routing, content filtering.      */
/* Protocol references: public XTLS/VLESS spec & Trojan-Go spec.        */
/* ------------------------------------------------------------------ */

const VLESS_VER = 0x00;

function parseVlessHeader(buf) {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  if (u8.length < 24) return null;
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
  if (atyp === 0x01) { if (u8.length < i + 4) return null; host = `${u8[i]}.${u8[i + 1]}.${u8[i + 2]}.${u8[i + 3]}`; i += 4; }
  else if (atyp === 0x02) { if (u8.length < i + 1) return null; const len = u8[i]; i += 1; if (u8.length < i + len) return null; host = TD.decode(u8.subarray(i, i + len)); i += len; }
  else if (atyp === 0x03) { if (u8.length < i + 16) return null; const p = []; for (let j = 0; j < 16; j += 2) p.push(((u8[i + j] << 8) | u8[i + j + 1]).toString(16)); host = p.join(':'); i += 16; }
  else throw new Error('bad-atyp');
  return { proto: 'vless', uuid, cmd, host, port, rest: u8.subarray(i) };
}

/* Compact SHA-224 (FIPS 180-4) */
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
  const H = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
  const ml = bytes.length;
  const withPad = new Uint8Array((((ml + 9) >> 6) + 1) << 6);
  withPad.set(bytes); withPad[ml] = 0x80;
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
async function trojanHashOf(uuidStr) { return sha224hex(TE.encode(uuidStr)); }

function parseTrojanHeader(buf) {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  const nl = u8.indexOf(0x0d);
  if (nl < 0 || u8[nl + 1] !== 0x0a) return null;
  const hash = TD.decode(u8.subarray(0, nl)).toLowerCase();
  if (!/^[0-9a-f]{56}$/.test(hash)) throw new Error('bad-trojan-hash');
  let i = nl + 2;
  if (u8.length < i + 4) return null;
  const cmd = u8[i]; i += 1;
  if (cmd !== 0x01 && cmd !== 0x03) throw new Error('bad-trojan-cmd');
  const atyp = u8[i]; i += 1;
  let host = '';
  if (atyp === 0x01) { if (u8.length < i + 4) return null; host = `${u8[i]}.${u8[i + 1]}.${u8[i + 2]}.${u8[i + 3]}`; i += 4; }
  else if (atyp === 0x03) { if (u8.length < i + 1) return null; const len = u8[i]; i += 1; if (u8.length < i + len) return null; host = TD.decode(u8.subarray(i, i + len)); i += len; }
  else if (atyp === 0x04) { if (u8.length < i + 16) return null; const p = []; for (let j = 0; j < 16; j += 2) p.push(((u8[i + j] << 8) | u8[i + j + 1]).toString(16)); host = p.join(':'); i += 16; }
  else throw new Error('bad-trojan-atyp');
  const port = (u8[i] << 8) | u8[i + 1]; i += 2;
  if (u8[i] === 0x0d && u8[i + 1] === 0x0a) i += 2;
  return { proto: 'trojan', hash, cmd: cmd === 0x03 ? 0x02 : 0x01, host, port, rest: u8.subarray(i) };
}

/* --- UDP framing (VLESS): [len:2][data] ; DNS relayed through DoH --- */
function parseUdpDatagram(u8, offset = 0) {
  let i = offset;
  if (u8.length < i + 4) return null;
  const atyp = u8[i]; i += 1;
  let host = '';
  if (atyp === 0x01) { host = `${u8[i]}.${u8[i + 1]}.${u8[i + 2]}.${u8[i + 3]}`; i += 4; }
  else if (atyp === 0x02) { const len = u8[i]; i += 1; host = TD.decode(u8.subarray(i, i + len)); i += len; }
  else if (atyp === 0x03) { const p = []; for (let j = 0; j < 16; j += 2) p.push(((u8[i + j] << 8) | u8[i + j + 1]).toString(16)); host = p.join(':'); i += 16; }
  else return null;
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
  if (isIPv4(host)) parts.push(new Uint8Array([0x01, ...host.split('.').map(Number)]));
  else parts.push(new Uint8Array([0x02, hb.length, ...hb]));
  parts.push(new Uint8Array([(port >> 8) & 0xff, port & 0xff, (data.length >> 8) & 0xff, data.length & 0xff]));
  parts.push(data);
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
async function relayDns(datagram, dohUrl) {
  try {
    const resp = await fetch(dohUrl || 'https://1.1.1.1/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message', Accept: 'application/dns-message' }, body: datagram.data });
    if (!resp.ok) return null;
    const answer = new Uint8Array(await resp.arrayBuffer());
    if (!answer.length) return null;
    return frameUdpDatagram(datagram.host, datagram.port, answer);
  } catch (e) { return null; }
}

/* Length-prefixed VLESS UDP stream: [len:2][payload] chunks */
function splitVlessUdp(u8) {
  const out = []; let i = 0;
  while (i + 2 <= u8.length) { const l = (u8[i] << 8) | u8[i + 1]; i += 2; if (i + l > u8.length) break; out.push(u8.subarray(i, i + l)); i += l; }
  return out;
}

const BLOCKED_HOSTS = new Set([
  'speed.cloudflare.com', 'cp.cloudflare.com', 'dash.cloudflare.com', 'api.cloudflare.com',
]);

/* ------------------------------------------------------------------ */
/* Outbound engine                                                      */
/* ------------------------------------------------------------------ */

const _outHealth = new Map();   // spec -> { fails, at }
let _rr = 0;
let _autoPool = { list: [], at: 0 };

function markOut(spec, ok) {
  const h = _outHealth.get(spec) || { fails: 0, at: 0 };
  if (ok) { h.fails = 0; } else { h.fails++; h.at = Date.now(); }
  _outHealth.set(spec, h);
}
function outHealthy(spec) {
  const h = _outHealth.get(spec);
  if (!h || h.fails < 3) return true;
  return Date.now() - h.at > 5 * 60_000; // retry after cooldown
}

async function getProxyPool(settings) {
  let pool = (settings.proxy_ips || []).slice();
  if (!pool.length && settings.auto_proxy) {
    if (Date.now() - _autoPool.at > 10 * 60_000) {
      try {
        const r = await fetch(BRAND.repo.replace('github.com', 'raw.githubusercontent.com') + '/main/proxies/pool.txt', { cf: { cacheTtl: 600 } });
        if (r.ok) _autoPool = { list: (await r.text()).split(/\r?\n/).map(x => x.trim()).filter(x => x && !x.startsWith('#')).map(normalizeOutbound), at: Date.now() };
      } catch (e) { _autoPool.at = Date.now(); }
    }
    pool = _autoPool.list.slice();
  }
  return pool;
}

function buildPlan(settings, loc, host, pool) {
  const plan = [];
  const isAi = settings.ai_route && matchesDomainList(host, settings.ai_domains || []);
  if (isAi) {
    if (settings.ai_route === 'pool') plan.push(...pool);
    else plan.push(settings.ai_route);
  }
  const primary = normalizeOutbound(loc && loc.out);
  plan.push(primary);
  if (primary !== 'direct') plan.push('direct');
  if (settings.proxy_ip) plan.push('proxyip:' + settings.proxy_ip);
  if (pool.length) {
    const start = (_rr++) % pool.length;
    for (let i = 0; i < Math.min(3, pool.length); i++) plan.push(pool[(start + i) % pool.length]);
  }
  const seen = new Set();
  return plan.filter(s => { if (!s || seen.has(s)) return false; seen.add(s); return true; }).filter(s => s === 'direct' || outHealthy(s));
}

function withTimeout(p, ms, label = 'timeout') {
  let t;
  return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(label)), ms); })]).finally(() => clearTimeout(t));
}

async function readExact(reader, n, buf = new Uint8Array(0)) {
  while (buf.length < n) {
    const { done, value } = await reader.read();
    if (done) throw new Error('socks-eof');
    const nb = new Uint8Array(buf.length + value.length); nb.set(buf); nb.set(value, buf.length); buf = nb;
  }
  return buf;
}

async function socks5Connect(out, host, port) {
  const sock = connect({ hostname: out.host, port: out.port });
  await withTimeout(sock.opened, 5000, 'socks-open');
  const w = sock.writable.getWriter();
  const r = sock.readable.getReader();
  try {
    const hasAuth = !!(out.user || out.pass);
    await w.write(new Uint8Array(hasAuth ? [5, 2, 0, 2] : [5, 1, 0]));
    let buf = await withTimeout(readExact(r, 2), 5000, 'socks-greet');
    if (buf[0] !== 5) throw new Error('socks-bad-ver');
    if (buf[1] === 2) {
      const u = TE.encode(out.user || ''), p = TE.encode(out.pass || '');
      await w.write(new Uint8Array([1, u.length, ...u, p.length, ...p]));
      buf = await withTimeout(readExact(r, 2), 5000, 'socks-auth');
      if (buf[1] !== 0) throw new Error('socks-auth-failed');
    } else if (buf[1] !== 0) throw new Error('socks-no-method');
    let addr;
    if (isIPv4(host)) addr = new Uint8Array([1, ...host.split('.').map(Number)]);
    else if (isIPv6(host)) { const parts = host.split(':'); const full = []; const idx = parts.indexOf(''); const exp = idx >= 0 ? [...parts.slice(0, idx), ...Array(8 - parts.filter(Boolean).length).fill('0'), ...parts.slice(idx + 1).filter(Boolean)] : parts; for (const p of exp) { const v = parseInt(p || '0', 16); full.push(v >> 8, v & 255); } addr = new Uint8Array([4, ...full]); }
    else { const hb = TE.encode(host); addr = new Uint8Array([3, hb.length, ...hb]); }
    await w.write(new Uint8Array([5, 1, 0, ...addr, port >> 8, port & 255]));
    buf = await withTimeout(readExact(r, 5), 6000, 'socks-connect');
    if (buf[1] !== 0) throw new Error('socks-connect-failed-' + buf[1]);
    const alen = buf[3] === 1 ? 4 : buf[3] === 4 ? 16 : buf[4] + 1;
    buf = await withTimeout(readExact(r, 4 + alen + 2, buf), 5000, 'socks-connect2');
    /* leftover bytes (rare) are dropped safely: server won't speak before client */
  } finally { w.releaseLock(); r.releaseLock(); }
  return sock;
}

async function openOutbound(spec, host, port) {
  const out = parseOutbound(spec);
  if (out.type === 'socks5') return socks5Connect(out, host, port);
  const target = out.type === 'proxyip' ? { hostname: out.host, port: out.port || port } : { hostname: host, port };
  const sock = connect(target);
  await withTimeout(sock.opened, out.type === 'direct' ? 4000 : 6000, 'open-timeout');
  return sock;
}

/* Try plan sequentially: open, write first payload, wait for first bytes (or short grace). */
async function establish(plan, host, port, firstPayload) {
  let lastErr = null;
  for (const spec of plan) {
    let sock = null;
    try {
      sock = await openOutbound(spec, host, port);
      const writer = sock.writable.getWriter();
      if (firstPayload && firstPayload.length) await writer.write(firstPayload);
      const reader = sock.readable.getReader();
      /* probe: first read within grace window — EOF w/o data means blocked path (e.g. CF-range) */
      let probe;
      try { probe = await withTimeout(reader.read(), firstPayload && firstPayload.length ? 2500 : 300, 'grace'); }
      catch (e) { probe = { grace: true }; }
      if (probe && probe.done && !probe.grace) throw new Error('closed-early');
      markOut(spec, true);
      return { sock, writer, reader, first: probe && probe.value ? probe.value : null, via: spec };
    } catch (e) {
      lastErr = e;
      markOut(spec, false);
      try { if (sock) sock.close(); } catch (e2) {}
    }
  }
  throw lastErr || new Error('no-route');
}

/* ------------------------------------------------------------------ */
/* WebSocket proxy entrypoint                                           */
/* ------------------------------------------------------------------ */

async function handleProxy(request, ctx) {
  const settings = await getSettings();
  const reqUrl = new URL(request.url);
  const locId = reqUrl.searchParams.get('loc') || '';
  const loc = findLocation(settings, locId);
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();
  countRequest(); countConn();

  const handle = async () => {
    let headerParsed = false;
    let user = null;
    let conn = null;
    let closed = false;
    let udpMode = false;
    let proto = 'vless';
    let chain = Promise.resolve();
    let earlyBuf = new Uint8Array(0);

    const closeAll = () => {
      if (closed) return;
      closed = true;
      try { server.close(1000); } catch (e) {}
      try { if (conn) { conn.writer.releaseLock(); } } catch (e) {}
      try { if (conn) conn.sock.close(); } catch (e) {}
      if (user) ctx.waitUntil(flushUsage(user.uuid, true).catch(() => {}));
      ctx.waitUntil(flushMetrics().catch(() => {}));
    };

    const process = async (u8) => {
      if (closed) return;
      if (!headerParsed) {
        if (earlyBuf.length) { const nb = new Uint8Array(earlyBuf.length + u8.length); nb.set(earlyBuf); nb.set(u8, earlyBuf.length); u8 = nb; earlyBuf = new Uint8Array(0); }
        let parsed = null;
        if (u8.length > 0 && u8[0] === VLESS_VER) parsed = parseVlessHeader(u8); else parsed = parseTrojanHeader(u8);
        if (parsed === null) { earlyBuf = u8; return; }
        headerParsed = true;
        proto = parsed.proto;

        /* ---- auth ---- */
        user = parsed.proto === 'vless' ? await getUserByUuid(parsed.uuid) : await getUserByTrojanHash(parsed.hash);
        if (!user) { closeAll(); return; }
        const st = userState(user);
        if (!st.ok) { closeAll(); return; }
        const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        if (!ipAllowed(user.uuid, ip, user.ip_limit)) { closeAll(); return; }
        /* per-user location restriction */
        const allowed = userLocationIds(user);
        if (allowed && loc && !allowed.includes(loc.id)) { closeAll(); return; }
        addRequest(user.uuid, ip);

        if (user.start_on_first && !user.first_connect_at) {
          const exp = user.days > 0 ? Date.now() + user.days * 86400000 : null;
          try { await dbRun('UPDATE users SET first_connect_at = ?, expiry_at = COALESCE(?, expiry_at) WHERE id = ? AND first_connect_at IS NULL', [Date.now(), exp, user.id]); user.first_connect_at = Date.now(); if (exp) user.expiry_at = exp; cacheUser({ ...user }); } catch (e) {}
        }
        if (user.reset_hours > 0 && (!user.last_reset_at || (Date.now() - user.last_reset_at) > user.reset_hours * 3600000)) {
          try { await dbRun('UPDATE users SET used_bytes = 0, used_requests = 0, last_reset_at = ? WHERE id = ?', [Date.now(), user.id]); user.used_bytes = 0; user.used_requests = 0; user.last_reset_at = Date.now(); cacheUser({ ...user }); } catch (e) {}
        }

        /* ---- UDP (DNS only, via DoH) ---- */
        if (parsed.cmd === 0x02) {
          udpMode = true;
          if (parsed.proto === 'vless') server.send(new Uint8Array([0, 0]));
          if (parsed.proto === 'vless') {
            if (parsed.port === 53) {
              for (const c of splitVlessUdp(parsed.rest)) {
                const reply = await relayDnsRaw(c, settings.dns);
                if (reply) { const r = new Uint8Array(reply.length + 2); r[0] = reply.length >> 8; r[1] = reply.length & 255; r.set(reply, 2); server.send(r); }
              }
            }
          } else {
            const dg = parseUdpDatagram(parsed.rest);
            if (dg && dg.port === 53) { const reply = await relayDns(dg, settings.dns); if (reply) server.send(reply); }
          }
          return;
        }
        if (parsed.cmd !== 0x01) { closeAll(); return; }

        /* ---- TCP: policy ---- */
        const host = parsed.host.toLowerCase();
        if (BLOCKED_HOSTS.has(host) || matchesDomainList(host, settings.block_hosts || [])) { closeAll(); return; }
        if (user.block_ads && await hostBlockedByFilter(host, 'ads')) { closeAll(); return; }
        if (user.block_nsfw && await hostBlockedByFilter(host, 'family')) { closeAll(); return; }

        /* ---- TCP: connect with failover ---- */
        const pool = await getProxyPool(settings);
        const plan = buildPlan(settings, loc, host, pool);
        try {
          conn = await establish(plan, parsed.host, parsed.port, parsed.rest);
        } catch (e) { closeAll(); return; }
        if (closed) { try { conn.sock.close(); } catch (e) {} return; }
        if (parsed.rest && parsed.rest.length) addUsage(user.uuid, parsed.rest.length);

        if (proto === 'vless') {
          if (conn.first) { const r = new Uint8Array(conn.first.length + 2); r[0] = 0; r[1] = 0; r.set(conn.first, 2); addUsage(user.uuid, conn.first.length); server.send(r); }
          else server.send(new Uint8Array([0, 0]));
        } else if (conn.first) { addUsage(user.uuid, conn.first.length); server.send(conn.first); }

        /* pump target -> client */
        (async () => {
          const reader = conn.reader;
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done || !value || closed) break;
              addUsage(user.uuid, value.length);
              server.send(value);
              ctx.waitUntil(flushUsage(user.uuid).catch(() => {}));
            }
          } catch (e) {}
          closeAll();
        })();
        return;
      }

      /* ---- subsequent payloads ---- */
      if (udpMode) {
        if (proto === 'vless') {
          for (const c of splitVlessUdp(u8)) {
            const reply = await relayDnsRaw(c, settings.dns);
            if (reply) { const r = new Uint8Array(reply.length + 2); r[0] = reply.length >> 8; r[1] = reply.length & 255; r.set(reply, 2); server.send(r); }
          }
        } else {
          let off = 0;
          while (off < u8.length) { const dg = parseUdpDatagram(u8, off); if (!dg) break; off = dg.next; if (dg.port === 53) { const reply = await relayDns(dg, settings.dns); if (reply) server.send(reply); } }
        }
        return;
      }
      if (conn) { addUsage(user.uuid, u8.length); await conn.writer.write(u8); }
    };

    server.addEventListener('message', (ev) => {
      const u8 = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data) : typeof ev.data === 'string' ? TE.encode(ev.data) : new Uint8Array(ev.data.buffer || ev.data);
      chain = chain.then(() => process(u8)).catch(() => closeAll());
    });
    server.addEventListener('close', () => closeAll());
    server.addEventListener('error', () => closeAll());
  };

  ctx.waitUntil(handle());
  return new Response(null, { status: 101, webSocket: client });
}

async function relayDnsRaw(query, dohUrl) {
  try {
    const resp = await fetch(dohUrl || 'https://1.1.1.1/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message', Accept: 'application/dns-message' }, body: query });
    if (!resp.ok) return null;
    const a = new Uint8Array(await resp.arrayBuffer());
    return a.length ? a : null;
  } catch (e) { return null; }
}

/* ------------------------------------------------------------------ */
/* ADMIN AUTH — session cookies (HMAC), lockout, first-run setup        */
/* ------------------------------------------------------------------ */

const SESSION_COOKIE = 'jn_session';
const SESSION_TTL = 12 * 3600 * 1000;
const MAX_FAILS = 5;
const BAN_MS = 15 * 60 * 1000;

async function getAdminCreds() {
  /* Priority: settings row (changed in-panel) → env ADMIN_PASS_HASH (deployer) */
  const row = await dbGet('SELECT value FROM settings WHERE key = ?', ['admin_hash']);
  if (row && row.value && row.value.includes('$')) { const [salt, hash] = row.value.split('$'); return { source: 'db', salt, hash }; }
  const envHash = typeof ADMIN_PASS_HASH !== 'undefined' ? ADMIN_PASS_HASH : null;
  if (envHash) return { source: 'env', salt: envHash.split('$')[0], hash: envHash.split('$')[1] };
  return null;
}
async function verifyAdminPassword(password) {
  const creds = await getAdminCreds();
  if (!creds) return { ok: false, noCreds: true };
  const calc = await sha256hex(creds.salt + ':' + password);
  return { ok: safeEqual(calc, creds.hash) };
}
async function setAdminPassword(pass) {
  const salt = rndHex(8);
  const hash = await sha256hex(salt + ':' + pass);
  await dbRun('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', ['admin_hash', `${salt}$${hash}`]);
}
async function getSessionSecret() {
  if (SESSION_SECRET) return SESSION_SECRET;
  const row = await dbGet('SELECT value FROM settings WHERE key = ?', ['session_secret']);
  if (!row) { const s = rndHex(32); await dbRun('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', ['session_secret', s]); return s; }
  return row.value;
}
async function makeSession() {
  const exp = Date.now() + SESSION_TTL;
  const sig = await hmacSign(await getSessionSecret(), String(exp));
  return `${exp}.${sig}`;
}
async function checkSession(request) {
  const cookies = (request.headers.get('Cookie') || '').split(/;\s*/);
  const raw = cookies.map(c => c.split('=')).find(p => p[0] === SESSION_COOKIE);
  if (!raw) return false;
  const [exp, sig] = decodeURIComponent(raw.slice(1).join('=')).split('.');
  if (!exp || !sig || Date.now() > Number(exp)) return false;
  return safeEqual(await hmacSign(await getSessionSecret(), exp), sig);
}
function sessionCookieHeader(value, maxAge = SESSION_TTL / 1000) {
  return `${SESSION_COOKIE}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Strict; Secure`;
}
function clearSessionHeader() { return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict; Secure`; }
async function loginBanned(ip) { const row = await dbGet('SELECT * FROM login_attempts WHERE ip = ?', [ip]); return !!(row && row.banned_until && Date.now() < row.banned_until); }
async function recordFail(ip) {
  const row = await dbGet('SELECT * FROM login_attempts WHERE ip = ?', [ip]);
  const fails = (row ? row.fails : 0) + 1;
  const bannedUntil = fails >= MAX_FAILS ? Date.now() + BAN_MS : null;
  await dbRun('INSERT INTO login_attempts (ip, fails, banned_until) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET fails = excluded.fails, banned_until = excluded.banned_until', [ip, fails, bannedUntil]);
  return { fails, banned: !!bannedUntil, remaining: Math.max(0, MAX_FAILS - fails) };
}
async function clearFails(ip) { await dbRun('DELETE FROM login_attempts WHERE ip = ?', [ip]); }
function clientIp(request) { return request.headers.get('CF-Connecting-IP') || 'unknown'; }

/* ------------------------------------------------------------------ */
/* Public user projection                                               */
/* ------------------------------------------------------------------ */

function userPublic(user, requestHost) {
  const st = userState(user);
  return {
    id: user.id, name: user.name, uuid: user.uuid, sub_token: user.sub_token,
    quota_bytes: user.quota_bytes, used_bytes: user.used_bytes, reset_hours: user.reset_hours,
    days: user.days, expiry_at: user.expiry_at, start_on_first: !!user.start_on_first,
    first_connect_at: user.first_connect_at, ip_limit: user.ip_limit, active: !!user.active,
    note: user.note, created_at: user.created_at,
    max_requests: user.max_requests || 0, used_requests: user.used_requests || 0,
    locations: userLocationIds(user), block_ads: !!user.block_ads, block_nsfw: !!user.block_nsfw,
    last_seen_at: user.last_seen_at || null, last_ip: user.last_ip || null,
    online_ips: activeIps(user.uuid),
    state: st,
    sub_url: `https://${requestHost}/sub/${user.sub_token}`,
    status_url: `https://${requestHost}/status/${user.sub_token}`,
  };
}

function sanitizeUserInput(b, existing) {
  const out = {};
  if ('name' in b) out.name = String(b.name || '').trim().slice(0, 60);
  if ('note' in b) out.note = String(b.note || '').slice(0, 200);
  if ('active' in b) out.active = b.active ? 1 : 0;
  if ('quota_gb' in b) out.quota_bytes = Math.round(Math.max(0, Number(b.quota_gb) || 0) * 1073741824);
  if ('ip_limit' in b) out.ip_limit = Math.min(50, Math.max(0, Number(b.ip_limit) || 0));
  if ('reset_hours' in b) out.reset_hours = Math.max(0, Number(b.reset_hours) || 0);
  if ('max_requests' in b) out.max_requests = Math.max(0, Math.floor(Number(b.max_requests) || 0));
  if ('block_ads' in b) out.block_ads = b.block_ads ? 1 : 0;
  if ('block_nsfw' in b) out.block_nsfw = b.block_nsfw ? 1 : 0;
  if ('locations' in b) {
    const arr = Array.isArray(b.locations) ? b.locations.map(x => String(x).replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 24)).filter(Boolean).slice(0, 8) : [];
    out.locations = arr.length ? JSON.stringify(arr) : null;
  }
  if ('start_on_first' in b) out.start_on_first = b.start_on_first ? 1 : 0;
  if ('days' in b) {
    const days = Math.max(0, Number(b.days) || 0);
    out.days = days;
    const sof = 'start_on_first' in b ? !!b.start_on_first : !!(existing && existing.start_on_first);
    if (days === 0) out.expiry_at = null;
    else if (sof && !(existing && existing.first_connect_at)) out.expiry_at = null;
    else out.expiry_at = Date.now() + days * 86400000;
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* ADMIN JSON API                                                       */
/* ------------------------------------------------------------------ */

async function handleAdminApi(request, url, ctx) {
  const path = url.pathname;
  const method = request.method;
  const ip = clientIp(request);
  countRequest();

  /* ---------- public ---------- */
  if (path === '/api/setup' && method === 'POST') {
    const creds = await getAdminCreds();
    if (creds) return jsonResponse({ error: 'رمز مدیریت قبلاً تنظیم شده است' }, 400);
    const body = await request.json().catch(() => ({}));
    const pass = String(body.password || '');
    if (pass.length < 8) return jsonResponse({ error: 'رمز باید حداقل ۸ کاراکتر باشد' }, 400);
    await setAdminPassword(pass);
    return jsonResponse({ ok: true });
  }
  if (path === '/api/login' && method === 'POST') {
    if (await loginBanned(ip)) return jsonResponse({ error: 'تلاش زیاد؛ ۱۵ دقیقه صبر کنید' }, 429);
    const body = await request.json().catch(() => ({}));
    const v = await verifyAdminPassword(String(body.password || ''));
    if (!v.ok) {
      if (v.noCreds) return jsonResponse({ error: 'نصب نشده', setup: true }, 400);
      const r = await recordFail(ip);
      return jsonResponse({ error: r.banned ? 'به دلیل تلاش زیاد ۱۵ دقیقه مسدود شدید' : `رمز اشتباه است (${r.remaining} تلاش باقی مانده)` }, 401);
    }
    await clearFails(ip);
    return jsonResponse({ ok: true }, 200, { 'Set-Cookie': sessionCookieHeader(await makeSession()) });
  }
  if (path === '/api/logout' && method === 'POST') return jsonResponse({ ok: true }, 200, { 'Set-Cookie': clearSessionHeader() });
  if (path === '/api/ping' && method === 'GET') return jsonResponse({ ok: true, t: Date.now(), colo: (request.cf && request.cf.colo) || null });

  /* ---------- authenticated ---------- */
  if (!(await checkSession(request))) return jsonResponse({ error: 'unauthorized' }, 401);
  const isMutation = method !== 'GET' && method !== 'HEAD';
  if (isMutation && request.headers.get('X-JN') !== '1') return jsonResponse({ error: 'csrf' }, 403);
  const body = isMutation ? await request.json().catch(() => ({})) : {};

  if (path === '/api/me' && method === 'GET') {
    const settings = await getSettings();
    return jsonResponse({ ok: true, version: VERSION, brand: BRAND, host: url.host, colo: (request.cf && request.cf.colo) || null, has_cf_token: !!settings.cf_token });
  }

  if (path === '/api/password' && method === 'POST') {
    const cur = String(body.current || ''), next = String(body.password || '');
    const v = await verifyAdminPassword(cur);
    if (!v.ok) return jsonResponse({ error: 'رمز فعلی اشتباه است' }, 400);
    if (next.length < 8) return jsonResponse({ error: 'رمز جدید باید حداقل ۸ کاراکتر باشد' }, 400);
    await setAdminPassword(next);
    return jsonResponse({ ok: true }, 200, { 'Set-Cookie': sessionCookieHeader(await makeSession()) });
  }

  if (path === '/api/stats' && method === 'GET') {
    await flushMetrics(true);
    const t = await dbGet('SELECT COUNT(*) AS total, SUM(active) AS active, SUM(used_bytes) AS used, SUM(quota_bytes) AS quota, SUM(used_requests) AS reqs FROM users');
    const now = Date.now();
    const soon = await dbGet('SELECT COUNT(*) AS n FROM users WHERE expiry_at IS NOT NULL AND expiry_at > ? AND expiry_at < ?', [now, now + 7 * 86400000]);
    const expired = await dbGet('SELECT COUNT(*) AS n FROM users WHERE expiry_at IS NOT NULL AND expiry_at < ?', [now]);
    const overq = await dbGet('SELECT COUNT(*) AS n FROM users WHERE quota_bytes > 0 AND used_bytes >= quota_bytes');
    const online = await dbGet('SELECT COUNT(*) AS n FROM users WHERE last_seen_at > ?', [now - 5 * 60000]);
    const days = await dbAll('SELECT * FROM metrics ORDER BY day DESC LIMIT 30');
    const today = days.find(d => d.day === todayKey()) || { requests: 0, conns: 0, bytes: 0 };
    const top = await dbAll('SELECT id, name, used_bytes, used_requests, last_seen_at FROM users ORDER BY used_bytes DESC LIMIT 5');
    return jsonResponse({
      users: { total: t?.total || 0, active: t?.active || 0, online: online?.n || 0, expiring_soon: soon?.n || 0, expired: expired?.n || 0, over_quota: overq?.n || 0 },
      traffic: { used: t?.used || 0, quota: t?.quota || 0, requests: t?.reqs || 0 },
      cf: { daily_limit: 100000, today_requests: today.requests, today_conns: today.conns, today_bytes: today.bytes, days: days.reverse() },
      top, version: VERSION, colo: (request.cf && request.cf.colo) || null, now,
    });
  }

  /* ---------- users ---------- */
  if (path === '/api/users' && method === 'GET') {
    const q = (url.searchParams.get('q') || '').trim().toLowerCase();
    const filter = url.searchParams.get('filter') || '';
    let rows = await dbAll('SELECT * FROM users ORDER BY created_at DESC');
    if (q) rows = rows.filter(u => (u.name || '').toLowerCase().includes(q) || u.uuid.includes(q) || (u.note || '').toLowerCase().includes(q));
    const now = Date.now();
    if (filter === 'active') rows = rows.filter(u => userState(u).ok);
    else if (filter === 'disabled') rows = rows.filter(u => !u.active);
    else if (filter === 'expired') rows = rows.filter(u => userState(u).expired);
    else if (filter === 'overquota') rows = rows.filter(u => userState(u).overQuota);
    else if (filter === 'online') rows = rows.filter(u => u.last_seen_at && now - u.last_seen_at < 5 * 60000);
    else if (filter === 'pending') rows = rows.filter(u => userState(u).pending);
    return jsonResponse({ users: rows.map(u => userPublic(u, url.host)) });
  }

  if (path === '/api/users' && method === 'POST') {
    const b = body;
    const count = Math.min(50, Math.max(1, Number(b.count) || 1));
    const created = [];
    for (let n = 0; n < count; n++) {
      const name = String(b.name || '').trim().slice(0, 60) || ('user-' + rndHex(2));
      const f = sanitizeUserInput({ quota_gb: 0, days: 0, ip_limit: 0, reset_hours: 0, max_requests: 0, block_ads: false, block_nsfw: false, locations: [], start_on_first: false, note: '', ...b, name: count > 1 ? `${name}-${n + 1}` : name }, null);
      const uuid = count === 1 && isUuid(b.uuid) ? b.uuid.toLowerCase() : crypto.randomUUID();
      const id = rndHex(8), subToken = rndHex(16);
      await dbRun(
        `INSERT INTO users (id, uuid, trojan_hash, name, sub_token, quota_bytes, used_bytes, reset_hours, days, expiry_at, start_on_first, ip_limit, active, note, created_at, max_requests, used_requests, locations, block_ads, block_nsfw)
         VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, 1, ?, ?, ?, 0, ?, ?, ?)`,
        [id, uuid, sha224hex(TE.encode(uuid)), f.name, subToken, f.quota_bytes, f.reset_hours, f.days, f.expiry_at, f.start_on_first, f.ip_limit, f.note, Date.now(), f.max_requests, f.locations, f.block_ads, f.block_nsfw]
      );
      created.push(userPublic(await dbGet('SELECT * FROM users WHERE id = ?', [id]), url.host));
    }
    return jsonResponse({ ok: true, user: created[0], users: created });
  }

  const userMatch = path.match(/^\/api\/users\/([0-9a-f]+)$/);
  if (userMatch) {
    const uid = userMatch[1];
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [uid]);
    if (!user) return jsonResponse({ error: 'کاربر پیدا نشد' }, 404);
    if (method === 'GET') return jsonResponse({ user: userPublic(user, url.host) });
    if (method === 'PATCH') {
      const f = sanitizeUserInput(body, user);
      const sets = [], vals = [];
      for (const [k, v] of Object.entries(f)) { sets.push(`${k} = ?`); vals.push(v); }
      if ('extend_days' in body && Number(body.extend_days) > 0) {
        const cur = user.expiry_at && user.expiry_at > Date.now() ? user.expiry_at : Date.now();
        sets.push('expiry_at = ?'); vals.push(cur + Number(body.extend_days) * 86400000);
      }
      if ('add_gb' in body && Number(body.add_gb) > 0) { sets.push('quota_bytes = quota_bytes + ?'); vals.push(Math.round(Number(body.add_gb) * 1073741824)); }
      if (body.regen_uuid) { const nu = crypto.randomUUID(); sets.push('uuid = ?', 'trojan_hash = ?'); vals.push(nu, sha224hex(TE.encode(nu))); }
      if (body.regen_token) { sets.push('sub_token = ?'); vals.push(rndHex(16)); }
      if (!sets.length) return jsonResponse({ error: 'چیزی برای تغییر نیست' }, 400);
      vals.push(uid);
      await dbRun(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`, vals);
      invalidateUser(user.uuid);
      return jsonResponse({ ok: true, user: userPublic(await dbGet('SELECT * FROM users WHERE id = ?', [uid]), url.host) });
    }
    if (method === 'DELETE') {
      await dbRun('DELETE FROM users WHERE id = ?', [uid]);
      invalidateUser(user.uuid);
      return jsonResponse({ ok: true });
    }
  }

  const resetMatch = path.match(/^\/api\/users\/([0-9a-f]+)\/reset$/);
  if (resetMatch && method === 'POST') {
    const uid = resetMatch[1];
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [uid]);
    if (!user) return jsonResponse({ error: 'کاربر پیدا نشد' }, 404);
    if (body.traffic) await dbRun('UPDATE users SET used_bytes = 0, last_reset_at = ? WHERE id = ?', [Date.now(), uid]);
    if (body.requests) await dbRun('UPDATE users SET used_requests = 0 WHERE id = ?', [uid]);
    if (body.expiry) {
      const exp = user.days > 0 && !user.start_on_first ? Date.now() + user.days * 86400000 : null;
      await dbRun('UPDATE users SET expiry_at = ?, first_connect_at = NULL WHERE id = ?', [exp, uid]);
    }
    invalidateUser(user.uuid); _ipMap.delete(user.uuid);
    return jsonResponse({ ok: true, user: userPublic(await dbGet('SELECT * FROM users WHERE id = ?', [uid]), url.host) });
  }

  if (path === '/api/bulk' && method === 'POST') {
    const ids = Array.isArray(body.ids) ? body.ids.filter(x => /^[0-9a-f]+$/.test(x)) : [];
    if (!ids.length) return jsonResponse({ error: 'شناسه نامعتبر' }, 400);
    const ph = ids.map(() => '?').join(',');
    const a = body.action;
    if (a === 'activate') await dbRun(`UPDATE users SET active = 1 WHERE id IN (${ph})`, ids);
    else if (a === 'deactivate') await dbRun(`UPDATE users SET active = 0 WHERE id IN (${ph})`, ids);
    else if (a === 'delete') await dbRun(`DELETE FROM users WHERE id IN (${ph})`, ids);
    else if (a === 'reset_traffic') await dbRun(`UPDATE users SET used_bytes = 0, used_requests = 0, last_reset_at = ? WHERE id IN (${ph})`, [Date.now(), ...ids]);
    else if (a === 'reset_expiry') await dbRun(`UPDATE users SET expiry_at = CASE WHEN days > 0 AND start_on_first = 0 THEN ? + days * 86400000 ELSE NULL END, first_connect_at = NULL WHERE id IN (${ph})`, [Date.now(), ...ids]);
    else if (a === 'extend') { const d = Math.max(0, Number(body.days) || 0); await dbRun(`UPDATE users SET expiry_at = CASE WHEN expiry_at IS NULL OR expiry_at < ? THEN ? ELSE expiry_at END + ? WHERE id IN (${ph})`, [Date.now(), Date.now(), d * 86400000, ...ids]); }
    else if (a === 'add_gb') { const g = Math.max(0, Number(body.gb) || 0); await dbRun(`UPDATE users SET quota_bytes = quota_bytes + ? WHERE id IN (${ph})`, [Math.round(g * 1073741824), ...ids]); }
    else if (a === 'set_locations') { const arr = Array.isArray(body.locations) ? body.locations.slice(0, 8) : []; await dbRun(`UPDATE users SET locations = ? WHERE id IN (${ph})`, [arr.length ? JSON.stringify(arr) : null, ...ids]); }
    else if (a === 'block_ads' || a === 'unblock_ads') await dbRun(`UPDATE users SET block_ads = ? WHERE id IN (${ph})`, [a === 'block_ads' ? 1 : 0, ...ids]);
    else if (a === 'block_nsfw' || a === 'unblock_nsfw') await dbRun(`UPDATE users SET block_nsfw = ? WHERE id IN (${ph})`, [a === 'block_nsfw' ? 1 : 0, ...ids]);
    else return jsonResponse({ error: 'عملیات نامعتبر' }, 400);
    _userCache.clear();
    return jsonResponse({ ok: true, n: ids.length });
  }

  /* ---------- settings ---------- */
  if (path === '/api/settings' && method === 'GET') {
    const s = await getSettings(true);
    return jsonResponse({ settings: { ...s, cf_token: s.cf_token ? '••••' + s.cf_token.slice(-4) : '', resolved_locations: resolveLocations(s, url.host, 'admin') }, fp_options: FP_OPTIONS, presets: ISP_PRESETS });
  }
  if (path === '/api/settings' && method === 'PUT') {
    try {
      if ('cf_token' in body && String(body.cf_token || '').startsWith('••••')) delete body.cf_token;
      const s = await saveSettings(body);
      return jsonResponse({ ok: true, settings: { ...s, cf_token: s.cf_token ? '••••' + s.cf_token.slice(-4) : '', resolved_locations: resolveLocations(s, url.host, 'admin') } });
    } catch (e) { return jsonResponse({ error: e.message || 'خطای ذخیره' }, 400); }
  }

  /* ---------- backup / restore ---------- */
  if (path === '/api/backup' && method === 'GET') {
    const users = await dbAll('SELECT * FROM users');
    const settingsRows = await dbAll("SELECT key, value FROM settings WHERE key NOT IN ('admin_hash', 'session_secret')");
    const metrics = await dbAll('SELECT * FROM metrics');
    return jsonResponse({
      app: 'javidnam', version: VERSION, exported_at: new Date().toISOString(),
      users: users.map(u => ({ ...u, trojan_hash: undefined })),
      settings: Object.fromEntries(settingsRows.map(r => [r.key, r.value])),
      metrics,
    }, 200, { 'Content-Disposition': `attachment; filename="javidnam-backup-${todayKey()}.json"` });
  }
  if (path === '/api/restore' && method === 'POST') {
    const b = body;
    if (b.app !== 'javidnam' || !Array.isArray(b.users)) return jsonResponse({ error: 'فایل پشتیبان نامعتبر است' }, 400);
    let n = 0;
    for (const u of b.users) {
      if (!isUuid(u.uuid)) continue;
      await dbRun(
        `INSERT INTO users (id, uuid, trojan_hash, name, sub_token, quota_bytes, used_bytes, reset_hours, days, expiry_at, start_on_first, first_connect_at, ip_limit, active, note, created_at, max_requests, used_requests, locations, block_ads, block_nsfw, last_seen_at, last_ip)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(uuid) DO UPDATE SET name = excluded.name, quota_bytes = excluded.quota_bytes, used_bytes = excluded.used_bytes, expiry_at = excluded.expiry_at, active = excluded.active, days = excluded.days, ip_limit = excluded.ip_limit, max_requests = excluded.max_requests, locations = excluded.locations, block_ads = excluded.block_ads, block_nsfw = excluded.block_nsfw`,
        [u.id || rndHex(8), u.uuid.toLowerCase(), sha224hex(TE.encode(u.uuid.toLowerCase())), u.name || 'بدون نام', u.sub_token || rndHex(16),
          u.quota_bytes || 0, u.used_bytes || 0, u.reset_hours || 0, u.days || 0, u.expiry_at || null, u.start_on_first ? 1 : 0, u.first_connect_at || null,
          u.ip_limit || 0, u.active === 0 ? 0 : 1, u.note || '', u.created_at || Date.now(), u.max_requests || 0, u.used_requests || 0,
          u.locations || null, u.block_ads ? 1 : 0, u.block_nsfw ? 1 : 0, u.last_seen_at || null, u.last_ip || null]
      );
      n++;
    }
    if (b.settings && typeof b.settings === 'object' && body.with_settings !== false) {
      for (const [k, v] of Object.entries(b.settings)) {
        if (!(k in SETTING_DEFAULTS) || k === 'proxy_path') continue;
        await dbRun('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', [k, typeof v === 'string' ? v : JSON.stringify(v)]);
      }
      _settingsCache = null;
    }
    _userCache.clear();
    return jsonResponse({ ok: true, restored: n });
  }

  /* ---------- tools ---------- */
  if (path === '/api/tools/direct' && method === 'POST') {
    /* Cloudflare → internet test (optionally through an outbound spec) */
    const host = String(body.host || 'www.google.com').trim().slice(0, 200);
    const port = Math.min(65535, Math.max(1, Number(body.port) || 443));
    const spec = normalizeOutbound(body.out || 'direct');
    const t0 = Date.now();
    try {
      const sock = await openOutbound(spec, host, port);
      const w = sock.writable.getWriter();
      await w.write(TE.encode(`HEAD / HTTP/1.0\r\nHost: ${host}\r\n\r\n`));
      const r = sock.readable.getReader();
      let got = 0;
      try { const { value } = await withTimeout(r.read(), 4000, 'read-timeout'); got = value ? value.length : 0; } catch (e) {}
      try { w.releaseLock(); r.releaseLock(); sock.close(); } catch (e) {}
      return jsonResponse({ ok: true, ms: Date.now() - t0, bytes: got, via: spec, note: got === 0 && port === 443 ? 'اتصال TCP برقرار شد (پاسخ TLS انتظار نمی‌رود)' : '' });
    } catch (e) { return jsonResponse({ ok: false, ms: Date.now() - t0, via: spec, error: String(e.message || e) }, 200); }
  }

  if (path === '/api/tools/proxycheck' && method === 'POST') {
    /* check VIP proxy pool entries in parallel */
    const list = (Array.isArray(body.list) ? body.list : String(body.list || '').split(/[\n,]+/)).map(x => normalizeOutbound(String(x).trim())).filter(x => x && x !== 'direct').slice(0, 30);
    const host = String(body.host || 'www.google.com');
    const results = await Promise.all(list.map(async (spec) => {
      const t0 = Date.now();
      try {
        const sock = await openOutbound(spec, host, 443);
        const w = sock.writable.getWriter();
        await w.write(new Uint8Array([0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03])); // junk client-hello prefix: expect TLS alert or close, not hang
        const r = sock.readable.getReader();
        let alive = true;
        try { await withTimeout(r.read(), 3000, 't'); } catch (e) { alive = true; }
        try { w.releaseLock(); r.releaseLock(); sock.close(); } catch (e) {}
        markOut(spec, true);
        return { spec, ok: alive, ms: Date.now() - t0 };
      } catch (e) { markOut(spec, false); return { spec, ok: false, ms: Date.now() - t0, error: String(e.message || e) }; }
    }));
    return jsonResponse({ results });
  }

  if (path === '/api/tools/health' && method === 'GET') {
    return jsonResponse({ outbounds: [..._outHealth.entries()].map(([spec, h]) => ({ spec, fails: h.fails, at: h.at, healthy: outHealthy(spec) })), filter_cache: _filterCache.size, user_cache: _userCache.size });
  }

  if (path === '/api/tools/ipinfo' && method === 'GET') {
    const cf = request.cf || {};
    return jsonResponse({ ip, colo: cf.colo || null, country: cf.country || null, city: cf.city || null, asn: cf.asn || null, asOrg: cf.asOrganization || null, tlsVersion: cf.tlsVersion || null, httpProtocol: cf.httpProtocol || null });
  }

  if (path === '/api/tools/cfcheck' && method === 'POST') {
    /* test a clean IP candidate list: connect to ip:443 and send SNI-less TLS hello (Cloudflare edge responds with alert/handshake quickly) */
    const ips = (Array.isArray(body.ips) ? body.ips : String(body.ips || '').split(/[\n,\s]+/)).map(x => String(x).trim()).filter(x => isIPv4(x)).slice(0, 40);
    const results = await Promise.all(ips.map(async (ipc) => {
      const t0 = Date.now();
      try {
        const sock = connect({ hostname: ipc, port: 443 });
        await withTimeout(sock.opened, 3000, 'open');
        try { sock.close(); } catch (e) {}
        return { ip: ipc, ok: true, ms: Date.now() - t0 };
      } catch (e) { return { ip: ipc, ok: false, ms: Date.now() - t0, error: String(e.message || e) }; }
    }));
    return jsonResponse({ results, note: 'اتصال از لبه‌ی کلودفلر به IP کلودفلر معمولاً مسدود است؛ برای نتیجه‌ی واقعی از اسکنر سمت کاربر استفاده کنید.' });
  }

  /* ---------- OTA update (in-panel) ---------- */
  if (path === '/api/update/check' && method === 'GET') {
    try {
      const r = await fetch(BRAND.raw, { cf: { cacheTtl: 60 } });
      if (!r.ok) throw new Error('fetch ' + r.status);
      const src = await r.text();
      const m = src.match(/const VERSION = '([^']+)'/);
      return jsonResponse({ current: VERSION, latest: m ? m[1] : null, size: src.length, update_available: !!(m && m[1] !== VERSION) });
    } catch (e) { return jsonResponse({ error: 'دسترسی به مخزن ممکن نشد: ' + e.message }, 502); }
  }
  if (path === '/api/update/apply' && method === 'POST') {
    const settings = await getSettings(true);
    const token = String(body.cf_token || settings.cf_token || '').trim();
    if (!token) return jsonResponse({ error: 'برای آپدیت از داخل پنل، توکن کلودفلر (Workers Scripts:Edit) را در تنظیمات وارد کن یا از بات تلگرام آپدیت کن.' }, 400);
    try {
      const src = await (await fetch(BRAND.raw)).text();
      if (!src.includes("const VERSION = '")) throw new Error('سورس نامعتبر');
      const accs = await cfApi(token, '/accounts');
      const scriptName = url.host.split('.')[0];
      let found = null;
      for (const a of accs) {
        try { await cfApi(token, `/accounts/${a.id}/workers/scripts/${scriptName}/settings`); found = a; break; } catch (e) {}
      }
      if (!found) throw new Error('ورکر با نام ' + scriptName + ' در حساب‌های این توکن پیدا نشد');
      const cur = await cfApi(token, `/accounts/${found.id}/workers/scripts/${scriptName}/settings`);
      const bindings = (cur.bindings || []).map(b => (b.type === 'secret_text' ? { type: 'inherit', name: b.name } : b));
      const meta = { main_module: 'worker.js', compatibility_date: cur.compatibility_date || '2025-09-01', compatibility_flags: cur.compatibility_flags || [], bindings };
      const fd = new FormData();
      fd.append('metadata', new Blob([JSON.stringify(meta)], { type: 'application/json' }));
      fd.append('worker.js', new Blob([src], { type: 'application/javascript+module' }), 'worker.js');
      const r = await fetch(`https://api.cloudflare.com/client/v4/accounts/${found.id}/workers/scripts/${scriptName}`, { method: 'PUT', headers: { Authorization: 'Bearer ' + token }, body: fd });
      const j = await r.json();
      if (!j.success) throw new Error((j.errors && j.errors[0] && j.errors[0].message) || 'upload failed');
      if (body.save_token && !settings.cf_token) await saveSettings({ cf_token: token });
      return jsonResponse({ ok: true, version: (src.match(/const VERSION = '([^']+)'/) || [])[1] });
    } catch (e) { return jsonResponse({ error: String(e.message || e) }, 500); }
  }

  if (path === '/api/cf/quota' && method === 'GET') {
    /* live worker request count via CF GraphQL (needs cf_token with Analytics read) — optional */
    const settings = await getSettings();
    const token = String(url.searchParams.get('token') || settings.cf_token || '');
    if (!token) return jsonResponse({ error: 'no-token' }, 400);
    try {
      const accs = await cfApi(token, '/accounts');
      const scriptName = url.host.split('.')[0];
      const start = new Date(); start.setUTCHours(0, 0, 0, 0);
      const q = { query: `query($a:String!,$s:Time!,$n:String!){viewer{accounts(filter:{accountTag:$a}){workersInvocationsAdaptive(limit:1,filter:{datetime_geq:$s,scriptName:$n}){sum{requests errors subrequests}}}}}`, variables: { a: accs[0].id, s: start.toISOString(), n: scriptName } };
      const r = await fetch('https://api.cloudflare.com/client/v4/graphql', { method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify(q) });
      const j = await r.json();
      const sum = j?.data?.viewer?.accounts?.[0]?.workersInvocationsAdaptive?.[0]?.sum || null;
      return jsonResponse({ ok: true, today: sum, limit: 100000 });
    } catch (e) { return jsonResponse({ error: String(e.message || e) }, 500); }
  }

  return jsonResponse({ error: 'not-found' }, 404);
}

async function cfApi(token, p, opts = {}) {
  const r = await fetch('https://api.cloudflare.com/client/v4' + p, { ...opts, headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json', ...(opts.headers || {}) } });
  const j = await r.json().catch(() => ({ success: false, errors: [{ message: 'bad-json' }] }));
  if (!j.success) throw new Error((j.errors && j.errors[0] && j.errors[0].message) || 'CF API error');
  return j.result;
}

/* ------------------------------------------------------------------ */
/* SUBSCRIPTION — config links, ISP presets, formats, status endpoint   */
/* ------------------------------------------------------------------ */

const ISP_PRESETS = [
  { id: 'auto',     label: 'خودکار',          fp: null,      frag: null,             note: 'تنظیمات سراسری پنل' },
  { id: 'mci',      label: 'همراه اول',       fp: 'chrome',  frag: ['10-20', '10-20'], note: 'fragment استاندارد؛ برای قطعی‌های MCI' },
  { id: 'irancell', label: 'ایرانسل',         fp: 'safari',  frag: ['40-50', '10-20'], note: 'fragment با بازه بلندتر' },
  { id: 'rightel',  label: 'رایتل',           fp: 'chrome',  frag: ['10-30', '10-20'], note: 'حالت متعادل' },
  { id: 'tci',      label: 'مخابرات / خانگی', fp: 'firefox', frag: ['5-10', '5-10'],   note: 'fragment ریز برای خطوط ثابت' },
  { id: 'shatel',   label: 'شاتل / آسیاتک',   fp: 'chrome',  frag: ['20-40', '10-20'], note: 'برای ADSL/FTTH خصوصی' },
  { id: 'gaming',   label: 'گیمینگ',          fp: 'chrome',  frag: false,            note: 'کم‌ترین تأخیر؛ fragment خاموش' },
];

const CLIENT_UA_HINTS = [
  'v2ray', 'hiddify', 'sing-box', 'singbox', 'clash', 'shadowrocket', 'streisand', 'loon', 'stash', 'surge',
  'sfa', 'sfi', 'sfm', 'karing', 'husi', 'v2box', 'napsternetv', 'shadowsocks', 'nekobox', 'nekoray', 'xray', 'mihomo', 'quantumult', 'exclave', 'happ', 'foxray', 'ktm', 'oblivion',
];

function fragFor(settings, preset) {
  if (preset && preset.frag === false) return null;
  if (preset && preset.frag) return { len: preset.frag[0], int: preset.frag[1], packets: settings.frag_packets || 'tlshello' };
  if (!settings.frag_enabled) return null;
  return { len: settings.frag_len || '10-20', int: settings.frag_int || '10-20', packets: settings.frag_packets || 'tlshello' };
}

function buildConfigLinks(user, settings, locations, panelHost, opts = {}) {
  const preset = opts.preset || null;
  const fp = (preset && preset.fp) || settings.fp || 'chrome';
  const frag = fragFor(settings, preset);
  const hostHeader = settings.host_mask || panelHost;
  const links = [];
  for (const loc of locations) {
    const sni = settings.sni_mask || loc.sni || (loc.isClean ? panelHost : loc.host);
    const path = `${settings.proxy_path}?ed=2560&loc=${encodeURIComponent(loc.id)}`;
    const common = { type: 'ws', host: hostHeader, path, security: loc.tls ? 'tls' : 'none' };
    if (loc.tls) { common.sni = sni; common.fp = fp; common.alpn = settings.alpn || 'h2,http/1.1'; }
    if (frag) { common.fragment = `${frag.packets},${frag.len},${frag.int}`; }
    const vp = new URLSearchParams({ encryption: 'none', ...common });
    links.push({ id: loc.id, name: loc.name, proto: 'vless', host: loc.host, port: loc.port, tls: loc.tls, sni, fp, frag, link: `vless://${user.uuid}@${bracket(loc.host)}:${loc.port}?${vp}#${encodeURIComponent(`${BRAND.en} | ${loc.name}`)}` });
    const tp = new URLSearchParams(common);
    links.push({ id: loc.id, name: loc.name, proto: 'trojan', host: loc.host, port: loc.port, tls: loc.tls, sni, fp, frag, link: `trojan://${user.uuid}@${bracket(loc.host)}:${loc.port}?${tp}#${encodeURIComponent(`${BRAND.en} TRJ | ${loc.name}`)}` });
  }
  return links;
}
function bracket(h) { return isIPv6(h) ? `[${h}]` : h; }

/* ---- sing-box JSON ---- */
function singboxConfig(user, links, settings) {
  const outbounds = [];
  const tags = [];
  for (const l of links) {
    const tag = `${l.proto === 'vless' ? '' : 'TRJ '}${l.name}`;
    tags.push(tag);
    const ob = {
      type: l.proto, tag, server: l.host, server_port: l.port,
      ...(l.proto === 'vless' ? { uuid: user.uuid, flow: '' } : { password: user.uuid }),
      transport: { type: 'ws', path: settings.proxy_path + '?loc=' + l.id, headers: { Host: settings.host_mask || l.sni }, max_early_data: 2560, early_data_header_name: 'Sec-WebSocket-Protocol' },
    };
    if (l.tls) ob.tls = { enabled: true, server_name: l.sni, insecure: false, utls: { enabled: true, fingerprint: l.fp === 'random' ? 'randomized' : l.fp }, alpn: (settings.alpn || 'h2,http/1.1').split(',') };
    if (l.frag) ob.tls = { ...(ob.tls || { enabled: true, server_name: l.sni }), fragment: true, fragment_fallback_delay: '500ms' };
    outbounds.push(ob);
  }
  return {
    log: { level: 'warn' },
    dns: { servers: [{ tag: 'remote', address: 'https://1.1.1.1/dns-query', detour: 'auto' }, { tag: 'local', address: 'local', detour: 'direct' }], rules: [{ outbound: 'any', server: 'local' }], strategy: 'ipv4_only' },
    inbounds: [{ type: 'tun', tag: 'tun-in', address: ['172.19.0.1/30'], auto_route: true, strict_route: true, stack: 'mixed', sniff: true }, { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 }],
    outbounds: [
      { type: 'selector', tag: 'proxy', outbounds: ['auto', ...tags], default: 'auto' },
      { type: 'urltest', tag: 'auto', outbounds: tags, url: 'https://www.gstatic.com/generate_204', interval: '5m', tolerance: 100 },
      ...outbounds,
      { type: 'direct', tag: 'direct' },
    ],
    route: { rules: [{ protocol: 'dns', action: 'hijack-dns' }, { ip_is_private: true, outbound: 'direct' }, { rule_set: [], domain_suffix: ['.ir'], outbound: 'direct' }], final: 'proxy', auto_detect_interface: true },
    experimental: { clash_api: { external_controller: '127.0.0.1:9090' }, cache_file: { enabled: true } },
  };
}

/* ---- Clash / Mihomo YAML ---- */
function clashConfig(user, links, settings) {
  const y = (s) => JSON.stringify(String(s));
  const names = [];
  const proxies = links.map(l => {
    const name = `${BRAND.en} ${l.proto === 'vless' ? '' : 'TRJ '}${l.name}`;
    names.push(name);
    const base = [
      `  - name: ${y(name)}`, `    type: ${l.proto}`, `    server: ${y(l.host)}`, `    port: ${l.port}`,
      l.proto === 'vless' ? `    uuid: ${user.uuid}` : `    password: ${user.uuid}`,
      `    udp: true`, `    tls: ${l.tls}`, `    network: ws`, `    servername: ${y(l.sni)}`, `    client-fingerprint: ${l.fp === 'random' ? 'random' : l.fp}`,
      `    ws-opts:`, `      path: ${y(settings.proxy_path + '?ed=2560&loc=' + l.id)}`, `      headers:`, `        Host: ${y(settings.host_mask || l.sni)}`,
    ];
    if (l.tls) base.push(`    alpn: [${(settings.alpn || 'h2,http/1.1').split(',').map(a => y(a.trim())).join(', ')}]`);
    return base.join('\n');
  });
  return [
    `# ${BRAND.en} — ${BRAND.memorial}`,
    'mixed-port: 7890', 'allow-lan: false', 'mode: rule', 'log-level: warning', 'ipv6: false', 'unified-delay: true', 'tcp-concurrent: true',
    'dns:', '  enable: true', '  enhanced-mode: fake-ip', '  nameserver: [https://1.1.1.1/dns-query, https://8.8.8.8/dns-query]', '  fallback: [https://dns.google/dns-query]',
    'proxies:', ...proxies,
    'proxy-groups:',
    `  - name: ${y(BRAND.en)}`, '    type: select', `    proxies: [${['⚡ خودکار', ...names].map(y).join(', ')}]`,
    `  - name: ${y('⚡ خودکار')}`, '    type: url-test', '    url: https://www.gstatic.com/generate_204', '    interval: 300', '    tolerance: 100', `    proxies: [${names.map(y).join(', ')}]`,
    'rules:', '  - GEOIP,PRIVATE,DIRECT,no-resolve', '  - DOMAIN-SUFFIX,ir,DIRECT', '  - GEOIP,IR,DIRECT', `  - MATCH,${y(BRAND.en)}`,
  ].join('\n') + '\n';
}

function subInfoHeader(state) {
  const parts = [`upload=0; download=${state.used}; total=${state.quota || 0}`];
  if (state.expiryAt) parts.push(`expire=${Math.floor(state.expiryAt / 1000)}`);
  return parts.join('; ');
}

async function handleSub(request, url, ctx) {
  const m = url.pathname.match(/^\/(sub|status)\/([0-9a-f]{8,64})(?:\/(sb|clash|raw|b64|json|links))?$/);
  if (!m) return notFound();
  const kind = m[1], token = m[2];
  countRequest();
  const user = await dbGet('SELECT * FROM users WHERE sub_token = ?', [token]);
  if (!user) return htmlResponse('<!doctype html><html dir="rtl"><body style="background:#000;color:#fff;font-family:sans-serif;display:grid;place-items:center;height:100vh"><h2>اشتراک یافت نشد</h2></body></html>', 404);

  const settings = await getSettings();
  const allowed = userLocationIds(user);
  let locations = resolveLocations(settings, url.host, user.uuid);
  if (allowed) locations = locations.filter(l => allowed.includes(l.baseId || l.id));
  if (!locations.length) locations = resolveLocations(settings, url.host, user.uuid).slice(0, 1);

  const presetId = url.searchParams.get('isp') || url.searchParams.get('preset') || '';
  const preset = ISP_PRESETS.find(p => p.id === presetId && p.id !== 'auto') || null;
  const links = buildConfigLinks(user, settings, locations, url.host, { preset });
  const state = userState(user);
  const subUrl = `https://${url.host}/sub/${token}`;
  const fmt = m[3] || url.searchParams.get('format') || url.searchParams.get('fmt') || (url.searchParams.get('json') === '1' ? 'json' : '');
  const ua = (request.headers.get('User-Agent') || '').toLowerCase();
  const isClient = CLIENT_UA_HINTS.some(h => ua.includes(h));
  const hdrs = { 'Profile-Update-Interval': '6', 'Subscription-Userinfo': subInfoHeader(state), 'Profile-Title': 'base64:' + b64encode(`${BRAND.en} | ${user.name}`), 'Support-Url': settings.contact || BRAND.repo, 'Profile-Web-Page-Url': subUrl };

  const statusPayload = () => ({
    app: BRAND.en, version: VERSION, name: user.name, state, active: !!user.active,
    quota_bytes: user.quota_bytes, used_bytes: user.used_bytes, expiry_at: user.expiry_at, days_left: state.daysLeft,
    max_requests: user.max_requests || 0, used_requests: user.used_requests || 0, ip_limit: user.ip_limit, online_ips: activeIps(user.uuid),
    last_seen_at: user.last_seen_at || null, expiry_jalali: user.expiry_at ? toJalali(user.expiry_at) : null,
    locations: locations.map(l => ({ id: l.id, name: l.name })), sub_url: subUrl, now: Date.now(),
  });

  if (fmt === 'json') return jsonResponse(statusPayload(), 200, { 'Access-Control-Allow-Origin': '*' });
  if (fmt === 'sb' || fmt === 'singbox' || (!fmt && /sing-box|sfa|sfi|sfm|husi|karing/.test(ua) && !/hiddify/.test(ua))) {
    return jsonResponse(singboxConfig(user, links.filter(l => l.proto === 'vless'), settings), 200, { ...hdrs, 'Content-Disposition': `attachment; filename="javidnam-${user.name}.json"` });
  }
  if (fmt === 'clash' || (!fmt && /clash|mihomo|stash/.test(ua) && !/hiddify/.test(ua))) {
    return new Response(clashConfig(user, links, settings), { headers: { 'Content-Type': 'text/yaml; charset=utf-8', ...hdrs, 'Content-Disposition': `attachment; filename="javidnam-${user.name}.yaml"` } });
  }
  if (fmt === 'b64' || fmt === 'base64') return textResponse(b64encode(links.map(l => l.link).join('\n')), hdrs);
  if (fmt === 'links') return jsonResponse({ links, presets: ISP_PRESETS, preset: preset ? preset.id : 'auto' }, 200, { 'Access-Control-Allow-Origin': '*' });
  if (isClient || fmt === 'raw' || fmt === 'txt') return textResponse(links.map(l => l.link).join('\n'), hdrs);

  /* HTML page (humans). /status/* shows same page with status tab first */
  const data = {
    brand: BRAND, version: VERSION, name: user.name, state, sub_url: subUrl, status_url: `https://${url.host}/status/${token}`,
    links, presets: ISP_PRESETS, preset: preset ? preset.id : 'auto',
    welcome: settings.welcome || '', contact: settings.contact || '', show_branding: !!settings.sub_branding,
    status: statusPayload(), view: kind === 'status' ? 'status' : 'configs',
    formats: { raw: subUrl, b64: subUrl + '/b64', clash: subUrl + '/clash', sb: subUrl + '/sb', json: subUrl + '/json' },
  };
  return htmlResponse(renderSubPage(data));
}

function renderSubPage(data) {
  const payload = JSON.stringify(data).replace(/</g, '\\u003c');
  return SUB_PAGE_TEMPLATE.replace('__SUB_DATA_JSON__', () => payload).replace('__TITLE__', escapeHtml(data.brand.fa + ' | ' + data.name));
}
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

/* ------------------------------------------------------------------ */
/* ROUTER — main fetch handler + PWA assets + scanner scripts           */
/* ------------------------------------------------------------------ */

const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f43f5e"/><stop offset="1" stop-color="#881337"/></linearGradient>
<radialGradient id="c" cx="0.5" cy="0.35" r="0.5"><stop offset="0" stop-color="#fbbf24"/><stop offset="1" stop-color="#f43f5e" stop-opacity="0"/></radialGradient></defs>
<rect width="64" height="64" rx="14" fill="#07070b"/>
<path d="M32 10c-1.8 5-6 7.2-6 12.6 0 3.4 1.9 6.3 4.2 8.4C29.6 39 27.4 44.6 22 50c7-1.6 11.2-5 13.4-9.6 2.2 4.6 6.4 8 13.4 9.6-5.4-5.4-7.6-11-8.2-19 2.3-2.1 4.2-5 4.2-8.4C44.8 17.2 40.6 15 38.8 10c-1.6 3.4-4.2 5-6.8 5s-5.2-1.6-6.8-5z" fill="url(#g)"/>
<ellipse cx="32" cy="24" rx="3.6" ry="6.5" fill="url(#c)" opacity="0.9"/></svg>`;

const MANIFEST_JSON = JSON.stringify({
  name: 'JavidNam | جاویدنام', short_name: 'JavidNam', description: 'پنل جاویدنام — به یاد ۱۸ و ۱۹ دی ۱۴۰۴',
  start_url: '/', scope: '/', display: 'standalone', orientation: 'portrait', background_color: '#07070b', theme_color: '#07070b', dir: 'rtl', lang: 'fa',
  icons: [{ src: '/favicon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' }, { src: '/icon-512.svg', sizes: '512x512', type: 'image/svg+xml', purpose: 'maskable' }],
});

const SW_JS = `const C='javidnam-%VERSION%';const STATIC=['/favicon.svg','/manifest.webmanifest'];
self.addEventListener('install',e=>{self.skipWaiting();e.waitUntil(caches.open(C).then(c=>c.addAll(STATIC)).catch(()=>{}))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==C).map(k=>caches.delete(k)))).then(()=>clients.claim()))});
self.addEventListener('fetch',e=>{const u=new URL(e.request.url);if(e.request.method!=='GET'||u.pathname.startsWith('/api/')||u.pathname.startsWith('/sub/')||u.pathname.startsWith('/status/'))return;
e.respondWith(fetch(e.request).then(r=>{if(r.ok){const cp=r.clone();caches.open(C).then(c=>c.put(e.request,cp)).catch(()=>{})}return r;}).catch(()=>caches.match(e.request)))});`;

/* Clean-IP scanner scripts served by the panel (user-side, where CF ranges ARE reachable) */
const SCANNER_PY = `# JavidNam Clean IP Scanner (Pydroid3 / Python 3) — GPL-3.0
import socket, ssl, time, random, ipaddress, concurrent.futures as cf
HOST = "__HOST__"; RANGES = ["104.16.0.0/13","172.64.0.0/13","162.159.0.0/16","188.114.96.0/20","141.101.64.0/18","190.93.240.0/20","198.41.128.0/17"]
N = 300; TOP = 15; TIMEOUT = 1.5
def probe(ip):
    t0 = time.time()
    try:
        s = socket.create_connection((ip, 443), timeout=TIMEOUT)
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        w = ctx.wrap_socket(s, server_hostname=HOST)
        w.send(("HEAD / HTTP/1.1\\r\\nHost: %s\\r\\nConnection: close\\r\\n\\r\\n" % HOST).encode()); w.recv(64); w.close()
        return ip, int((time.time()-t0)*1000)
    except Exception: return ip, None
ips = []
for r in RANGES:
    net = ipaddress.ip_network(r); size = net.num_addresses
    for _ in range(N // len(RANGES)): ips.append(str(net[random.randrange(size)]))
print("JavidNam scanner: testing %d IPs for %s ..." % (len(ips), HOST))
res = []
with cf.ThreadPoolExecutor(64) as ex:
    for ip, ms in ex.map(probe, ips):
        if ms is not None: res.append((ms, ip)); print("  ok %-16s %4d ms" % (ip, ms))
res.sort()
print("\\n=== TOP %d ===" % TOP)
for ms, ip in res[:TOP]: print("%-16s %4d ms" % (ip, ms))
print("\\nPaste the IPs into JavidNam panel → Settings → Clean IPs")
`;

const SCANNER_CMD = `@echo off
:: JavidNam Clean IP Scanner (Windows CMD) — tests random Cloudflare IPs with TLS to your panel host
setlocal enabledelayedexpansion
set HOST=__HOST__
set N=80
echo JavidNam scanner: testing %N% IPs for %HOST% ...
set OUT=%TEMP%\\jvn_scan.txt
if exist "%OUT%" del "%OUT%"
for /L %%i in (1,1,%N%) do (
  set /a a=104, b=16+!random! %% 8, c=!random! %% 256, d=1+!random! %% 254
  set IP=!a!.!b!.!c!.!d!
  for /f "tokens=*" %%t in ('curl -s -o NUL -w "%%{time_connect}" --connect-timeout 2 --resolve %HOST%:443:!IP! https://%HOST%/healthz 2^>NUL') do (
    if not "%%t"=="" if not "%%t"=="0.000000" (echo   ok !IP!  %%t s & echo %%t !IP!>>"%OUT%")
  )
)
echo.
echo === TOP 15 ===
if exist "%OUT%" sort "%OUT%" | more +0 | findstr /n "^" | findstr /r "^[0-9]:\\|^1[0-5]:"
echo.
echo Paste the IPs into JavidNam panel - Settings - Clean IPs
pause
`;

const SCANNER_SH = `#!/usr/bin/env bash
# JavidNam Clean IP Scanner (Linux/Termux/macOS) — GPL-3.0
HOST="__HOST__"; N=\${1:-200}
RANGES=(104.16 104.17 104.18 104.19 104.20 104.21 104.22 104.23 172.64 172.65 172.66 172.67 162.159 188.114 141.101)
echo "JavidNam scanner: testing $N IPs for $HOST ..."
probe(){ ip=$1; t=$(curl -s -o /dev/null -w '%{time_appconnect}' --connect-timeout 2 -m 4 --resolve "$HOST:443:$ip" "https://$HOST/healthz" 2>/dev/null); [ -n "$t" ] && [ "$t" != "0.000000" ] && printf '%s %s\\n' "$(awk "BEGIN{printf \\"%d\\", $t*1000}")" "$ip"; }
export -f probe; export HOST
for i in $(seq 1 $N); do r=\${RANGES[$RANDOM % \${#RANGES[@]}]}; echo "$r.$((RANDOM%256)).$((RANDOM%254+1))"; done | xargs -P 40 -I{} bash -c 'probe {}' | sort -n | head -15 | awk '{printf "%-16s %4d ms\\n", $2, $1}'
echo; echo "Paste the IPs into JavidNam panel → Settings → Clean IPs"
`;

export default {
  async fetch(request, env, ctx) {
    initEnv(env);
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      /* --- WebSocket proxy (VLESS/Trojan) --- */
      if ((request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') {
        const settings = await getSettings();
        if (pathMatches(path, settings.proxy_path)) return await handleProxy(request, ctx);
        return notFound();
      }

      if (path === '/healthz') return jsonResponse({ ok: true, app: 'javidnam', version: VERSION, colo: (request.cf && request.cf.colo) || null });
      if (path === '/robots.txt') return textResponse('User-agent: *\nDisallow: /\n');
      if (path === '/favicon.svg' || path === '/icon-512.svg') return new Response(FAVICON_SVG, { headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' } });
      if (path === '/favicon.ico') return Response.redirect(url.origin + '/favicon.svg', 302);
      if (path === '/manifest.webmanifest') return new Response(MANIFEST_JSON, { headers: { 'Content-Type': 'application/manifest+json' } });
      if (path === '/sw.js') return new Response(SW_JS.replace('%VERSION%', VERSION), { headers: { 'Content-Type': 'application/javascript', 'Cache-Control': 'no-cache' } });

      /* --- scanner scripts --- */
      if (path === '/tools/scanner.py') return textResponse(SCANNER_PY.replace('__HOST__', url.host), { 'Content-Disposition': 'attachment; filename="javidnam-scanner.py"' });
      if (path === '/tools/scanner.cmd') return textResponse(SCANNER_CMD.replace('__HOST__', url.host), { 'Content-Disposition': 'attachment; filename="javidnam-scanner.cmd"' });
      if (path === '/tools/scanner.sh') return textResponse(SCANNER_SH.replace('__HOST__', url.host), { 'Content-Disposition': 'attachment; filename="javidnam-scanner.sh"' });

      /* --- subscription / status --- */
      if (path.startsWith('/sub/') || path.startsWith('/status/')) return await handleSub(request, url, ctx);

      /* --- admin --- */
      if (path.startsWith('/api/')) return await handleAdminApi(request, url, ctx);
      if (path === '/' || path === '/index.html' || path === '/panel' || path === '/admin') {
        countRequest(); ctx.waitUntil(flushMetrics().catch(() => {}));
        return htmlResponse(renderAdminPage(url.origin));
      }

      /* decoy for unknown paths: look like a plain static site */
      return htmlResponse('<!doctype html><html><head><meta charset="utf-8"><title>Welcome</title></head><body style="font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0;color:#444"><div><h1>It works!</h1><p>This server is up and running.</p></div></body></html>', 404);
    } catch (e) {
      return jsonResponse({ error: 'internal', message: String(e && e.message || e) }, 500);
    }
  },
};

function renderAdminPage(origin) { return ADMIN_PAGE_TEMPLATE.replace('__ORIGIN__', origin).replace('__VERSION__', VERSION); }


/* ---------- embedded assets ---------- */

const ADMIN_PAGE_TEMPLATE = `<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#07070b">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="robots" content="noindex,nofollow">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/favicon.svg">
<title>جاویدنام | پنل مدیریت</title>
<style>
:root{--bg:#07070b;--bg2:#0c0c13;--card:#10101a;--card2:#151522;--line:#1e1e2c;--line2:#2a2a3c;--txt:#eaeaf2;--mut:#8f8fa3;--dim:#5c5c70;--rose:#f43f5e;--rose2:#be123c;--amber:#fbbf24;--green:#22c55e;--blue:#38bdf8;--violet:#a78bfa;--r:16px;--sh:0 10px 40px -10px rgba(0,0,0,.7)}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg);color:var(--txt);font-family:"Vazirmatn","Segoe UI",Tahoma,system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.7;-webkit-font-smoothing:antialiased;-webkit-tap-highlight-color:transparent}
body{overflow-x:hidden}
#bg{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.9}
#glow{position:fixed;inset:0;z-index:0;pointer-events:none;background:radial-gradient(900px 500px at 85% -10%,rgba(244,63,94,.14),transparent 60%),radial-gradient(700px 400px at 5% 110%,rgba(251,191,36,.08),transparent 60%)}
a{color:inherit;text-decoration:none}
button{font:inherit;color:inherit;background:none;border:0;cursor:pointer}
input,select,textarea{font:inherit;color:var(--txt);background:var(--bg2);border:1px solid var(--line2);border-radius:12px;padding:10px 12px;width:100%;outline:none;transition:.2s}
input:focus,select:focus,textarea:focus{border-color:var(--rose);box-shadow:0 0 0 3px rgba(244,63,94,.15)}
input[type=checkbox]{width:18px;height:18px;accent-color:var(--rose);padding:0}
select{appearance:none;background-image:linear-gradient(45deg,transparent 50%,var(--mut) 50%),linear-gradient(135deg,var(--mut) 50%,transparent 50%);background-position:calc(0% + 16px) 55%,calc(0% + 11px) 55%;background-size:5px 5px;background-repeat:no-repeat;padding-left:30px}
textarea{min-height:90px;resize:vertical;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;direction:ltr;text-align:left}
label{display:block;font-size:12.5px;color:var(--mut);margin-bottom:6px}
.hidden{display:none!important}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;direction:ltr;unicode-bidi:embed}
.ltr{direction:ltr;text-align:left}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.grow{flex:1}
.grid{display:grid;gap:12px}
.g2{grid-template-columns:repeat(2,1fr)}.g3{grid-template-columns:repeat(3,1fr)}.g4{grid-template-columns:repeat(4,1fr)}.g6{grid-template-columns:repeat(6,1fr)}
@media(max-width:1100px){.g6{grid-template-columns:repeat(3,1fr)}}
@media(max-width:900px){.g4{grid-template-columns:repeat(2,1fr)}.g3{grid-template-columns:repeat(2,1fr)}}
@media(max-width:560px){.g2,.g3{grid-template-columns:1fr}.g6{grid-template-columns:repeat(2,1fr)}}
.card{background:linear-gradient(180deg,var(--card),var(--bg2));border:1px solid var(--line);border-radius:var(--r);padding:16px;box-shadow:var(--sh);position:relative}
.card h3{font-size:15px;font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.card h3 small{font-weight:400;color:var(--mut);font-size:12px}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:9px 14px;border-radius:12px;border:1px solid var(--line2);background:var(--card2);font-weight:600;font-size:13px;transition:.15s;white-space:nowrap;line-height:1.4}
.btn:hover{border-color:var(--rose);transform:translateY(-1px)}
.btn:active{transform:translateY(0)}
.btn:disabled{opacity:.5;pointer-events:none}
.btn.p{background:linear-gradient(135deg,var(--rose),var(--rose2));border-color:transparent;color:#fff;box-shadow:0 6px 20px -6px rgba(244,63,94,.6)}
.btn.g{background:linear-gradient(135deg,#16a34a,#15803d);border-color:transparent;color:#fff}
.btn.b{background:linear-gradient(135deg,#0284c7,#0369a1);border-color:transparent;color:#fff}
.btn.d{background:rgba(244,63,94,.1);border-color:rgba(244,63,94,.35);color:#fda4af}
.btn.s{padding:6px 10px;font-size:12px;border-radius:10px}
.btn.i{padding:0;width:34px;height:34px;border-radius:10px;font-size:15px}
.chip{display:inline-flex;align-items:center;gap:5px;padding:2px 9px;border-radius:999px;font-size:11.5px;font-weight:600;border:1px solid var(--line2);background:var(--bg2);color:var(--mut);white-space:nowrap}
.chip.ok{color:#86efac;border-color:rgba(34,197,94,.35);background:rgba(34,197,94,.08)}
.chip.bad{color:#fda4af;border-color:rgba(244,63,94,.35);background:rgba(244,63,94,.08)}
.chip.warn{color:#fde68a;border-color:rgba(251,191,36,.35);background:rgba(251,191,36,.08)}
.chip.info{color:#7dd3fc;border-color:rgba(56,189,248,.35);background:rgba(56,189,248,.08)}
.chip.vio{color:#c4b5fd;border-color:rgba(167,139,250,.35);background:rgba(167,139,250,.08)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--dim);display:inline-block;flex:none}
.dot.on{background:var(--green);box-shadow:0 0 8px var(--green)}
.bar{height:6px;border-radius:99px;background:var(--line);overflow:hidden}
.bar>i{display:block;height:100%;background:linear-gradient(90deg,var(--rose),var(--amber));border-radius:99px;transition:width .6s}
.bar.g>i{background:linear-gradient(90deg,#22c55e,#38bdf8)}
.bar.w>i{background:linear-gradient(90deg,var(--amber),var(--rose))}
.switch{position:relative;display:inline-block;width:42px;height:24px;flex:none}
.switch input{opacity:0;width:0;height:0}
.switch i{position:absolute;inset:0;background:var(--line2);border-radius:99px;transition:.2s;cursor:pointer}
.switch i:before{content:"";position:absolute;width:18px;height:18px;right:3px;top:3px;background:#fff;border-radius:50%;transition:.2s}
.switch input:checked+i{background:var(--rose)}
.switch input:checked+i:before{transform:translateX(-18px)}
.sw{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 12px;border:1px solid var(--line);border-radius:12px;background:var(--bg2)}
.sw b{font-weight:600;font-size:13px}.sw small{display:block;color:var(--mut);font-size:11.5px}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px;border-bottom:1px solid var(--line);padding-bottom:10px}
.tabs button{padding:7px 12px;border-radius:10px;font-size:13px;color:var(--mut);font-weight:600}
.tabs button.on{background:rgba(244,63,94,.12);color:#fda4af}
.tabs button:hover{color:var(--txt)}
kbd,code{font-family:ui-monospace,Menlo,Consolas,monospace;background:var(--bg2);border:1px solid var(--line2);border-radius:6px;padding:1px 6px;font-size:12px;direction:ltr;unicode-bidi:embed}
.muted{color:var(--mut)}.small{font-size:12px}.xs{font-size:11px}
.hr{height:1px;background:var(--line);margin:14px 0}
pre.out{background:#050508;border:1px solid var(--line);border-radius:12px;padding:12px;font-size:12px;direction:ltr;text-align:left;max-height:260px;overflow:auto;white-space:pre-wrap;font-family:ui-monospace,Menlo,Consolas,monospace;color:#c7c7d6}
/* layout */
#app{position:relative;z-index:1;display:grid;grid-template-columns:240px 1fr;min-height:100vh}
aside{border-left:1px solid var(--line);background:rgba(10,10,16,.75);backdrop-filter:blur(14px);padding:18px 14px;position:sticky;top:0;height:100vh;display:flex;flex-direction:column;gap:4px;overflow:auto}
.logo{display:flex;align-items:center;gap:10px;padding:6px 8px 16px}
.logo .flame{width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,var(--rose),#7f1d1d);display:grid;place-items:center;box-shadow:0 8px 24px -8px var(--rose);flex:none}
.logo b{font-size:17px;display:block;line-height:1.2}.logo small{color:var(--mut);font-size:11px}
.nav a{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:12px;color:var(--mut);font-weight:600;font-size:13.5px;transition:.15s;cursor:pointer}
.nav a:hover{color:var(--txt);background:var(--card)}
.nav a.on{color:#fff;background:linear-gradient(90deg,rgba(244,63,94,.22),transparent);border-right:3px solid var(--rose)}
.nav a svg{width:18px;height:18px;flex:none}
.memo{margin-top:auto;padding:12px;border-radius:12px;background:rgba(244,63,94,.06);border:1px dashed rgba(244,63,94,.3);font-size:11.5px;color:#fda4af;line-height:1.8;text-align:center}
main{padding:20px 22px 90px;min-width:0}
header.top{display:flex;align-items:center;gap:12px;margin-bottom:18px;flex-wrap:wrap}
header.top h1{font-size:20px;font-weight:800}
header.top .sp{flex:1}
.stat{display:flex;flex-direction:column;gap:6px}
.stat .v{font-size:24px;font-weight:800;line-height:1.2}
.stat .k{font-size:12px;color:var(--mut)}
.stat .ic{position:absolute;left:14px;top:14px;width:36px;height:36px;border-radius:10px;display:grid;place-items:center;font-size:17px;background:var(--bg2);border:1px solid var(--line)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:right;color:var(--mut);font-weight:600;font-size:12px;padding:8px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:10px;border-bottom:1px solid var(--line);vertical-align:middle}
tr:hover td{background:rgba(255,255,255,.015)}
.tbl{overflow:auto;border-radius:12px;border:1px solid var(--line)}
.uname{font-weight:700;display:flex;align-items:center;gap:8px}
.uname small{font-weight:400;color:var(--dim);font-size:11px}
.acts{display:flex;gap:4px;justify-content:flex-end;flex-wrap:nowrap}
#bulkbar{position:sticky;bottom:12px;z-index:5;margin-top:10px;background:linear-gradient(135deg,#1c1c2c,#12121c);border:1px solid var(--rose);border-radius:14px;padding:10px 14px;box-shadow:0 10px 40px -8px rgba(244,63,94,.5)}
/* modal */
.modal{position:fixed;inset:0;z-index:50;background:rgba(0,0,0,.7);backdrop-filter:blur(6px);display:grid;place-items:center;padding:14px;animation:fade .15s}
.modal .box{background:linear-gradient(180deg,#12121c,#0b0b12);border:1px solid var(--line2);border-radius:20px;width:min(720px,100%);max-height:92vh;overflow:auto;padding:20px;box-shadow:0 30px 80px -20px #000;animation:pop .18s}
.modal .box h2{font-size:17px;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.modal .box h2 .x{margin-right:auto;color:var(--mut)}
@keyframes fade{from{opacity:0}}@keyframes pop{from{transform:translateY(12px) scale(.98);opacity:0}}
/* toasts */
#toasts{position:fixed;bottom:18px;left:18px;z-index:99;display:flex;flex-direction:column;gap:8px}
.toast{background:#15151f;border:1px solid var(--line2);border-right:3px solid var(--green);padding:10px 14px;border-radius:12px;font-size:13px;box-shadow:var(--sh);animation:pop .2s;max-width:340px}
.toast.err{border-right-color:var(--rose)}.toast.warn{border-right-color:var(--amber)}
/* login */
#login{position:relative;z-index:1;min-height:100vh;display:grid;place-items:center;padding:20px}
#login .box{width:min(400px,100%);text-align:center}
#login .flame{width:76px;height:76px;border-radius:22px;margin:0 auto 14px;background:linear-gradient(135deg,var(--rose),#7f1d1d);display:grid;place-items:center;box-shadow:0 20px 50px -14px var(--rose)}
#login h1{font-size:24px;font-weight:800}
#login p.m{color:var(--mut);font-size:12.5px;margin:4px 0 20px}
.qr{background:#fff;padding:10px;border-radius:12px;display:inline-block}
.qr canvas,.qr img{display:block}
.locpick{display:flex;flex-wrap:wrap;gap:6px}
.locpick label{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line2);border-radius:10px;padding:5px 10px;margin:0;cursor:pointer;color:var(--txt);font-size:12.5px;background:var(--bg2)}
.locpick label:has(input:checked){border-color:var(--rose);background:rgba(244,63,94,.1)}
.loc-row{display:grid;grid-template-columns:70px 1fr 1.4fr 70px 1fr 1fr 60px 34px;gap:8px;align-items:end;padding:10px;border:1px solid var(--line);border-radius:12px;background:var(--bg2);margin-bottom:8px}
.loc-row label{margin-bottom:2px;font-size:11px}
@media(max-width:1000px){.loc-row{grid-template-columns:1fr 1fr 1fr;} .loc-row>div:first-child{grid-column:span 1}}
.spark{display:flex;align-items:flex-end;gap:3px;height:64px}
.spark i{flex:1;background:linear-gradient(180deg,var(--rose),rgba(244,63,94,.25));border-radius:3px 3px 0 0;min-height:2px;position:relative}
.spark i:hover:after{content:attr(data-t);position:absolute;bottom:100%;left:50%;transform:translateX(-50%);background:#000;padding:2px 6px;border-radius:6px;font-size:10px;white-space:nowrap;color:#fff}
.mobnav{display:none}
@media(max-width:820px){
  #app{grid-template-columns:1fr}
  aside{display:none}
  main{padding:14px 12px 90px}
  .mobnav{display:flex;position:fixed;bottom:0;left:0;right:0;z-index:20;background:rgba(10,10,16,.9);backdrop-filter:blur(16px);border-top:1px solid var(--line);padding:6px 4px calc(6px + env(safe-area-inset-bottom));justify-content:space-around}
  .mobnav a{display:flex;flex-direction:column;align-items:center;gap:2px;font-size:10px;color:var(--mut);padding:4px 6px;border-radius:10px;cursor:pointer;min-width:52px}
  .mobnav a.on{color:#fda4af}
  .mobnav svg{width:20px;height:20px}
  header.top h1{font-size:17px}
  .acts{flex-wrap:wrap;justify-content:flex-start}
  td,th{padding:8px 6px}
}
.fadein{animation:fade .25s}
::-webkit-scrollbar{width:8px;height:8px}::-webkit-scrollbar-thumb{background:var(--line2);border-radius:99px}
</style>
</head>
<body>
<canvas id="bg"></canvas><div id="glow"></div>

<!-- ============ LOGIN ============ -->
<div id="login" class="hidden">
  <div class="card box fadein">
    <div class="flame"><svg width="40" height="40" viewBox="0 0 64 64"><path d="M32 10c-1.8 5-6 7.2-6 12.6 0 3.4 1.9 6.3 4.2 8.4C29.6 39 27.4 44.6 22 50c7-1.6 11.2-5 13.4-9.6 2.2 4.6 6.4 8 13.4 9.6-5.4-5.4-7.6-11-8.2-19 2.3-2.1 4.2-5 4.2-8.4C44.8 17.2 40.6 15 38.8 10c-1.6 3.4-4.2 5-6.8 5s-5.2-1.6-6.8-5z" fill="#fff"/></svg></div>
    <h1>جاویدنام</h1>
    <p class="m">به یاد جان‌باختگان ۱۸ و ۱۹ دی ۱۴۰۴ — نامشان جاوید</p>
    <div id="setupBox" class="hidden" style="text-align:right;margin-bottom:12px">
      <div class="chip warn" style="margin-bottom:8px">اولین ورود</div>
      <p class="small muted">هنوز رمزی تنظیم نشده. یک رمز قوی (حداقل ۸ کاراکتر) انتخاب کن و <b>حتماً جایی ذخیره‌اش کن</b>.</p>
    </div>
    <div style="text-align:right"><label>رمز مدیریت</label><input id="passInput" type="password" autocomplete="current-password" placeholder="••••••••" class="ltr"></div>
    <div id="loginErr" class="small" style="color:#fda4af;min-height:22px;margin:6px 0"></div>
    <button id="loginBtn" class="btn p" style="width:100%;padding:12px">ورود به پنل</button>
    <p class="xs muted" style="margin-top:14px">JavidNam v<span class="ver">__VERSION__</span> · GPL-3.0 · <a href="https://github.com/amirparsa1/JavidNam" target="_blank" style="color:#fda4af">GitHub</a></p>
  </div>
</div>

<!-- ============ APP ============ -->
<div id="app" class="hidden">
  <aside>
    <div class="logo">
      <div class="flame"><svg width="26" height="26" viewBox="0 0 64 64"><path d="M32 10c-1.8 5-6 7.2-6 12.6 0 3.4 1.9 6.3 4.2 8.4C29.6 39 27.4 44.6 22 50c7-1.6 11.2-5 13.4-9.6 2.2 4.6 6.4 8 13.4 9.6-5.4-5.4-7.6-11-8.2-19 2.3-2.1 4.2-5 4.2-8.4C44.8 17.2 40.6 15 38.8 10c-1.6 3.4-4.2 5-6.8 5s-5.2-1.6-6.8-5z" fill="#fff"/></svg></div>
      <div><b>جاویدنام</b><small>JavidNam v<span class="ver">__VERSION__</span></small></div>
    </div>
    <nav class="nav" id="nav"></nav>
    <div class="memo">🌷 به یاد جان‌باختگان<br>۱۸ و ۱۹ دی ۱۴۰۴<br><b>نامشان جاوید</b></div>
  </aside>
  <main>
    <header class="top">
      <h1 id="pageTitle">داشبورد</h1>
      <span id="coloChip" class="chip info hidden"></span>
      <div class="sp"></div>
      <button class="btn s" id="installBtn" style="display:none">📲 نصب اپ</button>
      <button class="btn s" onclick="refreshPage()">🔄 بروزرسانی</button>
      <button class="btn s d" onclick="logout()">خروج</button>
    </header>
    <div id="main"></div>
  </main>
  <nav class="mobnav" id="mobnav"></nav>
</div>
<div id="toasts"></div>
<div id="modalRoot"></div>
<script>
var qrcode=function(){function i(t,r){function a(t,r){g=function(t){for(var r=new Array(t),e=0;e<t;e+=1){r[e]=new Array(t);for(var n=0;n<t;n+=1)r[e][n]=null}return r}(l=4*u+17),e(0,0),e(l-7,0),e(0,l-7),i(),o(),v(t,r),7<=u&&h(t),null==n&&(n=w(u,f,c)),d(n,r)}var u=t,f=y[r],g=null,l=0,n=null,c=[],s={},e=function(t,r){for(var e=-1;e<=7;e+=1)if(!(t+e<=-1||l<=t+e))for(var n=-1;n<=7;n+=1)r+n<=-1||l<=r+n||(g[t+e][r+n]=0<=e&&e<=6&&(0==n||6==n)||0<=n&&n<=6&&(0==e||6==e)||2<=e&&e<=4&&2<=n&&n<=4)},o=function(){for(var t=8;t<l-8;t+=1)null==g[t][6]&&(g[t][6]=t%2==0);for(var r=8;r<l-8;r+=1)null==g[6][r]&&(g[6][r]=r%2==0)},i=function(){for(var t=B.getPatternPosition(u),r=0;r<t.length;r+=1)for(var e=0;e<t.length;e+=1){var n=t[r],o=t[e];if(null==g[n][o])for(var i=-2;i<=2;i+=1)for(var a=-2;a<=2;a+=1)g[n+i][o+a]=-2==i||2==i||-2==a||2==a||0==i&&0==a}},h=function(t){for(var r=B.getBCHTypeNumber(u),e=0;e<18;e+=1){var n=!t&&1==(r>>e&1);g[Math.floor(e/3)][e%3+l-8-3]=n}for(e=0;e<18;e+=1){n=!t&&1==(r>>e&1);g[e%3+l-8-3][Math.floor(e/3)]=n}},v=function(t,r){for(var e=f<<3|r,n=B.getBCHTypeInfo(e),o=0;o<15;o+=1){var i=!t&&1==(n>>o&1);o<6?g[o][8]=i:o<8?g[o+1][8]=i:g[l-15+o][8]=i}for(o=0;o<15;o+=1){i=!t&&1==(n>>o&1);o<8?g[8][l-o-1]=i:o<9?g[8][15-o-1+1]=i:g[8][15-o-1]=i}g[l-8][8]=!t},d=function(t,r){for(var e=-1,n=l-1,o=7,i=0,a=B.getMaskFunction(r),u=l-1;0<u;u-=2)for(6==u&&(u-=1);;){for(var f=0;f<2;f+=1)if(null==g[n][u-f]){var c=!1;i<t.length&&(c=1==(t[i]>>>o&1)),a(n,u-f)&&(c=!c),g[n][u-f]=c,-1==(o-=1)&&(i+=1,o=7)}if((n+=e)<0||l<=n){n-=e,e=-e;break}}},w=function(t,r,e){for(var n=b.getRSBlocks(t,r),o=M(),i=0;i<e.length;i+=1){var a=e[i];o.put(a.getMode(),4),o.put(a.getLength(),B.getLengthInBits(a.getMode(),t)),a.write(o)}var u=0;for(i=0;i<n.length;i+=1)u+=n[i].dataCount;if(o.getLengthInBits()>8*u)throw"code length overflow. ("+o.getLengthInBits()+">"+8*u+")";for(o.getLengthInBits()+4<=8*u&&o.put(0,4);o.getLengthInBits()%8!=0;)o.putBit(!1);for(;!(o.getLengthInBits()>=8*u||(o.put(236,8),o.getLengthInBits()>=8*u));)o.put(17,8);return function(t,r){for(var e=0,n=0,o=0,i=new Array(r.length),a=new Array(r.length),u=0;u<r.length;u+=1){var f=r[u].dataCount,c=r[u].totalCount-f;n=Math.max(n,f),o=Math.max(o,c),i[u]=new Array(f);for(var g=0;g<i[u].length;g+=1)i[u][g]=255&t.getBuffer()[g+e];e+=f;var l=B.getErrorCorrectPolynomial(c),h=C(i[u],l.getLength()-1).mod(l);a[u]=new Array(l.getLength()-1);for(g=0;g<a[u].length;g+=1){var s=g+h.getLength()-a[u].length;a[u][g]=0<=s?h.getAt(s):0}}var v=0;for(g=0;g<r.length;g+=1)v+=r[g].totalCount;var d=new Array(v),w=0;for(g=0;g<n;g+=1)for(u=0;u<r.length;u+=1)g<i[u].length&&(d[w]=i[u][g],w+=1);for(g=0;g<o;g+=1)for(u=0;u<r.length;u+=1)g<a[u].length&&(d[w]=a[u][g],w+=1);return d}(o,n)};s.addData=function(t,r){var e=null;switch(r=r||"Byte"){case"Numeric":e=x(t);break;case"Alphanumeric":e=m(t);break;case"Byte":e=L(t);break;case"Kanji":e=D(t);break;default:throw"mode:"+r}c.push(e),n=null},s.isDark=function(t,r){if(t<0||l<=t||r<0||l<=r)throw t+","+r;return g[t][r]},s.getModuleCount=function(){return l},s.make=function(){if(u<1){for(var t=1;t<40;t++){for(var r=b.getRSBlocks(t,f),e=M(),n=0;n<c.length;n++){var o=c[n];e.put(o.getMode(),4),e.put(o.getLength(),B.getLengthInBits(o.getMode(),t)),o.write(e)}var i=0;for(n=0;n<r.length;n++)i+=r[n].dataCount;if(e.getLengthInBits()<=8*i)break}u=t}a(!1,function(){for(var t=0,r=0,e=0;e<8;e+=1){a(!0,e);var n=B.getLostPoint(s);(0==e||n<t)&&(t=n,r=e)}return r}())},s.createTableTag=function(t,r){t=t||2;var e="";e+='<table style="',e+=" border-width: 0px; border-style: none;",e+=" border-collapse: collapse;",e+=" padding: 0px; margin: "+(r=void 0===r?4*t:r)+"px;",e+='">',e+="<tbody>";for(var n=0;n<s.getModuleCount();n+=1){e+="<tr>";for(var o=0;o<s.getModuleCount();o+=1)e+='<td style="',e+=" border-width: 0px; border-style: none;",e+=" border-collapse: collapse;",e+=" padding: 0px; margin: 0px;",e+=" width: "+t+"px;",e+=" height: "+t+"px;",e+=" background-color: ",e+=s.isDark(n,o)?"#000000":"#ffffff",e+=";",e+='"/>';e+="</tr>"}return e+="</tbody>",e+="</table>"},s.createSvgTag=function(t,r,e,n){var o={};"object"==typeof t&&(t=(o=t).cellSize,r=o.margin,e=o.alt,n=o.title),t=t||2,r=void 0===r?4*t:r,(e="string"==typeof e?{text:e}:e||{}).text=e.text||null,e.id=e.text?e.id||"qrcode-description":null,(n="string"==typeof n?{text:n}:n||{}).text=n.text||null,n.id=n.text?n.id||"qrcode-title":null;var i,a,u,f,c=s.getModuleCount()*t+2*r,g="";for(f="l"+t+",0 0,"+t+" -"+t+",0 0,-"+t+"z ",g+='<svg version="1.1" xmlns="http://www.w3.org/2000/svg"',g+=o.scalable?"":' width="'+c+'px" height="'+c+'px"',g+=' viewBox="0 0 '+c+" "+c+'" ',g+=' preserveAspectRatio="xMinYMin meet"',g+=n.text||e.text?' role="img" aria-labelledby="'+p([n.id,e.id].join(" ").trim())+'"':"",g+=">",g+=n.text?'<title id="'+p(n.id)+'">'+p(n.text)+"</title>":"",g+=e.text?'<description id="'+p(e.id)+'">'+p(e.text)+"</description>":"",g+='<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>',g+='<path d="',a=0;a<s.getModuleCount();a+=1)for(u=a*t+r,i=0;i<s.getModuleCount();i+=1)s.isDark(a,i)&&(g+="M"+(i*t+r)+","+u+f);return g+='" stroke="transparent" fill="black"/>',g+="</svg>"},s.createDataURL=function(o,t){o=o||2,t=void 0===t?4*o:t;var r=s.getModuleCount()*o+2*t,i=t,a=r-t;return I(r,r,function(t,r){if(i<=t&&t<a&&i<=r&&r<a){var e=Math.floor((t-i)/o),n=Math.floor((r-i)/o);return s.isDark(n,e)?0:1}return 1})},s.createImgTag=function(t,r,e){t=t||2,r=void 0===r?4*t:r;var n=s.getModuleCount()*t+2*r,o="";return o+="<img",o+=' src="',o+=s.createDataURL(t,r),o+='"',o+=' width="',o+=n,o+='"',o+=' height="',o+=n,o+='"',e&&(o+=' alt="',o+=p(e),o+='"'),o+="/>"};var p=function(t){for(var r="",e=0;e<t.length;e+=1){var n=t.charAt(e);switch(n){case"<":r+="&lt;";break;case">":r+="&gt;";break;case"&":r+="&amp;";break;case'"':r+="&quot;";break;default:r+=n}}return r};return s.createASCII=function(t,r){if((t=t||1)<2)return function(t){t=void 0===t?2:t;var r,e,n,o,i,a=1*s.getModuleCount()+2*t,u=t,f=a-t,c={"██":"█","█ ":"▀"," █":"▄","  ":" "},g={"██":"▀","█ ":"▀"," █":" ","  ":" "},l="";for(r=0;r<a;r+=2){for(n=Math.floor((r-u)/1),o=Math.floor((r+1-u)/1),e=0;e<a;e+=1)i="█",u<=e&&e<f&&u<=r&&r<f&&s.isDark(n,Math.floor((e-u)/1))&&(i=" "),u<=e&&e<f&&u<=r+1&&r+1<f&&s.isDark(o,Math.floor((e-u)/1))?i+=" ":i+="█",l+=t<1&&f<=r+1?g[i]:c[i];l+="\\n"}return a%2&&0<t?l.substring(0,l.length-a-1)+Array(1+a).join("▀"):l.substring(0,l.length-1)}(r);t-=1,r=void 0===r?2*t:r;var e,n,o,i,a=s.getModuleCount()*t+2*r,u=r,f=a-r,c=Array(t+1).join("██"),g=Array(t+1).join("  "),l="",h="";for(e=0;e<a;e+=1){for(o=Math.floor((e-u)/t),h="",n=0;n<a;n+=1)i=1,u<=n&&n<f&&u<=e&&e<f&&s.isDark(o,Math.floor((n-u)/t))&&(i=0),h+=i?c:g;for(o=0;o<t;o+=1)l+=h+"\\n"}return l.substring(0,l.length-1)},s.renderTo2dContext=function(t,r){r=r||2;for(var e=s.getModuleCount(),n=0;n<e;n++)for(var o=0;o<e;o++)t.fillStyle=s.isDark(n,o)?"black":"white",t.fillRect(n*r,o*r,r,r)},s}i.stringToBytes=(i.stringToBytesFuncs={default:function(t){for(var r=[],e=0;e<t.length;e+=1){var n=t.charCodeAt(e);r.push(255&n)}return r}}).default,i.createStringToBytes=function(u,f){var i=function(){function t(){var t=r.read();if(-1==t)throw"eof";return t}for(var r=S(u),e=0,n={};;){var o=r.read();if(-1==o)break;var i=t(),a=t()<<8|t();n[String.fromCharCode(o<<8|i)]=a,e+=1}if(e!=f)throw e+" != "+f;return n}(),a="?".charCodeAt(0);return function(t){for(var r=[],e=0;e<t.length;e+=1){var n=t.charCodeAt(e);if(n<128)r.push(n);else{var o=i[t.charAt(e)];"number"==typeof o?(255&o)==o?r.push(o):(r.push(o>>>8),r.push(255&o)):r.push(a)}}return r}};var r,t,a=1,u=2,o=4,f=8,y={L:1,M:0,Q:3,H:2},e=0,n=1,c=2,g=3,l=4,h=5,s=6,v=7,B=(r=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],(t={}).getBCHTypeInfo=function(t){for(var r=t<<10;0<=d(r)-d(1335);)r^=1335<<d(r)-d(1335);return 21522^(t<<10|r)},t.getBCHTypeNumber=function(t){for(var r=t<<12;0<=d(r)-d(7973);)r^=7973<<d(r)-d(7973);return t<<12|r},t.getPatternPosition=function(t){return r[t-1]},t.getMaskFunction=function(t){switch(t){case e:return function(t,r){return(t+r)%2==0};case n:return function(t,r){return t%2==0};case c:return function(t,r){return r%3==0};case g:return function(t,r){return(t+r)%3==0};case l:return function(t,r){return(Math.floor(t/2)+Math.floor(r/3))%2==0};case h:return function(t,r){return t*r%2+t*r%3==0};case s:return function(t,r){return(t*r%2+t*r%3)%2==0};case v:return function(t,r){return(t*r%3+(t+r)%2)%2==0};default:throw"bad maskPattern:"+t}},t.getErrorCorrectPolynomial=function(t){for(var r=C([1],0),e=0;e<t;e+=1)r=r.multiply(C([1,w.gexp(e)],0));return r},t.getLengthInBits=function(t,r){if(1<=r&&r<10)switch(t){case a:return 10;case u:return 9;case o:case f:return 8;default:throw"mode:"+t}else if(r<27)switch(t){case a:return 12;case u:return 11;case o:return 16;case f:return 10;default:throw"mode:"+t}else{if(!(r<41))throw"type:"+r;switch(t){case a:return 14;case u:return 13;case o:return 16;case f:return 12;default:throw"mode:"+t}}},t.getLostPoint=function(t){for(var r=t.getModuleCount(),e=0,n=0;n<r;n+=1)for(var o=0;o<r;o+=1){for(var i=0,a=t.isDark(n,o),u=-1;u<=1;u+=1)if(!(n+u<0||r<=n+u))for(var f=-1;f<=1;f+=1)o+f<0||r<=o+f||0==u&&0==f||a==t.isDark(n+u,o+f)&&(i+=1);5<i&&(e+=3+i-5)}for(n=0;n<r-1;n+=1)for(o=0;o<r-1;o+=1){var c=0;t.isDark(n,o)&&(c+=1),t.isDark(n+1,o)&&(c+=1),t.isDark(n,o+1)&&(c+=1),t.isDark(n+1,o+1)&&(c+=1),0!=c&&4!=c||(e+=3)}for(n=0;n<r;n+=1)for(o=0;o<r-6;o+=1)t.isDark(n,o)&&!t.isDark(n,o+1)&&t.isDark(n,o+2)&&t.isDark(n,o+3)&&t.isDark(n,o+4)&&!t.isDark(n,o+5)&&t.isDark(n,o+6)&&(e+=40);for(o=0;o<r;o+=1)for(n=0;n<r-6;n+=1)t.isDark(n,o)&&!t.isDark(n+1,o)&&t.isDark(n+2,o)&&t.isDark(n+3,o)&&t.isDark(n+4,o)&&!t.isDark(n+5,o)&&t.isDark(n+6,o)&&(e+=40);var g=0;for(o=0;o<r;o+=1)for(n=0;n<r;n+=1)t.isDark(n,o)&&(g+=1);return e+=Math.abs(100*g/r/r-50)/5*10},t);function d(t){for(var r=0;0!=t;)r+=1,t>>>=1;return r}var w=function(){for(var r=new Array(256),e=new Array(256),t=0;t<8;t+=1)r[t]=1<<t;for(t=8;t<256;t+=1)r[t]=r[t-4]^r[t-5]^r[t-6]^r[t-8];for(t=0;t<255;t+=1)e[r[t]]=t;var n={glog:function(t){if(t<1)throw"glog("+t+")";return e[t]},gexp:function(t){for(;t<0;)t+=255;for(;256<=t;)t-=255;return r[t]}};return n}();function C(n,o){if(void 0===n.length)throw n.length+"/"+o;var r=function(){for(var t=0;t<n.length&&0==n[t];)t+=1;for(var r=new Array(n.length-t+o),e=0;e<n.length-t;e+=1)r[e]=n[e+t];return r}(),i={getAt:function(t){return r[t]},getLength:function(){return r.length},multiply:function(t){for(var r=new Array(i.getLength()+t.getLength()-1),e=0;e<i.getLength();e+=1)for(var n=0;n<t.getLength();n+=1)r[e+n]^=w.gexp(w.glog(i.getAt(e))+w.glog(t.getAt(n)));return C(r,0)},mod:function(t){if(i.getLength()-t.getLength()<0)return i;for(var r=w.glog(i.getAt(0))-w.glog(t.getAt(0)),e=new Array(i.getLength()),n=0;n<i.getLength();n+=1)e[n]=i.getAt(n);for(n=0;n<t.getLength();n+=1)e[n]^=w.gexp(w.glog(t.getAt(n))+r);return C(e,0).mod(t)}};return i}function p(){var e=[],o={writeByte:function(t){e.push(255&t)},writeShort:function(t){o.writeByte(t),o.writeByte(t>>>8)},writeBytes:function(t,r,e){r=r||0,e=e||t.length;for(var n=0;n<e;n+=1)o.writeByte(t[n+r])},writeString:function(t){for(var r=0;r<t.length;r+=1)o.writeByte(t.charCodeAt(r))},toByteArray:function(){return e},toString:function(){var t="";t+="[";for(var r=0;r<e.length;r+=1)0<r&&(t+=","),t+=e[r];return t+="]"}};return o}var k,A,b=(k=[[1,26,19],[1,26,16],[1,26,13],[1,26,9],[1,44,34],[1,44,28],[1,44,22],[1,44,16],[1,70,55],[1,70,44],[2,35,17],[2,35,13],[1,100,80],[2,50,32],[2,50,24],[4,25,9],[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],[2,86,68],[4,43,27],[4,43,19],[4,43,15],[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],[3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12,7,37,13],[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],[3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14],[3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,43,15,10,44,16],[4,144,116,4,145,117],[17,68,42],[17,50,22,6,51,23],[19,46,16,6,47,17],[2,139,111,7,140,112],[17,74,46],[7,54,24,16,55,25],[34,37,13],[4,151,121,5,152,122],[4,75,47,14,76,48],[11,54,24,14,55,25],[16,45,15,14,46,16],[6,147,117,4,148,118],[6,73,45,14,74,46],[11,54,24,16,55,25],[30,46,16,2,47,17],[8,132,106,4,133,107],[8,75,47,13,76,48],[7,54,24,22,55,25],[22,45,15,13,46,16],[10,142,114,2,143,115],[19,74,46,4,75,47],[28,50,22,6,51,23],[33,46,16,4,47,17],[8,152,122,4,153,123],[22,73,45,3,74,46],[8,53,23,26,54,24],[12,45,15,28,46,16],[3,147,117,10,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],[7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],[5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],[13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],[17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],[17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,55,25],[11,45,15,46,46,16],[13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],[12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],[6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],[17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],[4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],[20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,45,15,67,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16]],(A={}).getRSBlocks=function(t,r){var e=function(t,r){switch(r){case y.L:return k[4*(t-1)+0];case y.M:return k[4*(t-1)+1];case y.Q:return k[4*(t-1)+2];case y.H:return k[4*(t-1)+3];default:return}}(t,r);if(void 0===e)throw"bad rs block @ typeNumber:"+t+"/errorCorrectionLevel:"+r;for(var n,o,i=e.length/3,a=[],u=0;u<i;u+=1)for(var f=e[3*u+0],c=e[3*u+1],g=e[3*u+2],l=0;l<f;l+=1)a.push((n=g,o=void 0,(o={}).totalCount=c,o.dataCount=n,o));return a},A),M=function(){var e=[],n=0,o={getBuffer:function(){return e},getAt:function(t){var r=Math.floor(t/8);return 1==(e[r]>>>7-t%8&1)},put:function(t,r){for(var e=0;e<r;e+=1)o.putBit(1==(t>>>r-e-1&1))},getLengthInBits:function(){return n},putBit:function(t){var r=Math.floor(n/8);e.length<=r&&e.push(0),t&&(e[r]|=128>>>n%8),n+=1}};return o},x=function(t){var r=a,n=t,e={getMode:function(){return r},getLength:function(t){return n.length},write:function(t){for(var r=n,e=0;e+2<r.length;)t.put(o(r.substring(e,e+3)),10),e+=3;e<r.length&&(r.length-e==1?t.put(o(r.substring(e,e+1)),4):r.length-e==2&&t.put(o(r.substring(e,e+2)),7))}},o=function(t){for(var r=0,e=0;e<t.length;e+=1)r=10*r+i(t.charAt(e));return r},i=function(t){if("0"<=t&&t<="9")return t.charCodeAt(0)-"0".charCodeAt(0);throw"illegal char :"+t};return e},m=function(t){var r=u,n=t,e={getMode:function(){return r},getLength:function(t){return n.length},write:function(t){for(var r=n,e=0;e+1<r.length;)t.put(45*o(r.charAt(e))+o(r.charAt(e+1)),11),e+=2;e<r.length&&t.put(o(r.charAt(e)),6)}},o=function(t){if("0"<=t&&t<="9")return t.charCodeAt(0)-"0".charCodeAt(0);if("A"<=t&&t<="Z")return t.charCodeAt(0)-"A".charCodeAt(0)+10;switch(t){case" ":return 36;case"$":return 37;case"%":return 38;case"*":return 39;case"+":return 40;case"-":return 41;case".":return 42;case"/":return 43;case":":return 44;default:throw"illegal char :"+t}};return e},L=function(t){var r=o,e=i.stringToBytes(t),n={getMode:function(){return r},getLength:function(t){return e.length},write:function(t){for(var r=0;r<e.length;r+=1)t.put(e[r],8)}};return n},D=function(t){var r=f,e=i.stringToBytesFuncs.SJIS;if(!e)throw"sjis not supported.";!function(){var t=e("友");if(2!=t.length||38726!=(t[0]<<8|t[1]))throw"sjis not supported."}();var o=e(t),n={getMode:function(){return r},getLength:function(t){return~~(o.length/2)},write:function(t){for(var r=o,e=0;e+1<r.length;){var n=(255&r[e])<<8|255&r[e+1];if(33088<=n&&n<=40956)n-=33088;else{if(!(57408<=n&&n<=60351))throw"illegal char at "+(e+1)+"/"+n;n-=49472}n=192*(n>>>8&255)+(255&n),t.put(n,13),e+=2}if(e<r.length)throw"illegal char at "+(e+1)}};return n},S=function(t){var e=t,n=0,o=0,i=0,r={read:function(){for(;i<8;){if(n>=e.length){if(0==i)return-1;throw"unexpected end of file./"+i}var t=e.charAt(n);if(n+=1,"="==t)return i=0,-1;t.match(/^\\s$/)||(o=o<<6|a(t.charCodeAt(0)),i+=6)}var r=o>>>i-8&255;return i-=8,r}},a=function(t){if(65<=t&&t<=90)return t-65;if(97<=t&&t<=122)return t-97+26;if(48<=t&&t<=57)return t-48+52;if(43==t)return 62;if(47==t)return 63;throw"c:"+t};return r},I=function(t,r,e){for(var n=function(t,r){var n=t,o=r,l=new Array(t*r),e={setPixel:function(t,r,e){l[r*n+t]=e},write:function(t){t.writeString("GIF87a"),t.writeShort(n),t.writeShort(o),t.writeByte(128),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(255),t.writeByte(255),t.writeByte(255),t.writeString(","),t.writeShort(0),t.writeShort(0),t.writeShort(n),t.writeShort(o),t.writeByte(0);var r=i(2);t.writeByte(2);for(var e=0;255<r.length-e;)t.writeByte(255),t.writeBytes(r,e,255),e+=255;t.writeByte(r.length-e),t.writeBytes(r,e,r.length-e),t.writeByte(0),t.writeString(";")}},i=function(t){for(var r=1<<t,e=1+(1<<t),n=t+1,o=h(),i=0;i<r;i+=1)o.add(String.fromCharCode(i));o.add(String.fromCharCode(r)),o.add(String.fromCharCode(e));var a=p(),u=function(t){var e=t,n=0,o=0,r={write:function(t,r){if(t>>>r!=0)throw"length over";for(;8<=n+r;)e.writeByte(255&(t<<n|o)),r-=8-n,t>>>=8-n,n=o=0;o|=t<<n,n+=r},flush:function(){0<n&&e.writeByte(o)}};return r}(a);u.write(r,n);var f=0,c=String.fromCharCode(l[f]);for(f+=1;f<l.length;){var g=String.fromCharCode(l[f]);f+=1,o.contains(c+g)?c+=g:(u.write(o.indexOf(c),n),o.size()<4095&&(o.size()==1<<n&&(n+=1),o.add(c+g)),c=g)}return u.write(o.indexOf(c),n),u.write(e,n),u.flush(),a.toByteArray()},h=function(){var r={},e=0,n={add:function(t){if(n.contains(t))throw"dup key:"+t;r[t]=e,e+=1},size:function(){return e},indexOf:function(t){return r[t]},contains:function(t){return void 0!==r[t]}};return n};return e}(t,r),o=0;o<r;o+=1)for(var i=0;i<t;i+=1)n.setPixel(i,o,e(i,o));var a=p();n.write(a);for(var u=function(){function e(t){a+=String.fromCharCode(r(63&t))}var n=0,o=0,i=0,a="",t={},r=function(t){if(t<0);else{if(t<26)return 65+t;if(t<52)return t-26+97;if(t<62)return t-52+48;if(62==t)return 43;if(63==t)return 47}throw"n:"+t};return t.writeByte=function(t){for(n=n<<8|255&t,o+=8,i+=1;6<=o;)e(n>>>o-6),o-=6},t.flush=function(){if(0<o&&(e(n<<6-o),o=n=0),i%3!=0)for(var t=3-i%3,r=0;r<t;r+=1)a+="="},t.toString=function(){return a},t}(),f=a.toByteArray(),c=0;c<f.length;c+=1)u.writeByte(f[c]);return u.flush(),"data:image/gif;base64,"+u};return i}();qrcode.stringToBytesFuncs["UTF-8"]=function(t){return function(t){for(var r=[],e=0;e<t.length;e++){var n=t.charCodeAt(e);n<128?r.push(n):n<2048?r.push(192|n>>6,128|63&n):n<55296||57344<=n?r.push(224|n>>12,128|n>>6&63,128|63&n):(e++,n=65536+((1023&n)<<10|1023&t.charCodeAt(e)),r.push(240|n>>18,128|n>>12&63,128|n>>6&63,128|63&n))}return r}(t)},function(t){"function"==typeof define&&define.amd?define([],t):"object"==typeof exports&&(module.exports=t())}(function(){return qrcode});
</script>
<script>
/* ===================== JavidNam Admin SPA (original, GPL-3.0) ===================== */
const ORIGIN = '__ORIGIN__';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const state = { me: null, users: [], settings: null, presets: [], fpOptions: [], stats: null, page: 'dash', sel: new Set(), filter: '', q: '', deferredPrompt: null, timer: null };
const GB = 1073741824;
const fmtB = (b) => { b = Number(b) || 0; if (b >= GB) return (b / GB).toFixed(2) + ' GB'; if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB'; if (b >= 1024) return (b / 1024).toFixed(0) + ' KB'; return b + ' B'; };
const fa = (n) => String(n).replace(/\\d/g, d => '۰۱۲۳۴۵۶۷۸۹'[d]);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const jdate = (ts) => { if (!ts) return '—'; try { return new Intl.DateTimeFormat('fa-IR', { dateStyle: 'medium' }).format(new Date(ts)); } catch (e) { return new Date(ts).toLocaleDateString(); } };
const jdt = (ts) => { if (!ts) return '—'; try { return new Intl.DateTimeFormat('fa-IR', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(ts)); } catch (e) { return new Date(ts).toLocaleString(); } };
const ago = (ts) => { if (!ts) return 'هرگز'; const d = Date.now() - ts; if (d < 60e3) return 'همین الان'; if (d < 3600e3) return fa(Math.floor(d / 60e3)) + ' دقیقه پیش'; if (d < 86400e3) return fa(Math.floor(d / 3600e3)) + ' ساعت پیش'; return fa(Math.floor(d / 86400e3)) + ' روز پیش'; };
function toast(msg, type = 'ok') { const t = document.createElement('div'); t.className = 'toast ' + type; t.textContent = msg; $('#toasts').appendChild(t); setTimeout(() => t.remove(), 3500); }
async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { 'Content-Type': 'application/json', 'X-JN': '1', ...(opts.headers || {}) }, body: opts.body && typeof opts.body !== 'string' ? JSON.stringify(opts.body) : opts.body });
  if (r.status === 401 && !path.includes('/api/login')) { showLogin(); throw new Error('unauthorized'); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok && !j.ok && j.error) throw new Error(j.error);
  return j;
}
function copy(text, msg = 'کپی شد ✓') { (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(() => toast(msg)).catch(() => { const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); toast(msg); }); }
function modal(html, opts = {}) {
  const root = $('#modalRoot'); root.innerHTML = \`<div class="modal" id="modal"><div class="box" style="\${opts.width ? 'width:min(' + opts.width + ',100%)' : ''}">\${html}</div></div>\`;
  const m = $('#modal'); m.addEventListener('click', e => { if (e.target === m && !opts.sticky) closeModal(); });
  return m;
}
function closeModal() { $('#modalRoot').innerHTML = ''; }
function confirmBox(title, text, okLabel = 'تأیید', cls = 'd') {
  return new Promise(res => {
    modal(\`<h2>\${title}<button class="x" onclick="closeModal()">✕</button></h2><p class="muted" style="margin-bottom:16px">\${text}</p><div class="row" style="justify-content:flex-end"><button class="btn" id="cNo">انصراف</button><button class="btn \${cls}" id="cYes">\${okLabel}</button></div>\`);
    $('#cNo').onclick = () => { closeModal(); res(false); }; $('#cYes').onclick = () => { closeModal(); res(true); };
  });
}
function promptBox(title, label, def = '', type = 'text') {
  return new Promise(res => {
    modal(\`<h2>\${title}<button class="x" onclick="closeModal()">✕</button></h2><label>\${label}</label><input id="pIn" type="\${type}" value="\${esc(def)}" class="ltr"><div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="cNo">انصراف</button><button class="btn p" id="cYes">تأیید</button></div>\`);
    $('#pIn').focus(); $('#cNo').onclick = () => { closeModal(); res(null); }; $('#cYes').onclick = () => { const v = $('#pIn').value; closeModal(); res(v); };
    $('#pIn').onkeydown = e => { if (e.key === 'Enter') $('#cYes').click(); };
  });
}
function qrInto(el, text, size = 180) {
  try { const q = qrcode(0, 'M'); q.addData(text); q.make(); el.innerHTML = q.createSvgTag({ cellSize: Math.max(2, Math.floor(size / q.getModuleCount())), margin: 0 }); } catch (e) { el.textContent = 'QR خیلی بزرگ است'; }
}

/* ---------- animated background (embers) ---------- */
(function bg() {
  const c = $('#bg'), x = c.getContext('2d'); let w, h, P = [];
  const rs = () => { w = c.width = innerWidth * devicePixelRatio; h = c.height = innerHeight * devicePixelRatio; };
  rs(); addEventListener('resize', rs);
  for (let i = 0; i < 70; i++) P.push({ x: Math.random(), y: Math.random(), r: Math.random() * 2 + .6, v: Math.random() * .0006 + .0002, o: Math.random() * .5 + .2, d: Math.random() * 6.28 });
  (function f(t) {
    x.clearRect(0, 0, w, h);
    for (const p of P) {
      p.y -= p.v; p.x += Math.sin(t / 2000 + p.d) * .00025; if (p.y < -.02) { p.y = 1.02; p.x = Math.random(); }
      const g = x.createRadialGradient(p.x * w, p.y * h, 0, p.x * w, p.y * h, p.r * 6 * devicePixelRatio);
      g.addColorStop(0, \`rgba(251,113,133,\${p.o})\`); g.addColorStop(1, 'rgba(251,113,133,0)');
      x.fillStyle = g; x.beginPath(); x.arc(p.x * w, p.y * h, p.r * 6 * devicePixelRatio, 0, 6.28); x.fill();
    }
    requestAnimationFrame(f);
  })(0);
})();

/* ---------- PWA ---------- */
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
addEventListener('beforeinstallprompt', e => { e.preventDefault(); state.deferredPrompt = e; const b = $('#installBtn'); if (b) b.style.display = ''; });
$('#installBtn').onclick = async () => { if (!state.deferredPrompt) return; state.deferredPrompt.prompt(); await state.deferredPrompt.userChoice; state.deferredPrompt = null; $('#installBtn').style.display = 'none'; };

/* ---------- auth ---------- */
function showLogin() { $('#login').classList.remove('hidden'); $('#app').classList.add('hidden'); clearInterval(state.timer); }
async function boot() {
  try { const me = await api('/api/me'); state.me = me; enterApp(); }
  catch (e) {
    showLogin();
    try { const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); const j = await r.json(); if (j.setup) $('#setupBox').classList.remove('hidden'); } catch (e2) {}
  }
}
$('#loginBtn').onclick = login;
$('#passInput').onkeydown = e => { if (e.key === 'Enter') login(); };
async function login() {
  const pass = $('#passInput').value; const err = $('#loginErr'); err.textContent = '';
  const setup = !$('#setupBox').classList.contains('hidden');
  try {
    if (setup) { await api('/api/setup', { method: 'POST', body: { password: pass } }); }
    const j = await api('/api/login', { method: 'POST', body: { password: pass } });
    if (!j.ok) throw new Error(j.error || 'خطا');
    state.me = await api('/api/me'); enterApp();
  } catch (e) { err.textContent = e.message; }
}
async function logout() { await api('/api/logout', { method: 'POST' }); location.reload(); }
function enterApp() {
  $('#login').classList.add('hidden'); $('#app').classList.remove('hidden');
  if (state.me.colo) { $('#coloChip').textContent = '📍 ' + state.me.colo; $('#coloChip').classList.remove('hidden'); }
  $$('.ver').forEach(v => v.textContent = state.me.version);
  renderNav(); go(location.hash.replace('#', '') || 'dash');
  clearInterval(state.timer); state.timer = setInterval(() => { if (state.page === 'dash' || state.page === 'users') refreshPage(true); }, 30000);
}

/* ---------- nav ---------- */
const ICONS = {
  dash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>',
  users: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><circle cx="17" cy="9" r="2.5"/><path d="M15.5 14.5a5 5 0 0 1 6 5"/></svg>',
  net: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>',
  settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>',
  tools: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a4 4 0 0 0 5 5l-9.4 9.4a2.1 2.1 0 0 1-3-3l9.4-9.4z"/><path d="M14.7 6.3L17 4l3 3-2.3 2.3"/></svg>',
  backup: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg>',
};
const PAGES = [['dash', 'داشبورد'], ['users', 'کاربران'], ['net', 'شبکه و لوکیشن‌ها'], ['settings', 'تنظیمات'], ['tools', 'ابزارها'], ['backup', 'پشتیبان و آپدیت']];
function renderNav() {
  $('#nav').innerHTML = PAGES.map(([id, t]) => \`<a data-p="\${id}" class="\${state.page === id ? 'on' : ''}" onclick="go('\${id}')">\${ICONS[id]}<span>\${t}</span></a>\`).join('');
  $('#mobnav').innerHTML = PAGES.map(([id, t]) => \`<a data-p="\${id}" class="\${state.page === id ? 'on' : ''}" onclick="go('\${id}')">\${ICONS[id]}<span>\${t.split(' ')[0]}</span></a>\`).join('');
}
function go(p) { state.page = p; location.hash = p; renderNav(); $('#pageTitle').textContent = (PAGES.find(x => x[0] === p) || [])[1] || ''; refreshPage(); }
async function refreshPage(silent = false) {
  const m = $('#main'); if (!silent) m.innerHTML = '<div class="muted" style="padding:40px;text-align:center">در حال بارگذاری…</div>';
  try {
    if (state.page === 'dash') await pageDash();
    else if (state.page === 'users') await pageUsers(silent);
    else if (state.page === 'net') await pageNet();
    else if (state.page === 'settings') await pageSettings();
    else if (state.page === 'tools') await pageTools();
    else if (state.page === 'backup') await pageBackup();
  } catch (e) { if (e.message !== 'unauthorized') { m.innerHTML = \`<div class="card">❌ \${esc(e.message)}</div>\`; } }
}

/* ===================== DASHBOARD ===================== */
async function pageDash() {
  const s = await api('/api/stats'); state.stats = s;
  const pct = Math.min(100, Math.round(s.cf.today_requests / s.cf.daily_limit * 100));
  const usedPct = s.traffic.quota > 0 ? Math.min(100, Math.round(s.traffic.used / s.traffic.quota * 100)) : 0;
  const days = s.cf.days || [];
  const mx = Math.max(1, ...days.map(d => d.requests));
  const st = (k, v, ic, sub = '') => \`<div class="card stat"><div class="ic">\${ic}</div><div class="v">\${v}</div><div class="k">\${k}</div>\${sub ? \`<div class="xs muted">\${sub}</div>\` : ''}</div>\`;
  $('#main').innerHTML = \`
  <div class="grid g6 fadein">
    \${st('کل کاربران', fa(s.users.total), '👥')}
    \${st('فعال', fa(s.users.active), '✅')}
    \${st('آنلاین (۵ دقیقه)', fa(s.users.online), '🟢')}
    \${st('رو به انقضا (۷ روز)', fa(s.users.expiring_soon), '⏳')}
    \${st('منقضی‌شده', fa(s.users.expired), '⛔')}
    \${st('حجم تمام‌شده', fa(s.users.over_quota), '📦')}
  </div>
  <div class="grid g3" style="margin-top:12px">
    <div class="card">
      <h3>☁️ سهمیه‌ی Cloudflare <small>امروز (UTC)</small></h3>
      <div class="row" style="justify-content:space-between"><b style="font-size:22px">\${fa(s.cf.today_requests.toLocaleString('en'))}</b><span class="muted small">از \${fa('100,000')} درخواست</span></div>
      <div class="bar \${pct > 80 ? 'w' : 'g'}" style="margin:8px 0"><i style="width:\${pct}%"></i></div>
      <div class="row small muted" style="justify-content:space-between"><span>\${fa(pct)}٪ مصرف شده</span><span>\${fa(s.cf.today_conns)} اتصال · \${fmtB(s.cf.today_bytes)}</span></div>
      <p class="xs muted" style="margin-top:8px">شمارش داخلی پنل (درخواست‌های پروکسی + ساب + API). با رسیدن به ۱۰۰k کلودفلر ورکر رایگان را تا فردا متوقف می‌کند.</p>
    </div>
    <div class="card">
      <h3>📊 ترافیک کل</h3>
      <div class="row" style="justify-content:space-between"><b style="font-size:22px">\${fmtB(s.traffic.used)}</b><span class="muted small">\${s.traffic.quota > 0 ? 'از ' + fmtB(s.traffic.quota) : 'نامحدود'}</span></div>
      <div class="bar" style="margin:8px 0"><i style="width:\${usedPct}%"></i></div>
      <div class="small muted">\${fa(Number(s.traffic.requests || 0).toLocaleString('en'))} اتصال از ابتدا</div>
      <div class="hr"></div>
      <div class="row small"><span class="chip info">v\${s.version}</span>\${s.colo ? \`<span class="chip">📍 \${s.colo}</span>\` : ''}<span class="chip">\${jdt(s.now)}</span></div>
    </div>
    <div class="card">
      <h3>📈 درخواست‌های ۳۰ روز اخیر</h3>
      <div class="spark">\${days.length ? days.map(d => \`<i style="height:\${Math.max(3, d.requests / mx * 100)}%" data-t="\${d.day}: \${d.requests}"></i>\`).join('') : '<span class="muted small">هنوز داده‌ای نیست</span>'}</div>
      <div class="row small muted" style="justify-content:space-between;margin-top:6px"><span>\${days[0]?.day || ''}</span><span>\${days[days.length - 1]?.day || ''}</span></div>
    </div>
  </div>
  <div class="grid g2" style="margin-top:12px">
    <div class="card">
      <h3>🏆 پرمصرف‌ترین کاربران</h3>
      <div class="tbl"><table><thead><tr><th>نام</th><th>مصرف</th><th>اتصال</th><th>آخرین فعالیت</th></tr></thead><tbody>
      \${(s.top || []).map(u => \`<tr><td><b>\${esc(u.name)}</b></td><td class="mono">\${fmtB(u.used_bytes)}</td><td>\${fa(u.used_requests || 0)}</td><td class="small muted">\${ago(u.last_seen_at)}</td></tr>\`).join('') || '<tr><td colspan="4" class="muted">—</td></tr>'}
      </tbody></table></div>
    </div>
    <div class="card">
      <h3>⚡ دسترسی سریع</h3>
      <div class="grid g2">
        <button class="btn p" onclick="openUserModal()">➕ کاربر جدید</button>
        <button class="btn" onclick="go('net')">🌍 لوکیشن‌ها</button>
        <button class="btn" onclick="go('tools')">🧪 تست و اسکنر</button>
        <button class="btn" onclick="go('backup')">💾 پشتیبان‌گیری</button>
      </div>
      <div class="hr"></div>
      <div class="small muted">🌷 جاویدنام — نرم‌افزار آزاد (GPL-3.0). بدون تبلیغ، بدون قفل، بدون DRM. <a href="https://github.com/amirparsa1/JavidNam" target="_blank" style="color:#fda4af">GitHub</a></div>
    </div>
  </div>\`;
}

/* ===================== USERS ===================== */
async function loadUsers() { const j = await api('/api/users?q=' + encodeURIComponent(state.q) + '&filter=' + state.filter); state.users = j.users; }
async function pageUsers(silent) {
  if (!state.settings) await loadSettings();
  await loadUsers();
  const m = $('#main');
  if (!silent || !$('#usersTable')) {
    m.innerHTML = \`
    <div class="card fadein">
      <div class="row" style="margin-bottom:12px">
        <input id="userSearch" placeholder="🔍 جستجو نام / UUID / یادداشت" value="\${esc(state.q)}" style="max-width:300px">
        <select id="userFilter" style="max-width:170px">
          \${[['', 'همه'], ['active', 'فعال'], ['online', 'آنلاین'], ['disabled', 'غیرفعال'], ['expired', 'منقضی'], ['overquota', 'حجم تمام'], ['pending', 'منتظر اولین اتصال']].map(([v, t]) => \`<option value="\${v}" \${state.filter === v ? 'selected' : ''}>\${t}</option>\`).join('')}
        </select>
        <span class="chip" id="userCount"></span>
        <div class="grow"></div>
        <button class="btn" onclick="openBulkCreate()">📚 ساخت گروهی</button>
        <button class="btn p" onclick="openUserModal()">➕ کاربر جدید</button>
      </div>
      <div class="tbl"><table id="usersTable"><thead><tr>
        <th style="width:30px"><input type="checkbox" id="selAll"></th><th>کاربر</th><th>وضعیت</th><th>حجم</th><th>زمان</th><th>اتصال / IP</th><th>لوکیشن</th><th style="text-align:left">عملیات</th>
      </tr></thead><tbody id="usersBody"></tbody></table></div>
      <div id="bulkbar" class="hidden"></div>
    </div>\`;
    $('#userSearch').oninput = debounce(() => { state.q = $('#userSearch').value; pageUsers(true); }, 300);
    $('#userFilter').onchange = () => { state.filter = $('#userFilter').value; pageUsers(true); };
    $('#selAll').onchange = (e) => { state.sel = new Set(e.target.checked ? state.users.map(u => u.id) : []); renderUsersBody(); };
  }
  renderUsersBody();
}
function debounce(f, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => f(...a), ms); }; }
function stateChip(u) {
  const s = u.state;
  if (!s.active) return '<span class="chip bad">غیرفعال</span>';
  if (s.expired) return '<span class="chip bad">منقضی</span>';
  if (s.overQuota) return '<span class="chip bad">حجم تمام</span>';
  if (s.overRequests) return '<span class="chip bad">سقف اتصال</span>';
  if (s.pending) return '<span class="chip warn">منتظر اتصال</span>';
  const online = u.last_seen_at && Date.now() - u.last_seen_at < 5 * 60000;
  return \`<span class="chip ok"><span class="dot \${online ? 'on' : ''}"></span>\${online ? 'آنلاین' : 'فعال'}</span>\`;
}
function renderUsersBody() {
  const locs = (state.settings && state.settings.locations) || [];
  $('#userCount').textContent = fa(state.users.length) + ' کاربر';
  $('#usersBody').innerHTML = state.users.map(u => {
    const q = u.quota_bytes > 0 ? Math.min(100, Math.round(u.used_bytes / u.quota_bytes * 100)) : 0;
    const userLocs = u.locations ? u.locations.map(id => (locs.find(l => l.id === id) || {}).name || id).join('، ') : 'همه';
    return \`<tr>
      <td><input type="checkbox" \${state.sel.has(u.id) ? 'checked' : ''} onchange="toggleSel('\${u.id}',this.checked)"></td>
      <td><div class="uname">\${esc(u.name)} \${u.block_ads ? '<span class="chip xs" title="مسدودسازی تبلیغات">🛡</span>' : ''}\${u.block_nsfw ? '<span class="chip xs" title="فیلتر محتوای بزرگسال">🔞</span>' : ''}</div><small class="mono xs muted">\${u.uuid.slice(0, 8)}… \${u.note ? '· ' + esc(u.note) : ''}</small></td>
      <td>\${stateChip(u)}<div class="xs muted">\${ago(u.last_seen_at)}</div></td>
      <td style="min-width:120px"><div class="small">\${fmtB(u.used_bytes)} <span class="muted">/ \${u.quota_bytes > 0 ? fmtB(u.quota_bytes) : '∞'}</span></div><div class="bar \${q > 85 ? 'w' : ''}"><i style="width:\${q}%"></i></div>\${u.reset_hours ? \`<div class="xs muted">ریست هر \${fa(u.reset_hours)}h</div>\` : ''}</td>
      <td class="small">\${u.expiry_at ? \`\${jdate(u.expiry_at)}<div class="xs muted">\${u.state.daysLeft > 0 ? fa(u.state.daysLeft) + ' روز مانده' : 'تمام شده'}</div>\` : u.start_on_first && u.days ? \`<span class="muted">\${fa(u.days)} روز پس از اولین اتصال</span>\` : '<span class="muted">نامحدود</span>'}</td>
      <td class="small"><div>\${fa(u.used_requests || 0)}\${u.max_requests ? ' / ' + fa(u.max_requests) : ''}</div><div class="xs muted">\${u.ip_limit ? fa(u.online_ips) + ' / ' + fa(u.ip_limit) + ' IP' : 'IP نامحدود'}</div></td>
      <td class="small muted" style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="\${esc(userLocs)}">\${esc(userLocs)}</td>
      <td><div class="acts">
        <button class="btn i" title="لینک ساب و QR" onclick="openShare('\${u.id}')">🔗</button>
        <button class="btn i" title="ویرایش" onclick="openUserModal('\${u.id}')">✏️</button>
        <button class="btn i" title="\${u.active ? 'غیرفعال کن' : 'فعال کن'}" onclick="toggleActive('\${u.id}',\${u.active ? 0 : 1})">\${u.active ? '⏸' : '▶️'}</button>
        <button class="btn i" title="ریست حجم" onclick="resetUser('\${u.id}','traffic')">♻️</button>
        <button class="btn i d" title="حذف" onclick="delUser('\${u.id}')">🗑</button>
      </div></td></tr>\`;
  }).join('') || \`<tr><td colspan="8" class="muted" style="text-align:center;padding:30px">کاربری نیست. با «➕ کاربر جدید» شروع کن.</td></tr>\`;
  renderBulkbar();
}
function toggleSel(id, on) { if (on) state.sel.add(id); else state.sel.delete(id); renderBulkbar(); }
function renderBulkbar() {
  const b = $('#bulkbar'); if (!b) return;
  if (!state.sel.size) { b.classList.add('hidden'); return; }
  b.classList.remove('hidden');
  b.innerHTML = \`<div class="row"><b>\${fa(state.sel.size)} انتخاب‌شده</b>
    <button class="btn s g" onclick="bulk('activate')">▶️ فعال</button><button class="btn s" onclick="bulk('deactivate')">⏸ غیرفعال</button>
    <button class="btn s" onclick="bulk('reset_traffic')">♻️ ریست حجم</button><button class="btn s" onclick="bulk('reset_expiry')">⏰ ریست زمان</button>
    <button class="btn s" onclick="bulkExtend()">➕ تمدید</button><button class="btn s" onclick="bulkAddGb()">📦 افزودن حجم</button>
    <button class="btn s" onclick="bulkLocations()">🌍 لوکیشن</button>
    <button class="btn s" onclick="bulk('block_ads')">🛡 تبلیغات</button><button class="btn s" onclick="bulk('block_nsfw')">🔞 فیلتر</button>
    <button class="btn s d" onclick="bulk('delete')">🗑 حذف</button>
    <div class="grow"></div><button class="btn s" onclick="state.sel.clear();renderUsersBody()">✕</button></div>\`;
}
async function bulk(action, extra = {}) {
  if (action === 'delete' && !(await confirmBox('حذف گروهی', \`\${fa(state.sel.size)} کاربر برای همیشه حذف شوند؟\`, 'حذف'))) return;
  await api('/api/bulk', { method: 'POST', body: { action, ids: [...state.sel], ...extra } });
  toast('انجام شد'); state.sel.clear(); pageUsers(true);
}
async function bulkExtend() { const d = await promptBox('تمدید گروهی', 'چند روز اضافه شود؟', '30', 'number'); if (d) bulk('extend', { days: Number(d) }); }
async function bulkAddGb() { const g = await promptBox('افزودن حجم گروهی', 'چند گیگابایت اضافه شود؟', '10', 'number'); if (g) bulk('add_gb', { gb: Number(g) }); }
async function bulkLocations() {
  const locs = state.settings.locations;
  modal(\`<h2>🌍 لوکیشن‌های گروهی<button class="x" onclick="closeModal()">✕</button></h2><p class="small muted">هیچ‌کدام = همه‌ی لوکیشن‌ها</p><div class="locpick" id="blp">\${locs.map(l => \`<label><input type="checkbox" value="\${l.id}">\${esc(l.name)}</label>\`).join('')}</div><div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn p" id="blOk">اعمال</button></div>\`);
  $('#blOk').onclick = () => { const ids = $$('#blp input:checked').map(i => i.value); closeModal(); bulk('set_locations', { locations: ids }); };
}
async function toggleActive(id, active) { await api('/api/users/' + id, { method: 'PATCH', body: { active: !!active } }); toast(active ? 'فعال شد' : 'غیرفعال شد'); pageUsers(true); }
async function resetUser(id, what) {
  const body = what === 'traffic' ? { traffic: true, requests: true } : what === 'expiry' ? { expiry: true } : { traffic: true, requests: true, expiry: true };
  await api('/api/users/' + id + '/reset', { method: 'POST', body }); toast('ریست شد'); pageUsers(true);
}
async function delUser(id) {
  const u = state.users.find(x => x.id === id);
  if (!(await confirmBox('حذف کاربر', \`«\${esc(u.name)}» برای همیشه حذف شود؟\`, 'حذف'))) return;
  await api('/api/users/' + id, { method: 'DELETE' }); toast('حذف شد'); pageUsers(true);
}

/* ---- user modal (create / edit) ---- */
function openUserModal(id) {
  const u = id ? state.users.find(x => x.id === id) : null;
  const locs = state.settings.locations;
  const v = (k, d = '') => u ? (u[k] ?? d) : d;
  modal(\`
  <h2>\${u ? '✏️ ویرایش ' + esc(u.name) : '➕ کاربر جدید'}<button class="x" onclick="closeModal()">✕</button></h2>
  <div class="tabs"><button class="on" data-t="t1">پایه</button><button data-t="t2">محدودیت‌ها</button><button data-t="t3">لوکیشن و فیلتر</button>\${u ? '<button data-t="t4">پیشرفته</button>' : ''}</div>
  <div id="t1">
    <div class="grid g2">
      <div><label>نام کاربر *</label><input id="f_name" value="\${esc(v('name'))}" placeholder="مثلاً: علی"></div>
      <div><label>یادداشت</label><input id="f_note" value="\${esc(v('note'))}" placeholder="اختیاری"></div>
      <div><label>حجم (GB) — ۰ = نامحدود</label><input id="f_quota" type="number" min="0" step="0.5" value="\${u ? (u.quota_bytes / GB) : 20}" class="ltr"></div>
      <div><label>مدت (روز) — ۰ = نامحدود</label><input id="f_days" type="number" min="0" value="\${v('days', 30)}" class="ltr"></div>
    </div>
    <div class="grid g2" style="margin-top:10px">
      <div class="sw"><div><b>شروع از اولین اتصال</b><small>شمارش زمان بعد از اولین وصل‌شدن</small></div><label class="switch"><input type="checkbox" id="f_sof" \${v('start_on_first') ? 'checked' : ''}><i></i></label></div>
      <div class="sw"><div><b>فعال</b><small>اجازه‌ی اتصال</small></div><label class="switch"><input type="checkbox" id="f_active" \${u ? (u.active ? 'checked' : '') : 'checked'}><i></i></label></div>
    </div>
    \${u ? \`<div class="grid g2" style="margin-top:10px"><div><label>➕ تمدید (روز اضافه)</label><input id="f_extend" type="number" min="0" value="0" class="ltr"></div><div><label>📦 افزودن حجم (GB اضافه)</label><input id="f_addgb" type="number" min="0" step="0.5" value="0" class="ltr"></div></div>\` : ''}
  </div>
  <div id="t2" class="hidden">
    <div class="grid g2">
      <div><label>محدودیت دستگاه هم‌زمان (IP) — ۰ = نامحدود</label><input id="f_ip" type="number" min="0" max="50" value="\${v('ip_limit', 0)}" class="ltr"></div>
      <div><label>سقف تعداد اتصال — ۰ = نامحدود</label><input id="f_maxreq" type="number" min="0" value="\${v('max_requests', 0)}" class="ltr"></div>
      <div><label>ریست خودکار حجم هر N ساعت — ۰ = خاموش</label><input id="f_reset" type="number" min="0" value="\${v('reset_hours', 0)}" class="ltr"><span class="xs muted">مثال: ۲۴ = روزانه، ۷۲۰ = ماهانه</span></div>
      \${!u ? \`<div><label>UUID سفارشی (اختیاری)</label><input id="f_uuid" class="mono" placeholder="خالی = تولید خودکار"></div>\` : ''}
    </div>
  </div>
  <div id="t3" class="hidden">
    <label>لوکیشن‌های مجاز <span class="muted">(هیچ‌کدام = همه · حداکثر ۸)</span></label>
    <div class="locpick" id="f_locs">\${locs.map(l => \`<label><input type="checkbox" value="\${l.id}" \${u && u.locations && u.locations.includes(l.id) ? 'checked' : ''}>\${esc(l.name)}\${l.enabled ? '' : ' <span class="xs muted">(خاموش)</span>'}</label>\`).join('')}</div>
    <div class="grid g2" style="margin-top:12px">
      <div class="sw"><div><b>🛡 مسدودسازی تبلیغات</b><small>DNS فیلتر AdGuard روی اتصال این کاربر</small></div><label class="switch"><input type="checkbox" id="f_ads" \${v('block_ads') ? 'checked' : ''}><i></i></label></div>
      <div class="sw"><div><b>🔞 فیلتر محتوای بزرگسال</b><small>Cloudflare Family (1.1.1.3)</small></div><label class="switch"><input type="checkbox" id="f_nsfw" \${v('block_nsfw') ? 'checked' : ''}><i></i></label></div>
    </div>
  </div>
  \${u ? \`<div id="t4" class="hidden">
    <div class="grid g2">
      <div><label>UUID</label><div class="row"><input class="mono" value="\${u.uuid}" readonly><button class="btn i" onclick="copy('\${u.uuid}')">📋</button></div></div>
      <div><label>توکن ساب</label><div class="row"><input class="mono" value="\${u.sub_token}" readonly><button class="btn i" onclick="copy('\${u.sub_token}')">📋</button></div></div>
    </div>
    <div class="row" style="margin-top:12px">
      <button class="btn d s" onclick="regen('\${u.id}','uuid')">🔁 تعویض UUID</button>
      <button class="btn d s" onclick="regen('\${u.id}','token')">🔁 تعویض لینک ساب</button>
      <button class="btn s" onclick="resetUser('\${u.id}','expiry');closeModal()">⏰ ریست زمان</button>
    </div>
    <div class="hr"></div>
    <div class="small muted">ساخته‌شده: \${jdt(u.created_at)} · اولین اتصال: \${jdt(u.first_connect_at)} · آخرین IP: <span class="mono">\${esc(u.last_ip || '—')}</span></div>
  </div>\` : ''}
  <div id="mErr" class="small" style="color:#fda4af;min-height:20px;margin-top:8px"></div>
  <div class="row" style="justify-content:flex-end"><button class="btn" onclick="closeModal()">انصراف</button><button class="btn p" id="mSave">\${u ? 'ذخیره' : 'ساخت کاربر'}</button></div>\`, { width: '720px' });
  $$('.tabs button').forEach(b => b.onclick = () => { $$('.tabs button').forEach(x => x.classList.remove('on')); b.classList.add('on'); ['t1', 't2', 't3', 't4'].forEach(t => $('#' + t)?.classList.toggle('hidden', t !== b.dataset.t)); });
  $('#mSave').onclick = async () => {
    const body = {
      name: $('#f_name').value, note: $('#f_note').value, quota_gb: Number($('#f_quota').value), days: Number($('#f_days').value),
      start_on_first: $('#f_sof').checked, active: $('#f_active').checked, ip_limit: Number($('#f_ip').value), max_requests: Number($('#f_maxreq').value),
      reset_hours: Number($('#f_reset').value), locations: $$('#f_locs input:checked').map(i => i.value), block_ads: $('#f_ads').checked, block_nsfw: $('#f_nsfw').checked,
    };
    if (!body.name.trim()) { $('#mErr').textContent = 'نام الزامی است'; return; }
    if (!u && $('#f_uuid') && $('#f_uuid').value.trim()) body.uuid = $('#f_uuid').value.trim();
    if (u) { if (Number($('#f_extend').value) > 0) body.extend_days = Number($('#f_extend').value); if (Number($('#f_addgb').value) > 0) body.add_gb = Number($('#f_addgb').value); }
    try {
      $('#mSave').disabled = true;
      if (u) {
        /* don't overwrite expiry when days unchanged */
        if (Number(body.days) === Number(u.days) && body.start_on_first === u.start_on_first) delete body.days;
        await api('/api/users/' + u.id, { method: 'PATCH', body }); toast('ذخیره شد'); closeModal(); pageUsers(true);
      } else { const j = await api('/api/users', { method: 'POST', body }); toast('کاربر ساخته شد'); closeModal(); await pageUsers(true); openShare(j.user.id, j.user); }
    } catch (e) { $('#mErr').textContent = e.message; $('#mSave').disabled = false; }
  };
}
async function regen(id, what) {
  if (!(await confirmBox('تعویض ' + (what === 'uuid' ? 'UUID' : 'لینک ساب'), 'کانفیگ‌های قبلی کاربر از کار می‌افتد. ادامه؟', 'تعویض'))) return;
  await api('/api/users/' + id, { method: 'PATCH', body: what === 'uuid' ? { regen_uuid: true } : { regen_token: true } }); toast('انجام شد'); closeModal(); pageUsers(true);
}
function openBulkCreate() {
  modal(\`<h2>📚 ساخت گروهی کاربر<button class="x" onclick="closeModal()">✕</button></h2>
  <div class="grid g2">
    <div><label>پیشوند نام</label><input id="b_name" value="user"></div><div><label>تعداد (حداکثر ۵۰)</label><input id="b_count" type="number" min="1" max="50" value="10" class="ltr"></div>
    <div><label>حجم (GB)</label><input id="b_quota" type="number" min="0" value="20" class="ltr"></div><div><label>مدت (روز)</label><input id="b_days" type="number" min="0" value="30" class="ltr"></div>
    <div><label>محدودیت IP</label><input id="b_ip" type="number" min="0" value="2" class="ltr"></div>
    <div class="sw"><div><b>شروع از اولین اتصال</b></div><label class="switch"><input type="checkbox" id="b_sof" checked><i></i></label></div>
  </div>
  <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn p" id="bGo">ساخت</button></div>\`);
  $('#bGo').onclick = async () => {
    $('#bGo').disabled = true;
    try {
      const j = await api('/api/users', { method: 'POST', body: { name: $('#b_name').value, count: Number($('#b_count').value), quota_gb: Number($('#b_quota').value), days: Number($('#b_days').value), ip_limit: Number($('#b_ip').value), start_on_first: $('#b_sof').checked } });
      closeModal(); toast(fa(j.users.length) + ' کاربر ساخته شد'); await pageUsers(true);
      const txt = j.users.map(u => \`\${u.name}\\t\${u.sub_url}\`).join('\\n');
      modal(\`<h2>✅ لینک‌های ساب<button class="x" onclick="closeModal()">✕</button></h2><textarea style="min-height:220px">\${esc(txt)}</textarea><div class="row" style="justify-content:flex-end;margin-top:10px"><button class="btn p" onclick="copy(\${JSON.stringify(txt).replace(/"/g, '&quot;')})">📋 کپی همه</button></div>\`);
    } catch (e) { toast(e.message, 'err'); $('#bGo').disabled = false; }
  };
}

/* ---- share modal (sub link, QR, formats, per-config) ---- */
async function openShare(id, uObj) {
  const u = uObj || state.users.find(x => x.id === id);
  const j = await fetch(u.sub_url + '/links').then(r => r.json()).catch(() => ({ links: [] }));
  const links = j.links || [];
  modal(\`<h2>🔗 اشتراک \${esc(u.name)}<button class="x" onclick="closeModal()">✕</button></h2>
  <div class="row" style="align-items:flex-start">
    <div class="qr" id="shQr"></div>
    <div class="grow">
      <label>لینک ساب (همه‌ی کلاینت‌ها)</label><div class="row"><input class="mono" value="\${u.sub_url}" readonly><button class="btn i" onclick="copy('\${u.sub_url}','لینک ساب کپی شد')">📋</button></div>
      <div class="row" style="margin-top:8px;gap:6px">
        <button class="btn s" onclick="copy('\${u.sub_url}/b64','کپی شد')">Base64</button>
        <button class="btn s" onclick="copy('\${u.sub_url}/clash','کپی شد')">Clash / Mihomo</button>
        <button class="btn s" onclick="copy('\${u.sub_url}/sb','کپی شد')">sing-box</button>
        <button class="btn s" onclick="window.open('\${u.status_url}','_blank')">📊 صفحه وضعیت</button>
      </div>
      <div class="row" style="margin-top:8px;gap:6px">
        <a class="btn s b" href="hiddify://import/\${u.sub_url}">Hiddify</a>
        <a class="btn s b" href="v2rayng://install-sub?url=\${encodeURIComponent(u.sub_url)}&name=\${encodeURIComponent('JavidNam ' + u.name)}">v2rayNG</a>
        <a class="btn s b" href="streisand://import/\${u.sub_url}">Streisand</a>
        <a class="btn s b" href="sing-box://import-remote-profile?url=\${encodeURIComponent(u.sub_url + '/sb')}#JavidNam">sing-box</a>
        <a class="btn s b" href="clash://install-config?url=\${encodeURIComponent(u.sub_url + '/clash')}">Clash</a>
      </div>
    </div>
  </div>
  <div class="hr"></div>
  <label>کانفیگ‌های تکی</label>
  <div class="grid" style="gap:6px">\${links.map((l, i) => \`<div class="row" style="border:1px solid var(--line);border-radius:10px;padding:6px 10px"><span class="chip \${l.proto === 'vless' ? 'info' : 'vio'}">\${l.proto.toUpperCase()}</span><b class="small">\${esc(l.name)}</b><span class="xs muted mono">\${esc(l.host)}:\${l.port}</span><div class="grow"></div><button class="btn s" onclick="copy(\${JSON.stringify(l.link).replace(/"/g, '&quot;')})">📋</button><button class="btn s" onclick="qrInto($('#shQr'),\${JSON.stringify(l.link).replace(/"/g, '&quot;')},200)">QR</button></div>\`).join('') || '<span class="muted small">لوکیشنی برای این کاربر فعال نیست</span>'}</div>\`, { width: '760px' });
  qrInto($('#shQr'), u.sub_url, 200);
}

/* ===================== NETWORK / LOCATIONS ===================== */
async function loadSettings() { const j = await api('/api/settings'); state.settings = j.settings; state.presets = j.presets; state.fpOptions = j.fp_options; }
async function pageNet() {
  await loadSettings();
  const s = state.settings;
  $('#main').innerHTML = \`
  <div class="card fadein">
    <h3>🌍 لوکیشن‌ها <small>هر لوکیشن = یک آدرس ورودی + یک مسیر خروجی (outbound). حداکثر ۱۶.</small></h3>
    <div id="locList"></div>
    <div class="row"><button class="btn" onclick="addLoc()">➕ لوکیشن جدید</button><button class="btn s" onclick="addLoc({name:'IP تمیز',host:'__CLEAN_IP__'})">➕ IP تمیز</button><button class="btn s" onclick="addLoc({name:'اصلی',host:'__PANEL_HOST__'})">➕ دامنه پنل</button><div class="grow"></div><button class="btn p" onclick="saveLocs()">💾 ذخیره لوکیشن‌ها</button></div>
    <div class="xs muted" style="margin-top:10px;line-height:1.9">
      <b>Host</b>: آدرس ورودی کلاینت — دامنه‌ی پنل، دامنه‌ی کاستوم متصل به ورکر، یا <code>__CLEAN_IP__</code> (از لیست IP تمیز با چرخش خودکار) / <code>__PANEL_HOST__</code>.<br>
      <b>Outbound</b>: مسیر خروجی از ورکر — <code>direct</code> · <code>proxyip:host[:port]</code> (برای سایت‌های پشت کلودفلر) · <code>socks5://user:pass@host:port</code> (VIP اختصاصی). اگر خراب شود، خودکار به مسیر بعدی/استخر VIP می‌رود.
    </div>
  </div>
  <div class="grid g2" style="margin-top:12px">
    <div class="card">
      <h3>🧊 IP تمیز و چرخش خودکار</h3>
      <label>لیست IP/دامنه‌ی تمیز (هر خط یکی)</label><textarea id="n_clean" style="min-height:120px">\${esc((s.clean_ips || []).join('\\n'))}</textarea>
      <div class="grid g2" style="margin-top:8px">
        <div><label>تعداد IP در هر ساب</label><input id="n_cleancount" type="number" min="1" max="8" value="\${s.clean_count}" class="ltr"></div>
        <div><label>چرخش هر N دقیقه (۰ = ثابت برای هر کاربر)</label><input id="n_rotate" type="number" min="0" value="\${s.rotate_minutes}" class="ltr"></div>
      </div>
      <p class="xs muted" style="margin-top:6px">با چرخش، لینک‌های ساب هر N دقیقه IP‌های متفاوتی از این لیست می‌گیرند (کلاینت‌ها هر ۶ ساعت ساب را رفرش می‌کنند). IP تمیز را با «ابزارها → اسکنر» پیدا کن.</p>
    </div>
    <div class="card">
      <h3>🛰 استخر پروکسی VIP و ProxyIP</h3>
      <label>ProxyIP سراسری (برای سایت‌های پشت کلودفلر)</label><input id="n_proxyip" class="ltr mono" value="\${esc(s.proxy_ip)}" placeholder="مثال: proxyip.example.com یا 1.2.3.4:443">
      <label style="margin-top:8px">استخر VIP (هر خط یکی — proxyip:… یا socks5://…)</label><textarea id="n_pool" style="min-height:100px">\${esc((s.proxy_ips || []).join('\\n'))}</textarea>
      <div class="sw" style="margin-top:8px"><div><b>دریافت خودکار استخر از مخزن</b><small>وقتی استخر خالی است، از GitHub جاویدنام بارگیری می‌شود</small></div><label class="switch"><input type="checkbox" id="n_autoproxy" \${s.auto_proxy ? 'checked' : ''}><i></i></label></div>
      <div class="row" style="margin-top:8px"><button class="btn s" onclick="checkPool()">🩺 تست استخر</button><span class="xs muted">اتصال ورکر → پروکسی → google.com:443</span></div>
      <pre class="out hidden" id="poolOut"></pre>
    </div>
  </div>
  <div class="grid g2" style="margin-top:12px">
    <div class="card">
      <h3>🧠 مسیر هوش مصنوعی <small>دور زدن تحریم Gemini/ChatGPT/Claude…</small></h3>
      <label>خروجی برای دامنه‌های AI</label>
      <select id="n_airoute"><option value="" \${!s.ai_route ? 'selected' : ''}>خاموش (مسیر عادی)</option><option value="pool" \${s.ai_route === 'pool' ? 'selected' : ''}>استخر VIP</option><option value="custom" \${s.ai_route && s.ai_route !== 'pool' ? 'selected' : ''}>سفارشی…</option></select>
      <input id="n_airoute_custom" class="ltr mono \${s.ai_route && s.ai_route !== 'pool' ? '' : 'hidden'}" style="margin-top:6px" value="\${esc(s.ai_route && s.ai_route !== 'pool' ? s.ai_route : '')}" placeholder="socks5://user:pass@host:port یا proxyip:host">
      <label style="margin-top:8px">دامنه‌های AI</label><textarea id="n_aidomains" style="min-height:110px">\${esc((s.ai_domains || []).join('\\n'))}</textarea>
      <p class="xs muted">اتصال مستقیم از لبه‌ی کلودفلر معمولاً از کشورهای تحریم‌نشده خارج می‌شود؛ اگر باز هم خطای منطقه گرفتی، یک SOCKS5 روی VPS آمریکا/اروپا بگذار و این‌جا مسیر بده.</p>
    </div>
    <div class="card">
      <h3>🚫 مسدودسازی سراسری</h3>
      <label>دامنه‌های مسدود برای همه‌ی کاربران (هر خط یکی)</label><textarea id="n_block" style="min-height:110px">\${esc((s.block_hosts || []).join('\\n'))}</textarea>
      <label style="margin-top:8px">DNS-over-HTTPS برای درخواست‌های UDP/53</label><input id="n_dns" class="ltr mono" value="\${esc(s.dns)}">
      <p class="xs muted">فیلتر تبلیغات/محتوا به‌صورت جداگانه برای هر کاربر در فرم کاربر فعال می‌شود.</p>
    </div>
  </div>
  <div class="row" style="margin-top:12px;justify-content:flex-end"><button class="btn p" onclick="saveNet()">💾 ذخیره تنظیمات شبکه</button></div>\`;
  $('#n_airoute').onchange = () => $('#n_airoute_custom').classList.toggle('hidden', $('#n_airoute').value !== 'custom');
  renderLocs();
}
function renderLocs() {
  const locs = state.settings.locations;
  $('#locList').innerHTML = locs.map((l, i) => \`<div class="loc-row" data-i="\${i}">
    <div><label>فعال</label><label class="switch"><input type="checkbox" class="l_en" \${l.enabled ? 'checked' : ''}><i></i></label></div>
    <div><label>نام</label><input class="l_name" value="\${esc(l.name)}"></div>
    <div><label>Host / آدرس</label><input class="l_host ltr mono" value="\${esc(l.host)}" list="hostHints"></div>
    <div><label>پورت</label><input class="l_port ltr" type="number" value="\${l.port}"></div>
    <div><label>SNI (اختیاری)</label><input class="l_sni ltr mono" value="\${esc(l.sni || '')}" placeholder="پیش‌فرض: خودکار"></div>
    <div><label>Outbound</label><input class="l_out ltr mono" value="\${esc(l.out || 'direct')}" list="outHints"></div>
    <div><label>TLS</label><label class="switch"><input type="checkbox" class="l_tls" \${l.tls ? 'checked' : ''}><i></i></label></div>
    <div><button class="btn i d" onclick="state.settings.locations.splice(\${i},1);renderLocs()">🗑</button></div>
    <input type="hidden" class="l_id" value="\${esc(l.id)}">
  </div>\`).join('') + \`<datalist id="hostHints"><option value="__PANEL_HOST__"><option value="__CLEAN_IP__"></datalist><datalist id="outHints"><option value="direct"><option value="proxyip:"><option value="socks5://"></datalist>\`;
}
function collectLocs() {
  return $$('.loc-row').map(r => ({ id: $('.l_id', r).value, enabled: $('.l_en', r).checked, name: $('.l_name', r).value, host: $('.l_host', r).value.trim(), port: Number($('.l_port', r).value) || 443, sni: $('.l_sni', r).value.trim(), out: $('.l_out', r).value.trim() || 'direct', tls: $('.l_tls', r).checked }));
}
function addLoc(p = {}) { state.settings.locations = collectLocs(); state.settings.locations.push({ id: 'loc' + Math.random().toString(36).slice(2, 6), name: p.name || 'لوکیشن جدید', host: p.host || '', port: 443, tls: true, sni: '', out: 'direct', enabled: true }); renderLocs(); }
async function saveLocs() { try { const j = await api('/api/settings', { method: 'PUT', body: { locations: collectLocs() } }); state.settings = j.settings; renderLocs(); toast('لوکیشن‌ها ذخیره شد'); } catch (e) { toast(e.message, 'err'); } }
async function saveNet() {
  const ai = $('#n_airoute').value === 'custom' ? $('#n_airoute_custom').value.trim() : $('#n_airoute').value;
  try {
    const j = await api('/api/settings', { method: 'PUT', body: { clean_ips: $('#n_clean').value, clean_count: Number($('#n_cleancount').value), rotate_minutes: Number($('#n_rotate').value), proxy_ip: $('#n_proxyip').value.trim(), proxy_ips: $('#n_pool').value, auto_proxy: $('#n_autoproxy').checked, ai_route: ai, ai_domains: $('#n_aidomains').value, block_hosts: $('#n_block').value, dns: $('#n_dns').value.trim(), locations: collectLocs() } });
    state.settings = j.settings; toast('ذخیره شد');
  } catch (e) { toast(e.message, 'err'); }
}
async function checkPool() {
  const out = $('#poolOut'); out.classList.remove('hidden'); out.textContent = 'در حال تست…';
  const j = await api('/api/tools/proxycheck', { method: 'POST', body: { list: $('#n_pool').value } });
  out.textContent = j.results.map(r => \`\${r.ok ? '✅' : '❌'} \${r.spec}  \${r.ms}ms \${r.error || ''}\`).join('\\n') || 'استخر خالی است';
}

/* ===================== SETTINGS ===================== */
async function pageSettings() {
  await loadSettings(); const s = state.settings;
  $('#main').innerHTML = \`
  <div class="grid g2 fadein">
    <div class="card">
      <h3>🎭 ضدفیلتر و TLS</h3>
      <div class="grid g2">
        <div><label>Fingerprint (uTLS)</label><select id="s_fp">\${state.fpOptions.map(f => \`<option \${s.fp === f ? 'selected' : ''}>\${f}</option>\`).join('')}</select></div>
        <div><label>ALPN</label><input id="s_alpn" class="ltr mono" value="\${esc(s.alpn)}"></div>
      </div>
      <div class="sw" style="margin-top:10px"><div><b>TLS Fragment</b><small>شکستن ClientHello برای عبور از DPI (در کانفیگ‌ها اعمال می‌شود)</small></div><label class="switch"><input type="checkbox" id="s_frag" \${s.frag_enabled ? 'checked' : ''}><i></i></label></div>
      <div class="grid g3" style="margin-top:10px">
        <div><label>Length</label><input id="s_fraglen" class="ltr mono" value="\${esc(s.frag_len)}"></div>
        <div><label>Interval</label><input id="s_fragint" class="ltr mono" value="\${esc(s.frag_int)}"></div>
        <div><label>Packets</label><select id="s_fragpk">\${['tlshello', '1-1', '1-2', '1-3'].map(v => \`<option \${s.frag_packets === v ? 'selected' : ''}>\${v}</option>\`).join('')}</select></div>
      </div>
      <div class="row" style="margin-top:8px;gap:6px">\${state.presets.filter(p => p.id !== 'auto').map(p => \`<button class="btn s" onclick="applyPreset('\${p.id}')">\${esc(p.label)}</button>\`).join('')}</div>
      <div class="hr"></div>
      <div class="grid g2">
        <div><label>SNI Mask (TLS masking)</label><input id="s_sni" class="ltr mono" value="\${esc(s.sni_mask)}" placeholder="خالی = آدرس لوکیشن"></div>
        <div><label>Host Mask (WS Host header)</label><input id="s_host" class="ltr mono" value="\${esc(s.host_mask)}" placeholder="خالی = دامنه پنل"></div>
      </div>
      <p class="xs muted" style="margin-top:6px">⚠️ SNI/Host Mask فقط وقتی کار می‌کند که آن دامنه واقعاً روی همین ورکر (Custom Domain / Route) باشد یا از IP تمیز استفاده کنی — وگرنه اتصال قطع می‌شود.</p>
    </div>
    <div class="card">
      <h3>🏷 برندینگ و صفحه‌ی ساب</h3>
      <div><label>عنوان پنل</label><input id="s_title" value="\${esc(s.title)}"></div>
      <div style="margin-top:8px"><label>پیام خوش‌آمد صفحه‌ی ساب</label><input id="s_welcome" value="\${esc(s.welcome)}"></div>
      <div style="margin-top:8px"><label>لینک پشتیبانی (تلگرام/…)</label><input id="s_contact" class="ltr" value="\${esc(s.contact)}" placeholder="https://t.me/…"></div>
      <div class="sw" style="margin-top:10px"><div><b>نمایش یادبود در صفحه‌ی ساب</b><small>🌷 به یاد جان‌باختگان ۱۸ و ۱۹ دی</small></div><label class="switch"><input type="checkbox" id="s_brand" \${s.sub_branding ? 'checked' : ''}><i></i></label></div>
      <div class="hr"></div>
      <h3>🔐 امنیت</h3>
      <div><label>مسیر پروکسی (WebSocket path)</label><div class="row"><input id="s_path" class="ltr mono" value="\${esc(s.proxy_path)}"><button class="btn i" title="تصادفی" onclick="$('#s_path').value='/jvn-'+Math.random().toString(36).slice(2,12)">🎲</button></div><span class="xs muted">تغییر مسیر، کانفیگ‌های قبلی را از کار می‌اندازد (کاربران با ساب خودکار می‌گیرند).</span></div>
      <div class="row" style="margin-top:10px"><button class="btn" onclick="changePass()">🔑 تغییر رمز مدیریت</button></div>
    </div>
  </div>
  <div class="row" style="margin-top:12px;justify-content:flex-end"><button class="btn p" onclick="saveSettingsPage()">💾 ذخیره تنظیمات</button></div>\`;
}
function applyPreset(id) { const p = state.presets.find(x => x.id === id); if (!p) return; if (p.fp) $('#s_fp').value = p.fp; if (p.frag === false) $('#s_frag').checked = false; else if (p.frag) { $('#s_frag').checked = true; $('#s_fraglen').value = p.frag[0]; $('#s_fragint').value = p.frag[1]; } toast('پریست ' + p.label + ' اعمال شد — ذخیره یادت نره'); }
async function saveSettingsPage() {
  try {
    const j = await api('/api/settings', { method: 'PUT', body: { fp: $('#s_fp').value, alpn: $('#s_alpn').value.trim(), frag_enabled: $('#s_frag').checked, frag_len: $('#s_fraglen').value.trim(), frag_int: $('#s_fragint').value.trim(), frag_packets: $('#s_fragpk').value, sni_mask: $('#s_sni').value.trim(), host_mask: $('#s_host').value.trim(), title: $('#s_title').value, welcome: $('#s_welcome').value, contact: $('#s_contact').value.trim(), sub_branding: $('#s_brand').checked, proxy_path: $('#s_path').value.trim() } });
    state.settings = j.settings; toast('ذخیره شد');
  } catch (e) { toast(e.message, 'err'); }
}
function changePass() {
  modal(\`<h2>🔑 تغییر رمز<button class="x" onclick="closeModal()">✕</button></h2><label>رمز فعلی</label><input id="p_cur" type="password" class="ltr"><label style="margin-top:8px">رمز جدید (حداقل ۸)</label><input id="p_new" type="password" class="ltr"><div id="pErr" class="small" style="color:#fda4af;min-height:20px"></div><div class="row" style="justify-content:flex-end"><button class="btn p" id="pGo">تغییر</button></div>\`);
  $('#pGo').onclick = async () => { try { await api('/api/password', { method: 'POST', body: { current: $('#p_cur').value, password: $('#p_new').value } }); closeModal(); toast('رمز عوض شد'); } catch (e) { $('#pErr').textContent = e.message; } };
}

/* ===================== TOOLS ===================== */
async function pageTools() {
  $('#main').innerHTML = \`
  <div class="grid g2 fadein">
    <div class="card">
      <h3>📡 پینگ زنده <small>مرورگر شما ↔ این پنل (لبه‌ی کلودفلر)</small></h3>
      <div class="row"><b id="pingVal" style="font-size:26px">—</b><span class="muted small" id="pingColo"></span><div class="grow"></div><button class="btn s" onclick="livePing()">▶️ شروع</button><button class="btn s" onclick="clearInterval(state.pingTimer)">⏹</button></div>
      <div class="spark" id="pingSpark" style="height:44px;margin-top:8px"></div>
    </div>
    <div class="card">
      <h3>🌐 تست مستقیم <small>لبه‌ی کلودفلر → اینترنت</small></h3>
      <div class="row"><input id="d_host" class="ltr mono" value="www.google.com" style="max-width:220px"><input id="d_port" class="ltr" type="number" value="443" style="max-width:90px"><input id="d_out" class="ltr mono" value="direct" placeholder="outbound" style="max-width:220px"><button class="btn s p" onclick="directTest()">تست</button></div>
      <pre class="out" id="dOut" style="margin-top:8px;max-height:120px">نتیجه این‌جا نمایش داده می‌شود</pre>
      <div class="row" style="gap:6px;margin-top:6px">\${['www.google.com', 'www.youtube.com', 'gemini.google.com', 'chatgpt.com', 'web.telegram.org', 'www.instagram.com', 'discord.com'].map(h => \`<button class="btn s" onclick="$('#d_host').value='\${h}';directTest()">\${h.replace('www.', '')}</button>\`).join('')}</div>
    </div>
  </div>
  <div class="grid g2" style="margin-top:12px">
    <div class="card">
      <h3>🔎 اسکنر IP تمیز <small>روی دستگاه خودت اجرا کن</small></h3>
      <p class="small muted">ورکر نمی‌تواند به IPهای کلودفلر وصل شود، پس اسکن باید از سمت کاربر باشد. اسکریپت آماده را دانلود کن؛ آدرس پنل داخلش ست شده و بهترین IPها را برمی‌گرداند.</p>
      <div class="row" style="gap:6px;margin-top:8px"><a class="btn s b" href="/tools/scanner.py" download>🐍 Python / Pydroid3</a><a class="btn s b" href="/tools/scanner.cmd" download>🪟 Windows CMD</a><a class="btn s b" href="/tools/scanner.sh" download>🐧 Linux / Termux</a></div>
      <div class="hr"></div>
      <label>اسکن سریع از داخل مرورگر (تقریبی — تأخیر TLS به هر IP از دستگاه شما)</label>
      <div class="row"><input id="sc_n" type="number" value="40" min="5" max="200" class="ltr" style="max-width:90px"><button class="btn s p" onclick="browserScan()">▶️ اسکن</button><span class="xs muted" id="scStatus"></span></div>
      <pre class="out" id="scOut" style="margin-top:8px">—</pre>
      <div class="row" style="margin-top:6px"><button class="btn s" onclick="addScanToClean()">➕ افزودن ۵ تای برتر به لیست IP تمیز</button></div>
    </div>
    <div class="card">
      <h3>🩺 سلامت مسیرهای خروجی</h3>
      <pre class="out" id="hOut">—</pre>
      <div class="row" style="margin-top:6px"><button class="btn s" onclick="loadHealth()">🔄 بروزرسانی</button></div>
      <div class="hr"></div>
      <h3>🧾 اطلاعات اتصال شما</h3>
      <pre class="out" id="ipOut">—</pre>
    </div>
  </div>\`;
  loadHealth(); api('/api/tools/ipinfo').then(j => $('#ipOut').textContent = JSON.stringify(j, null, 1)).catch(() => {});
}
let pingHist = [];
function livePing() {
  clearInterval(state.pingTimer); pingHist = [];
  const tick = async () => { const t0 = performance.now(); try { const j = await api('/api/ping'); const ms = Math.round(performance.now() - t0); pingHist.push(ms); if (pingHist.length > 40) pingHist.shift(); $('#pingVal').textContent = fa(ms) + ' ms'; $('#pingColo').textContent = j.colo ? '📍 ' + j.colo : ''; const mx = Math.max(...pingHist, 50); $('#pingSpark').innerHTML = pingHist.map(v => \`<i style="height:\${v / mx * 100}%" data-t="\${v}ms"></i>\`).join(''); } catch (e) { $('#pingVal').textContent = '✖'; } };
  tick(); state.pingTimer = setInterval(tick, 1500);
}
async function directTest() { $('#dOut').textContent = '⏳ …'; const j = await api('/api/tools/direct', { method: 'POST', body: { host: $('#d_host').value.trim(), port: Number($('#d_port').value), out: $('#d_out').value.trim() } }); $('#dOut').textContent = (j.ok ? \`✅ \${j.ms} ms  via \${j.via}  (\${j.bytes} bytes)\` : \`❌ \${j.error}  (\${j.ms} ms)  via \${j.via}\`) + (j.note ? '\\n' + j.note : ''); }
async function loadHealth() { const j = await api('/api/tools/health'); $('#hOut').textContent = j.outbounds.length ? j.outbounds.map(o => \`\${o.healthy ? '🟢' : '🔴'} \${o.spec}  fails=\${o.fails}\`).join('\\n') : 'هنوز مسیر غیرمستقیمی استفاده نشده.'; }
let scanRes = [];
async function browserScan() {
  const N = Number($('#sc_n').value) || 40; const host = location.host; scanRes = [];
  const prefixes = ['104.16', '104.17', '104.18', '104.19', '104.20', '104.21', '104.22', '104.23', '104.24', '104.25', '104.26', '104.27', '172.64', '172.65', '172.66', '172.67', '162.159', '188.114', '141.101'];
  const ips = Array.from({ length: N }, () => prefixes[Math.floor(Math.random() * prefixes.length)] + '.' + Math.floor(Math.random() * 256) + '.' + (1 + Math.floor(Math.random() * 254)));
  $('#scOut').textContent = ''; let done = 0;
  const probe = async (ip) => {
    const t0 = performance.now();
    try { const c = new AbortController(); const t = setTimeout(() => c.abort(), 2500); await fetch(\`https://\${ip}/cdn-cgi/trace\`, { mode: 'no-cors', cache: 'no-store', signal: c.signal }); clearTimeout(t); scanRes.push([Math.round(performance.now() - t0), ip]); }
    catch (e) {}
    done++; $('#scStatus').textContent = \`\${done}/\${N}\`;
  };
  const q = ips.slice(); await Promise.all(Array.from({ length: 8 }, async () => { while (q.length) await probe(q.shift()); }));
  scanRes.sort((a, b) => a[0] - b[0]);
  $('#scOut').textContent = scanRes.length ? scanRes.slice(0, 15).map(([ms, ip]) => \`\${ip.padEnd(16)} \${ms} ms\`).join('\\n') : 'هیچ IP پاسخ نداد (مرورگر ممکن است HTTPS به IP خام را مسدود کند — از اسکریپت استفاده کن)';
}
async function addScanToClean() {
  if (!scanRes.length) return toast('اول اسکن کن', 'warn');
  if (!state.settings) await loadSettings();
  const list = [...new Set([...scanRes.slice(0, 5).map(x => x[1]), ...state.settings.clean_ips])];
  const j = await api('/api/settings', { method: 'PUT', body: { clean_ips: list } }); state.settings = j.settings; toast('به لیست IP تمیز اضافه شد');
}

/* ===================== BACKUP / UPDATE ===================== */
async function pageBackup() {
  const me = state.me;
  $('#main').innerHTML = \`
  <div class="grid g2 fadein">
    <div class="card">
      <h3>💾 پشتیبان‌گیری کامل</h3>
      <p class="small muted">تمام کاربران، تنظیمات و آمار در یک فایل JSON. برای انتقال به ورکر/اکانت دیگر یا بازیابی بعد از حذف.</p>
      <div class="row" style="margin-top:10px"><a class="btn p" href="/api/backup" download>⬇️ دانلود پشتیبان</a><label class="btn" style="margin:0;cursor:pointer">⬆️ بازیابی<input id="impFile" type="file" accept="application/json" class="hidden"></label></div>
      <div class="sw" style="margin-top:10px"><div><b>بازیابی تنظیمات هم انجام شود</b><small>لوکیشن‌ها، fragment، پروکسی‌ها… (مسیر پروکسی دست نمی‌خورد)</small></div><label class="switch"><input type="checkbox" id="impSettings" checked><i></i></label></div>
    </div>
    <div class="card">
      <h3>🔄 آپدیت OTA <small>از مخزن رسمی GitHub</small></h3>
      <div class="row"><span class="chip info">نسخه‌ی فعلی: v\${me.version}</span><span class="chip" id="latestChip">در حال بررسی…</span></div>
      <p class="small muted" style="margin-top:8px">آپدیت بدون از دست رفتن دیتابیس انجام می‌شود. دو راه:<br>۱) از بات تلگرام (🔄 روی پنل) — بدون نیاز به توکن این‌جا.<br>۲) از همین‌جا با توکن کلودفلر (Workers Scripts:Edit). توکن فقط در D1 خودت ذخیره می‌شود.</p>
      <div class="row" style="margin-top:8px"><input id="cfTok" class="ltr mono" placeholder="\${me.has_cf_token ? 'توکن ذخیره شده — برای تعویض وارد کن' : 'Cloudflare API Token (اختیاری)'}"><button class="btn g" id="updBtn" onclick="applyUpdate()">⚡ آپدیت کن</button></div>
      <label style="margin-top:6px"><input type="checkbox" id="saveTok" checked> توکن را برای آپدیت‌های بعدی ذخیره کن</label>
      <pre class="out hidden" id="updOut"></pre>
    </div>
  </div>
  <div class="card" style="margin-top:12px">
    <h3>ℹ️ درباره</h3>
    <p class="small muted" style="line-height:2">
      <b>جاویدنام</b> یک پنل کاملاً اورجینال و آزاد (GPL-3.0) برای Cloudflare Workers است — بدون تبلیغ، بدون DRM، بدون «غیرقابل فروش». هر کاری خواستی باهاش بکن؛ فقط آزاد نگهش دار.<br>
      🌷 به یاد جان‌باختگان ۱۸ و ۱۹ دی ۱۴۰۴ — نامشان جاوید.<br>
      <a href="https://github.com/amirparsa1/JavidNam" target="_blank" style="color:#fda4af">github.com/amirparsa1/JavidNam</a>
    </p>
  </div>\`;
  $('#impFile').onchange = async (e) => {
    const f = e.target.files[0]; if (!f) return;
    try { const data = JSON.parse(await f.text()); if (!(await confirmBox('بازیابی', \`\${fa((data.users || []).length)} کاربر بازیابی شود؟ کاربران هم‌UUID به‌روزرسانی می‌شوند.\`, 'بازیابی', 'g'))) return; const j = await api('/api/restore', { method: 'POST', body: { ...data, with_settings: $('#impSettings').checked } }); toast(fa(j.restored) + ' کاربر بازیابی شد'); } catch (err) { toast(err.message, 'err'); }
  };
  api('/api/update/check').then(j => { const c = $('#latestChip'); if (j.error) { c.textContent = '⚠️ ' + j.error; c.className = 'chip warn'; return; } c.textContent = j.update_available ? '🆕 نسخه‌ی جدید: v' + j.latest : '✅ آخرین نسخه'; c.className = 'chip ' + (j.update_available ? 'warn' : 'ok'); }).catch(() => {});
}
async function applyUpdate() {
  const out = $('#updOut'); out.classList.remove('hidden'); out.textContent = '⏳ در حال دریافت و آپلود نسخه‌ی جدید…'; $('#updBtn').disabled = true;
  try { const j = await api('/api/update/apply', { method: 'POST', body: { cf_token: $('#cfTok').value.trim(), save_token: $('#saveTok').checked } }); out.textContent = \`✅ آپدیت شد به v\${j.version}. صفحه تا چند ثانیه دیگر رفرش می‌شود…\`; setTimeout(() => location.reload(), 4000); }
  catch (e) { out.textContent = '❌ ' + e.message; $('#updBtn').disabled = false; }
}

boot();

</script>
</body>
</html>
`;

const SUB_PAGE_TEMPLATE = `<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#07070b">
<meta name="robots" content="noindex,nofollow">
<meta name="apple-mobile-web-app-capable" content="yes">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<title>__TITLE__</title>
<style>
:root{--bg:#07070b;--bg2:#0d0d14;--card:#11111a;--line:#1f1f2d;--line2:#2b2b3d;--txt:#ecebf3;--mut:#8f8fa3;--rose:#f43f5e;--rose2:#be123c;--amber:#fbbf24;--green:#22c55e;--blue:#38bdf8;--vio:#a78bfa}
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:var(--bg);color:var(--txt);font-family:"Vazirmatn","Segoe UI",Tahoma,system-ui,sans-serif;font-size:14px;line-height:1.7;-webkit-font-smoothing:antialiased;-webkit-tap-highlight-color:transparent}
#bg{position:fixed;inset:0;z-index:0;pointer-events:none}
#glow{position:fixed;inset:0;z-index:0;pointer-events:none;background:radial-gradient(700px 400px at 90% -10%,rgba(244,63,94,.16),transparent 60%),radial-gradient(600px 400px at 0% 100%,rgba(251,191,36,.07),transparent 60%)}
.wrap{position:relative;z-index:1;max-width:640px;margin:0 auto;padding:18px 14px 60px}
.hero{text-align:center;padding:18px 0 12px}
.flame{width:66px;height:66px;border-radius:20px;margin:0 auto 10px;background:linear-gradient(135deg,var(--rose),#7f1d1d);display:grid;place-items:center;box-shadow:0 18px 50px -14px var(--rose)}
.hero h1{font-size:22px;font-weight:800}
.hero p{color:var(--mut);font-size:12.5px}
.card{background:linear-gradient(180deg,var(--card),var(--bg2));border:1px solid var(--line);border-radius:18px;padding:16px;margin-top:12px;box-shadow:0 12px 40px -14px #000}
.card h3{font-size:14.5px;font-weight:700;margin-bottom:10px;display:flex;align-items:center;gap:8px}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.row.nw{flex-wrap:nowrap}.row.nw input{min-width:0;flex:1}
.grow{flex:1}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:10px 14px;border-radius:12px;border:1px solid var(--line2);background:#161624;color:var(--txt);font:inherit;font-weight:600;font-size:13px;cursor:pointer;text-decoration:none;transition:.15s;white-space:nowrap}
.btn:hover{border-color:var(--rose)}
.btn.p{background:linear-gradient(135deg,var(--rose),var(--rose2));border-color:transparent;color:#fff}
.btn.b{background:linear-gradient(135deg,#0284c7,#0369a1);border-color:transparent;color:#fff}
.btn.s{padding:7px 10px;font-size:12px;border-radius:10px}
.btn.i{width:38px;height:38px;padding:0;font-size:16px}
.chip{display:inline-flex;align-items:center;gap:5px;padding:2px 10px;border-radius:999px;font-size:11.5px;font-weight:700;border:1px solid var(--line2);background:var(--bg2);color:var(--mut)}
.chip.ok{color:#86efac;border-color:rgba(34,197,94,.4);background:rgba(34,197,94,.08)}
.chip.bad{color:#fda4af;border-color:rgba(244,63,94,.4);background:rgba(244,63,94,.08)}
.chip.warn{color:#fde68a;border-color:rgba(251,191,36,.4);background:rgba(251,191,36,.08)}
.chip.info{color:#7dd3fc;border-color:rgba(56,189,248,.4);background:rgba(56,189,248,.08)}
.chip.vio{color:#c4b5fd;border-color:rgba(167,139,250,.4);background:rgba(167,139,250,.08)}
.bar{height:10px;border-radius:99px;background:#1a1a26;overflow:hidden}
.bar>i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--rose),var(--amber));transition:width 1s}
.bar.w>i{background:linear-gradient(90deg,var(--amber),var(--rose))}
.kv{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:10px}
.kv div{background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:10px;text-align:center}
.kv b{display:block;font-size:16px}
.kv small{color:var(--mut);font-size:11px}
.ring{position:relative;width:118px;height:118px;margin:0 auto}
.ring svg{transform:rotate(-90deg)}
.ring .c{position:absolute;inset:0;display:grid;place-items:center;text-align:center;line-height:1.2}
.ring .c b{font-size:20px}.ring .c small{font-size:10.5px;color:var(--mut)}
.tabs{display:flex;background:var(--bg2);border:1px solid var(--line);border-radius:14px;padding:4px;margin-top:14px}
.tabs button{flex:1;padding:9px;border:0;border-radius:11px;background:none;color:var(--mut);font:inherit;font-weight:700;font-size:13px;cursor:pointer}
.tabs button.on{background:linear-gradient(135deg,var(--rose),var(--rose2));color:#fff}
.hidden{display:none!important}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;direction:ltr;unicode-bidi:embed}
input,select{font:inherit;color:var(--txt);background:var(--bg2);border:1px solid var(--line2);border-radius:12px;padding:10px 12px;width:100%;outline:none}
select{appearance:none;padding-left:30px;background-image:linear-gradient(45deg,transparent 50%,var(--mut) 50%),linear-gradient(135deg,var(--mut) 50%,transparent 50%);background-position:calc(0% + 16px) 55%,calc(0% + 11px) 55%;background-size:5px 5px;background-repeat:no-repeat}
.qr{background:#fff;padding:10px;border-radius:14px;display:inline-block;margin:0 auto}
.qr svg{display:block}
.cfg{border:1px solid var(--line);border-radius:14px;padding:10px 12px;margin-top:8px;background:var(--bg2)}
.cfg .t{display:flex;align-items:center;gap:8px}
.cfg .t b{font-size:13.5px}
.cfg .h{font-size:11px;color:var(--mut);margin-top:2px}
.apps{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.apps a{display:flex;flex-direction:column;align-items:center;gap:4px;padding:12px 6px;border-radius:14px;border:1px solid var(--line2);background:#161624;color:var(--txt);text-decoration:none;font-size:12px;font-weight:700}
.apps a span{font-size:22px}
.apps a small{font-weight:400;color:var(--mut);font-size:10.5px}
.muted{color:var(--mut)}.small{font-size:12px}.xs{font-size:11px}
.foot{text-align:center;color:var(--mut);font-size:11.5px;margin-top:22px;line-height:2}
.foot .m{color:#fda4af}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#15151f;border:1px solid var(--line2);border-right:3px solid var(--green);padding:10px 16px;border-radius:12px;z-index:9;font-size:13px;animation:pop .2s}
@keyframes pop{from{opacity:0;transform:translate(-50%,8px)}}
.steps{font-size:12.5px;color:var(--mut);line-height:2}
.steps b{color:var(--txt)}
</style>
</head>
<body>
<canvas id="bg"></canvas><div id="glow"></div>
<div class="wrap" id="root"></div>
<script>
var qrcode=function(){function i(t,r){function a(t,r){g=function(t){for(var r=new Array(t),e=0;e<t;e+=1){r[e]=new Array(t);for(var n=0;n<t;n+=1)r[e][n]=null}return r}(l=4*u+17),e(0,0),e(l-7,0),e(0,l-7),i(),o(),v(t,r),7<=u&&h(t),null==n&&(n=w(u,f,c)),d(n,r)}var u=t,f=y[r],g=null,l=0,n=null,c=[],s={},e=function(t,r){for(var e=-1;e<=7;e+=1)if(!(t+e<=-1||l<=t+e))for(var n=-1;n<=7;n+=1)r+n<=-1||l<=r+n||(g[t+e][r+n]=0<=e&&e<=6&&(0==n||6==n)||0<=n&&n<=6&&(0==e||6==e)||2<=e&&e<=4&&2<=n&&n<=4)},o=function(){for(var t=8;t<l-8;t+=1)null==g[t][6]&&(g[t][6]=t%2==0);for(var r=8;r<l-8;r+=1)null==g[6][r]&&(g[6][r]=r%2==0)},i=function(){for(var t=B.getPatternPosition(u),r=0;r<t.length;r+=1)for(var e=0;e<t.length;e+=1){var n=t[r],o=t[e];if(null==g[n][o])for(var i=-2;i<=2;i+=1)for(var a=-2;a<=2;a+=1)g[n+i][o+a]=-2==i||2==i||-2==a||2==a||0==i&&0==a}},h=function(t){for(var r=B.getBCHTypeNumber(u),e=0;e<18;e+=1){var n=!t&&1==(r>>e&1);g[Math.floor(e/3)][e%3+l-8-3]=n}for(e=0;e<18;e+=1){n=!t&&1==(r>>e&1);g[e%3+l-8-3][Math.floor(e/3)]=n}},v=function(t,r){for(var e=f<<3|r,n=B.getBCHTypeInfo(e),o=0;o<15;o+=1){var i=!t&&1==(n>>o&1);o<6?g[o][8]=i:o<8?g[o+1][8]=i:g[l-15+o][8]=i}for(o=0;o<15;o+=1){i=!t&&1==(n>>o&1);o<8?g[8][l-o-1]=i:o<9?g[8][15-o-1+1]=i:g[8][15-o-1]=i}g[l-8][8]=!t},d=function(t,r){for(var e=-1,n=l-1,o=7,i=0,a=B.getMaskFunction(r),u=l-1;0<u;u-=2)for(6==u&&(u-=1);;){for(var f=0;f<2;f+=1)if(null==g[n][u-f]){var c=!1;i<t.length&&(c=1==(t[i]>>>o&1)),a(n,u-f)&&(c=!c),g[n][u-f]=c,-1==(o-=1)&&(i+=1,o=7)}if((n+=e)<0||l<=n){n-=e,e=-e;break}}},w=function(t,r,e){for(var n=b.getRSBlocks(t,r),o=M(),i=0;i<e.length;i+=1){var a=e[i];o.put(a.getMode(),4),o.put(a.getLength(),B.getLengthInBits(a.getMode(),t)),a.write(o)}var u=0;for(i=0;i<n.length;i+=1)u+=n[i].dataCount;if(o.getLengthInBits()>8*u)throw"code length overflow. ("+o.getLengthInBits()+">"+8*u+")";for(o.getLengthInBits()+4<=8*u&&o.put(0,4);o.getLengthInBits()%8!=0;)o.putBit(!1);for(;!(o.getLengthInBits()>=8*u||(o.put(236,8),o.getLengthInBits()>=8*u));)o.put(17,8);return function(t,r){for(var e=0,n=0,o=0,i=new Array(r.length),a=new Array(r.length),u=0;u<r.length;u+=1){var f=r[u].dataCount,c=r[u].totalCount-f;n=Math.max(n,f),o=Math.max(o,c),i[u]=new Array(f);for(var g=0;g<i[u].length;g+=1)i[u][g]=255&t.getBuffer()[g+e];e+=f;var l=B.getErrorCorrectPolynomial(c),h=C(i[u],l.getLength()-1).mod(l);a[u]=new Array(l.getLength()-1);for(g=0;g<a[u].length;g+=1){var s=g+h.getLength()-a[u].length;a[u][g]=0<=s?h.getAt(s):0}}var v=0;for(g=0;g<r.length;g+=1)v+=r[g].totalCount;var d=new Array(v),w=0;for(g=0;g<n;g+=1)for(u=0;u<r.length;u+=1)g<i[u].length&&(d[w]=i[u][g],w+=1);for(g=0;g<o;g+=1)for(u=0;u<r.length;u+=1)g<a[u].length&&(d[w]=a[u][g],w+=1);return d}(o,n)};s.addData=function(t,r){var e=null;switch(r=r||"Byte"){case"Numeric":e=x(t);break;case"Alphanumeric":e=m(t);break;case"Byte":e=L(t);break;case"Kanji":e=D(t);break;default:throw"mode:"+r}c.push(e),n=null},s.isDark=function(t,r){if(t<0||l<=t||r<0||l<=r)throw t+","+r;return g[t][r]},s.getModuleCount=function(){return l},s.make=function(){if(u<1){for(var t=1;t<40;t++){for(var r=b.getRSBlocks(t,f),e=M(),n=0;n<c.length;n++){var o=c[n];e.put(o.getMode(),4),e.put(o.getLength(),B.getLengthInBits(o.getMode(),t)),o.write(e)}var i=0;for(n=0;n<r.length;n++)i+=r[n].dataCount;if(e.getLengthInBits()<=8*i)break}u=t}a(!1,function(){for(var t=0,r=0,e=0;e<8;e+=1){a(!0,e);var n=B.getLostPoint(s);(0==e||n<t)&&(t=n,r=e)}return r}())},s.createTableTag=function(t,r){t=t||2;var e="";e+='<table style="',e+=" border-width: 0px; border-style: none;",e+=" border-collapse: collapse;",e+=" padding: 0px; margin: "+(r=void 0===r?4*t:r)+"px;",e+='">',e+="<tbody>";for(var n=0;n<s.getModuleCount();n+=1){e+="<tr>";for(var o=0;o<s.getModuleCount();o+=1)e+='<td style="',e+=" border-width: 0px; border-style: none;",e+=" border-collapse: collapse;",e+=" padding: 0px; margin: 0px;",e+=" width: "+t+"px;",e+=" height: "+t+"px;",e+=" background-color: ",e+=s.isDark(n,o)?"#000000":"#ffffff",e+=";",e+='"/>';e+="</tr>"}return e+="</tbody>",e+="</table>"},s.createSvgTag=function(t,r,e,n){var o={};"object"==typeof t&&(t=(o=t).cellSize,r=o.margin,e=o.alt,n=o.title),t=t||2,r=void 0===r?4*t:r,(e="string"==typeof e?{text:e}:e||{}).text=e.text||null,e.id=e.text?e.id||"qrcode-description":null,(n="string"==typeof n?{text:n}:n||{}).text=n.text||null,n.id=n.text?n.id||"qrcode-title":null;var i,a,u,f,c=s.getModuleCount()*t+2*r,g="";for(f="l"+t+",0 0,"+t+" -"+t+",0 0,-"+t+"z ",g+='<svg version="1.1" xmlns="http://www.w3.org/2000/svg"',g+=o.scalable?"":' width="'+c+'px" height="'+c+'px"',g+=' viewBox="0 0 '+c+" "+c+'" ',g+=' preserveAspectRatio="xMinYMin meet"',g+=n.text||e.text?' role="img" aria-labelledby="'+p([n.id,e.id].join(" ").trim())+'"':"",g+=">",g+=n.text?'<title id="'+p(n.id)+'">'+p(n.text)+"</title>":"",g+=e.text?'<description id="'+p(e.id)+'">'+p(e.text)+"</description>":"",g+='<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>',g+='<path d="',a=0;a<s.getModuleCount();a+=1)for(u=a*t+r,i=0;i<s.getModuleCount();i+=1)s.isDark(a,i)&&(g+="M"+(i*t+r)+","+u+f);return g+='" stroke="transparent" fill="black"/>',g+="</svg>"},s.createDataURL=function(o,t){o=o||2,t=void 0===t?4*o:t;var r=s.getModuleCount()*o+2*t,i=t,a=r-t;return I(r,r,function(t,r){if(i<=t&&t<a&&i<=r&&r<a){var e=Math.floor((t-i)/o),n=Math.floor((r-i)/o);return s.isDark(n,e)?0:1}return 1})},s.createImgTag=function(t,r,e){t=t||2,r=void 0===r?4*t:r;var n=s.getModuleCount()*t+2*r,o="";return o+="<img",o+=' src="',o+=s.createDataURL(t,r),o+='"',o+=' width="',o+=n,o+='"',o+=' height="',o+=n,o+='"',e&&(o+=' alt="',o+=p(e),o+='"'),o+="/>"};var p=function(t){for(var r="",e=0;e<t.length;e+=1){var n=t.charAt(e);switch(n){case"<":r+="&lt;";break;case">":r+="&gt;";break;case"&":r+="&amp;";break;case'"':r+="&quot;";break;default:r+=n}}return r};return s.createASCII=function(t,r){if((t=t||1)<2)return function(t){t=void 0===t?2:t;var r,e,n,o,i,a=1*s.getModuleCount()+2*t,u=t,f=a-t,c={"██":"█","█ ":"▀"," █":"▄","  ":" "},g={"██":"▀","█ ":"▀"," █":" ","  ":" "},l="";for(r=0;r<a;r+=2){for(n=Math.floor((r-u)/1),o=Math.floor((r+1-u)/1),e=0;e<a;e+=1)i="█",u<=e&&e<f&&u<=r&&r<f&&s.isDark(n,Math.floor((e-u)/1))&&(i=" "),u<=e&&e<f&&u<=r+1&&r+1<f&&s.isDark(o,Math.floor((e-u)/1))?i+=" ":i+="█",l+=t<1&&f<=r+1?g[i]:c[i];l+="\\n"}return a%2&&0<t?l.substring(0,l.length-a-1)+Array(1+a).join("▀"):l.substring(0,l.length-1)}(r);t-=1,r=void 0===r?2*t:r;var e,n,o,i,a=s.getModuleCount()*t+2*r,u=r,f=a-r,c=Array(t+1).join("██"),g=Array(t+1).join("  "),l="",h="";for(e=0;e<a;e+=1){for(o=Math.floor((e-u)/t),h="",n=0;n<a;n+=1)i=1,u<=n&&n<f&&u<=e&&e<f&&s.isDark(o,Math.floor((n-u)/t))&&(i=0),h+=i?c:g;for(o=0;o<t;o+=1)l+=h+"\\n"}return l.substring(0,l.length-1)},s.renderTo2dContext=function(t,r){r=r||2;for(var e=s.getModuleCount(),n=0;n<e;n++)for(var o=0;o<e;o++)t.fillStyle=s.isDark(n,o)?"black":"white",t.fillRect(n*r,o*r,r,r)},s}i.stringToBytes=(i.stringToBytesFuncs={default:function(t){for(var r=[],e=0;e<t.length;e+=1){var n=t.charCodeAt(e);r.push(255&n)}return r}}).default,i.createStringToBytes=function(u,f){var i=function(){function t(){var t=r.read();if(-1==t)throw"eof";return t}for(var r=S(u),e=0,n={};;){var o=r.read();if(-1==o)break;var i=t(),a=t()<<8|t();n[String.fromCharCode(o<<8|i)]=a,e+=1}if(e!=f)throw e+" != "+f;return n}(),a="?".charCodeAt(0);return function(t){for(var r=[],e=0;e<t.length;e+=1){var n=t.charCodeAt(e);if(n<128)r.push(n);else{var o=i[t.charAt(e)];"number"==typeof o?(255&o)==o?r.push(o):(r.push(o>>>8),r.push(255&o)):r.push(a)}}return r}};var r,t,a=1,u=2,o=4,f=8,y={L:1,M:0,Q:3,H:2},e=0,n=1,c=2,g=3,l=4,h=5,s=6,v=7,B=(r=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],(t={}).getBCHTypeInfo=function(t){for(var r=t<<10;0<=d(r)-d(1335);)r^=1335<<d(r)-d(1335);return 21522^(t<<10|r)},t.getBCHTypeNumber=function(t){for(var r=t<<12;0<=d(r)-d(7973);)r^=7973<<d(r)-d(7973);return t<<12|r},t.getPatternPosition=function(t){return r[t-1]},t.getMaskFunction=function(t){switch(t){case e:return function(t,r){return(t+r)%2==0};case n:return function(t,r){return t%2==0};case c:return function(t,r){return r%3==0};case g:return function(t,r){return(t+r)%3==0};case l:return function(t,r){return(Math.floor(t/2)+Math.floor(r/3))%2==0};case h:return function(t,r){return t*r%2+t*r%3==0};case s:return function(t,r){return(t*r%2+t*r%3)%2==0};case v:return function(t,r){return(t*r%3+(t+r)%2)%2==0};default:throw"bad maskPattern:"+t}},t.getErrorCorrectPolynomial=function(t){for(var r=C([1],0),e=0;e<t;e+=1)r=r.multiply(C([1,w.gexp(e)],0));return r},t.getLengthInBits=function(t,r){if(1<=r&&r<10)switch(t){case a:return 10;case u:return 9;case o:case f:return 8;default:throw"mode:"+t}else if(r<27)switch(t){case a:return 12;case u:return 11;case o:return 16;case f:return 10;default:throw"mode:"+t}else{if(!(r<41))throw"type:"+r;switch(t){case a:return 14;case u:return 13;case o:return 16;case f:return 12;default:throw"mode:"+t}}},t.getLostPoint=function(t){for(var r=t.getModuleCount(),e=0,n=0;n<r;n+=1)for(var o=0;o<r;o+=1){for(var i=0,a=t.isDark(n,o),u=-1;u<=1;u+=1)if(!(n+u<0||r<=n+u))for(var f=-1;f<=1;f+=1)o+f<0||r<=o+f||0==u&&0==f||a==t.isDark(n+u,o+f)&&(i+=1);5<i&&(e+=3+i-5)}for(n=0;n<r-1;n+=1)for(o=0;o<r-1;o+=1){var c=0;t.isDark(n,o)&&(c+=1),t.isDark(n+1,o)&&(c+=1),t.isDark(n,o+1)&&(c+=1),t.isDark(n+1,o+1)&&(c+=1),0!=c&&4!=c||(e+=3)}for(n=0;n<r;n+=1)for(o=0;o<r-6;o+=1)t.isDark(n,o)&&!t.isDark(n,o+1)&&t.isDark(n,o+2)&&t.isDark(n,o+3)&&t.isDark(n,o+4)&&!t.isDark(n,o+5)&&t.isDark(n,o+6)&&(e+=40);for(o=0;o<r;o+=1)for(n=0;n<r-6;n+=1)t.isDark(n,o)&&!t.isDark(n+1,o)&&t.isDark(n+2,o)&&t.isDark(n+3,o)&&t.isDark(n+4,o)&&!t.isDark(n+5,o)&&t.isDark(n+6,o)&&(e+=40);var g=0;for(o=0;o<r;o+=1)for(n=0;n<r;n+=1)t.isDark(n,o)&&(g+=1);return e+=Math.abs(100*g/r/r-50)/5*10},t);function d(t){for(var r=0;0!=t;)r+=1,t>>>=1;return r}var w=function(){for(var r=new Array(256),e=new Array(256),t=0;t<8;t+=1)r[t]=1<<t;for(t=8;t<256;t+=1)r[t]=r[t-4]^r[t-5]^r[t-6]^r[t-8];for(t=0;t<255;t+=1)e[r[t]]=t;var n={glog:function(t){if(t<1)throw"glog("+t+")";return e[t]},gexp:function(t){for(;t<0;)t+=255;for(;256<=t;)t-=255;return r[t]}};return n}();function C(n,o){if(void 0===n.length)throw n.length+"/"+o;var r=function(){for(var t=0;t<n.length&&0==n[t];)t+=1;for(var r=new Array(n.length-t+o),e=0;e<n.length-t;e+=1)r[e]=n[e+t];return r}(),i={getAt:function(t){return r[t]},getLength:function(){return r.length},multiply:function(t){for(var r=new Array(i.getLength()+t.getLength()-1),e=0;e<i.getLength();e+=1)for(var n=0;n<t.getLength();n+=1)r[e+n]^=w.gexp(w.glog(i.getAt(e))+w.glog(t.getAt(n)));return C(r,0)},mod:function(t){if(i.getLength()-t.getLength()<0)return i;for(var r=w.glog(i.getAt(0))-w.glog(t.getAt(0)),e=new Array(i.getLength()),n=0;n<i.getLength();n+=1)e[n]=i.getAt(n);for(n=0;n<t.getLength();n+=1)e[n]^=w.gexp(w.glog(t.getAt(n))+r);return C(e,0).mod(t)}};return i}function p(){var e=[],o={writeByte:function(t){e.push(255&t)},writeShort:function(t){o.writeByte(t),o.writeByte(t>>>8)},writeBytes:function(t,r,e){r=r||0,e=e||t.length;for(var n=0;n<e;n+=1)o.writeByte(t[n+r])},writeString:function(t){for(var r=0;r<t.length;r+=1)o.writeByte(t.charCodeAt(r))},toByteArray:function(){return e},toString:function(){var t="";t+="[";for(var r=0;r<e.length;r+=1)0<r&&(t+=","),t+=e[r];return t+="]"}};return o}var k,A,b=(k=[[1,26,19],[1,26,16],[1,26,13],[1,26,9],[1,44,34],[1,44,28],[1,44,22],[1,44,16],[1,70,55],[1,70,44],[2,35,17],[2,35,13],[1,100,80],[2,50,32],[2,50,24],[4,25,9],[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],[2,86,68],[4,43,27],[4,43,19],[4,43,15],[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],[3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12,7,37,13],[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],[3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14],[3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,43,15,10,44,16],[4,144,116,4,145,117],[17,68,42],[17,50,22,6,51,23],[19,46,16,6,47,17],[2,139,111,7,140,112],[17,74,46],[7,54,24,16,55,25],[34,37,13],[4,151,121,5,152,122],[4,75,47,14,76,48],[11,54,24,14,55,25],[16,45,15,14,46,16],[6,147,117,4,148,118],[6,73,45,14,74,46],[11,54,24,16,55,25],[30,46,16,2,47,17],[8,132,106,4,133,107],[8,75,47,13,76,48],[7,54,24,22,55,25],[22,45,15,13,46,16],[10,142,114,2,143,115],[19,74,46,4,75,47],[28,50,22,6,51,23],[33,46,16,4,47,17],[8,152,122,4,153,123],[22,73,45,3,74,46],[8,53,23,26,54,24],[12,45,15,28,46,16],[3,147,117,10,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],[7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],[5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],[13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],[17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],[17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,55,25],[11,45,15,46,46,16],[13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],[12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],[6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],[17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],[4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],[20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,45,15,67,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16]],(A={}).getRSBlocks=function(t,r){var e=function(t,r){switch(r){case y.L:return k[4*(t-1)+0];case y.M:return k[4*(t-1)+1];case y.Q:return k[4*(t-1)+2];case y.H:return k[4*(t-1)+3];default:return}}(t,r);if(void 0===e)throw"bad rs block @ typeNumber:"+t+"/errorCorrectionLevel:"+r;for(var n,o,i=e.length/3,a=[],u=0;u<i;u+=1)for(var f=e[3*u+0],c=e[3*u+1],g=e[3*u+2],l=0;l<f;l+=1)a.push((n=g,o=void 0,(o={}).totalCount=c,o.dataCount=n,o));return a},A),M=function(){var e=[],n=0,o={getBuffer:function(){return e},getAt:function(t){var r=Math.floor(t/8);return 1==(e[r]>>>7-t%8&1)},put:function(t,r){for(var e=0;e<r;e+=1)o.putBit(1==(t>>>r-e-1&1))},getLengthInBits:function(){return n},putBit:function(t){var r=Math.floor(n/8);e.length<=r&&e.push(0),t&&(e[r]|=128>>>n%8),n+=1}};return o},x=function(t){var r=a,n=t,e={getMode:function(){return r},getLength:function(t){return n.length},write:function(t){for(var r=n,e=0;e+2<r.length;)t.put(o(r.substring(e,e+3)),10),e+=3;e<r.length&&(r.length-e==1?t.put(o(r.substring(e,e+1)),4):r.length-e==2&&t.put(o(r.substring(e,e+2)),7))}},o=function(t){for(var r=0,e=0;e<t.length;e+=1)r=10*r+i(t.charAt(e));return r},i=function(t){if("0"<=t&&t<="9")return t.charCodeAt(0)-"0".charCodeAt(0);throw"illegal char :"+t};return e},m=function(t){var r=u,n=t,e={getMode:function(){return r},getLength:function(t){return n.length},write:function(t){for(var r=n,e=0;e+1<r.length;)t.put(45*o(r.charAt(e))+o(r.charAt(e+1)),11),e+=2;e<r.length&&t.put(o(r.charAt(e)),6)}},o=function(t){if("0"<=t&&t<="9")return t.charCodeAt(0)-"0".charCodeAt(0);if("A"<=t&&t<="Z")return t.charCodeAt(0)-"A".charCodeAt(0)+10;switch(t){case" ":return 36;case"$":return 37;case"%":return 38;case"*":return 39;case"+":return 40;case"-":return 41;case".":return 42;case"/":return 43;case":":return 44;default:throw"illegal char :"+t}};return e},L=function(t){var r=o,e=i.stringToBytes(t),n={getMode:function(){return r},getLength:function(t){return e.length},write:function(t){for(var r=0;r<e.length;r+=1)t.put(e[r],8)}};return n},D=function(t){var r=f,e=i.stringToBytesFuncs.SJIS;if(!e)throw"sjis not supported.";!function(){var t=e("友");if(2!=t.length||38726!=(t[0]<<8|t[1]))throw"sjis not supported."}();var o=e(t),n={getMode:function(){return r},getLength:function(t){return~~(o.length/2)},write:function(t){for(var r=o,e=0;e+1<r.length;){var n=(255&r[e])<<8|255&r[e+1];if(33088<=n&&n<=40956)n-=33088;else{if(!(57408<=n&&n<=60351))throw"illegal char at "+(e+1)+"/"+n;n-=49472}n=192*(n>>>8&255)+(255&n),t.put(n,13),e+=2}if(e<r.length)throw"illegal char at "+(e+1)}};return n},S=function(t){var e=t,n=0,o=0,i=0,r={read:function(){for(;i<8;){if(n>=e.length){if(0==i)return-1;throw"unexpected end of file./"+i}var t=e.charAt(n);if(n+=1,"="==t)return i=0,-1;t.match(/^\\s$/)||(o=o<<6|a(t.charCodeAt(0)),i+=6)}var r=o>>>i-8&255;return i-=8,r}},a=function(t){if(65<=t&&t<=90)return t-65;if(97<=t&&t<=122)return t-97+26;if(48<=t&&t<=57)return t-48+52;if(43==t)return 62;if(47==t)return 63;throw"c:"+t};return r},I=function(t,r,e){for(var n=function(t,r){var n=t,o=r,l=new Array(t*r),e={setPixel:function(t,r,e){l[r*n+t]=e},write:function(t){t.writeString("GIF87a"),t.writeShort(n),t.writeShort(o),t.writeByte(128),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(0),t.writeByte(255),t.writeByte(255),t.writeByte(255),t.writeString(","),t.writeShort(0),t.writeShort(0),t.writeShort(n),t.writeShort(o),t.writeByte(0);var r=i(2);t.writeByte(2);for(var e=0;255<r.length-e;)t.writeByte(255),t.writeBytes(r,e,255),e+=255;t.writeByte(r.length-e),t.writeBytes(r,e,r.length-e),t.writeByte(0),t.writeString(";")}},i=function(t){for(var r=1<<t,e=1+(1<<t),n=t+1,o=h(),i=0;i<r;i+=1)o.add(String.fromCharCode(i));o.add(String.fromCharCode(r)),o.add(String.fromCharCode(e));var a=p(),u=function(t){var e=t,n=0,o=0,r={write:function(t,r){if(t>>>r!=0)throw"length over";for(;8<=n+r;)e.writeByte(255&(t<<n|o)),r-=8-n,t>>>=8-n,n=o=0;o|=t<<n,n+=r},flush:function(){0<n&&e.writeByte(o)}};return r}(a);u.write(r,n);var f=0,c=String.fromCharCode(l[f]);for(f+=1;f<l.length;){var g=String.fromCharCode(l[f]);f+=1,o.contains(c+g)?c+=g:(u.write(o.indexOf(c),n),o.size()<4095&&(o.size()==1<<n&&(n+=1),o.add(c+g)),c=g)}return u.write(o.indexOf(c),n),u.write(e,n),u.flush(),a.toByteArray()},h=function(){var r={},e=0,n={add:function(t){if(n.contains(t))throw"dup key:"+t;r[t]=e,e+=1},size:function(){return e},indexOf:function(t){return r[t]},contains:function(t){return void 0!==r[t]}};return n};return e}(t,r),o=0;o<r;o+=1)for(var i=0;i<t;i+=1)n.setPixel(i,o,e(i,o));var a=p();n.write(a);for(var u=function(){function e(t){a+=String.fromCharCode(r(63&t))}var n=0,o=0,i=0,a="",t={},r=function(t){if(t<0);else{if(t<26)return 65+t;if(t<52)return t-26+97;if(t<62)return t-52+48;if(62==t)return 43;if(63==t)return 47}throw"n:"+t};return t.writeByte=function(t){for(n=n<<8|255&t,o+=8,i+=1;6<=o;)e(n>>>o-6),o-=6},t.flush=function(){if(0<o&&(e(n<<6-o),o=n=0),i%3!=0)for(var t=3-i%3,r=0;r<t;r+=1)a+="="},t.toString=function(){return a},t}(),f=a.toByteArray(),c=0;c<f.length;c+=1)u.writeByte(f[c]);return u.flush(),"data:image/gif;base64,"+u};return i}();qrcode.stringToBytesFuncs["UTF-8"]=function(t){return function(t){for(var r=[],e=0;e<t.length;e++){var n=t.charCodeAt(e);n<128?r.push(n):n<2048?r.push(192|n>>6,128|63&n):n<55296||57344<=n?r.push(224|n>>12,128|n>>6&63,128|63&n):(e++,n=65536+((1023&n)<<10|1023&t.charCodeAt(e)),r.push(240|n>>18,128|n>>12&63,128|n>>6&63,128|63&n))}return r}(t)},function(t){"function"==typeof define&&define.amd?define([],t):"object"==typeof exports&&(module.exports=t())}(function(){return qrcode});
</script>
<script>
const D = __SUB_DATA_JSON__;
const $ = (s, r = document) => r.querySelector(s);
const GB = 1073741824;
const fa = (n) => String(n).replace(/\\d/g, d => '۰۱۲۳۴۵۶۷۸۹'[d]);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtB = (b) => { b = Number(b) || 0; if (b >= GB) return (b / GB).toFixed(2) + ' GB'; if (b >= 1048576) return (b / 1048576).toFixed(0) + ' MB'; return (b / 1024).toFixed(0) + ' KB'; };
const jdate = (ts) => { if (!ts) return '—'; try { return new Intl.DateTimeFormat('fa-IR', { dateStyle: 'medium' }).format(new Date(ts)); } catch (e) { return new Date(ts).toLocaleDateString(); } };
const ago = (ts) => { if (!ts) return 'هنوز وصل نشده'; const d = Date.now() - ts; if (d < 60e3) return 'همین الان'; if (d < 3600e3) return fa(Math.floor(d / 60e3)) + ' دقیقه پیش'; if (d < 86400e3) return fa(Math.floor(d / 3600e3)) + ' ساعت پیش'; return fa(Math.floor(d / 86400e3)) + ' روز پیش'; };
function toast(m) { const t = document.createElement('div'); t.className = 'toast'; t.textContent = m; document.body.appendChild(t); setTimeout(() => t.remove(), 2500); }
function copy(t, m = 'کپی شد ✓') { (navigator.clipboard ? navigator.clipboard.writeText(t) : Promise.reject()).then(() => toast(m)).catch(() => { const a = document.createElement('textarea'); a.value = t; document.body.appendChild(a); a.select(); document.execCommand('copy'); a.remove(); toast(m); }); }
function qr(el, text, size = 200) { try { const q = qrcode(0, 'M'); q.addData(text); q.make(); el.innerHTML = q.createSvgTag({ cellSize: Math.max(2, Math.floor(size / q.getModuleCount())), margin: 0 }); } catch (e) { el.textContent = '—'; } }

(function bg() { const c = $('#bg'), x = c.getContext('2d'); let w, h, P = []; const rs = () => { w = c.width = innerWidth * devicePixelRatio; h = c.height = innerHeight * devicePixelRatio; }; rs(); addEventListener('resize', rs); for (let i = 0; i < 45; i++) P.push({ x: Math.random(), y: Math.random(), r: Math.random() * 2 + .6, v: Math.random() * .0006 + .0002, o: Math.random() * .5 + .2, d: Math.random() * 6.28 }); (function f(t) { x.clearRect(0, 0, w, h); for (const p of P) { p.y -= p.v; p.x += Math.sin(t / 2000 + p.d) * .00025; if (p.y < -.02) { p.y = 1.02; p.x = Math.random(); } const g = x.createRadialGradient(p.x * w, p.y * h, 0, p.x * w, p.y * h, p.r * 6 * devicePixelRatio); g.addColorStop(0, \`rgba(251,113,133,\${p.o})\`); g.addColorStop(1, 'rgba(251,113,133,0)'); x.fillStyle = g; x.beginPath(); x.arc(p.x * w, p.y * h, p.r * 6 * devicePixelRatio, 0, 6.28); x.fill(); } requestAnimationFrame(f); })(0); })();

const st = D.state, S = D.status;
let view = D.view, links = D.links, preset = D.preset;
function statusChip() { if (!st.active) return '<span class="chip bad">غیرفعال</span>'; if (st.expired) return '<span class="chip bad">منقضی شده</span>'; if (st.overQuota) return '<span class="chip bad">حجم تمام شده</span>'; if (st.overRequests) return '<span class="chip bad">سقف اتصال</span>'; if (st.pending) return '<span class="chip warn">منتظر اولین اتصال</span>'; const on = S.last_seen_at && Date.now() - S.last_seen_at < 5 * 60000; return \`<span class="chip ok">\${on ? '🟢 آنلاین' : '✅ فعال'}</span>\`; }
function render() {
  const pct = st.quota ? Math.min(100, Math.round(st.used / st.quota * 100)) : 0;
  const R = 50, C = 2 * Math.PI * R, dash = C * (1 - pct / 100);
  $('#root').innerHTML = \`
  <div class="hero">
    <div class="flame"><svg width="36" height="36" viewBox="0 0 64 64"><path d="M32 10c-1.8 5-6 7.2-6 12.6 0 3.4 1.9 6.3 4.2 8.4C29.6 39 27.4 44.6 22 50c7-1.6 11.2-5 13.4-9.6 2.2 4.6 6.4 8 13.4 9.6-5.4-5.4-7.6-11-8.2-19 2.3-2.1 4.2-5 4.2-8.4C44.8 17.2 40.6 15 38.8 10c-1.6 3.4-4.2 5-6.8 5s-5.2-1.6-6.8-5z" fill="#fff"/></svg></div>
    <h1>\${esc(D.name)}</h1><p>\${esc(D.welcome || D.brand.fa)}</p>
    <div style="margin-top:8px">\${statusChip()}</div>
  </div>
  <div class="tabs"><button class="\${view === 'configs' ? 'on' : ''}" onclick="view='configs';render()">⚡ اتصال</button><button class="\${view === 'status' ? 'on' : ''}" onclick="view='status';render()">📊 وضعیت</button><button class="\${view === 'help' ? 'on' : ''}" onclick="view='help';render()">📖 راهنما</button></div>
  \${view === 'status' ? \`
  <div class="card" style="text-align:center">
    <div class="ring"><svg width="118" height="118"><circle cx="59" cy="59" r="\${R}" stroke="#1a1a26" stroke-width="10" fill="none"/><circle cx="59" cy="59" r="\${R}" stroke="\${pct > 85 ? '#f43f5e' : '#fbbf24'}" stroke-width="10" fill="none" stroke-linecap="round" stroke-dasharray="\${C}" stroke-dashoffset="\${dash}" style="transition:stroke-dashoffset 1s"/></svg><div class="c"><div><b>\${st.quota ? fa(pct) + '٪' : '∞'}</b><br><small>مصرف شده</small></div></div></div>
    <div class="kv">
      <div><b>\${fmtB(st.used)}</b><small>مصرف</small></div>
      <div><b>\${st.quota ? fmtB(st.remainingBytes) : '∞'}</b><small>باقی‌مانده</small></div>
      <div><b>\${st.quota ? fmtB(st.quota) : '∞'}</b><small>کل حجم</small></div>
      <div><b>\${st.expiryAt ? fa(st.daysLeft) : '∞'}</b><small>روز مانده</small></div>
      <div><b style="font-size:13px">\${st.expiryAt ? jdate(st.expiryAt) : st.pending ? 'پس از اتصال' : 'نامحدود'}</b><small>تاریخ انقضا</small></div>
      <div><b>\${S.ip_limit ? fa(S.online_ips) + ' / ' + fa(S.ip_limit) : '∞'}</b><small>دستگاه آنلاین</small></div>
    </div>
    <div class="small muted" style="margin-top:10px">آخرین اتصال: \${ago(S.last_seen_at)}\${S.max_requests ? ' · اتصال‌ها: ' + fa(S.used_requests) + ' / ' + fa(S.max_requests) : ''}</div>
    <div class="row" style="justify-content:center;margin-top:10px"><button class="btn s" onclick="location.reload()">🔄 بروزرسانی</button><button class="btn s" onclick="copy(D.status_url,'لینک وضعیت کپی شد')">🔗 لینک این صفحه</button></div>
  </div>\` : view === 'help' ? \`
  <div class="card"><h3>📱 اندروید — v2rayNG / Hiddify</h3><div class="steps">۱) برنامه را نصب کن. ۲) در تب «اتصال» روی دکمه‌ی برنامه بزن تا ساب خودکار اضافه شود (یا لینک ساب را کپی و در برنامه <b>+ → Subscription</b> بچسبان). ۳) روی کانفیگ بزن و وصل شو. ۴) اگر وصل نشد، اپراتورت را از منوی «بهینه‌سازی» انتخاب کن و ساب را دوباره آپدیت کن.</div></div>
  <div class="card"><h3>🍎 آیفون — Streisand / Hiddify / Shadowrocket</h3><div class="steps">Streisand رایگان است. لینک ساب را کپی کن → در برنامه <b>+ → Import from clipboard</b> → کانفیگ‌ها اضافه می‌شوند. برای Shadowrocket: <b>+ → Subscribe</b>.</div></div>
  <div class="card"><h3>💻 ویندوز / مک / لینوکس</h3><div class="steps"><b>Hiddify</b> (همه‌ی سیستم‌ها)، <b>v2rayN</b> (ویندوز)، <b>Clash Verge / Mihomo</b> با فرمت Clash. لینک ساب یکسان است؛ فرمت به‌صورت خودکار بر اساس برنامه انتخاب می‌شود.</div></div>
  <div class="card"><h3>🩹 رفع مشکل</h3><div class="steps">• <b>وصل می‌شود ولی سایت باز نمی‌شود:</b> اپراتور را عوض کن (بهینه‌سازی) یا لوکیشن دیگری را امتحان کن.<br>• <b>سرعت پایین:</b> لوکیشن «IP تمیز» را انتخاب کن؛ هر ۶ ساعت IPها به‌روز می‌شوند.<br>• <b>هیچ‌کدام وصل نمی‌شود:</b> ساب را حذف و دوباره اضافه کن؛ حالت «همه‌ی سایت‌ها از پروکسی» را فعال کن.<br>\${D.contact ? \`• پشتیبانی: <a href="\${esc(D.contact)}" style="color:#7dd3fc">\${esc(D.contact)}</a>\` : ''}</div></div>\` : \`
  <div class="card">
    <h3>🔗 لینک اشتراک <span class="chip info">خودکار</span></h3>
    <div class="row nw"><input class="mono" value="\${D.sub_url}" readonly onclick="this.select()"><button class="btn i p" onclick="copy(D.sub_url,'لینک ساب کپی شد')">📋</button></div>
    <p class="xs muted" style="margin:6px 0 10px">این لینک را در برنامه‌ات وارد کن؛ کانفیگ‌ها و IPهای جدید خودکار می‌رسند.</p>
    <div class="apps">
      <a href="hiddify://import/\${D.sub_url}"><span>🟣</span>Hiddify<small>همه‌ی سیستم‌ها</small></a>
      <a href="v2rayng://install-sub?url=\${encodeURIComponent(D.sub_url)}&name=\${encodeURIComponent('JavidNam ' + D.name)}"><span>🟢</span>v2rayNG<small>اندروید</small></a>
      <a href="streisand://import/\${D.sub_url}"><span>🔵</span>Streisand<small>آیفون</small></a>
      <a href="sing-box://import-remote-profile?url=\${encodeURIComponent(D.formats.sb)}#JavidNam"><span>📦</span>sing-box<small>SFA / SFI</small></a>
      <a href="clash://install-config?url=\${encodeURIComponent(D.formats.clash)}&name=JavidNam"><span>🐱</span>Clash<small>Verge / Mihomo</small></a>
      <a href="shadowrocket://add/sub://\${btoa(D.sub_url)}?remark=JavidNam"><span>🚀</span>Shadowrocket<small>آیفون</small></a>
    </div>
    <div class="row" style="margin-top:10px;gap:6px"><span class="xs muted">فرمت‌های دیگر:</span><button class="btn s" onclick="copy(D.formats.b64)">Base64</button><button class="btn s" onclick="copy(D.formats.clash)">Clash YAML</button><button class="btn s" onclick="copy(D.formats.sb)">sing-box JSON</button></div>
  </div>
  <div class="card">
    <h3>📶 بهینه‌سازی اپراتور</h3>
    <select id="isp" onchange="changePreset(this.value)">\${D.presets.map(p => \`<option value="\${p.id}" \${preset === p.id ? 'selected' : ''}>\${esc(p.label)} — \${esc(p.note)}</option>\`).join('')}</select>
    <p class="xs muted" style="margin-top:6px">با انتخاب اپراتور، کانفیگ‌های زیر با fragment و fingerprint مخصوص همان شبکه ساخته می‌شوند. برای اضافه‌کردن ساب با همین تنظیم: <button class="btn s" onclick="copy(subWithPreset(),'لینک ساب اختصاصی اپراتور کپی شد')">📋 لینک ساب این اپراتور</button></p>
  </div>
  <div class="card" style="text-align:center">
    <h3 style="justify-content:center">📷 اسکن با گوشی</h3>
    <div class="qr" id="qrMain"></div>
    <div class="xs muted" style="margin-top:6px" id="qrLabel">لینک اشتراک</div>
  </div>
  <div class="card">
    <h3>⚙️ کانفیگ‌های تکی <span class="chip">\${fa(links.length)}</span></h3>
    <div id="cfgs">\${links.map((l, i) => \`<div class="cfg"><div class="t"><span class="chip \${l.proto === 'vless' ? 'info' : 'vio'}">\${l.proto.toUpperCase()}</span><b>\${esc(l.name)}</b><div class="grow"></div><button class="btn s" onclick="showQr(\${i})">QR</button><button class="btn s p" onclick="copy(links[\${i}].link)">کپی</button></div><div class="h mono">\${esc(l.host)}:\${l.port} · \${l.fp}\${l.frag ? ' · frag ' + l.frag.len : ''}</div></div>\`).join('')}</div>
    <div class="row" style="margin-top:10px"><button class="btn" style="width:100%" onclick="copy(links.map(l=>l.link).join('\\\\n'),'همه‌ی کانفیگ‌ها کپی شد')">📋 کپی همه‌ی کانفیگ‌ها</button></div>
  </div>\`}
  <div class="foot">\${D.show_branding ? \`<div class="m">🌷 \${esc(D.brand.memorial)} — \${esc(D.brand.eternal)}</div>\` : ''}<div>\${esc(D.brand.en)} v\${esc(D.version)}\${D.contact ? \` · <a href="\${esc(D.contact)}" style="color:#7dd3fc">پشتیبانی</a>\` : ''}</div></div>\`;
  if (view === 'configs') { qr($('#qrMain'), D.sub_url, 190); }
}
function subWithPreset() { return preset === 'auto' ? D.sub_url : D.sub_url + '?isp=' + preset; }
function showQr(i) { qr($('#qrMain'), links[i].link, 190); $('#qrLabel').textContent = links[i].proto.toUpperCase() + ' · ' + links[i].name; $('#qrMain').scrollIntoView({ behavior: 'smooth', block: 'center' }); }
async function changePreset(id) { preset = id; try { const j = await fetch(D.sub_url + '/links' + (id === 'auto' ? '' : '?isp=' + id)).then(r => r.json()); links = j.links; render(); toast('کانفیگ‌ها برای ' + (D.presets.find(p => p.id === id) || {}).label + ' ساخته شد'); } catch (e) { toast('خطا در دریافت'); } }
render();
</script>
</body>
</html>
`;
