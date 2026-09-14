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

const VERSION = '2.1.0';
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
const CLEAN_IPS_DEFAULT = ['www.speedtest.net', 'zula.ir', 'www.visa.com.sg', 'cf.090227.xyz', '104.16.1.1', '104.17.1.1', '172.67.1.1', '162.159.129.1'];

const SETTING_DEFAULTS = {
  proxy_path: '/jvn-setup',            // seeded random on first read
  title: 'جاویدنام | JavidNam',
  welcome: 'سلام! این اشتراک اختصاصی توئه. لذت ببر 🌷',
  contact: '',
  sub_branding: true,
  /* network */
  fp: 'chrome',
  alpn: 'http/1.1',                   // ws needs http/1.1 (no RFC8441 in clients)
  frag_enabled: true,
  frag_len: '10-20',
  frag_int: '10-20',
  frag_packets: 'tlshello',
  sni_mask: '',                        // custom SNI (TLS masking); empty = location host
  host_mask: '',                       // custom WS Host header; empty = panel host
  /* outbound */
  proxy_ip: 'proxyip.cmliussss.net',    // global fallback proxyIP for CF-fronted targets (Workers can't dial CF IPs directly)
  proxy_ips: ['proxyip:bpb.yousef.isegaro.com', 'proxyip:cdn.xn--b6gac.eu.org', 'proxyip:cdn-all.xn--b6gac.eu.org', 'proxyip:nima.nscl.ir'], // VIP proxy pool (proxyip:.. or socks5://..) — round-robin + failover
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
