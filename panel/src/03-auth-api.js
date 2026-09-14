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
