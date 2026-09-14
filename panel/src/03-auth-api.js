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
