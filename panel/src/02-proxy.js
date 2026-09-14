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
      /* probe: first read within grace window — EOF w/o data means blocked path (e.g. CF-range).
         IMPORTANT: the read() promise must NOT be abandoned on timeout — its eventual value would be lost.
         We keep it and hand it to the pump as `pending`. */
      const pendingRead = reader.read();
      let probe;
      try { probe = await withTimeout(pendingRead, firstPayload && firstPayload.length ? 1500 : 250, 'grace'); }
      catch (e) { probe = { grace: true }; }
      if (probe && probe.done && !probe.grace) throw new Error('closed-early');
      markOut(spec, true);
      return { sock, writer, reader, first: probe && probe.value ? probe.value : null, pending: probe && probe.grace ? pendingRead : null, via: spec };
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
          let pending = conn.pending;
          try {
            while (true) {
              const { done, value } = await (pending || reader.read());
              pending = null;
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

    /* Early data (xray/v2ray `?ed=` mode): first payload arrives base64url in Sec-WebSocket-Protocol */
    const ed = request.headers.get('Sec-WebSocket-Protocol');
    if (ed) {
      try {
        const b = atob(ed.replace(/-/g, '+').replace(/_/g, '/'));
        const u8 = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u8[i] = b.charCodeAt(i);
        if (u8.length) chain = chain.then(() => process(u8)).catch(() => closeAll());
      } catch (e) {}
    }

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
