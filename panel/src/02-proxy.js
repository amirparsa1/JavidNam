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
