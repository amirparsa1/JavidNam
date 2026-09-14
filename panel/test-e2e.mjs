#!/usr/bin/env node
/**
 * JavidNam end-to-end proxy test — speaks REAL VLESS and Trojan over
 * WebSocket/TLS to the deployed worker, like v2rayNG/Hiddify would.
 */
import https from 'node:https';
import crypto from 'node:crypto';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const HOST = process.env.PANEL_HOST || 'javidnam-panel.ir-srroot.workers.dev';
const PROXY_PATH = process.env.PROXY_PATH;
const UUID = process.env.TEST_UUID;
if (!PROXY_PATH || !UUID) { console.error('need PROXY_PATH and TEST_UUID env'); process.exit(1); }

/* ---- sha224 (same original implementation as the worker) ---- */
const SHA224_K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function sha224hex(bytes) {
  const H = [0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4];
  const ml = bytes.length;
  const wp = new Uint8Array((((ml + 9) >> 6) + 1) << 6);
  wp.set(bytes); wp[ml] = 0x80;
  const dv = new DataView(wp.buffer);
  dv.setUint32(wp.length - 4, ml << 3);
  dv.setUint32(wp.length - 8, Math.floor((ml * 8) / 0x100000000));
  const w = new Int32Array(64);
  const rr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < wp.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getInt32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rr(w[i-15],7) ^ rr(w[i-15],18) ^ (w[i-15] >>> 3);
      const s1 = rr(w[i-2],17) ^ rr(w[i-2],19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }
    let [a,b,c,d,e,f,g,h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rr(e,6)^rr(e,11)^rr(e,25), ch = (e&f)^(~e&g);
      const t1 = (h + S1 + ch + SHA224_K[i] + w[i])|0;
      const S0 = rr(a,2)^rr(a,13)^rr(a,22), mj = (a&b)^(a&c)^(b&c);
      const t2 = (S0+mj)|0;
      h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
    }
    H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0;
  }
  return H.slice(0,7).map(x=>(x>>>0).toString(16).padStart(8,'0')).join('');
}

/* ---- minimal RFC6455 WebSocket client ---- */
function wsConnect(path, opts = {}) {
  return new Promise((resolve, reject) => {
    const key = crypto.randomBytes(16).toString('base64');
    const headers = {
      Host: HOST, Connection: 'Upgrade', Upgrade: 'websocket',
      'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': key,
      'User-Agent': 'javidnam-e2e/1.0',
    };
    if (opts.earlyData) headers['Sec-WebSocket-Protocol'] = Buffer.from(opts.earlyData).toString('base64url');
    const req = https.request({
      host: opts.ip || HOST, servername: HOST, path, port: 443, method: 'GET', ALPNProtocols: ['http/1.1'],
      headers,
    });
    req.on('upgrade', (res, socket) => resolve(socket));
    req.on('error', reject);
    req.setTimeout(15000, () => { reject(new Error('ws timeout')); req.destroy(); });
    req.end();
  });
}
function wsSend(socket, payload) {
  const mask = crypto.randomBytes(4);
  const len = payload.length;
  let header;
  if (len < 126) header = Buffer.from([0x82, 0x80 | len]);
  else if (len < 65536) { header = Buffer.alloc(4); header[0] = 0x82; header[1] = 0x80 | 126; header.writeUInt16BE(len, 2); }
  else { header = Buffer.alloc(10); header[0] = 0x82; header[1] = 0x80 | 127; header.writeBigUInt64BE(BigInt(len), 2); }
  const masked = Buffer.from(payload);
  for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i % 4];
  socket.write(Buffer.concat([header, mask, masked]));
}
function wsParse(buf) {
  const frames = [];
  let i = 0;
  while (i + 2 <= buf.length) {
    const b0 = buf[i], b1 = buf[i + 1];
    const opcode = b0 & 0x0f;
    let len = b1 & 0x7f, off = i + 2;
    if (len === 126) { if (buf.length < off + 2) break; len = buf.readUInt16BE(off); off += 2; }
    else if (len === 127) { if (buf.length < off + 8) break; len = Number(buf.readBigUInt64BE(off)); off += 8; }
    if (buf.length < off + len) break;
    frames.push({ opcode, data: buf.subarray(off, off + len) });
    i = off + len;
  }
  return { frames, rest: buf.subarray(i) };
}
function collect(socket, ms = 12000) {
  return new Promise((resolve) => {
    const chunks = [];
    let buf = Buffer.alloc(0);
    const done = () => { try { socket.destroy(); } catch (e) {} resolve(Buffer.concat(chunks)); };
    const t = setTimeout(done, ms);
    socket.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      const { frames, rest } = wsParse(buf);
      buf = Buffer.from(rest); /* consume parsed frames to avoid duplicates */
      for (const f of frames) if (f.opcode === 2 || f.opcode === 1) chunks.push(f.data);
      if (chunks.length >= 2) { clearTimeout(t); done(); }
    });
    socket.on('close', () => { clearTimeout(t); done(); });
    socket.on('error', () => { clearTimeout(t); done(); });
  });
}

const uuidBytes = Buffer.from(UUID.replace(/-/g, ''), 'hex');
const targetHost = process.env.TARGET_HOST || 'www.gstatic.com';
const httpReq = Buffer.from(`GET /generate_204 HTTP/1.1\r\nHost: ${targetHost}\r\nUser-Agent: javidnam-e2e\r\nConnection: close\r\n\r\n`);

/* ---- TEST 1: VLESS ---- */
{
  console.log('— VLESS over WS/TLS →', targetHost + ':80');
  const socket = await wsConnect(PROXY_PATH);
  const vless = Buffer.concat([
    Buffer.from([0x00]), uuidBytes, Buffer.from([0x00, 0x01]), // ver, uuid, addon, cmd=TCP
    Buffer.from([0x00, 0x50]),                                  // port 80
    Buffer.from([0x02, targetHost.length]), Buffer.from(targetHost),
    httpReq,
  ]);
  wsSend(socket, vless);
  const resp = await collect(socket);
  const txt = resp.toString('latin1');
  assert.strictEqual(resp[0], 0x00, 'vless reply version byte');
  assert.strictEqual(resp[1], 0x00, 'vless reply addon len');
  assert.ok(/HTTP\/1\.[01] \d{3}/.test(txt.slice(2, 600)), 'got example.com response');
  console.log('  ✓ VLESS proxy works! (received', resp.length, 'bytes via Cloudflare → example.com)');
}

/* ---- TEST 1b: VLESS exactly like xray does with ?ed=2048 (early data in Sec-WebSocket-Protocol) via a clean IP ---- */
{
  const ip = process.env.CLEAN_IP || '162.159.129.1';
  console.log('— VLESS early-data mode (xray ?ed=2048) via clean IP', ip, '→', targetHost + ':80');
  const vless = Buffer.concat([
    Buffer.from([0x00]), uuidBytes, Buffer.from([0x00, 0x01]),
    Buffer.from([0x00, 0x50]),
    Buffer.from([0x02, targetHost.length]), Buffer.from(targetHost),
    httpReq,
  ]);
  const socket = await wsConnect(PROXY_PATH + '?loc=main', { earlyData: vless, ip });
  const resp = await collect(socket);
  const txt = resp.toString('latin1');
  assert.strictEqual(resp[0], 0x00, 'vless reply version byte (early-data)');
  assert.ok(/HTTP\/1\.[01] \d{3}/.test(txt.slice(2, 600)), 'got response via early-data');
  console.log('  ✓ early-data VLESS works via clean IP! (received', resp.length, 'bytes)');
}

/* ---- TEST 2: Trojan ---- */
{
  console.log('— Trojan over WS/TLS →', targetHost + ':80');
  const socket = await wsConnect(PROXY_PATH);
  const hash = sha224hex(Buffer.from(UUID, 'utf8'));
  assert.strictEqual(hash.length, 56, 'sha224 hex is 56 chars');
  const trojan = Buffer.concat([
    Buffer.from(hash, 'ascii'), Buffer.from('\r\n'),
    Buffer.from([0x01]),                              // CONNECT
    Buffer.from([0x03, targetHost.length]), Buffer.from(targetHost),
    Buffer.from([0x00, 0x50]), Buffer.from('\r\n'),
    httpReq,
  ]);
  wsSend(socket, trojan);
  const resp = await collect(socket);
  const txt = resp.toString('latin1');
  assert.ok(/HTTP\/1\.[01] \d{3}/.test(txt.slice(0, 600)), 'got example.com response');
  console.log('  ✓ Trojan proxy works! (received', resp.length, 'bytes)');
}

/* ---- TEST 3: bad UUID must be rejected ---- */
{
  console.log('— VLESS with WRONG uuid (must fail)');
  const socket = await wsConnect(PROXY_PATH);
  const badUuid = Buffer.from('00000000-0000-0000-0000-000000000000'.replace(/-/g, ''), 'hex');
  const vless = Buffer.concat([
    Buffer.from([0x00]), badUuid, Buffer.from([0x00, 0x01]),
    Buffer.from([0x00, 0x50]), Buffer.from([0x02, targetHost.length]), Buffer.from(targetHost),
    httpReq,
  ]);
  wsSend(socket, vless);
  const resp = await collect(socket, 8000);
  assert.strictEqual(resp.length, 0, 'no data for invalid user');
  console.log('  ✓ Invalid UUID correctly rejected');
}

console.log('\n🎉 E2E PROXY TESTS PASSED — panel is fully operational');
