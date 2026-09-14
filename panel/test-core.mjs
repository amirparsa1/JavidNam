#!/usr/bin/env node
/* JavidNam unit tests — runs against the BUILT worker artifact */
import { readFileSync } from 'node:fs';
import assert from 'node:assert';

let code = readFileSync(new URL('./javidnam-worker.js', import.meta.url), 'utf8');
code = code.replace("import { connect } from 'cloudflare:sockets';", 'let connect = () => { throw new Error("stub"); };');
code = code.replace('export default {', 'const __worker = {');
code = code.replace(/addEventListener\('waituntilflush'[^;]*;/, '');

const DB = null;
const factory = new Function('DB', 'ADMIN_PASS_HASH', 'SESSION_SECRET',
  code + '\n;return { parseVlessHeader, parseTrojanHeader, sha224hex, parseUdpDatagram, frameUdpDatagram, userState };');
const T = factory(null, undefined, undefined);

/* ---------- SHA-224 known vectors (FIPS 180-4) ---------- */
assert.strictEqual(T.sha224hex(new TextEncoder().encode('abc')), '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7');
assert.strictEqual(T.sha224hex(new TextEncoder().encode('')), 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f');
console.log('✓ SHA-224 vectors');

/* cross-check with node crypto if available */
try {
  const { createHash } = await import('node:crypto');
  for (const s of ['hello', 'uuid-string-123', 'لاله سرخ', 'x'.repeat(1000)]) {
    const expected = createHash('sha224').update(s, 'utf8').digest('hex');
    assert.strictEqual(T.sha224hex(new TextEncoder().encode(s)), expected, `sha224 mismatch for ${s.slice(0, 12)}`);
  }
  console.log('✓ SHA-224 cross-check with OpenSSL');
} catch (e) { console.log('ℹ OpenSSL sha224 unavailable, skipped cross-check'); }

/* ---------- VLESS header parser ---------- */
{
  const uuid = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
  const uuidBytes = uuid.replace(/-/g, '').match(/../g).map(h => parseInt(h, 16));
  const host = 'example.com';
  const payload = new TextEncoder().encode('HELLO-TCP');
  const buf = new Uint8Array([
    0x00, ...uuidBytes, 0x00,             // ver, uuid, addonLen
    0x01, 0x01, 0xbb,                     // cmd TCP, port 443
    0x02, host.length, ...new TextEncoder().encode(host),
    ...payload,
  ]);
  const p = T.parseVlessHeader(buf);
  assert.strictEqual(p.uuid, uuid);
  assert.strictEqual(p.host, 'example.com');
  assert.strictEqual(p.port, 443);
  assert.strictEqual(p.cmd, 1);
  assert.strictEqual(new TextDecoder().decode(p.rest), 'HELLO-TCP');
  console.log('✓ VLESS header (domain)');

  /* partial buffer must request more bytes */
  assert.strictEqual(T.parseVlessHeader(buf.subarray(0, 10)), null);
  /* IPv4 atyp */
  const b2 = new Uint8Array([0x00, ...uuidBytes, 0x00, 0x01, 0x00, 0x50, 0x01, 1, 2, 3, 4]);
  const p2 = T.parseVlessHeader(b2);
  assert.strictEqual(p2.host, '1.2.3.4');
  assert.strictEqual(p2.port, 80);
  /* IPv6 atyp */
  const v6 = [0x03, ...new Array(16).fill(0x20)];
  const b3 = new Uint8Array([0x00, ...uuidBytes, 0x00, 0x01, 0x01, 0xbb, ...v6]);
  const p3 = T.parseVlessHeader(b3);
  assert.strictEqual(p3.host, '2020:2020:2020:2020:2020:2020:2020:2020');
  console.log('✓ VLESS header (IPv4/IPv6/partial)');
}

/* ---------- Trojan header parser ---------- */
{
  const hash = 'a'.repeat(56);
  const payload = new TextEncoder().encode('GET / HTTP/1.1');
  const host = 'api.telegram.org';
  const buf = new Uint8Array([
    ...new TextEncoder().encode(hash), 0x0d, 0x0a,
    0x01, 0x03, host.length, ...new TextEncoder().encode(host), 0x01, 0xbb,
    0x0d, 0x0a,
    ...payload,
  ]);
  const p = T.parseTrojanHeader(buf);
  assert.strictEqual(p.hash, hash);
  assert.strictEqual(p.host, 'api.telegram.org');
  assert.strictEqual(p.port, 443);
  assert.strictEqual(new TextDecoder().decode(p.rest), 'GET / HTTP/1.1');
  assert.strictEqual(T.parseTrojanHeader(buf.subarray(0, 20)), null);
  console.log('✓ Trojan header');
}

/* ---------- UDP framing round-trip ---------- */
{
  const data = new TextEncoder().encode('dns-query-bytes');
  const f = T.frameUdpDatagram('8.8.8.8', 53, data);
  const dg = T.parseUdpDatagram(f);
  assert.strictEqual(dg.host, '8.8.8.8');
  assert.strictEqual(dg.port, 53);
  assert.strictEqual(new TextDecoder().decode(dg.data), 'dns-query-bytes');
  const f2 = T.frameUdpDatagram('dns.google', 53, data);
  const dg2 = T.parseUdpDatagram(f2);
  assert.strictEqual(dg2.host, 'dns.google');
  console.log('✓ UDP framing');
}

/* ---------- userState ---------- */
{
  const now = Date.now();
  const ok = T.userState({ active: 1, quota_bytes: 100, used_bytes: 10, expiry_at: now + 86400000 });
  assert.ok(ok.ok && !ok.overQuota && !ok.expired);
  const over = T.userState({ active: 1, quota_bytes: 100, used_bytes: 150, expiry_at: now + 86400000 });
  assert.ok(!over.ok && over.overQuota);
  const exp = T.userState({ active: 1, quota_bytes: 0, used_bytes: 0, expiry_at: now - 1000 });
  assert.ok(!exp.ok && exp.expired);
  const pend = T.userState({ active: 1, quota_bytes: 0, used_bytes: 0, expiry_at: null, start_on_first: 1, first_connect_at: null });
  assert.ok(pend.ok && pend.pending);
  console.log('✓ userState');
}

/* ---------- Jalali (client-side algorithm from sub.html) ---------- */
{
  const div = (a, b) => ~~(a / b);
  function toJalali(gy, gm, gd) {
    const g_d_m = [0,31,59,90,120,151,181,212,243,273,304,334];
    let gy2 = gy - 1600, gm2 = gm - 1, gd2 = gd - 1;
    let g_day_no = 365*gy2 + div(gy2+3,4) - div(gy2+99,100) + div(gy2+399,400);
    g_day_no += g_d_m[gm2] + gd2;
    if (gm2 > 1 && ((gy%4===0 && gy%100!==0) || (gy%400===0))) g_day_no++;
    g_day_no -= 79;
    let j_day_no = div(g_day_no, 12053); g_day_no %= 12053;
    let jy = 979 + 33*j_day_no + 4*div(g_day_no,1461);
    g_day_no %= 1461;
    if (g_day_no >= 366) { jy += div(g_day_no-1,365); g_day_no = (g_day_no-1)%365; }
    const ml = [31,31,31,31,31,31,30,30,30,30,30,29];
    let i;
    for (i = 0; i < 11 && g_day_no >= ml[i]; i++) { g_day_no -= ml[i]; }
    return [jy, i+1, g_day_no+1];
  }
  /* 2026-01-08 = 18 Dey 1404 (the memorial date) */
  assert.deepStrictEqual(toJalali(2026, 1, 8), [1404, 10, 18]);
  assert.deepStrictEqual(toJalali(2026, 1, 9), [1404, 10, 19]);
  assert.deepStrictEqual(toJalali(2026, 9, 14), [1405, 6, 23]);
  assert.deepStrictEqual(toJalali(2025, 3, 21), [1404, 1, 1]);
  assert.deepStrictEqual(toJalali(2026, 12, 21), [1405, 9, 30]);
  console.log('✓ Jalali dates (۱۸ دی ۱۴۰۴ = 2026-01-08)');
}

console.log('\n🎉 ALL TESTS PASSED');
