#!/usr/bin/env node
/**
 * Generates static preview demos of the JavidNam UIs (sub page + admin page)
 * from the REAL assets, with realistic sample data — so you can see the
 * design without deploying anything.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const subHtml = readFileSync(join(root, 'panel/assets/sub.html'), 'utf8');
const adminHtml = readFileSync(join(root, 'panel/assets/admin.html'), 'utf8');
const qrLib = readFileSync(join(root, 'vendor/qrcode.min.js'), 'utf8');

mkdirSync(join(root, 'preview'), { recursive: true });

/* ---------- sub demo ---------- */
const demoSub = {
  brand: { fa: 'جاویدنام', en: 'JavidNam' },
  version: '1.0.0',
  name: 'سارا',
  welcome: 'سلام! این اشتراک اختصاصی توئه. لذت ببر 🌷',
  state: {
    ok: true, overQuota: false, expired: false, pending: false,
    expiryAt: new Date('2026-11-20T12:00:00Z').getTime(),
    quota: 100 * 1073741824,
    used: 37.2 * 1073741824,
    remainingBytes: 62.8 * 1073741824,
  },
  sub_url: 'https://demo.javidnam.workers.dev/sub/ab12cd34ef56',
  links: [
    { name: 'اصلی', proto: 'vless', link: 'vless://6ba7b810-9dad-11d1-80b4-00c04fd430c8@demo.javidnam.workers.dev:443?encryption=none&security=tls&type=ws&host=demo.javidnam.workers.dev&path=%2Fjvn-demo%3Fed%3D2048&sni=demo.javidnam.workers.dev&fp=chrome#JavidNam%20%7C%20%D8%A7%D8%B5%D9%84%DB%8C' },
    { name: 'اصلی', proto: 'trojan', link: 'trojan://6ba7b810-9dad-11d1-80b4-00c04fd430c8@demo.javidnam.workers.dev:443?security=tls&type=ws&host=demo.javidnam.workers.dev&path=%2Fjvn-demo%3Fed%3D2048&sni=demo.javidnam.workers.dev#JavidNam%20TRJ%20%7C%20%D8%A7%D8%B5%D9%84%DB%8C' },
    { name: 'آلمان', proto: 'vless', link: 'vless://6ba7b810-9dad-11d1-80b4-00c04fd430c8@cdn-clean-example.com:443?encryption=none&security=tls&type=ws&host=demo.javidnam.workers.dev&path=%2Fjvn-demo%3Fed%3D2048&sni=cdn-clean-example.com&fp=chrome#JavidNam%20%7C%20%D8%A2%D9%84%D9%85%D8%A7%D9%86' },
    { name: 'آلمان', proto: 'trojan', link: 'trojan://6ba7b810-9dad-11d1-80b4-00c04fd430c8@cdn-clean-example.com:443?security=tls&type=ws&host=demo.javidnam.workers.dev&path=%2Fjvn-demo%3Fed%3D2048&sni=cdn-clean-example.com#JavidNam%20TRJ%20%7C%20%D8%A2%D9%84%D9%85%D8%A7%D9%86' },
  ],
  presets: [
    { id: 'all', label: 'همه', fp: 'chrome', frag: null, note: 'حالت پیش‌فرض و پیشنهادی برای شروع' },
    { id: 'mci', label: 'همراه اول', fp: 'chrome', frag: [10, 20, 10, 20], note: 'fragment فعال؛ برای قطعی‌های شدید MCI' },
    { id: 'irancell', label: 'ایرانسل', fp: 'safari', frag: [40, 50, 10, 20], note: 'fragment با بازه بلندتر؛ مناسب اینترنت‌های ضعیف' },
    { id: 'gaming', label: 'گیمینگ', fp: 'chrome', frag: null, note: 'کم‌ترین تأخیر؛ fragment خاموش' },
  ],
  contact: '@javidnam',
  proxy_path: '/jvn-demo',
  show_branding: true,
};

const subOut = subHtml
  .replace('__QRCODE_JS__', () => qrLib)
  .replace('__SUB_DATA_JSON__', () => JSON.stringify(demoSub).replace(/</g, '\\u003c'))
  .replace('__TITLE__', 'جاویدنام | اشتراک سارا');
writeFileSync(join(root, 'preview/sub-demo.html'), subOut);
console.log('✓ preview/sub-demo.html');

/* ---------- admin demo: strip the boot logic so login shows ---------- */
const adminOut = adminHtml
  .replace("link rel=\"icon\" href=\"/favicon.svg\"", () => {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f43f5e"/><stop offset="1" stop-color="#881337"/></linearGradient></defs><rect width="64" height="64" rx="14" fill="#0a0a10"/><path d="M32 10c-1.8 5-6 7.2-6 12.6 0 3.4 1.9 6.3 4.2 8.4C29.6 39 27.4 44.6 22 50c7-1.6 11.2-5 13.4-9.6 2.2 4.6 6.4 8 13.4 9.6-5.4-5.4-7.6-11-8.2-19 2.3-2.1 4.2-5 4.2-8.4C44.8 17.2 40.6 15 38.8 10c-1.6 3.4-4.2 5-6.8 5s-5.2-1.6-6.8-5z" fill="url(#g)"/></svg>`;
    return `<link rel="icon" href="data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}"`;
  })
  .replace("src=\"/favicon.svg\"", 'src="data:image/svg+xml;base64,__ICON__"')
  .replace(/__ICON__/g, () => {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f43f5e"/><stop offset="1" stop-color="#881337"/></linearGradient></defs><rect width="64" height="64" rx="14" fill="#0a0a10"/><path d="M32 10c-1.8 5-6 7.2-6 12.6 0 3.4 1.9 6.3 4.2 8.4C29.6 39 27.4 44.6 22 50c7-1.6 11.2-5 13.4-9.6 2.2 4.6 6.4 8 13.4 9.6-5.4-5.4-7.6-11-8.2-19 2.3-2.1 4.2-5 4.2-8.4C44.8 17.2 40.6 15 38.8 10c-1.6 3.4-4.2 5-6.8 5s-5.2-1.6-6.8-5z" fill="url(#g)"/></svg>`;
    return Buffer.from(svg).toString('base64');
  })
  /* neutralize network boot so the demo shows the login screen */
  .replace('(async()=>{\n  try{\n    await api(\'/api/me\');', '(async()=>{\n  if(location.protocol==="file:"||true){return}\n  try{\n    await api(\'/api/me\');');
writeFileSync(join(root, 'preview/admin-demo.html'), adminOut);
console.log('✓ preview/admin-demo.html');
