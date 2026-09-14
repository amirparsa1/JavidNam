#!/usr/bin/env node
/**
 * JavidNam panel builder — concatenates src parts + inlines HTML/JS assets
 * and the MIT-licensed qrcode-generator library into a single Worker module.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)));
const src = (...p) => readFileSync(join(root, 'src', ...p), 'utf8');
const asset = (...p) => readFileSync(join(root, 'assets', ...p), 'utf8');
function escTpl(s) { return s.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${'); }

const parts = ['01-core.js', '02-proxy.js', '03-auth-api.js', '04-sub.js', '05-router.js'].map(f => src(f));
const qrLib = readFileSync(join(root, '..', 'vendor', 'qrcode.min.js'), 'utf8');
const adminHtml = asset('admin.html').replace('__QRCODE_JS__', () => qrLib).replace('__ADMIN_JS__', () => asset('admin.js'));
const subHtml = asset('sub.html').replace('__QRCODE_JS__', () => qrLib);

const banner = `/* ============================================================
 * JavidNam Panel — BUILT ARTIFACT (edit src/ + assets/, then run build.mjs)
 * جاویدنام — به یاد جان‌باختگان ۱۸ و ۱۹ دی ۱۴۰۴
 * License: GPL-3.0 | QR: qrcode-generator 1.4.4 (MIT, Kazuhiko Arase)
 * Build time: ${new Date().toISOString()}
 * ============================================================ */
`;
const out = [banner, ...parts, '\n/* ---------- embedded assets ---------- */\n',
  `const ADMIN_PAGE_TEMPLATE = \`${escTpl(adminHtml)}\`;\n`,
  `const SUB_PAGE_TEMPLATE = \`${escTpl(subHtml)}\`;\n`].join('\n');
const outPath = join(root, 'javidnam-worker.js');
writeFileSync(outPath, out);
console.log(`built ${outPath} — ${(out.length / 1024).toFixed(1)} KB`);
