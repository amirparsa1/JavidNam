#!/usr/bin/env node
/**
 * JavidNam panel builder — concatenates src parts + inlines HTML assets
 * and the MIT-licensed qrcode-generator library into a single deployable
 * Cloudflare Worker module.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)));
const src = (...p) => readFileSync(join(root, 'src', ...p), 'utf8');
const asset = (...p) => readFileSync(join(root, 'assets', ...p), 'utf8');

/* Escape a raw string so it can live inside a JS template literal */
function escTpl(s) {
  return s.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${');
}

const parts = [
  src('01-core.js'),
  src('02-proxy.js'),
  src('03-auth-api.js'),
  src('04-sub.js'),
  src('05-router.js'),
];

const adminHtml = asset('admin.html');
const subHtml = asset('sub.html');
const qrLib = readFileSync(join(root, '..', 'vendor', 'qrcode.min.js'), 'utf8');

/* inject QR lib into sub page (plain script — safe inside template literal) */
const subHtmlWithQr = subHtml.replace('__QRCODE_JS__', () => escTpl(qrLib));

const banner = `/* ============================================================
 * JavidNam Panel — BUILT ARTIFACT (do not edit; edit src/ + build)
 * جاویدنام — به یاد جان‌بافتگان ۱۸ و ۱۹ دی ۱۴۰۴
 * License: GPL-3.0 | QR: qrcode-generator 1.4.4 (MIT, Kazuhiko Arase)
 * Build time: ${new Date().toISOString()}
 * ============================================================ */

`;

const out = [
  banner,
  ...parts,
  '\n/* ---------- embedded assets ---------- */\n',
  `const ADMIN_PAGE_TEMPLATE = \`${escTpl(adminHtml)}\`;\n`,
  `const SUB_PAGE_TEMPLATE = \`${escTpl(subHtmlWithQr)}\`;\n`,
].join('\n');

const outPath = join(root, 'javidnam-worker.js');
writeFileSync(outPath, out);
console.log(`built ${outPath} — ${(out.length / 1024).toFixed(1)} KB`);
