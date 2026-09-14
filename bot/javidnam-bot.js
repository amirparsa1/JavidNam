/**
 * ============================================================================
 *  JavidNam Deployer Bot — ربات دیپلوی پنل جاویدنام
 *  Telegram bot (webhook worker) that auto-deploys JavidNam panels onto
 *  users' own Cloudflare accounts (D1 + Workers) and manages them.
 *
 *  Copyright (C) 2026 amirparsa1 (JavidNam) — GPL-3.0
 * ============================================================================
 */

/* ---------------- config ---------------- */
const BOT_VERSION = '1.1.0';
const DEFAULT_SOURCE = 'https://raw.githubusercontent.com/amirparsa1/JavidNam/main/panel/javidnam-worker.js';
const CF_API = 'https://api.cloudflare.com/client/v4';
const MAX_PANELS_PER_USER = 10;
const DEPLOY_COOLDOWN_SEC = 60;
const SESSION_TTL = 900;

/* ---------------- tiny utils ---------------- */
const TE = new TextEncoder();
const TD = new TextDecoder();
function hex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''); }
function rndHex(n) { const b = new Uint8Array(n); crypto.getRandomValues(b); return hex(b); }
function rndPass() {
  const c = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const b = new Uint8Array(16); crypto.getRandomValues(b);
  return [...b].map(x => c[x % c.length]).join('');
}
async function sha256hex(s) { return hex(await crypto.subtle.digest('SHA-256', TE.encode(s))); }
const esc = s => String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

/* ---------------- AES-GCM storage encryption ---------------- */
async function storageKey() {
  const raw = TE.encode(env.BOT_KEY);
  return crypto.subtle.importKey('raw', await crypto.subtle.digest('SHA-256', raw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function enc(text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await storageKey(), TE.encode(text)));
  const out = new Uint8Array(iv.length + ct.length); out.set(iv); out.set(ct, iv.length);
  return btoa(String.fromCharCode(...out));
}
async function dec(b64) {
  const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const iv = bin.subarray(0, 12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, await storageKey(), bin.subarray(12));
  return TD.decode(pt);
}

/* ---------------- env accessor ---------------- */
const env = {};
function initEnv(e) { Object.assign(env, e); }

/* ---------------- Telegram API ---------------- */
async function tg(method, params = {}) {
  const r = await fetch(`https://api.telegram.org/bot${env.TG_TOKEN}/${method}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(params),
  });
  return r.json();
}
async function sendMsg(chatId, text, kb) {
  return tg('sendMessage', {
    chat_id: chatId, text, parse_mode: 'HTML', link_preview_options: { is_disabled: true },
    ...(kb ? { reply_markup: { inline_keyboard: kb } } : {}),
  });
}
async function editMsg(chatId, msgId, text, kb) {
  return tg('editMessageText', {
    chat_id: chatId, message_id: msgId, text, parse_mode: 'HTML',
    link_preview_options: { is_disabled: true },
    ...(kb ? { reply_markup: { inline_keyboard: kb } } : {}),
  });
}
async function answerCb(id, text) { return tg('answerCallbackQuery', { callback_query_id: id, ...(text ? { text, show_alert: false } : {}) }); }

/* ---------------- KV state helpers ---------------- */
async function kvGet(k) { const v = await env.BOT_KV.get(k); return v ? JSON.parse(v) : null; }
async function kvPut(k, v, ttl) { await env.BOT_KV.put(k, JSON.stringify(v), ttl ? { expirationTtl: ttl } : {}); }
async function kvDel(k) { await env.BOT_KV.delete(k); }

async function getStep(chatId) { return kvGet('sess:' + chatId); }
async function setStep(chatId, step, data = {}) { await kvPut('sess:' + chatId, { step, data }, SESSION_TTL); }
async function clearStep(chatId) { await kvDel('sess:' + chatId); }

/* ---------------- Cloudflare API wrapper ---------------- */
async function cf(token, path, opts = {}) {
  const r = await fetch(CF_API + path, {
    ...opts,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...(opts.headers || {}) },
  });
  const j = await r.json().catch(() => ({ success: false, errors: [{ message: 'bad-json' }] }));
  if (!j.success) {
    const msg = (j.errors && j.errors[0] && j.errors[0].message) || 'Cloudflare API error';
    throw new Error(msg);
  }
  return j.result;
}

async function verifyCfToken(token) {
  const v = await cf(token, '/user/tokens/verify');
  if (v.status !== 'active') throw new Error('توکن غیرفعال است');
  const accounts = await cf(token, '/accounts');
  if (!accounts.length) throw new Error('هیچ اکانتی روی این توکن دیده نمی‌شود');
  return accounts;
}

/* probe required permissions without side effects */
async function probePerms(token, accId) {
  const missing = [];
  try { await cf(token, `/accounts/${accId}/workers/scripts`); } catch (e) { missing.push('Workers Scripts:Edit'); }
  try { await cf(token, `/accounts/${accId}/d1/database`); } catch (e) { missing.push('D1:Edit'); }
  return missing;
}

async function getSubdomain(token, accId) {
  try {
    const r = await cf(token, `/accounts/${accId}/workers/subdomain`);
    if (r && r.subdomain) return r.subdomain;
  } catch (e) {}
  /* try to enable with a random name */
  const name = 'javidnam-' + rndHex(4).replace(/[^a-z0-9]/g, '').slice(0, 6);
  try {
    const r = await cf(token, `/accounts/${accId}/workers/subdomain`, { method: 'POST', body: JSON.stringify({ subdomain: name, enabled: true, previews_enabled: true }) });
    if (r && r.subdomain) return r.subdomain;
  } catch (e) {}
  throw new Error('نمی‌توان دامنه workers.dev اکانت را یافت/فعال کرد');
}

/* ---------------- panel deployment ---------------- */
async function deployPanel(token, accId, scriptName, adminPass, sessionSecret, dbId) {
  const salt = rndHex(8);
  const hash = await sha256hex(salt + ':' + adminPass);
  const adminHash = `${salt}$${hash}`;

  let src;
  const srcUrl = env.PANEL_SOURCE_URL || DEFAULT_SOURCE;
  const r = await fetch(srcUrl, { cache: 'no-store' });
  if (!r.ok) throw new Error(`دریافت سورس پنل ناموفق (${r.status})`);
  src = await r.text();

  const metadata = {
    main_module: 'worker.js',
    compatibility_date: '2025-09-01',
    bindings: [
      { type: 'd1', name: 'DB', id: dbId },
      { type: 'secret_text', name: 'ADMIN_PASS_HASH', text: adminHash },
      { type: 'secret_text', name: 'SESSION_SECRET', text: sessionSecret },
    ],
  };

  const fd = new FormData();
  fd.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }), 'metadata.json');
  fd.append('worker.js', new Blob([src], { type: 'application/javascript+module' }), 'worker.js');

  const up = await fetch(`${CF_API}/accounts/${accId}/workers/scripts/${scriptName}`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${token}` },
    body: fd,
  });
  const j = await up.json().catch(() => ({ success: false, errors: [{ message: 'upload failed' }] }));
  if (!j.success) throw new Error((j.errors && j.errors[0] && j.errors[0].message) || 'آپلود پنل ناموفق بود');
  return true;
}

async function enableWorkersDev(token, accId, scriptName) {
  try {
    await cf(token, `/accounts/${accId}/workers/scripts/${scriptName}/subdomain`, { method: 'POST', body: JSON.stringify({ enabled: true, previews_enabled: false }) });
  } catch (e) { /* often already enabled */ }
}

/* ---------------- flow: main menu ---------------- */
function mainMenu() {
  return [
    [{ text: '🚀 ساخت پنل جدید', callback_data: 'a:build' }],
    [{ text: '📦 پنل‌های من', callback_data: 'a:panels' }, { text: '👤 حساب‌های Cloudflare', callback_data: 'a:accounts' }],
    [{ text: '📖 راهنما', callback_data: 'a:help' }],
  ];
}

const WELCOME = `🕯 <b>به جاویدنام خوش آمدی</b>

<i>JavidNam</i> — دیپلوی خودکار و رایگان پنل اختصاصی VLESS/Trojan روی زیرساخت <b>Cloudflare Workers</b>.

به یاد جان‌باختگان ۱۸ و ۱۹ دی ۱۴۰۴؛ نامشان جاوید. 🌷

<i>بدون سرور، بدون هزینه، بدون تبلیغ — فقط با یک توکن کلودفلر.</i>

از دکمه‌های زیر انتخاب کن: 👇`;

/* ---------------- flow: register account ---------------- */
/* Cloudflare's official "API token template URL": opens the Create-Token form
   with permissions, account/zone scope and the token name already filled in.
   User just clicks "Continue to summary" → "Create Token". */
const TOKEN_PERMS = [
  { key: 'workers_scripts', type: 'edit' },
  { key: 'd1', type: 'edit' },
  { key: 'account_settings', type: 'read' },
];
const TOKEN_TEMPLATE_URL = 'https://dash.cloudflare.com/profile/api-tokens'
  + '?permissionGroupKeys=' + encodeURIComponent(JSON.stringify(TOKEN_PERMS))
  + '&accountId=*&zoneId=all&name=' + encodeURIComponent('JavidNam Panel');
const CF_LOGIN_URL = 'https://dash.cloudflare.com/login';
const CF_SIGNUP_URL = 'https://dash.cloudflare.com/sign-up/workers-and-pages';

function accountGuide() {
  return [
    [{ text: '🌐 ورود به حساب کلودفلر', url: CF_LOGIN_URL }],
    [{ text: '🔑 دریافت توکن اختصاصی جاویدنام', url: TOKEN_TEMPLATE_URL }],
    [{ text: '🆕 حساب کلودفلر ندارم', url: CF_SIGNUP_URL }, { text: '🎬 راهنمای تصویری', callback_data: 'a:tokhelp' }],
    [{ text: '🔙 انصراف و بازگشت به منو', callback_data: 'a:home' }],
  ];
}
const TOKEN_HELP = `☁️ <b>اتصال حساب کلودفلر به جاویدنام</b>

⚠️ <b>توجه مهم:</b> برای اینکه خطا نگیری، مراحل زیر را <u>به ترتیب</u> انجام بده. اگر در مرورگر لاگین نیستی، حتماً از گام اول شروع کن.

🔹 <b>گام اول:</b>
روی دکمه‌ی <b>«ورود به حساب کلودفلر»</b> بزن و وارد حسابت شو.
<i>(بعد از ورود موفق، دوباره به همین‌جا در تلگرام برگرد)</i>

🔹 <b>گام دوم:</b>
حالا روی <b>«دریافت توکن اختصاصی جاویدنام»</b> بزن.
صفحه‌ای باز می‌شود که <b>همه‌ی دسترسی‌ها از قبل تنظیم شده‌اند</b> ✅ — هیچ چیزی را تغییر نده؛ فقط برو پایین صفحه، دکمه‌ی آبی <code>Continue to summary</code> و بعد <code>Create Token</code> را بزن.

🔹 <b>گام سوم:</b>
توکن تولیدشده را کپی کن و <b>دقیقاً در همین چت</b> بفرست.

🔐 <i>پیام توکن بلافاصله بعد از بررسی حذف و توکن به‌صورت رمزنگاری‌شده ذخیره می‌شود.</i>

👇 <i>منتظر توکن تو هستم… (برای لغو، دکمه‌ی بازگشت را بزن)</i>`;

const TOKEN_HELP_DETAILS = `🎬 <b>راهنمای گام‌به‌گام دریافت توکن</b>

۱) دکمه‌ی «ورود به حساب کلودفلر» → ایمیل و رمزت را بزن (اگر حساب نداری، از «حساب کلودفلر ندارم» رایگان بساز؛ فقط ایمیل لازم است).

۲) دکمه‌ی «دریافت توکن اختصاصی جاویدنام» → صفحه‌ی <b>Create Custom Token</b> باز می‌شود و این‌ها از قبل انتخاب شده‌اند:
<blockquote>🟢 Account · Workers Scripts · Edit
🟢 Account · D1 · Edit
🟢 Account · Account Settings · Read
📛 Token name: JavidNam Panel</blockquote>

۳) اسکرول کن پایین → <code>Continue to summary</code> → <code>Create Token</code>.

۴) توکن (یک رشته‌ی ۴۰ کاراکتری) را با دکمه‌ی <b>Copy</b> کپی کن و همین‌جا بفرست. ✅

❓ <b>اگر صفحه‌ی توکن خالی باز شد یا خطا داد:</b> یعنی در مرورگر لاگین نبودی؛ اول گام ۱ را انجام بده و دوباره دکمه‌ی گام ۲ را بزن.
❓ <b>اگر بات گفت «دسترسی کافی نیست»:</b> توکن را از همین دکمه بساز، نه به‌صورت دستی.`;

/* ---------------- flow: help ---------------- */
const HELP_TEXT = `📖 <b>راهنمای جاویدنام</b>

<b>۱. ثبت حساب</b> — منوی «حساب‌های Cloudflare» → توکن بساز و بفرست. (رایگان و امن؛ توکن رمزنگاری می‌شود و پیامش حذف می‌شود)

<b>۲. ساخت پنل</b> — «ساخت پنل جدید» → حسابت را انتخاب کن. بات به‌صورت خودکار:
• دیتابیس D1 می‌سازد
• پنل JavidNam را روی Workers آپلود می‌کند
• دامنه اختصاصی می‌سازد و رمز مدیریت تولید می‌کند

<b>۳. مدیریت</b> — با لینک و رمزی که گرفتی وارد پنل شو؛ کاربر بساز، حجم/انقضا تعیین کن و لینک ساب اختصاصی بده.

<b>۴. کانفیگ‌ها</b> — کاربرانت لینک ساب را در v2rayNG/Hiddify/Streisand وارد می‌کنند؛ کانفیگ VLESS و Trojan با لوکیشن‌های دلخواه و بهینه‌سازی اپراتور (fragment) تحویل می‌گیرند.

<b>۵. آپدیت</b> — «پنل‌های من» → 🔄؛ آخرین نسخه‌ی پنل از گیت‌هاب روی پنلت نصب می‌شود؛ کاربران و تنظیمات دست‌نخورده می‌مانند.

🌷 <i>جاویدنام — به یاد جان‌باختگان ۱۸ و ۱۹ دی ۱۴۰۴؛ نامشان جاوید.</i>`;

/* ---------------- router ---------------- */
export default {
  async fetch(request, e, ctx) {
    initEnv(e);
    const url = new URL(request.url);

    if (request.method === 'GET') {
      if (url.pathname === '/healthz') return Response.json({ ok: true, app: 'javidnam-bot', version: BOT_VERSION });
      return new Response('404', { status: 404 });
    }
    if (request.method !== 'POST') return new Response('405', { status: 405 });

    /* webhook path + secret verification */
    if (url.pathname !== '/' + (env.PATH_TOKEN || 'tg')) return new Response('404', { status: 404 });
    if (request.headers.get('X-Telegram-Bot-Api-Secret-Token') !== env.BOT_KEY) return new Response('403', { status: 403 });

    const update = await request.json().catch(() => null);
    if (!update) return Response.json({ ok: true });
    ctx.waitUntil(handleUpdate(update).catch(async (err) => {
      try {
        const chatId = update.message?.chat?.id || update.callback_query?.message?.chat?.id;
        if (chatId) await sendMsg(chatId, '⚠️ خطای غیرمنتظره: ' + esc(String(err.message || err)));
      } catch (e) {}
    }));
    return Response.json({ ok: true });
  },
};

/* ---------------- update dispatcher ---------------- */
async function handleUpdate(upd) {
  if (upd.callback_query) return handleCallback(upd.callback_query);
  if (upd.message) return handleMessage(upd.message);
}

async function handleMessage(msg) {
  const chatId = msg.chat.id;
  const text = (msg.text || '').trim();

  if (text.startsWith('/start')) {
    await clearStep(chatId);
    return sendMsg(chatId, WELCOME, mainMenu());
  }
  if (text.startsWith('/help')) return sendMsg(chatId, HELP_TEXT, mainMenu());

  /* owner claim */
  if (text.startsWith('/login')) {
    const code = text.split(/\s+/)[1] || '';
    if (code && code === env.OWNER_CODE) {
      const owner = await kvGet('owner');
      if (owner && owner.chatId !== chatId) return sendMsg(chatId, '🔒 یک مالک دیگر از قبل ثبت شده است.');
      await kvPut('owner', { chatId });
      return sendMsg(chatId, '👑 تو مالک این بات شدی.\nدستورات مدیریتی: /admin', mainMenu());
    }
    return sendMsg(chatId, 'کد مالکیت نامعتبر است.');
  }
  if (text.startsWith('/admin')) {
    const owner = await kvGet('owner');
    if (!owner || owner.chatId !== chatId) return sendMsg(chatId, '⛔ این دستور فقط برای مالک بات است.');
    const list = await env.BOT_KV.list({ prefix: 'panel:' });
    const accList = await env.BOT_KV.list({ prefix: 'acc:' });
    return sendMsg(chatId,
      `👑 <b>آمار بات جاویدنام</b>\n\n📦 پنل‌های فعال: <b>${list.keys.length}</b>\n👤 حساب‌های ثبت‌شده: <b>${accList.keys.length}</b>\n🤖 نسخه: <code>${BOT_VERSION}</code>`, mainMenu());
  }

  const step = await getStep(chatId);
  if (step && step.step === 'await_token') return processTokenMessage(chatId, text, msg.message_id);
  return sendMsg(chatId, 'از منوی زیر استفاده کن 👇', mainMenu());
}

/* ---------------- callback router ---------------- */
async function handleCallback(cb) {
  const chatId = cb.message.chat.id;
  const data = cb.data || '';
  await answerCb(cb.id);

  if (data === 'a:home') { await clearStep(chatId); return sendMsg(chatId, WELCOME, mainMenu()); }
  if (data === 'a:help') return sendMsg(chatId, HELP_TEXT, mainMenu());

  if (data === 'a:accounts') return showAccounts(chatId);
  if (data === 'a:accadd') {
    await setStep(chatId, 'await_token');
    return sendMsg(chatId, TOKEN_HELP, accountGuide());
  }
  if (data === 'a:tokhelp') {
    await setStep(chatId, 'await_token');
    return sendMsg(chatId, TOKEN_HELP_DETAILS, accountGuide());
  }
  if (data.startsWith('a:accdel:')) return deleteAccount(chatId, data.split(':')[2]);

  if (data === 'a:build') return startBuild(chatId);
  if (data.startsWith('a:buildacc:')) return buildPanel(chatId, data.split(':')[2], cb.message.message_id);
  if (data === 'a:panels') return showPanels(chatId);
  if (data.startsWith('a:panel:')) return panelMenu(chatId, data.split(':')[2]);
  if (data.startsWith('a:pupd:')) return updatePanel(chatId, data.split(':')[2]);
  if (data.startsWith('a:pstat:')) return panelStatus(chatId, data.split(':')[2]);
  if (data.startsWith('a:ppass:')) return resetPanelPass(chatId, data.split(':')[2]);
  if (data.startsWith('a:pdel:')) return confirmDeletePanel(chatId, data.split(':')[2]);
  if (data.startsWith('a:pdel2:')) return deletePanel(chatId, data.split(':')[2]);
}

/* ---------------- accounts ---------------- */
async function userAccountIds(chatId) { return (await kvGet('useraccs:' + chatId)) || []; }

async function showAccounts(chatId) {
  const ids = await userAccountIds(chatId);
  if (!ids.length) {
    return sendMsg(chatId,
      `⚠️ <b>هیچ اکانت کلودفلری یافت نشد!</b>\n\n` + TOKEN_HELP, accountGuide());
  }
  const kb = [];
  for (const id of ids) {
    const acc = await kvGet('acc:' + id);
    if (!acc) continue;
    kb.push([{ text: `🗑 ${acc.name}`, callback_data: `a:accdel:${id}` }]);
  }
  kb.push([{ text: '➕ ثبت حساب جدید', callback_data: 'a:accadd' }]);
  kb.push([{ text: '🔙 منوی اصلی', callback_data: 'a:home' }]);
  return sendMsg(chatId, `👤 <b>حساب‌های ثبت‌شده‌ی تو</b>\n\nبرای حذف روی حساب بزن:`, kb);
}

async function processTokenMessage(chatId, token, msgId) {
  /* delete the token message immediately for security */
  if (msgId) await tg('deleteMessage', { chat_id: chatId, message_id: msgId }).catch(() => {});
  await sendMsg(chatId, '🔍 در حال بررسی توکن…');
  try {
    if (!/^([A-Za-z0-9_-]{20,})$/.test(token)) throw new Error('قالب توکن معتبر نیست');
    const accounts = await verifyCfToken(token);
    const acc = accounts[0];
    const missing = await probePerms(token, acc.id);
    if (missing.length) throw new Error('به این دسترسی‌ها نیاز است: ' + missing.join('، '));
    const accId = acc.id;
    await kvPut('acc:' + accId, { enc: await enc(token), name: acc.name || acc.id, accId });
    const ids = new Set(await userAccountIds(chatId));
    ids.add(accId);
    await kvPut('useraccs:' + chatId, [...ids]);
    await clearStep(chatId);
    /* try to delete the raw token message */
    return sendMsg(chatId,
      `✅ <b>حساب ثبت شد!</b>\n\n🏷 ${esc(acc.name || acc.id)}\n\nحالا می‌توانی پنل بسازی 🚀`,
      [[{ text: '🚀 ساخت پنل جدید', callback_data: 'a:build' }], [{ text: '🔙 منوی اصلی', callback_data: 'a:home' }]]);
  } catch (e) {
    return sendMsg(chatId, '❌ ' + esc(e.message) + '\n\nدوباره توکن را بفرست یا از راهنما کمک بگیر:', accountGuide());
  }
}

async function deleteAccount(chatId, accId) {
  const ids = (await userAccountIds(chatId)).filter(x => x !== accId);
  await kvPut('useraccs:' + chatId, ids);
  await kvDel('acc:' + accId);
  return showAccounts(chatId);
}

/* ---------------- build ---------------- */
async function startBuild(chatId) {
  const ids = await userAccountIds(chatId);
  if (!ids.length) {
    return sendMsg(chatId, '❗ اول یک حساب Cloudflare ثبت کن:', accountGuide());
  }
  const kb = [];
  for (const id of ids) {
    const acc = await kvGet('acc:' + id);
    if (acc) kb.push([{ text: '☁️ ' + esc(acc.name), callback_data: `a:buildacc:${id}` }]);
  }
  kb.push([{ text: '🔙 منوی اصلی', callback_data: 'a:home' }]);
  return sendMsg(chatId, '🚀 <b>روی کدام حساب پنل ساخته شود؟</b>', kb);
}

async function buildPanel(chatId, accId, msgId) {
  const acc = await kvGet('acc:' + accId);
  if (!acc) return sendMsg(chatId, 'حساب یافت نشد؛ دوباره ثبتش کن.');

  /* cooldown + quota */
  const cool = await kvGet('cool:' + chatId);
  if (cool && Date.now() - cool.at < DEPLOY_COOLDOWN_SEC * 1000) {
    return sendMsg(chatId, '⏳ کمی صبر کن و دوباره امتحان کن (حداکثر هر دقیقه یک استقرار).');
  }
  const panels = (await kvGet('userpanels:' + chatId)) || [];
  if (panels.length >= MAX_PANELS_PER_USER) {
    return sendMsg(chatId, `⚠️ سقف ${MAX_PANELS_PER_USER} پنل برای هر کاربر. اول یکی را حذف کن.`);
  }
  await kvPut('cool:' + chatId, { at: Date.now() }, DEPLOY_COOLDOWN_SEC + 5);

  const status = async (t, kb) => (msgId ? editMsg(chatId, msgId, t, kb).catch(() => sendMsg(chatId, t, kb)) : sendMsg(chatId, t, kb));

  try {
    const token = await dec(acc.enc);
    await status('⏳ ۱/۴ آماده‌سازی دیتابیس D1…');

    /* 1) D1 */
    const dbName = 'javidnam-db-' + rndHex(2);
    const db = await cf(token, `/accounts/${accId}/d1/database`, { method: 'POST', body: JSON.stringify({ name: dbName }) });
    const dbId = db.uuid;

    await status('⏳ ۲/۴ دریافت سورس پنل و ساخت ساختار…');

    /* 2) panel secrets */
    const adminPass = rndPass();
    const sessionSecret = rndHex(32);
    const scriptName = 'javidnam-panel-' + rndHex(2);

    /* 3) upload worker */
    await status('⏳ ۳/۴ آپلود پنل روی Workers…');
    await deployPanel(token, accId, scriptName, adminPass, sessionSecret, dbId);

    /* 4) workers.dev domain */
    await status('⏳ ۴/۴ فعال‌سازی دامنه…');
    await enableWorkersDev(token, accId, scriptName);
    const subdomain = await getSubdomain(token, accId);
    const panelUrl = `https://${scriptName}.${subdomain}.workers.dev`;

    /* store meta */
    const meta = {
      scriptName, accId, dbId, panelUrl,
      passEnc: await enc(adminPass), sessionEnc: await enc(sessionSecret),
      createdAt: Date.now(), owner: chatId, version: BOT_VERSION,
    };
    await kvPut('panel:' + scriptName, meta);
    const plist = (await kvGet('userpanels:' + chatId)) || [];
    plist.push(scriptName);
    await kvPut('userpanels:' + chatId, plist);

    /* verify panel is alive */
    let alive = false;
    try { const r = await fetch(panelUrl + '/healthz', { cache: 'no-store' }); alive = r.ok; } catch (e) {}

    return sendMsg(chatId,
      `${alive ? '✅' : '🟡'} <b>پنل جاویدنام آماده شد!</b>

🌐 <b>آدرس پنل:</b>
<code>${panelUrl}</code>

🔑 <b>رمز مدیریت</b> (یک‌بار نمایش داده می‌شود):
<code>${adminPass}</code>

▫️ پروتکل: VLESS + Trojan روی WebSocket
▫️ دیتابیس: D1 (<code>${dbName}</code>)
▫️ بدون تبلیغ — به یاد ۱۸ و ۱۹ دی ۱۴۰۴ 🕯

<b>قدم بعدی:</b> وارد پنل شو ← کاربر بساز ← لینک ساب را برای کاربرت بفرست.
💡 این پیام شامل رمز است؛ بعد از ذخیره می‌توانی حذفش کنی.`,
      [[{ text: '📦 مدیریت این پنل', callback_data: `a:panel:${scriptName}` }], [{ text: '🔙 منوی اصلی', callback_data: 'a:home' }]]);
  } catch (e) {
    return status('❌ ساخت پنل ناموفق بود:\n<code>' + esc(e.message) + '</code>\n\nتوکن را بررسی کن (دسترسی‌های Workers و D1) و دوباره تلاش کن.', [[{ text: '🔁 تلاش مجدد', callback_data: 'a:build' }], [{ text: '🔙 منوی اصلی', callback_data: 'a:home' }]]);
  }
}

/* ---------------- panels management ---------------- */
async function userPanelList(chatId) { return (await kvGet('userpanels:' + chatId)) || []; }

async function showPanels(chatId) {
  const list = await userPanelList(chatId);
  if (!list.length) return sendMsg(chatId, '📦 هنوز پنلی نساختی.\n\n🚀 از منوی اصلی «ساخت پنل جدید» را بزن.', [[{ text: '🚀 ساخت پنل جدید', callback_data: 'a:build' }], [{ text: '🔙 منوی اصلی', callback_data: 'a:home' }]]);
  const kb = [];
  for (const s of list) {
    const p = await kvGet('panel:' + s);
    if (!p) continue;
    kb.push([{ text: '🌐 ' + p.scriptName, callback_data: `a:panel:${s}` }]);
  }
  kb.push([{ text: '🔙 منوی اصلی', callback_data: 'a:home' }]);
  return sendMsg(chatId, '📦 <b>پنل‌های تو</b>\nبرای مدیریت، پنل را انتخاب کن:', kb);
}

async function panelMenu(chatId, scriptName) {
  const p = await kvGet('panel:' + scriptName);
  if (!p) return sendMsg(chatId, 'پنل یافت نشد.');
  return sendMsg(chatId,
    `🌐 <b>${esc(p.scriptName)}</b>\n<code>${p.panelUrl}</code>\n\nمی‌خواهی چه کاری انجام شود؟`,
    [
      [{ text: '🔄 آپدیت پنل', callback_data: `a:pupd:${scriptName}` }, { text: '📊 وضعیت', callback_data: `a:pstat:${scriptName}` }],
      [{ text: '🔑 ریست رمز', callback_data: `a:ppass:${scriptName}` }, { text: '🗑 حذف', callback_data: `a:pdel:${scriptName}` }],
      [{ text: '🔙 پنل‌های من', callback_data: 'a:panels' }],
    ]);
}

async function updatePanel(chatId, scriptName) {
  const p = await kvGet('panel:' + scriptName);
  if (!p) return sendMsg(chatId, 'پنل یافت نشد.');
  const acc = await kvGet('acc:' + p.accId);
  if (!acc) return sendMsg(chatId, '❌ حساب Cloudflare این پنل حذف شده است.');
  await sendMsg(chatId, '⏳ در حال دریافت آخرین نسخه و آپدیت پنل…');
  try {
    const token = await dec(acc.enc);
    /* new admin pass keeps the old one */
    const oldPass = await dec(p.passEnc);
    const sessionSecret = await dec(p.sessionEnc);
    await deployPanel(token, p.accId, p.scriptName, oldPass, sessionSecret, p.dbId);
    await enableWorkersDev(token, p.accId, p.scriptName);
    p.version = BOT_VERSION;
    p.updatedAt = Date.now();
    await kvPut('panel:' + scriptName, p);
    return sendMsg(chatId, `✅ پنل آپدیت شد!\n\n🌐 <code>${p.panelUrl}</code>\n\n🔑 رمز و کاربران و تنظیمات همه دست‌نخورده باقی مانده‌اند.`);
  } catch (e) {
    return sendMsg(chatId, '❌ آپدیت ناموفق: <code>' + esc(e.message) + '</code>');
  }
}

async function panelStatus(chatId, scriptName) {
  const p = await kvGet('panel:' + scriptName);
  if (!p) return sendMsg(chatId, 'پنل یافت نشد.');
  await sendMsg(chatId, '⏳ دریافت وضعیت…');
  try {
    const pass = await dec(p.passEnc);
    const login = await fetch(p.panelUrl + '/api/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-JN': '1' },
      body: JSON.stringify({ password: pass }), cache: 'no-store',
    });
    const cookie = (login.headers.get('set-cookie') || '').split(';')[0];
    if (!login.ok) throw new Error('ورود به پنل ناموفق (رمز تغییر کرده؟)');
    const st = await fetch(p.panelUrl + '/api/stats', { headers: { Cookie: cookie }, cache: 'no-store' }).then(r => r.json());
    const gb = b => {
      if (!b) return '0';
      const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0, v = b;
      while (v >= 1024 && i < 4) { v /= 1024; i++; }
      return v.toFixed(1) + ' ' + u[i];
    };
    return sendMsg(chatId,
      `📊 <b>وضعیت ${esc(p.scriptName)}</b>\n\n👥 کاربران: <b>${st.users.total}</b>\n✅ فعال: <b>${st.users.active}</b>\n📉 مصرف کل: <b>${gb(st.traffic.used)}</b>\n⏳ در حال انقضا (۷ روز): <b>${st.expiring_soon}</b>\n🏷 نسخه: <code>${st.version}</code>`);
  } catch (e) {
    return sendMsg(chatId, '🟡 وضعیت دقیق در دسترس نیست: ' + esc(e.message) + '\n(پنل ممکن است رمز جدیدی داشته باشد؛ آپدیت/ریست رمز مشکل را حل می‌کند)');
  }
}

async function resetPanelPass(chatId, scriptName) {
  const p = await kvGet('panel:' + scriptName);
  if (!p) return sendMsg(chatId, 'پنل یافت نشد.');
  const acc = await kvGet('acc:' + p.accId);
  if (!acc) return sendMsg(chatId, '❌ حساب Cloudflare این پنل حذف شده است.');
  await sendMsg(chatId, '⏳ تولید رمز جدید…');
  try {
    const token = await dec(acc.enc);
    const newPass = rndPass();
    const sessionSecret = rndHex(32);
    await deployPanel(token, p.accId, p.scriptName, newPass, sessionSecret, p.dbId);
    p.passEnc = await enc(newPass);
    p.sessionEnc = await enc(sessionSecret);
    await kvPut('panel:' + scriptName, p);
    return sendMsg(chatId,
      `🔑 رمز جدید ست شد!\n\n🔐 <code>${newPass}</code>\n\n🌐 ${p.panelUrl}\n💡 این پیام را بعد از ذخیره حذف کن.`);
  } catch (e) {
    return sendMsg(chatId, '❌ تغییر رمز ناموفق: <code>' + esc(e.message) + '</code>');
  }
}

async function confirmDeletePanel(chatId, scriptName) {
  return sendMsg(chatId, `⚠️ پنل <code>${esc(scriptName)}</code> به‌همراه دیتابیس و همه‌ی کاربرانش حذف شود؟\n\nاین عمل <b>برگشت‌پذیر نیست.</b>`,
    [[{ text: '🗑 بله، حذف کن', callback_data: `a:pdel2:${scriptName}` }], [{ text: '❌ انصراف', callback_data: `a:panel:${scriptName}` }]]);
}

async function deletePanel(chatId, scriptName) {
  const p = await kvGet('panel:' + scriptName);
  if (!p) return sendMsg(chatId, 'پنل یافت نشد.');
  const acc = await kvGet('acc:' + p.accId);
  await sendMsg(chatId, '⏳ در حال حذف…');
  try {
    if (acc) {
      const token = await dec(acc.enc);
      await cf(token, `/accounts/${p.accId}/workers/scripts/${p.scriptName}`, { method: 'DELETE' });
      try { await cf(token, `/accounts/${p.accId}/d1/database/${p.dbId}`, { method: 'DELETE' }); } catch (e) {}
    }
    await kvDel('panel:' + scriptName);
    const plist = (await kvGet('userpanels:' + chatId)).filter(x => x !== scriptName);
    await kvPut('userpanels:' + chatId, plist);
    return sendMsg(chatId, '🗑 پنل حذف شد.', mainMenu());
  } catch (e) {
    return sendMsg(chatId, '❌ حذف ناموفق: <code>' + esc(e.message) + '</code>');
  }
}
