/* ------------------------------------------------------------------ */
/* SUBSCRIPTION — config links, ISP presets, sub page data              */
/* ------------------------------------------------------------------ */

const ISP_PRESETS = [
  { id: 'all',      label: 'همه',            fp: 'chrome',  frag: null,          mux: false, note: 'حالت پیش‌فرض و پیشنهادی برای شروع' },
  { id: 'mci',      label: 'همراه اول',       fp: 'chrome',  frag: [10, 20, 10, 20], mux: false, note: 'fragment فعال؛ برای قطعی‌های شدید MCI' },
  { id: 'irancell', label: 'ایرانسل',         fp: 'safari',  frag: [40, 50, 10, 20], mux: false, note: 'fragment با بازه بلندتر؛ مناسب اینترنت‌های ضعیف' },
  { id: 'rightel',  label: 'رایتل',           fp: 'chrome',  frag: [10, 30, 10, 20], mux: false, note: 'حالت متعادل' },
  { id: 'tci',      label: 'تلکام (خانگی)',   fp: 'chrome',  frag: [5, 10, 5, 10],   mux: false, note: 'fragment ریز برای خطوط ثابت' },
  { id: 'gaming',   label: 'گیمینگ',          fp: 'chrome',  frag: null,          mux: false, note: 'کم‌ترین تأخیر؛ fragment خاموش' },
];

const CLIENT_UA_HINTS = [
  'v2ray', 'hiddify', 'sing-box', 'singbox', 'clash', 'shadowrocket', 'streisand',
  'loon', 'stash', 'surge', 'sfa', 'karing', 'husi', 'v2box', 'napsternetv', 'shadowsocks',
];

function buildConfigLinks(user, locations, proxyPath, panelHost) {
  const links = [];
  for (const loc of locations) {
    const tag = encodeURIComponent(`${BRAND.en} | ${loc.name}`);
    const vp = new URLSearchParams({
      encryption: 'none',
      security: loc.tls ? 'tls' : 'none',
      type: 'ws',
      host: panelHost,
      path: `${proxyPath}?ed=2048`,
    });
    if (loc.tls) { vp.set('sni', loc.host); vp.set('fp', 'chrome'); }
    links.push({
      name: loc.name,
      proto: 'vless',
      link: `vless://${user.uuid}@${loc.host}:${loc.port}?${vp.toString()}#${tag}`,
    });
    const tp = new URLSearchParams({
      security: loc.tls ? 'tls' : 'none',
      type: 'ws',
      host: panelHost,
      path: `${proxyPath}?ed=2048`,
    });
    if (loc.tls) tp.set('sni', loc.host);
    links.push({
      name: loc.name,
      proto: 'trojan',
      link: `trojan://${user.uuid}@${loc.host}:${loc.port}?${tp.toString()}#${encodeURIComponent(`${BRAND.en} TRJ | ${loc.name}`)}`,
    });
  }
  return links;
}

/* Apply an ISP preset to a link (client-side tunables) */
function applyPresetToLink(link, preset) {
  try {
    const u = new URL(link);
    u.searchParams.set('fp', preset.fp);
    if (preset.frag) {
      u.searchParams.set('frag', `${preset.frag[0]}-${preset.frag[1]}-${preset.frag[2]}-${preset.frag[3]}`);
    } else {
      u.searchParams.delete('frag');
    }
    return u.toString();
  } catch (e) { return link; }
}

async function handleSub(request, url, ctx) {
  const m = url.pathname.match(/^\/sub\/([0-9a-f]{8,64})$/);
  if (!m) return notFound();
  const token = m[1];
  const user = await dbGet('SELECT * FROM users WHERE sub_token = ?', [token]);
  if (!user) return new Response('<h1 dir="rtl">اشتراک یافت نشد</h1>', { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' } });

  const settings = await getSettings();
  const locations = resolveLocations(settings, url.host);
  const links = buildConfigLinks(user, locations, settings.proxy_path, url.host);
  const state = userState(user);
  const subUrl = `https://${url.host}/sub/${token}`;

  const fmt = url.searchParams.get('format') || url.searchParams.get('fmt');
  const ua = (request.headers.get('User-Agent') || '').toLowerCase();
  const isClient = CLIENT_UA_HINTS.some(h => ua.includes(h));

  if (url.searchParams.get('json') === '1') {
    return jsonResponse({
      name: user.name, state, sub_url: subUrl, version: VERSION,
      updated_at: Date.now(),
    });
  }

  if (fmt === 'b64' || fmt === 'base64') {
    return new Response(b64encode(links.map(l => l.link).join('\n')), {
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Profile-Update-Interval': '6', 'Subscription-Userinfo': subInfoHeader(state) },
    });
  }

  if (isClient || fmt === 'raw' || fmt === 'txt') {
    return new Response(links.map(l => l.link).join('\n'), {
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Profile-Update-Interval': '6', 'Subscription-Userinfo': subInfoHeader(state) },
    });
  }

  /* Pretty HTML page (humans) */
  const data = {
    brand: BRAND,
    version: VERSION,
    name: user.name,
    state,
    sub_url: subUrl,
    links,
    presets: ISP_PRESETS,
    welcome: settings.welcome || '',
    contact: settings.contact || '',
    proxy_path: settings.proxy_path,
    show_branding: !!settings.sub_branding,
  };
  const html = renderSubPage(data);
  return htmlResponse(html, 200, { 'Cache-Control': 'no-store' });
}

function subInfoHeader(state) {
  const parts = [];
  if (state.quota !== null) parts.push(`upload=0; download=${state.used}; total=${state.quota}`);
  else parts.push(`upload=0; download=${state.used}; total=0`);
  if (state.expiryAt) parts.push(`expire=${Math.floor(state.expiryAt / 1000)}`);
  return parts.join('; ');
}

/* Render the sub page: template + runtime data injection (template comes
   from assets/sub.html at build time as SUB_PAGE_TEMPLATE) */
function renderSubPage(data) {
  const payload = JSON.stringify(data).replace(/</g, '\\u003c');
  return SUB_PAGE_TEMPLATE
    .replace('__SUB_DATA_JSON__', payload)
    .replace('__TITLE__', escapeHtml(data.brand.fa + ' | اشتراک ' + data.name));
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
