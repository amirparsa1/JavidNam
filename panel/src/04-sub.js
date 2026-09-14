/* ------------------------------------------------------------------ */
/* SUBSCRIPTION — config links, ISP presets, formats, status endpoint   */
/* ------------------------------------------------------------------ */

const ISP_PRESETS = [
  { id: 'auto',     label: 'خودکار',          fp: null,      frag: null,             note: 'تنظیمات سراسری پنل' },
  { id: 'mci',      label: 'همراه اول',       fp: 'chrome',  frag: ['10-20', '10-20'], note: 'fragment استاندارد؛ برای قطعی‌های MCI' },
  { id: 'irancell', label: 'ایرانسل',         fp: 'safari',  frag: ['40-50', '10-20'], note: 'fragment با بازه بلندتر' },
  { id: 'rightel',  label: 'رایتل',           fp: 'chrome',  frag: ['10-30', '10-20'], note: 'حالت متعادل' },
  { id: 'tci',      label: 'مخابرات / خانگی', fp: 'firefox', frag: ['5-10', '5-10'],   note: 'fragment ریز برای خطوط ثابت' },
  { id: 'shatel',   label: 'شاتل / آسیاتک',   fp: 'chrome',  frag: ['20-40', '10-20'], note: 'برای ADSL/FTTH خصوصی' },
  { id: 'gaming',   label: 'گیمینگ',          fp: 'chrome',  frag: false,            note: 'کم‌ترین تأخیر؛ fragment خاموش' },
];

const CLIENT_UA_HINTS = [
  'v2ray', 'hiddify', 'sing-box', 'singbox', 'clash', 'shadowrocket', 'streisand', 'loon', 'stash', 'surge',
  'sfa', 'sfi', 'sfm', 'karing', 'husi', 'v2box', 'napsternetv', 'shadowsocks', 'nekobox', 'nekoray', 'xray', 'mihomo', 'quantumult', 'exclave', 'happ', 'foxray', 'ktm', 'oblivion',
];

function fragFor(settings, preset) {
  if (preset && preset.frag === false) return null;
  if (preset && preset.frag) return { len: preset.frag[0], int: preset.frag[1], packets: settings.frag_packets || 'tlshello' };
  if (!settings.frag_enabled) return null;
  return { len: settings.frag_len || '10-20', int: settings.frag_int || '10-20', packets: settings.frag_packets || 'tlshello' };
}

function buildConfigLinks(user, settings, locations, panelHost, opts = {}) {
  const preset = opts.preset || null;
  const fp = (preset && preset.fp) || settings.fp || 'chrome';
  const frag = fragFor(settings, preset);
  const hostHeader = settings.host_mask || panelHost;
  const links = [];
  for (const loc of locations) {
    const sni = settings.sni_mask || loc.sni || (loc.isClean ? panelHost : loc.host);
    const path = `${settings.proxy_path}?ed=2048&loc=${encodeURIComponent(loc.id)}`;
    const common = { type: 'ws', host: hostHeader, path, security: loc.tls ? 'tls' : 'none' };
    if (loc.tls) { common.sni = sni; common.fp = fp; common.alpn = settings.alpn || 'http/1.1'; }
    if (frag) { common.fragment = `${frag.packets},${frag.len},${frag.int}`; }
    const vp = new URLSearchParams({ encryption: 'none', ...common });
    links.push({ id: loc.id, name: loc.name, proto: 'vless', host: loc.host, port: loc.port, tls: loc.tls, sni, fp, frag, link: `vless://${user.uuid}@${bracket(loc.host)}:${loc.port}?${vp}#${encodeURIComponent(`${BRAND.en} | ${loc.name}`)}` });
    const tp = new URLSearchParams(common);
    links.push({ id: loc.id, name: loc.name, proto: 'trojan', host: loc.host, port: loc.port, tls: loc.tls, sni, fp, frag, link: `trojan://${user.uuid}@${bracket(loc.host)}:${loc.port}?${tp}#${encodeURIComponent(`${BRAND.en} TRJ | ${loc.name}`)}` });
  }
  return links;
}
function bracket(h) { return isIPv6(h) ? `[${h}]` : h; }

/* ---- sing-box JSON ---- */
function singboxConfig(user, links, settings) {
  const outbounds = [];
  const tags = [];
  for (const l of links) {
    const tag = `${l.proto === 'vless' ? '' : 'TRJ '}${l.name}`;
    tags.push(tag);
    const ob = {
      type: l.proto, tag, server: l.host, server_port: l.port,
      ...(l.proto === 'vless' ? { uuid: user.uuid, flow: '' } : { password: user.uuid }),
      transport: { type: 'ws', path: settings.proxy_path + '?loc=' + l.id, headers: { Host: settings.host_mask || l.sni }, max_early_data: 2048, early_data_header_name: 'Sec-WebSocket-Protocol' },
    };
    if (l.tls) ob.tls = { enabled: true, server_name: l.sni, insecure: false, utls: { enabled: true, fingerprint: l.fp === 'random' ? 'randomized' : l.fp }, alpn: (settings.alpn || 'http/1.1').split(',') };
    if (l.frag) ob.tls = { ...(ob.tls || { enabled: true, server_name: l.sni }), fragment: true, fragment_fallback_delay: '500ms' };
    outbounds.push(ob);
  }
  return {
    log: { level: 'warn' },
    dns: { servers: [{ tag: 'remote', address: 'https://1.1.1.1/dns-query', detour: 'auto' }, { tag: 'local', address: 'local', detour: 'direct' }], rules: [{ outbound: 'any', server: 'local' }], strategy: 'ipv4_only' },
    inbounds: [{ type: 'tun', tag: 'tun-in', address: ['172.19.0.1/30'], auto_route: true, strict_route: true, stack: 'mixed', sniff: true }, { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 }],
    outbounds: [
      { type: 'selector', tag: 'proxy', outbounds: ['auto', ...tags], default: 'auto' },
      { type: 'urltest', tag: 'auto', outbounds: tags, url: 'https://www.gstatic.com/generate_204', interval: '5m', tolerance: 100 },
      ...outbounds,
      { type: 'direct', tag: 'direct' },
    ],
    route: { rules: [{ protocol: 'dns', action: 'hijack-dns' }, { ip_is_private: true, outbound: 'direct' }, { rule_set: [], domain_suffix: ['.ir'], outbound: 'direct' }], final: 'proxy', auto_detect_interface: true },
    experimental: { clash_api: { external_controller: '127.0.0.1:9090' }, cache_file: { enabled: true } },
  };
}

/* ---- Clash / Mihomo YAML ---- */
function clashConfig(user, links, settings) {
  const y = (s) => JSON.stringify(String(s));
  const names = [];
  const proxies = links.map(l => {
    const name = `${BRAND.en} ${l.proto === 'vless' ? '' : 'TRJ '}${l.name}`;
    names.push(name);
    const base = [
      `  - name: ${y(name)}`, `    type: ${l.proto}`, `    server: ${y(l.host)}`, `    port: ${l.port}`,
      l.proto === 'vless' ? `    uuid: ${user.uuid}` : `    password: ${user.uuid}`,
      `    udp: true`, `    tls: ${l.tls}`, `    network: ws`, `    servername: ${y(l.sni)}`, `    client-fingerprint: ${l.fp === 'random' ? 'random' : l.fp}`,
      `    ws-opts:`, `      path: ${y(settings.proxy_path + '?ed=2048&loc=' + l.id)}`, `      headers:`, `        Host: ${y(settings.host_mask || l.sni)}`,
    ];
    if (l.tls) base.push(`    alpn: [${(settings.alpn || 'http/1.1').split(',').map(a => y(a.trim())).join(', ')}]`);
    return base.join('\n');
  });
  return [
    `# ${BRAND.en} — ${BRAND.memorial}`,
    'mixed-port: 7890', 'allow-lan: false', 'mode: rule', 'log-level: warning', 'ipv6: false', 'unified-delay: true', 'tcp-concurrent: true',
    'dns:', '  enable: true', '  enhanced-mode: fake-ip', '  nameserver: [https://1.1.1.1/dns-query, https://8.8.8.8/dns-query]', '  fallback: [https://dns.google/dns-query]',
    'proxies:', ...proxies,
    'proxy-groups:',
    `  - name: ${y(BRAND.en)}`, '    type: select', `    proxies: [${['⚡ خودکار', ...names].map(y).join(', ')}]`,
    `  - name: ${y('⚡ خودکار')}`, '    type: url-test', '    url: https://www.gstatic.com/generate_204', '    interval: 300', '    tolerance: 100', `    proxies: [${names.map(y).join(', ')}]`,
    'rules:', '  - GEOIP,PRIVATE,DIRECT,no-resolve', '  - DOMAIN-SUFFIX,ir,DIRECT', '  - GEOIP,IR,DIRECT', `  - MATCH,${y(BRAND.en)}`,
  ].join('\n') + '\n';
}

function subInfoHeader(state) {
  const parts = [`upload=0; download=${state.used}; total=${state.quota || 0}`];
  if (state.expiryAt) parts.push(`expire=${Math.floor(state.expiryAt / 1000)}`);
  return parts.join('; ');
}

async function handleSub(request, url, ctx) {
  const m = url.pathname.match(/^\/(sub|status)\/([0-9a-f]{8,64})(?:\/(sb|clash|raw|b64|json|links))?$/);
  if (!m) return notFound();
  const kind = m[1], token = m[2];
  countRequest();
  const user = await dbGet('SELECT * FROM users WHERE sub_token = ?', [token]);
  if (!user) return htmlResponse('<!doctype html><html dir="rtl"><body style="background:#000;color:#fff;font-family:sans-serif;display:grid;place-items:center;height:100vh"><h2>اشتراک یافت نشد</h2></body></html>', 404);

  const settings = await getSettings();
  const allowed = userLocationIds(user);
  let locations = resolveLocations(settings, url.host, user.uuid);
  if (allowed) locations = locations.filter(l => allowed.includes(l.baseId || l.id));
  if (!locations.length) locations = resolveLocations(settings, url.host, user.uuid).slice(0, 1);

  const presetId = url.searchParams.get('isp') || url.searchParams.get('preset') || '';
  const preset = ISP_PRESETS.find(p => p.id === presetId && p.id !== 'auto') || null;
  const links = buildConfigLinks(user, settings, locations, url.host, { preset });
  const state = userState(user);
  const subUrl = `https://${url.host}/sub/${token}`;
  const fmt = m[3] || url.searchParams.get('format') || url.searchParams.get('fmt') || (url.searchParams.get('json') === '1' ? 'json' : '');
  const ua = (request.headers.get('User-Agent') || '').toLowerCase();
  const isClient = CLIENT_UA_HINTS.some(h => ua.includes(h));
  const hdrs = { 'Profile-Update-Interval': '6', 'Subscription-Userinfo': subInfoHeader(state), 'Profile-Title': 'base64:' + b64encode(`${BRAND.en} | ${user.name}`), 'Support-Url': settings.contact || BRAND.repo, 'Profile-Web-Page-Url': subUrl };

  const statusPayload = () => ({
    app: BRAND.en, version: VERSION, name: user.name, state, active: !!user.active,
    quota_bytes: user.quota_bytes, used_bytes: user.used_bytes, expiry_at: user.expiry_at, days_left: state.daysLeft,
    max_requests: user.max_requests || 0, used_requests: user.used_requests || 0, ip_limit: user.ip_limit, online_ips: activeIps(user.uuid),
    last_seen_at: user.last_seen_at || null, expiry_jalali: user.expiry_at ? toJalali(user.expiry_at) : null,
    locations: locations.map(l => ({ id: l.id, name: l.name })), sub_url: subUrl, now: Date.now(),
  });

  if (fmt === 'json') return jsonResponse(statusPayload(), 200, { 'Access-Control-Allow-Origin': '*' });
  if (fmt === 'sb' || fmt === 'singbox' || (!fmt && /sing-box|sfa|sfi|sfm|husi|karing/.test(ua) && !/hiddify/.test(ua))) {
    return jsonResponse(singboxConfig(user, links.filter(l => l.proto === 'vless'), settings), 200, { ...hdrs, 'Content-Disposition': `attachment; filename="javidnam-${user.name}.json"` });
  }
  if (fmt === 'clash' || (!fmt && /clash|mihomo|stash/.test(ua) && !/hiddify/.test(ua))) {
    return new Response(clashConfig(user, links, settings), { headers: { 'Content-Type': 'text/yaml; charset=utf-8', ...hdrs, 'Content-Disposition': `attachment; filename="javidnam-${user.name}.yaml"` } });
  }
  if (fmt === 'b64' || fmt === 'base64') return textResponse(b64encode(links.map(l => l.link).join('\n')), hdrs);
  if (fmt === 'links') return jsonResponse({ links, presets: ISP_PRESETS, preset: preset ? preset.id : 'auto' }, 200, { 'Access-Control-Allow-Origin': '*' });
  if (isClient || fmt === 'raw' || fmt === 'txt') return textResponse(links.map(l => l.link).join('\n'), hdrs);

  /* HTML page (humans). /status/* shows same page with status tab first */
  const data = {
    brand: BRAND, version: VERSION, name: user.name, state, sub_url: subUrl, status_url: `https://${url.host}/status/${token}`,
    links, presets: ISP_PRESETS, preset: preset ? preset.id : 'auto',
    welcome: settings.welcome || '', contact: settings.contact || '', show_branding: !!settings.sub_branding,
    status: statusPayload(), view: kind === 'status' ? 'status' : 'configs',
    formats: { raw: subUrl, b64: subUrl + '/b64', clash: subUrl + '/clash', sb: subUrl + '/sb', json: subUrl + '/json' },
  };
  return htmlResponse(renderSubPage(data));
}

function renderSubPage(data) {
  const payload = JSON.stringify(data).replace(/</g, '\\u003c');
  return SUB_PAGE_TEMPLATE.replace('__SUB_DATA_JSON__', () => payload).replace('__TITLE__', escapeHtml(data.brand.fa + ' | ' + data.name));
}
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
