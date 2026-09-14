/* ------------------------------------------------------------------ */
/* ROUTER — main fetch handler + PWA assets + scanner scripts           */
/* ------------------------------------------------------------------ */

const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f43f5e"/><stop offset="1" stop-color="#881337"/></linearGradient>
<radialGradient id="c" cx="0.5" cy="0.35" r="0.5"><stop offset="0" stop-color="#fbbf24"/><stop offset="1" stop-color="#f43f5e" stop-opacity="0"/></radialGradient></defs>
<rect width="64" height="64" rx="14" fill="#07070b"/>
<path d="M32 10c-1.8 5-6 7.2-6 12.6 0 3.4 1.9 6.3 4.2 8.4C29.6 39 27.4 44.6 22 50c7-1.6 11.2-5 13.4-9.6 2.2 4.6 6.4 8 13.4 9.6-5.4-5.4-7.6-11-8.2-19 2.3-2.1 4.2-5 4.2-8.4C44.8 17.2 40.6 15 38.8 10c-1.6 3.4-4.2 5-6.8 5s-5.2-1.6-6.8-5z" fill="url(#g)"/>
<ellipse cx="32" cy="24" rx="3.6" ry="6.5" fill="url(#c)" opacity="0.9"/></svg>`;

const MANIFEST_JSON = JSON.stringify({
  name: 'JavidNam | جاویدنام', short_name: 'JavidNam', description: 'پنل جاویدنام — به یاد ۱۸ و ۱۹ دی ۱۴۰۴',
  start_url: '/', scope: '/', display: 'standalone', orientation: 'portrait', background_color: '#07070b', theme_color: '#07070b', dir: 'rtl', lang: 'fa',
  icons: [{ src: '/favicon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' }, { src: '/icon-512.svg', sizes: '512x512', type: 'image/svg+xml', purpose: 'maskable' }],
});

const SW_JS = `const C='javidnam-%VERSION%';const STATIC=['/favicon.svg','/manifest.webmanifest'];
self.addEventListener('install',e=>{self.skipWaiting();e.waitUntil(caches.open(C).then(c=>c.addAll(STATIC)).catch(()=>{}))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==C).map(k=>caches.delete(k)))).then(()=>clients.claim()))});
self.addEventListener('fetch',e=>{const u=new URL(e.request.url);if(e.request.method!=='GET'||u.pathname.startsWith('/api/')||u.pathname.startsWith('/sub/')||u.pathname.startsWith('/status/'))return;
e.respondWith(fetch(e.request).then(r=>{if(r.ok){const cp=r.clone();caches.open(C).then(c=>c.put(e.request,cp)).catch(()=>{})}return r;}).catch(()=>caches.match(e.request)))});`;

/* Clean-IP scanner scripts served by the panel (user-side, where CF ranges ARE reachable) */
const SCANNER_PY = `# JavidNam Clean IP Scanner (Pydroid3 / Python 3) — GPL-3.0
import socket, ssl, time, random, ipaddress, concurrent.futures as cf
HOST = "__HOST__"; RANGES = ["104.16.0.0/13","172.64.0.0/13","162.159.0.0/16","188.114.96.0/20","141.101.64.0/18","190.93.240.0/20","198.41.128.0/17"]
N = 300; TOP = 15; TIMEOUT = 1.5
def probe(ip):
    t0 = time.time()
    try:
        s = socket.create_connection((ip, 443), timeout=TIMEOUT)
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        w = ctx.wrap_socket(s, server_hostname=HOST)
        w.send(("HEAD / HTTP/1.1\\r\\nHost: %s\\r\\nConnection: close\\r\\n\\r\\n" % HOST).encode()); w.recv(64); w.close()
        return ip, int((time.time()-t0)*1000)
    except Exception: return ip, None
ips = []
for r in RANGES:
    net = ipaddress.ip_network(r); size = net.num_addresses
    for _ in range(N // len(RANGES)): ips.append(str(net[random.randrange(size)]))
print("JavidNam scanner: testing %d IPs for %s ..." % (len(ips), HOST))
res = []
with cf.ThreadPoolExecutor(64) as ex:
    for ip, ms in ex.map(probe, ips):
        if ms is not None: res.append((ms, ip)); print("  ok %-16s %4d ms" % (ip, ms))
res.sort()
print("\\n=== TOP %d ===" % TOP)
for ms, ip in res[:TOP]: print("%-16s %4d ms" % (ip, ms))
print("\\nPaste the IPs into JavidNam panel → Settings → Clean IPs")
`;

const SCANNER_CMD = `@echo off
:: JavidNam Clean IP Scanner (Windows CMD) — tests random Cloudflare IPs with TLS to your panel host
setlocal enabledelayedexpansion
set HOST=__HOST__
set N=80
echo JavidNam scanner: testing %N% IPs for %HOST% ...
set OUT=%TEMP%\\jvn_scan.txt
if exist "%OUT%" del "%OUT%"
for /L %%i in (1,1,%N%) do (
  set /a a=104, b=16+!random! %% 8, c=!random! %% 256, d=1+!random! %% 254
  set IP=!a!.!b!.!c!.!d!
  for /f "tokens=*" %%t in ('curl -s -o NUL -w "%%{time_connect}" --connect-timeout 2 --resolve %HOST%:443:!IP! https://%HOST%/healthz 2^>NUL') do (
    if not "%%t"=="" if not "%%t"=="0.000000" (echo   ok !IP!  %%t s & echo %%t !IP!>>"%OUT%")
  )
)
echo.
echo === TOP 15 ===
if exist "%OUT%" sort "%OUT%" | more +0 | findstr /n "^" | findstr /r "^[0-9]:\\|^1[0-5]:"
echo.
echo Paste the IPs into JavidNam panel - Settings - Clean IPs
pause
`;

const SCANNER_SH = `#!/usr/bin/env bash
# JavidNam Clean IP Scanner (Linux/Termux/macOS) — GPL-3.0
HOST="__HOST__"; N=\${1:-200}
RANGES=(104.16 104.17 104.18 104.19 104.20 104.21 104.22 104.23 172.64 172.65 172.66 172.67 162.159 188.114 141.101)
echo "JavidNam scanner: testing $N IPs for $HOST ..."
probe(){ ip=$1; t=$(curl -s -o /dev/null -w '%{time_appconnect}' --connect-timeout 2 -m 4 --resolve "$HOST:443:$ip" "https://$HOST/healthz" 2>/dev/null); [ -n "$t" ] && [ "$t" != "0.000000" ] && printf '%s %s\\n' "$(awk "BEGIN{printf \\"%d\\", $t*1000}")" "$ip"; }
export -f probe; export HOST
for i in $(seq 1 $N); do r=\${RANGES[$RANDOM % \${#RANGES[@]}]}; echo "$r.$((RANDOM%256)).$((RANDOM%254+1))"; done | xargs -P 40 -I{} bash -c 'probe {}' | sort -n | head -15 | awk '{printf "%-16s %4d ms\\n", $2, $1}'
echo; echo "Paste the IPs into JavidNam panel → Settings → Clean IPs"
`;

export default {
  async fetch(request, env, ctx) {
    initEnv(env);
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      /* --- WebSocket proxy (VLESS/Trojan) --- */
      if ((request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') {
        const settings = await getSettings();
        if (pathMatches(path, settings.proxy_path)) return await handleProxy(request, ctx);
        return notFound();
      }

      if (path === '/healthz') return jsonResponse({ ok: true, app: 'javidnam', version: VERSION, colo: (request.cf && request.cf.colo) || null });
      if (path === '/robots.txt') return textResponse('User-agent: *\nDisallow: /\n');
      if (path === '/favicon.svg' || path === '/icon-512.svg') return new Response(FAVICON_SVG, { headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' } });
      if (path === '/favicon.ico') return Response.redirect(url.origin + '/favicon.svg', 302);
      if (path === '/manifest.webmanifest') return new Response(MANIFEST_JSON, { headers: { 'Content-Type': 'application/manifest+json' } });
      if (path === '/sw.js') return new Response(SW_JS.replace('%VERSION%', VERSION), { headers: { 'Content-Type': 'application/javascript', 'Cache-Control': 'no-cache' } });

      /* --- scanner scripts --- */
      if (path === '/tools/scanner.py') return textResponse(SCANNER_PY.replace('__HOST__', url.host), { 'Content-Disposition': 'attachment; filename="javidnam-scanner.py"' });
      if (path === '/tools/scanner.cmd') return textResponse(SCANNER_CMD.replace('__HOST__', url.host), { 'Content-Disposition': 'attachment; filename="javidnam-scanner.cmd"' });
      if (path === '/tools/scanner.sh') return textResponse(SCANNER_SH.replace('__HOST__', url.host), { 'Content-Disposition': 'attachment; filename="javidnam-scanner.sh"' });

      /* --- subscription / status --- */
      if (path.startsWith('/sub/') || path.startsWith('/status/')) return await handleSub(request, url, ctx);

      /* --- admin --- */
      if (path.startsWith('/api/')) return await handleAdminApi(request, url, ctx);
      if (path === '/' || path === '/index.html' || path === '/panel' || path === '/admin') {
        countRequest(); ctx.waitUntil(flushMetrics().catch(() => {}));
        return htmlResponse(renderAdminPage(url.origin));
      }

      /* decoy for unknown paths: look like a plain static site */
      return htmlResponse('<!doctype html><html><head><meta charset="utf-8"><title>Welcome</title></head><body style="font-family:system-ui;display:grid;place-items:center;height:100vh;margin:0;color:#444"><div><h1>It works!</h1><p>This server is up and running.</p></div></body></html>', 404);
    } catch (e) {
      return jsonResponse({ error: 'internal', message: String(e && e.message || e) }, 500);
    }
  },
};

function renderAdminPage(origin) { return ADMIN_PAGE_TEMPLATE.replace('__ORIGIN__', origin).replace('__VERSION__', VERSION); }
