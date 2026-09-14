/* ------------------------------------------------------------------ */
/* ROUTER — main fetch handler + PWA assets                             */
/* ------------------------------------------------------------------ */

const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
<stop offset="0" stop-color="#f43f5e"/><stop offset="1" stop-color="#881337"/></linearGradient>
<radialGradient id="c" cx="0.5" cy="0.35" r="0.5">
<stop offset="0" stop-color="#fbbf24"/><stop offset="1" stop-color="#f43f5e" stop-opacity="0"/></radialGradient></defs>
<rect width="64" height="64" rx="14" fill="#0a0a10"/>
<path d="M32 10c-1.8 5-6 7.2-6 12.6 0 3.4 1.9 6.3 4.2 8.4C29.6 39 27.4 44.6 22 50c7-1.6 11.2-5 13.4-9.6 2.2 4.6 6.4 8 13.4 9.6-5.4-5.4-7.6-11-8.2-19 2.3-2.1 4.2-5 4.2-8.4C44.8 17.2 40.6 15 38.8 10c-1.6 3.4-4.2 5-6.8 5s-5.2-1.6-6.8-5z" fill="url(#g)"/>
<ellipse cx="32" cy="24" rx="3.6" ry="6.5" fill="url(#c)" opacity="0.9"/>
</svg>`;

const MANIFEST_JSON = JSON.stringify({
  name: 'JavidNam | جاویدنام',
  short_name: 'JavidNam',
  description: 'پنل اشتراک جاویدنام — به یاد ۱۸ و ۱۹ دی ۱۴۰۴',
  start_url: '/',
  display: 'standalone',
  background_color: '#0a0a10',
  theme_color: '#0a0a10',
  icons: [
    { src: '/favicon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' },
  ],
});

const SW_JS = `const C='javidnam-v${'%VERSION%'}';
self.addEventListener('install',e=>{self.skipWaiting()});
self.addEventListener('activate',e=>{e.waitUntil(clients.claim())});
self.addEventListener('fetch',e=>{e.respondWith(
  fetch(e.request).then(r=>{const cp=r.clone();caches.open(C).then(c=>c.put(e.request,cp)).catch(()=>{});return r;})
  .catch(()=>caches.match(e.request))
)});`;

export default {
  async fetch(request, env, ctx) {
    initEnv(env);
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      /* --- WebSocket proxy (VLESS/Trojan) --- */
      if (request.headers.get('Upgrade') === 'websocket') {
        const settings = await getSettings();
        if (pathMatches(path, settings.proxy_path)) {
          return await handleProxy(request, ctx);
        }
        return notFound();
      }

      /* --- health & robots --- */
      if (path === '/healthz') return jsonResponse({ ok: true, app: 'javidnam', version: VERSION });
      if (path === '/robots.txt') return new Response('User-agent: *\nDisallow: /\n', { headers: { 'Content-Type': 'text/plain' } });
      if (path === '/favicon.svg') return new Response(FAVICON_SVG, { headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' } });
      if (path === '/manifest.webmanifest') return new Response(MANIFEST_JSON, { headers: { 'Content-Type': 'application/manifest+json' } });
      if (path === '/sw.js') return new Response(SW_JS.replace('%VERSION%', VERSION), { headers: { 'Content-Type': 'application/javascript', 'Cache-Control': 'public, max-age=3600' } });

      /* --- subscription --- */
      if (path.startsWith('/sub/')) return await handleSub(request, url, ctx);
      if (/^\/status\/[0-9a-f]+$/.test(path)) {
        return Response.redirect(url.origin + '/sub/' + path.split('/')[2], 302);
      }

      /* --- admin --- */
      if (path.startsWith('/api/')) return await handleAdminApi(request, url, ctx);
      if (path === '/' || path === '/index.html' || path === '/panel') {
        return htmlResponse(renderAdminPage(url.origin), 200, { 'Cache-Control': 'no-store' });
      }

      return notFound();
    } catch (e) {
      return jsonResponse({ error: 'internal', message: String(e && e.message || e) }, 500);
    }
  },
};

/* Render admin SPA shell (template from assets/admin.html at build time) */
function renderAdminPage(origin) {
  return ADMIN_PAGE_TEMPLATE.replace('__ORIGIN__', origin);
}

/* periodic safety: flush traffic counters on isolate eviction */
addEventListener('waituntilflush', () => {});
