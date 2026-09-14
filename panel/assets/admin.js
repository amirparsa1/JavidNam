/* ===================== JavidNam Admin SPA (original, GPL-3.0) ===================== */
const ORIGIN = '__ORIGIN__';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const state = { me: null, users: [], settings: null, presets: [], fpOptions: [], stats: null, page: 'dash', sel: new Set(), filter: '', q: '', deferredPrompt: null, timer: null };
const GB = 1073741824;
const fmtB = (b) => { b = Number(b) || 0; if (b >= GB) return (b / GB).toFixed(2) + ' GB'; if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB'; if (b >= 1024) return (b / 1024).toFixed(0) + ' KB'; return b + ' B'; };
const fa = (n) => String(n).replace(/\d/g, d => '۰۱۲۳۴۵۶۷۸۹'[d]);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const jdate = (ts) => { if (!ts) return '—'; try { return new Intl.DateTimeFormat('fa-IR', { dateStyle: 'medium' }).format(new Date(ts)); } catch (e) { return new Date(ts).toLocaleDateString(); } };
const jdt = (ts) => { if (!ts) return '—'; try { return new Intl.DateTimeFormat('fa-IR', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(ts)); } catch (e) { return new Date(ts).toLocaleString(); } };
const ago = (ts) => { if (!ts) return 'هرگز'; const d = Date.now() - ts; if (d < 60e3) return 'همین الان'; if (d < 3600e3) return fa(Math.floor(d / 60e3)) + ' دقیقه پیش'; if (d < 86400e3) return fa(Math.floor(d / 3600e3)) + ' ساعت پیش'; return fa(Math.floor(d / 86400e3)) + ' روز پیش'; };
function toast(msg, type = 'ok') { const t = document.createElement('div'); t.className = 'toast ' + type; t.textContent = msg; $('#toasts').appendChild(t); setTimeout(() => t.remove(), 3500); }
async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { 'Content-Type': 'application/json', 'X-JN': '1', ...(opts.headers || {}) }, body: opts.body && typeof opts.body !== 'string' ? JSON.stringify(opts.body) : opts.body });
  if (r.status === 401 && !path.includes('/api/login')) { showLogin(); throw new Error('unauthorized'); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok && !j.ok && j.error) throw new Error(j.error);
  return j;
}
function copy(text, msg = 'کپی شد ✓') { (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(() => toast(msg)).catch(() => { const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); toast(msg); }); }
function modal(html, opts = {}) {
  const root = $('#modalRoot'); root.innerHTML = `<div class="modal" id="modal"><div class="box" style="${opts.width ? 'width:min(' + opts.width + ',100%)' : ''}">${html}</div></div>`;
  const m = $('#modal'); m.addEventListener('click', e => { if (e.target === m && !opts.sticky) closeModal(); });
  return m;
}
function closeModal() { $('#modalRoot').innerHTML = ''; }
function confirmBox(title, text, okLabel = 'تأیید', cls = 'd') {
  return new Promise(res => {
    modal(`<h2>${title}<button class="x" onclick="closeModal()">✕</button></h2><p class="muted" style="margin-bottom:16px">${text}</p><div class="row" style="justify-content:flex-end"><button class="btn" id="cNo">انصراف</button><button class="btn ${cls}" id="cYes">${okLabel}</button></div>`);
    $('#cNo').onclick = () => { closeModal(); res(false); }; $('#cYes').onclick = () => { closeModal(); res(true); };
  });
}
function promptBox(title, label, def = '', type = 'text') {
  return new Promise(res => {
    modal(`<h2>${title}<button class="x" onclick="closeModal()">✕</button></h2><label>${label}</label><input id="pIn" type="${type}" value="${esc(def)}" class="ltr"><div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn" id="cNo">انصراف</button><button class="btn p" id="cYes">تأیید</button></div>`);
    $('#pIn').focus(); $('#cNo').onclick = () => { closeModal(); res(null); }; $('#cYes').onclick = () => { const v = $('#pIn').value; closeModal(); res(v); };
    $('#pIn').onkeydown = e => { if (e.key === 'Enter') $('#cYes').click(); };
  });
}
function qrInto(el, text, size = 180) {
  try { const q = qrcode(0, 'M'); q.addData(text); q.make(); el.innerHTML = q.createSvgTag({ cellSize: Math.max(2, Math.floor(size / q.getModuleCount())), margin: 0 }); } catch (e) { el.textContent = 'QR خیلی بزرگ است'; }
}

/* ---------- animated background (embers) ---------- */
(function bg() {
  const c = $('#bg'), x = c.getContext('2d'); let w, h, P = [];
  const rs = () => { w = c.width = innerWidth * devicePixelRatio; h = c.height = innerHeight * devicePixelRatio; };
  rs(); addEventListener('resize', rs);
  for (let i = 0; i < 70; i++) P.push({ x: Math.random(), y: Math.random(), r: Math.random() * 2 + .6, v: Math.random() * .0006 + .0002, o: Math.random() * .5 + .2, d: Math.random() * 6.28 });
  (function f(t) {
    x.clearRect(0, 0, w, h);
    for (const p of P) {
      p.y -= p.v; p.x += Math.sin(t / 2000 + p.d) * .00025; if (p.y < -.02) { p.y = 1.02; p.x = Math.random(); }
      const g = x.createRadialGradient(p.x * w, p.y * h, 0, p.x * w, p.y * h, p.r * 6 * devicePixelRatio);
      g.addColorStop(0, `rgba(251,113,133,${p.o})`); g.addColorStop(1, 'rgba(251,113,133,0)');
      x.fillStyle = g; x.beginPath(); x.arc(p.x * w, p.y * h, p.r * 6 * devicePixelRatio, 0, 6.28); x.fill();
    }
    requestAnimationFrame(f);
  })(0);
})();

/* ---------- PWA ---------- */
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
addEventListener('beforeinstallprompt', e => { e.preventDefault(); state.deferredPrompt = e; const b = $('#installBtn'); if (b) b.style.display = ''; });
$('#installBtn').onclick = async () => { if (!state.deferredPrompt) return; state.deferredPrompt.prompt(); await state.deferredPrompt.userChoice; state.deferredPrompt = null; $('#installBtn').style.display = 'none'; };

/* ---------- auth ---------- */
function showLogin() { $('#login').classList.remove('hidden'); $('#app').classList.add('hidden'); clearInterval(state.timer); }
async function boot() {
  try { const me = await api('/api/me'); state.me = me; enterApp(); }
  catch (e) {
    showLogin();
    try { const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); const j = await r.json(); if (j.setup) $('#setupBox').classList.remove('hidden'); } catch (e2) {}
  }
}
$('#loginBtn').onclick = login;
$('#passInput').onkeydown = e => { if (e.key === 'Enter') login(); };
async function login() {
  const pass = $('#passInput').value; const err = $('#loginErr'); err.textContent = '';
  const setup = !$('#setupBox').classList.contains('hidden');
  try {
    if (setup) { await api('/api/setup', { method: 'POST', body: { password: pass } }); }
    const j = await api('/api/login', { method: 'POST', body: { password: pass } });
    if (!j.ok) throw new Error(j.error || 'خطا');
    state.me = await api('/api/me'); enterApp();
  } catch (e) { err.textContent = e.message; }
}
async function logout() { await api('/api/logout', { method: 'POST' }); location.reload(); }
function enterApp() {
  $('#login').classList.add('hidden'); $('#app').classList.remove('hidden');
  if (state.me.colo) { $('#coloChip').textContent = '📍 ' + state.me.colo; $('#coloChip').classList.remove('hidden'); }
  $$('.ver').forEach(v => v.textContent = state.me.version);
  renderNav(); go(location.hash.replace('#', '') || 'dash');
  clearInterval(state.timer); state.timer = setInterval(() => { if (state.page === 'dash' || state.page === 'users') refreshPage(true); }, 30000);
}

/* ---------- nav ---------- */
const ICONS = {
  dash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>',
  users: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><circle cx="17" cy="9" r="2.5"/><path d="M15.5 14.5a5 5 0 0 1 6 5"/></svg>',
  net: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>',
  settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>',
  tools: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a4 4 0 0 0 5 5l-9.4 9.4a2.1 2.1 0 0 1-3-3l9.4-9.4z"/><path d="M14.7 6.3L17 4l3 3-2.3 2.3"/></svg>',
  backup: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg>',
};
const PAGES = [['dash', 'داشبورد'], ['users', 'کاربران'], ['net', 'شبکه و لوکیشن‌ها'], ['settings', 'تنظیمات'], ['tools', 'ابزارها'], ['backup', 'پشتیبان و آپدیت']];
function renderNav() {
  $('#nav').innerHTML = PAGES.map(([id, t]) => `<a data-p="${id}" class="${state.page === id ? 'on' : ''}" onclick="go('${id}')">${ICONS[id]}<span>${t}</span></a>`).join('');
  $('#mobnav').innerHTML = PAGES.map(([id, t]) => `<a data-p="${id}" class="${state.page === id ? 'on' : ''}" onclick="go('${id}')">${ICONS[id]}<span>${t.split(' ')[0]}</span></a>`).join('');
}
function go(p) { state.page = p; location.hash = p; renderNav(); $('#pageTitle').textContent = (PAGES.find(x => x[0] === p) || [])[1] || ''; refreshPage(); }
async function refreshPage(silent = false) {
  const m = $('#main'); if (!silent) m.innerHTML = '<div class="muted" style="padding:40px;text-align:center">در حال بارگذاری…</div>';
  try {
    if (state.page === 'dash') await pageDash();
    else if (state.page === 'users') await pageUsers(silent);
    else if (state.page === 'net') await pageNet();
    else if (state.page === 'settings') await pageSettings();
    else if (state.page === 'tools') await pageTools();
    else if (state.page === 'backup') await pageBackup();
  } catch (e) { if (e.message !== 'unauthorized') { m.innerHTML = `<div class="card">❌ ${esc(e.message)}</div>`; } }
}

/* ===================== DASHBOARD ===================== */
async function pageDash() {
  const s = await api('/api/stats'); state.stats = s;
  const pct = Math.min(100, Math.round(s.cf.today_requests / s.cf.daily_limit * 100));
  const usedPct = s.traffic.quota > 0 ? Math.min(100, Math.round(s.traffic.used / s.traffic.quota * 100)) : 0;
  const days = s.cf.days || [];
  const mx = Math.max(1, ...days.map(d => d.requests));
  const st = (k, v, ic, sub = '') => `<div class="card stat"><div class="ic">${ic}</div><div class="v">${v}</div><div class="k">${k}</div>${sub ? `<div class="xs muted">${sub}</div>` : ''}</div>`;
  $('#main').innerHTML = `
  <div class="grid g6 fadein">
    ${st('کل کاربران', fa(s.users.total), '👥')}
    ${st('فعال', fa(s.users.active), '✅')}
    ${st('آنلاین (۵ دقیقه)', fa(s.users.online), '🟢')}
    ${st('رو به انقضا (۷ روز)', fa(s.users.expiring_soon), '⏳')}
    ${st('منقضی‌شده', fa(s.users.expired), '⛔')}
    ${st('حجم تمام‌شده', fa(s.users.over_quota), '📦')}
  </div>
  <div class="grid g3" style="margin-top:12px">
    <div class="card">
      <h3>☁️ سهمیه‌ی Cloudflare <small>امروز (UTC)</small></h3>
      <div class="row" style="justify-content:space-between"><b style="font-size:22px">${fa(s.cf.today_requests.toLocaleString('en'))}</b><span class="muted small">از ${fa('100,000')} درخواست</span></div>
      <div class="bar ${pct > 80 ? 'w' : 'g'}" style="margin:8px 0"><i style="width:${pct}%"></i></div>
      <div class="row small muted" style="justify-content:space-between"><span>${fa(pct)}٪ مصرف شده</span><span>${fa(s.cf.today_conns)} اتصال · ${fmtB(s.cf.today_bytes)}</span></div>
      <p class="xs muted" style="margin-top:8px">شمارش داخلی پنل (درخواست‌های پروکسی + ساب + API). با رسیدن به ۱۰۰k کلودفلر ورکر رایگان را تا فردا متوقف می‌کند.</p>
    </div>
    <div class="card">
      <h3>📊 ترافیک کل</h3>
      <div class="row" style="justify-content:space-between"><b style="font-size:22px">${fmtB(s.traffic.used)}</b><span class="muted small">${s.traffic.quota > 0 ? 'از ' + fmtB(s.traffic.quota) : 'نامحدود'}</span></div>
      <div class="bar" style="margin:8px 0"><i style="width:${usedPct}%"></i></div>
      <div class="small muted">${fa(Number(s.traffic.requests || 0).toLocaleString('en'))} اتصال از ابتدا</div>
      <div class="hr"></div>
      <div class="row small"><span class="chip info">v${s.version}</span>${s.colo ? `<span class="chip">📍 ${s.colo}</span>` : ''}<span class="chip">${jdt(s.now)}</span></div>
    </div>
    <div class="card">
      <h3>📈 درخواست‌های ۳۰ روز اخیر</h3>
      <div class="spark">${days.length ? days.map(d => `<i style="height:${Math.max(3, d.requests / mx * 100)}%" data-t="${d.day}: ${d.requests}"></i>`).join('') : '<span class="muted small">هنوز داده‌ای نیست</span>'}</div>
      <div class="row small muted" style="justify-content:space-between;margin-top:6px"><span>${days[0]?.day || ''}</span><span>${days[days.length - 1]?.day || ''}</span></div>
    </div>
  </div>
  <div class="grid g2" style="margin-top:12px">
    <div class="card">
      <h3>🏆 پرمصرف‌ترین کاربران</h3>
      <div class="tbl"><table><thead><tr><th>نام</th><th>مصرف</th><th>اتصال</th><th>آخرین فعالیت</th></tr></thead><tbody>
      ${(s.top || []).map(u => `<tr><td><b>${esc(u.name)}</b></td><td class="mono">${fmtB(u.used_bytes)}</td><td>${fa(u.used_requests || 0)}</td><td class="small muted">${ago(u.last_seen_at)}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">—</td></tr>'}
      </tbody></table></div>
    </div>
    <div class="card">
      <h3>⚡ دسترسی سریع</h3>
      <div class="grid g2">
        <button class="btn p" onclick="openUserModal()">➕ کاربر جدید</button>
        <button class="btn" onclick="go('net')">🌍 لوکیشن‌ها</button>
        <button class="btn" onclick="go('tools')">🧪 تست و اسکنر</button>
        <button class="btn" onclick="go('backup')">💾 پشتیبان‌گیری</button>
      </div>
      <div class="hr"></div>
      <div class="small muted">🌷 جاویدنام — نرم‌افزار آزاد (GPL-3.0). بدون تبلیغ، بدون قفل، بدون DRM. <a href="https://github.com/amirparsa1/JavidNam" target="_blank" style="color:#fda4af">GitHub</a></div>
    </div>
  </div>`;
}

/* ===================== USERS ===================== */
async function loadUsers() { const j = await api('/api/users?q=' + encodeURIComponent(state.q) + '&filter=' + state.filter); state.users = j.users; }
async function pageUsers(silent) {
  if (!state.settings) await loadSettings();
  await loadUsers();
  const m = $('#main');
  if (!silent || !$('#usersTable')) {
    m.innerHTML = `
    <div class="card fadein">
      <div class="row" style="margin-bottom:12px">
        <input id="userSearch" placeholder="🔍 جستجو نام / UUID / یادداشت" value="${esc(state.q)}" style="max-width:300px">
        <select id="userFilter" style="max-width:170px">
          ${[['', 'همه'], ['active', 'فعال'], ['online', 'آنلاین'], ['disabled', 'غیرفعال'], ['expired', 'منقضی'], ['overquota', 'حجم تمام'], ['pending', 'منتظر اولین اتصال']].map(([v, t]) => `<option value="${v}" ${state.filter === v ? 'selected' : ''}>${t}</option>`).join('')}
        </select>
        <span class="chip" id="userCount"></span>
        <div class="grow"></div>
        <button class="btn" onclick="openBulkCreate()">📚 ساخت گروهی</button>
        <button class="btn p" onclick="openUserModal()">➕ کاربر جدید</button>
      </div>
      <div class="tbl"><table id="usersTable"><thead><tr>
        <th style="width:30px"><input type="checkbox" id="selAll"></th><th>کاربر</th><th>وضعیت</th><th>حجم</th><th>زمان</th><th>اتصال / IP</th><th>لوکیشن</th><th style="text-align:left">عملیات</th>
      </tr></thead><tbody id="usersBody"></tbody></table></div>
      <div id="bulkbar" class="hidden"></div>
    </div>`;
    $('#userSearch').oninput = debounce(() => { state.q = $('#userSearch').value; pageUsers(true); }, 300);
    $('#userFilter').onchange = () => { state.filter = $('#userFilter').value; pageUsers(true); };
    $('#selAll').onchange = (e) => { state.sel = new Set(e.target.checked ? state.users.map(u => u.id) : []); renderUsersBody(); };
  }
  renderUsersBody();
}
function debounce(f, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => f(...a), ms); }; }
function stateChip(u) {
  const s = u.state;
  if (!s.active) return '<span class="chip bad">غیرفعال</span>';
  if (s.expired) return '<span class="chip bad">منقضی</span>';
  if (s.overQuota) return '<span class="chip bad">حجم تمام</span>';
  if (s.overRequests) return '<span class="chip bad">سقف اتصال</span>';
  if (s.pending) return '<span class="chip warn">منتظر اتصال</span>';
  const online = u.last_seen_at && Date.now() - u.last_seen_at < 5 * 60000;
  return `<span class="chip ok"><span class="dot ${online ? 'on' : ''}"></span>${online ? 'آنلاین' : 'فعال'}</span>`;
}
function renderUsersBody() {
  const locs = (state.settings && state.settings.locations) || [];
  $('#userCount').textContent = fa(state.users.length) + ' کاربر';
  $('#usersBody').innerHTML = state.users.map(u => {
    const q = u.quota_bytes > 0 ? Math.min(100, Math.round(u.used_bytes / u.quota_bytes * 100)) : 0;
    const userLocs = u.locations ? u.locations.map(id => (locs.find(l => l.id === id) || {}).name || id).join('، ') : 'همه';
    return `<tr>
      <td><input type="checkbox" ${state.sel.has(u.id) ? 'checked' : ''} onchange="toggleSel('${u.id}',this.checked)"></td>
      <td><div class="uname">${esc(u.name)} ${u.block_ads ? '<span class="chip xs" title="مسدودسازی تبلیغات">🛡</span>' : ''}${u.block_nsfw ? '<span class="chip xs" title="فیلتر محتوای بزرگسال">🔞</span>' : ''}</div><small class="mono xs muted">${u.uuid.slice(0, 8)}… ${u.note ? '· ' + esc(u.note) : ''}</small></td>
      <td>${stateChip(u)}<div class="xs muted">${ago(u.last_seen_at)}</div></td>
      <td style="min-width:120px"><div class="small">${fmtB(u.used_bytes)} <span class="muted">/ ${u.quota_bytes > 0 ? fmtB(u.quota_bytes) : '∞'}</span></div><div class="bar ${q > 85 ? 'w' : ''}"><i style="width:${q}%"></i></div>${u.reset_hours ? `<div class="xs muted">ریست هر ${fa(u.reset_hours)}h</div>` : ''}</td>
      <td class="small">${u.expiry_at ? `${jdate(u.expiry_at)}<div class="xs muted">${u.state.daysLeft > 0 ? fa(u.state.daysLeft) + ' روز مانده' : 'تمام شده'}</div>` : u.start_on_first && u.days ? `<span class="muted">${fa(u.days)} روز پس از اولین اتصال</span>` : '<span class="muted">نامحدود</span>'}</td>
      <td class="small"><div>${fa(u.used_requests || 0)}${u.max_requests ? ' / ' + fa(u.max_requests) : ''}</div><div class="xs muted">${u.ip_limit ? fa(u.online_ips) + ' / ' + fa(u.ip_limit) + ' IP' : 'IP نامحدود'}</div></td>
      <td class="small muted" style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(userLocs)}">${esc(userLocs)}</td>
      <td><div class="acts">
        <button class="btn i" title="لینک ساب و QR" onclick="openShare('${u.id}')">🔗</button>
        <button class="btn i" title="ویرایش" onclick="openUserModal('${u.id}')">✏️</button>
        <button class="btn i" title="${u.active ? 'غیرفعال کن' : 'فعال کن'}" onclick="toggleActive('${u.id}',${u.active ? 0 : 1})">${u.active ? '⏸' : '▶️'}</button>
        <button class="btn i" title="ریست حجم" onclick="resetUser('${u.id}','traffic')">♻️</button>
        <button class="btn i d" title="حذف" onclick="delUser('${u.id}')">🗑</button>
      </div></td></tr>`;
  }).join('') || `<tr><td colspan="8" class="muted" style="text-align:center;padding:30px">کاربری نیست. با «➕ کاربر جدید» شروع کن.</td></tr>`;
  renderBulkbar();
}
function toggleSel(id, on) { if (on) state.sel.add(id); else state.sel.delete(id); renderBulkbar(); }
function renderBulkbar() {
  const b = $('#bulkbar'); if (!b) return;
  if (!state.sel.size) { b.classList.add('hidden'); return; }
  b.classList.remove('hidden');
  b.innerHTML = `<div class="row"><b>${fa(state.sel.size)} انتخاب‌شده</b>
    <button class="btn s g" onclick="bulk('activate')">▶️ فعال</button><button class="btn s" onclick="bulk('deactivate')">⏸ غیرفعال</button>
    <button class="btn s" onclick="bulk('reset_traffic')">♻️ ریست حجم</button><button class="btn s" onclick="bulk('reset_expiry')">⏰ ریست زمان</button>
    <button class="btn s" onclick="bulkExtend()">➕ تمدید</button><button class="btn s" onclick="bulkAddGb()">📦 افزودن حجم</button>
    <button class="btn s" onclick="bulkLocations()">🌍 لوکیشن</button>
    <button class="btn s" onclick="bulk('block_ads')">🛡 تبلیغات</button><button class="btn s" onclick="bulk('block_nsfw')">🔞 فیلتر</button>
    <button class="btn s d" onclick="bulk('delete')">🗑 حذف</button>
    <div class="grow"></div><button class="btn s" onclick="state.sel.clear();renderUsersBody()">✕</button></div>`;
}
async function bulk(action, extra = {}) {
  if (action === 'delete' && !(await confirmBox('حذف گروهی', `${fa(state.sel.size)} کاربر برای همیشه حذف شوند؟`, 'حذف'))) return;
  await api('/api/bulk', { method: 'POST', body: { action, ids: [...state.sel], ...extra } });
  toast('انجام شد'); state.sel.clear(); pageUsers(true);
}
async function bulkExtend() { const d = await promptBox('تمدید گروهی', 'چند روز اضافه شود؟', '30', 'number'); if (d) bulk('extend', { days: Number(d) }); }
async function bulkAddGb() { const g = await promptBox('افزودن حجم گروهی', 'چند گیگابایت اضافه شود؟', '10', 'number'); if (g) bulk('add_gb', { gb: Number(g) }); }
async function bulkLocations() {
  const locs = state.settings.locations;
  modal(`<h2>🌍 لوکیشن‌های گروهی<button class="x" onclick="closeModal()">✕</button></h2><p class="small muted">هیچ‌کدام = همه‌ی لوکیشن‌ها</p><div class="locpick" id="blp">${locs.map(l => `<label><input type="checkbox" value="${l.id}">${esc(l.name)}</label>`).join('')}</div><div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn p" id="blOk">اعمال</button></div>`);
  $('#blOk').onclick = () => { const ids = $$('#blp input:checked').map(i => i.value); closeModal(); bulk('set_locations', { locations: ids }); };
}
async function toggleActive(id, active) { await api('/api/users/' + id, { method: 'PATCH', body: { active: !!active } }); toast(active ? 'فعال شد' : 'غیرفعال شد'); pageUsers(true); }
async function resetUser(id, what) {
  const body = what === 'traffic' ? { traffic: true, requests: true } : what === 'expiry' ? { expiry: true } : { traffic: true, requests: true, expiry: true };
  await api('/api/users/' + id + '/reset', { method: 'POST', body }); toast('ریست شد'); pageUsers(true);
}
async function delUser(id) {
  const u = state.users.find(x => x.id === id);
  if (!(await confirmBox('حذف کاربر', `«${esc(u.name)}» برای همیشه حذف شود؟`, 'حذف'))) return;
  await api('/api/users/' + id, { method: 'DELETE' }); toast('حذف شد'); pageUsers(true);
}

/* ---- user modal (create / edit) ---- */
function openUserModal(id) {
  const u = id ? state.users.find(x => x.id === id) : null;
  const locs = state.settings.locations;
  const v = (k, d = '') => u ? (u[k] ?? d) : d;
  modal(`
  <h2>${u ? '✏️ ویرایش ' + esc(u.name) : '➕ کاربر جدید'}<button class="x" onclick="closeModal()">✕</button></h2>
  <div class="tabs"><button class="on" data-t="t1">پایه</button><button data-t="t2">محدودیت‌ها</button><button data-t="t3">لوکیشن و فیلتر</button>${u ? '<button data-t="t4">پیشرفته</button>' : ''}</div>
  <div id="t1">
    <div class="grid g2">
      <div><label>نام کاربر *</label><input id="f_name" value="${esc(v('name'))}" placeholder="مثلاً: علی"></div>
      <div><label>یادداشت</label><input id="f_note" value="${esc(v('note'))}" placeholder="اختیاری"></div>
      <div><label>حجم (GB) — ۰ = نامحدود</label><input id="f_quota" type="number" min="0" step="0.5" value="${u ? (u.quota_bytes / GB) : 20}" class="ltr"></div>
      <div><label>مدت (روز) — ۰ = نامحدود</label><input id="f_days" type="number" min="0" value="${v('days', 30)}" class="ltr"></div>
    </div>
    <div class="grid g2" style="margin-top:10px">
      <div class="sw"><div><b>شروع از اولین اتصال</b><small>شمارش زمان بعد از اولین وصل‌شدن</small></div><label class="switch"><input type="checkbox" id="f_sof" ${v('start_on_first') ? 'checked' : ''}><i></i></label></div>
      <div class="sw"><div><b>فعال</b><small>اجازه‌ی اتصال</small></div><label class="switch"><input type="checkbox" id="f_active" ${u ? (u.active ? 'checked' : '') : 'checked'}><i></i></label></div>
    </div>
    ${u ? `<div class="grid g2" style="margin-top:10px"><div><label>➕ تمدید (روز اضافه)</label><input id="f_extend" type="number" min="0" value="0" class="ltr"></div><div><label>📦 افزودن حجم (GB اضافه)</label><input id="f_addgb" type="number" min="0" step="0.5" value="0" class="ltr"></div></div>` : ''}
  </div>
  <div id="t2" class="hidden">
    <div class="grid g2">
      <div><label>محدودیت دستگاه هم‌زمان (IP) — ۰ = نامحدود</label><input id="f_ip" type="number" min="0" max="50" value="${v('ip_limit', 0)}" class="ltr"></div>
      <div><label>سقف تعداد اتصال — ۰ = نامحدود</label><input id="f_maxreq" type="number" min="0" value="${v('max_requests', 0)}" class="ltr"></div>
      <div><label>ریست خودکار حجم هر N ساعت — ۰ = خاموش</label><input id="f_reset" type="number" min="0" value="${v('reset_hours', 0)}" class="ltr"><span class="xs muted">مثال: ۲۴ = روزانه، ۷۲۰ = ماهانه</span></div>
      ${!u ? `<div><label>UUID سفارشی (اختیاری)</label><input id="f_uuid" class="mono" placeholder="خالی = تولید خودکار"></div>` : ''}
    </div>
  </div>
  <div id="t3" class="hidden">
    <label>لوکیشن‌های مجاز <span class="muted">(هیچ‌کدام = همه · حداکثر ۸)</span></label>
    <div class="locpick" id="f_locs">${locs.map(l => `<label><input type="checkbox" value="${l.id}" ${u && u.locations && u.locations.includes(l.id) ? 'checked' : ''}>${esc(l.name)}${l.enabled ? '' : ' <span class="xs muted">(خاموش)</span>'}</label>`).join('')}</div>
    <div class="grid g2" style="margin-top:12px">
      <div class="sw"><div><b>🛡 مسدودسازی تبلیغات</b><small>DNS فیلتر AdGuard روی اتصال این کاربر</small></div><label class="switch"><input type="checkbox" id="f_ads" ${v('block_ads') ? 'checked' : ''}><i></i></label></div>
      <div class="sw"><div><b>🔞 فیلتر محتوای بزرگسال</b><small>Cloudflare Family (1.1.1.3)</small></div><label class="switch"><input type="checkbox" id="f_nsfw" ${v('block_nsfw') ? 'checked' : ''}><i></i></label></div>
    </div>
  </div>
  ${u ? `<div id="t4" class="hidden">
    <div class="grid g2">
      <div><label>UUID</label><div class="row"><input class="mono" value="${u.uuid}" readonly><button class="btn i" onclick="copy('${u.uuid}')">📋</button></div></div>
      <div><label>توکن ساب</label><div class="row"><input class="mono" value="${u.sub_token}" readonly><button class="btn i" onclick="copy('${u.sub_token}')">📋</button></div></div>
    </div>
    <div class="row" style="margin-top:12px">
      <button class="btn d s" onclick="regen('${u.id}','uuid')">🔁 تعویض UUID</button>
      <button class="btn d s" onclick="regen('${u.id}','token')">🔁 تعویض لینک ساب</button>
      <button class="btn s" onclick="resetUser('${u.id}','expiry');closeModal()">⏰ ریست زمان</button>
    </div>
    <div class="hr"></div>
    <div class="small muted">ساخته‌شده: ${jdt(u.created_at)} · اولین اتصال: ${jdt(u.first_connect_at)} · آخرین IP: <span class="mono">${esc(u.last_ip || '—')}</span></div>
  </div>` : ''}
  <div id="mErr" class="small" style="color:#fda4af;min-height:20px;margin-top:8px"></div>
  <div class="row" style="justify-content:flex-end"><button class="btn" onclick="closeModal()">انصراف</button><button class="btn p" id="mSave">${u ? 'ذخیره' : 'ساخت کاربر'}</button></div>`, { width: '720px' });
  $$('.tabs button').forEach(b => b.onclick = () => { $$('.tabs button').forEach(x => x.classList.remove('on')); b.classList.add('on'); ['t1', 't2', 't3', 't4'].forEach(t => $('#' + t)?.classList.toggle('hidden', t !== b.dataset.t)); });
  $('#mSave').onclick = async () => {
    const body = {
      name: $('#f_name').value, note: $('#f_note').value, quota_gb: Number($('#f_quota').value), days: Number($('#f_days').value),
      start_on_first: $('#f_sof').checked, active: $('#f_active').checked, ip_limit: Number($('#f_ip').value), max_requests: Number($('#f_maxreq').value),
      reset_hours: Number($('#f_reset').value), locations: $$('#f_locs input:checked').map(i => i.value), block_ads: $('#f_ads').checked, block_nsfw: $('#f_nsfw').checked,
    };
    if (!body.name.trim()) { $('#mErr').textContent = 'نام الزامی است'; return; }
    if (!u && $('#f_uuid') && $('#f_uuid').value.trim()) body.uuid = $('#f_uuid').value.trim();
    if (u) { if (Number($('#f_extend').value) > 0) body.extend_days = Number($('#f_extend').value); if (Number($('#f_addgb').value) > 0) body.add_gb = Number($('#f_addgb').value); }
    try {
      $('#mSave').disabled = true;
      if (u) {
        /* don't overwrite expiry when days unchanged */
        if (Number(body.days) === Number(u.days) && body.start_on_first === u.start_on_first) delete body.days;
        await api('/api/users/' + u.id, { method: 'PATCH', body }); toast('ذخیره شد'); closeModal(); pageUsers(true);
      } else { const j = await api('/api/users', { method: 'POST', body }); toast('کاربر ساخته شد'); closeModal(); await pageUsers(true); openShare(j.user.id, j.user); }
    } catch (e) { $('#mErr').textContent = e.message; $('#mSave').disabled = false; }
  };
}
async function regen(id, what) {
  if (!(await confirmBox('تعویض ' + (what === 'uuid' ? 'UUID' : 'لینک ساب'), 'کانفیگ‌های قبلی کاربر از کار می‌افتد. ادامه؟', 'تعویض'))) return;
  await api('/api/users/' + id, { method: 'PATCH', body: what === 'uuid' ? { regen_uuid: true } : { regen_token: true } }); toast('انجام شد'); closeModal(); pageUsers(true);
}
function openBulkCreate() {
  modal(`<h2>📚 ساخت گروهی کاربر<button class="x" onclick="closeModal()">✕</button></h2>
  <div class="grid g2">
    <div><label>پیشوند نام</label><input id="b_name" value="user"></div><div><label>تعداد (حداکثر ۵۰)</label><input id="b_count" type="number" min="1" max="50" value="10" class="ltr"></div>
    <div><label>حجم (GB)</label><input id="b_quota" type="number" min="0" value="20" class="ltr"></div><div><label>مدت (روز)</label><input id="b_days" type="number" min="0" value="30" class="ltr"></div>
    <div><label>محدودیت IP</label><input id="b_ip" type="number" min="0" value="2" class="ltr"></div>
    <div class="sw"><div><b>شروع از اولین اتصال</b></div><label class="switch"><input type="checkbox" id="b_sof" checked><i></i></label></div>
  </div>
  <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn p" id="bGo">ساخت</button></div>`);
  $('#bGo').onclick = async () => {
    $('#bGo').disabled = true;
    try {
      const j = await api('/api/users', { method: 'POST', body: { name: $('#b_name').value, count: Number($('#b_count').value), quota_gb: Number($('#b_quota').value), days: Number($('#b_days').value), ip_limit: Number($('#b_ip').value), start_on_first: $('#b_sof').checked } });
      closeModal(); toast(fa(j.users.length) + ' کاربر ساخته شد'); await pageUsers(true);
      const txt = j.users.map(u => `${u.name}\t${u.sub_url}`).join('\n');
      modal(`<h2>✅ لینک‌های ساب<button class="x" onclick="closeModal()">✕</button></h2><textarea style="min-height:220px">${esc(txt)}</textarea><div class="row" style="justify-content:flex-end;margin-top:10px"><button class="btn p" onclick="copy(${JSON.stringify(txt).replace(/"/g, '&quot;')})">📋 کپی همه</button></div>`);
    } catch (e) { toast(e.message, 'err'); $('#bGo').disabled = false; }
  };
}

/* ---- share modal (sub link, QR, formats, per-config) ---- */
async function openShare(id, uObj) {
  const u = uObj || state.users.find(x => x.id === id);
  const j = await fetch(u.sub_url + '/links').then(r => r.json()).catch(() => ({ links: [] }));
  const links = j.links || [];
  modal(`<h2>🔗 اشتراک ${esc(u.name)}<button class="x" onclick="closeModal()">✕</button></h2>
  <div class="row" style="align-items:flex-start">
    <div class="qr" id="shQr"></div>
    <div class="grow">
      <label>لینک ساب (همه‌ی کلاینت‌ها)</label><div class="row"><input class="mono" value="${u.sub_url}" readonly><button class="btn i" onclick="copy('${u.sub_url}','لینک ساب کپی شد')">📋</button></div>
      <div class="row" style="margin-top:8px;gap:6px">
        <button class="btn s" onclick="copy('${u.sub_url}/b64','کپی شد')">Base64</button>
        <button class="btn s" onclick="copy('${u.sub_url}/clash','کپی شد')">Clash / Mihomo</button>
        <button class="btn s" onclick="copy('${u.sub_url}/sb','کپی شد')">sing-box</button>
        <button class="btn s" onclick="window.open('${u.status_url}','_blank')">📊 صفحه وضعیت</button>
      </div>
      <div class="row" style="margin-top:8px;gap:6px">
        <a class="btn s b" href="hiddify://import/${u.sub_url}">Hiddify</a>
        <a class="btn s b" href="v2rayng://install-sub?url=${encodeURIComponent(u.sub_url)}&name=${encodeURIComponent('JavidNam ' + u.name)}">v2rayNG</a>
        <a class="btn s b" href="streisand://import/${u.sub_url}">Streisand</a>
        <a class="btn s b" href="sing-box://import-remote-profile?url=${encodeURIComponent(u.sub_url + '/sb')}#JavidNam">sing-box</a>
        <a class="btn s b" href="clash://install-config?url=${encodeURIComponent(u.sub_url + '/clash')}">Clash</a>
      </div>
    </div>
  </div>
  <div class="hr"></div>
  <label>کانفیگ‌های تکی</label>
  <div class="grid" style="gap:6px">${links.map((l, i) => `<div class="row" style="border:1px solid var(--line);border-radius:10px;padding:6px 10px"><span class="chip ${l.proto === 'vless' ? 'info' : 'vio'}">${l.proto.toUpperCase()}</span><b class="small">${esc(l.name)}</b><span class="xs muted mono">${esc(l.host)}:${l.port}</span><div class="grow"></div><button class="btn s" onclick="copy(${JSON.stringify(l.link).replace(/"/g, '&quot;')})">📋</button><button class="btn s" onclick="qrInto($('#shQr'),${JSON.stringify(l.link).replace(/"/g, '&quot;')},200)">QR</button></div>`).join('') || '<span class="muted small">لوکیشنی برای این کاربر فعال نیست</span>'}</div>`, { width: '760px' });
  qrInto($('#shQr'), u.sub_url, 200);
}

/* ===================== NETWORK / LOCATIONS ===================== */
async function loadSettings() { const j = await api('/api/settings'); state.settings = j.settings; state.presets = j.presets; state.fpOptions = j.fp_options; }
async function pageNet() {
  await loadSettings();
  const s = state.settings;
  $('#main').innerHTML = `
  <div class="card fadein">
    <h3>🌍 لوکیشن‌ها <small>هر لوکیشن = یک آدرس ورودی + یک مسیر خروجی (outbound). حداکثر ۱۶.</small></h3>
    <div id="locList"></div>
    <div class="row"><button class="btn" onclick="addLoc()">➕ لوکیشن جدید</button><button class="btn s" onclick="addLoc({name:'IP تمیز',host:'__CLEAN_IP__'})">➕ IP تمیز</button><button class="btn s" onclick="addLoc({name:'اصلی',host:'__PANEL_HOST__'})">➕ دامنه پنل</button><div class="grow"></div><button class="btn p" onclick="saveLocs()">💾 ذخیره لوکیشن‌ها</button></div>
    <div class="xs muted" style="margin-top:10px;line-height:1.9">
      <b>Host</b>: آدرس ورودی کلاینت — دامنه‌ی پنل، دامنه‌ی کاستوم متصل به ورکر، یا <code>__CLEAN_IP__</code> (از لیست IP تمیز با چرخش خودکار) / <code>__PANEL_HOST__</code>.<br>
      <b>Outbound</b>: مسیر خروجی از ورکر — <code>direct</code> · <code>proxyip:host[:port]</code> (برای سایت‌های پشت کلودفلر) · <code>socks5://user:pass@host:port</code> (VIP اختصاصی). اگر خراب شود، خودکار به مسیر بعدی/استخر VIP می‌رود.
    </div>
  </div>
  <div class="grid g2" style="margin-top:12px">
    <div class="card">
      <h3>🧊 IP تمیز و چرخش خودکار</h3>
      <label>لیست IP/دامنه‌ی تمیز (هر خط یکی)</label><textarea id="n_clean" style="min-height:120px">${esc((s.clean_ips || []).join('\n'))}</textarea>
      <div class="grid g2" style="margin-top:8px">
        <div><label>تعداد IP در هر ساب</label><input id="n_cleancount" type="number" min="1" max="8" value="${s.clean_count}" class="ltr"></div>
        <div><label>چرخش هر N دقیقه (۰ = ثابت برای هر کاربر)</label><input id="n_rotate" type="number" min="0" value="${s.rotate_minutes}" class="ltr"></div>
      </div>
      <p class="xs muted" style="margin-top:6px">با چرخش، لینک‌های ساب هر N دقیقه IP‌های متفاوتی از این لیست می‌گیرند (کلاینت‌ها هر ۶ ساعت ساب را رفرش می‌کنند). IP تمیز را با «ابزارها → اسکنر» پیدا کن.</p>
    </div>
    <div class="card">
      <h3>🛰 استخر پروکسی VIP و ProxyIP</h3>
      <label>ProxyIP سراسری (برای سایت‌های پشت کلودفلر)</label><input id="n_proxyip" class="ltr mono" value="${esc(s.proxy_ip)}" placeholder="مثال: proxyip.example.com یا 1.2.3.4:443">
      <label style="margin-top:8px">استخر VIP (هر خط یکی — proxyip:… یا socks5://…)</label><textarea id="n_pool" style="min-height:100px">${esc((s.proxy_ips || []).join('\n'))}</textarea>
      <div class="sw" style="margin-top:8px"><div><b>دریافت خودکار استخر از مخزن</b><small>وقتی استخر خالی است، از GitHub جاویدنام بارگیری می‌شود</small></div><label class="switch"><input type="checkbox" id="n_autoproxy" ${s.auto_proxy ? 'checked' : ''}><i></i></label></div>
      <div class="row" style="margin-top:8px"><button class="btn s" onclick="checkPool()">🩺 تست استخر</button><span class="xs muted">اتصال ورکر → پروکسی → google.com:443</span></div>
      <pre class="out hidden" id="poolOut"></pre>
    </div>
  </div>
  <div class="grid g2" style="margin-top:12px">
    <div class="card">
      <h3>🧠 مسیر هوش مصنوعی <small>دور زدن تحریم Gemini/ChatGPT/Claude…</small></h3>
      <label>خروجی برای دامنه‌های AI</label>
      <select id="n_airoute"><option value="" ${!s.ai_route ? 'selected' : ''}>خاموش (مسیر عادی)</option><option value="pool" ${s.ai_route === 'pool' ? 'selected' : ''}>استخر VIP</option><option value="custom" ${s.ai_route && s.ai_route !== 'pool' ? 'selected' : ''}>سفارشی…</option></select>
      <input id="n_airoute_custom" class="ltr mono ${s.ai_route && s.ai_route !== 'pool' ? '' : 'hidden'}" style="margin-top:6px" value="${esc(s.ai_route && s.ai_route !== 'pool' ? s.ai_route : '')}" placeholder="socks5://user:pass@host:port یا proxyip:host">
      <label style="margin-top:8px">دامنه‌های AI</label><textarea id="n_aidomains" style="min-height:110px">${esc((s.ai_domains || []).join('\n'))}</textarea>
      <p class="xs muted">اتصال مستقیم از لبه‌ی کلودفلر معمولاً از کشورهای تحریم‌نشده خارج می‌شود؛ اگر باز هم خطای منطقه گرفتی، یک SOCKS5 روی VPS آمریکا/اروپا بگذار و این‌جا مسیر بده.</p>
    </div>
    <div class="card">
      <h3>🚫 مسدودسازی سراسری</h3>
      <label>دامنه‌های مسدود برای همه‌ی کاربران (هر خط یکی)</label><textarea id="n_block" style="min-height:110px">${esc((s.block_hosts || []).join('\n'))}</textarea>
      <label style="margin-top:8px">DNS-over-HTTPS برای درخواست‌های UDP/53</label><input id="n_dns" class="ltr mono" value="${esc(s.dns)}">
      <p class="xs muted">فیلتر تبلیغات/محتوا به‌صورت جداگانه برای هر کاربر در فرم کاربر فعال می‌شود.</p>
    </div>
  </div>
  <div class="row" style="margin-top:12px;justify-content:flex-end"><button class="btn p" onclick="saveNet()">💾 ذخیره تنظیمات شبکه</button></div>`;
  $('#n_airoute').onchange = () => $('#n_airoute_custom').classList.toggle('hidden', $('#n_airoute').value !== 'custom');
  renderLocs();
}
function renderLocs() {
  const locs = state.settings.locations;
  $('#locList').innerHTML = locs.map((l, i) => `<div class="loc-row" data-i="${i}">
    <div><label>فعال</label><label class="switch"><input type="checkbox" class="l_en" ${l.enabled ? 'checked' : ''}><i></i></label></div>
    <div><label>نام</label><input class="l_name" value="${esc(l.name)}"></div>
    <div><label>Host / آدرس</label><input class="l_host ltr mono" value="${esc(l.host)}" list="hostHints"></div>
    <div><label>پورت</label><input class="l_port ltr" type="number" value="${l.port}"></div>
    <div><label>SNI (اختیاری)</label><input class="l_sni ltr mono" value="${esc(l.sni || '')}" placeholder="پیش‌فرض: خودکار"></div>
    <div><label>Outbound</label><input class="l_out ltr mono" value="${esc(l.out || 'direct')}" list="outHints"></div>
    <div><label>TLS</label><label class="switch"><input type="checkbox" class="l_tls" ${l.tls ? 'checked' : ''}><i></i></label></div>
    <div><button class="btn i d" onclick="state.settings.locations.splice(${i},1);renderLocs()">🗑</button></div>
    <input type="hidden" class="l_id" value="${esc(l.id)}">
  </div>`).join('') + `<datalist id="hostHints"><option value="__PANEL_HOST__"><option value="__CLEAN_IP__"></datalist><datalist id="outHints"><option value="direct"><option value="proxyip:"><option value="socks5://"></datalist>`;
}
function collectLocs() {
  return $$('.loc-row').map(r => ({ id: $('.l_id', r).value, enabled: $('.l_en', r).checked, name: $('.l_name', r).value, host: $('.l_host', r).value.trim(), port: Number($('.l_port', r).value) || 443, sni: $('.l_sni', r).value.trim(), out: $('.l_out', r).value.trim() || 'direct', tls: $('.l_tls', r).checked }));
}
function addLoc(p = {}) { state.settings.locations = collectLocs(); state.settings.locations.push({ id: 'loc' + Math.random().toString(36).slice(2, 6), name: p.name || 'لوکیشن جدید', host: p.host || '', port: 443, tls: true, sni: '', out: 'direct', enabled: true }); renderLocs(); }
async function saveLocs() { try { const j = await api('/api/settings', { method: 'PUT', body: { locations: collectLocs() } }); state.settings = j.settings; renderLocs(); toast('لوکیشن‌ها ذخیره شد'); } catch (e) { toast(e.message, 'err'); } }
async function saveNet() {
  const ai = $('#n_airoute').value === 'custom' ? $('#n_airoute_custom').value.trim() : $('#n_airoute').value;
  try {
    const j = await api('/api/settings', { method: 'PUT', body: { clean_ips: $('#n_clean').value, clean_count: Number($('#n_cleancount').value), rotate_minutes: Number($('#n_rotate').value), proxy_ip: $('#n_proxyip').value.trim(), proxy_ips: $('#n_pool').value, auto_proxy: $('#n_autoproxy').checked, ai_route: ai, ai_domains: $('#n_aidomains').value, block_hosts: $('#n_block').value, dns: $('#n_dns').value.trim(), locations: collectLocs() } });
    state.settings = j.settings; toast('ذخیره شد');
  } catch (e) { toast(e.message, 'err'); }
}
async function checkPool() {
  const out = $('#poolOut'); out.classList.remove('hidden'); out.textContent = 'در حال تست…';
  const j = await api('/api/tools/proxycheck', { method: 'POST', body: { list: $('#n_pool').value } });
  out.textContent = j.results.map(r => `${r.ok ? '✅' : '❌'} ${r.spec}  ${r.ms}ms ${r.error || ''}`).join('\n') || 'استخر خالی است';
}

/* ===================== SETTINGS ===================== */
async function pageSettings() {
  await loadSettings(); const s = state.settings;
  $('#main').innerHTML = `
  <div class="grid g2 fadein">
    <div class="card">
      <h3>🎭 ضدفیلتر و TLS</h3>
      <div class="grid g2">
        <div><label>Fingerprint (uTLS)</label><select id="s_fp">${state.fpOptions.map(f => `<option ${s.fp === f ? 'selected' : ''}>${f}</option>`).join('')}</select></div>
        <div><label>ALPN</label><input id="s_alpn" class="ltr mono" value="${esc(s.alpn)}"></div>
      </div>
      <div class="sw" style="margin-top:10px"><div><b>TLS Fragment</b><small>شکستن ClientHello برای عبور از DPI (در کانفیگ‌ها اعمال می‌شود)</small></div><label class="switch"><input type="checkbox" id="s_frag" ${s.frag_enabled ? 'checked' : ''}><i></i></label></div>
      <div class="grid g3" style="margin-top:10px">
        <div><label>Length</label><input id="s_fraglen" class="ltr mono" value="${esc(s.frag_len)}"></div>
        <div><label>Interval</label><input id="s_fragint" class="ltr mono" value="${esc(s.frag_int)}"></div>
        <div><label>Packets</label><select id="s_fragpk">${['tlshello', '1-1', '1-2', '1-3'].map(v => `<option ${s.frag_packets === v ? 'selected' : ''}>${v}</option>`).join('')}</select></div>
      </div>
      <div class="row" style="margin-top:8px;gap:6px">${state.presets.filter(p => p.id !== 'auto').map(p => `<button class="btn s" onclick="applyPreset('${p.id}')">${esc(p.label)}</button>`).join('')}</div>
      <div class="hr"></div>
      <div class="grid g2">
        <div><label>SNI Mask (TLS masking)</label><input id="s_sni" class="ltr mono" value="${esc(s.sni_mask)}" placeholder="خالی = آدرس لوکیشن"></div>
        <div><label>Host Mask (WS Host header)</label><input id="s_host" class="ltr mono" value="${esc(s.host_mask)}" placeholder="خالی = دامنه پنل"></div>
      </div>
      <p class="xs muted" style="margin-top:6px">⚠️ SNI/Host Mask فقط وقتی کار می‌کند که آن دامنه واقعاً روی همین ورکر (Custom Domain / Route) باشد یا از IP تمیز استفاده کنی — وگرنه اتصال قطع می‌شود.</p>
    </div>
    <div class="card">
      <h3>🏷 برندینگ و صفحه‌ی ساب</h3>
      <div><label>عنوان پنل</label><input id="s_title" value="${esc(s.title)}"></div>
      <div style="margin-top:8px"><label>پیام خوش‌آمد صفحه‌ی ساب</label><input id="s_welcome" value="${esc(s.welcome)}"></div>
      <div style="margin-top:8px"><label>لینک پشتیبانی (تلگرام/…)</label><input id="s_contact" class="ltr" value="${esc(s.contact)}" placeholder="https://t.me/…"></div>
      <div class="sw" style="margin-top:10px"><div><b>نمایش یادبود در صفحه‌ی ساب</b><small>🌷 به یاد جان‌باختگان ۱۸ و ۱۹ دی</small></div><label class="switch"><input type="checkbox" id="s_brand" ${s.sub_branding ? 'checked' : ''}><i></i></label></div>
      <div class="hr"></div>
      <h3>🔐 امنیت</h3>
      <div><label>مسیر پروکسی (WebSocket path)</label><div class="row"><input id="s_path" class="ltr mono" value="${esc(s.proxy_path)}"><button class="btn i" title="تصادفی" onclick="$('#s_path').value='/jvn-'+Math.random().toString(36).slice(2,12)">🎲</button></div><span class="xs muted">تغییر مسیر، کانفیگ‌های قبلی را از کار می‌اندازد (کاربران با ساب خودکار می‌گیرند).</span></div>
      <div class="row" style="margin-top:10px"><button class="btn" onclick="changePass()">🔑 تغییر رمز مدیریت</button></div>
    </div>
  </div>
  <div class="row" style="margin-top:12px;justify-content:flex-end"><button class="btn p" onclick="saveSettingsPage()">💾 ذخیره تنظیمات</button></div>`;
}
function applyPreset(id) { const p = state.presets.find(x => x.id === id); if (!p) return; if (p.fp) $('#s_fp').value = p.fp; if (p.frag === false) $('#s_frag').checked = false; else if (p.frag) { $('#s_frag').checked = true; $('#s_fraglen').value = p.frag[0]; $('#s_fragint').value = p.frag[1]; } toast('پریست ' + p.label + ' اعمال شد — ذخیره یادت نره'); }
async function saveSettingsPage() {
  try {
    const j = await api('/api/settings', { method: 'PUT', body: { fp: $('#s_fp').value, alpn: $('#s_alpn').value.trim(), frag_enabled: $('#s_frag').checked, frag_len: $('#s_fraglen').value.trim(), frag_int: $('#s_fragint').value.trim(), frag_packets: $('#s_fragpk').value, sni_mask: $('#s_sni').value.trim(), host_mask: $('#s_host').value.trim(), title: $('#s_title').value, welcome: $('#s_welcome').value, contact: $('#s_contact').value.trim(), sub_branding: $('#s_brand').checked, proxy_path: $('#s_path').value.trim() } });
    state.settings = j.settings; toast('ذخیره شد');
  } catch (e) { toast(e.message, 'err'); }
}
function changePass() {
  modal(`<h2>🔑 تغییر رمز<button class="x" onclick="closeModal()">✕</button></h2><label>رمز فعلی</label><input id="p_cur" type="password" class="ltr"><label style="margin-top:8px">رمز جدید (حداقل ۸)</label><input id="p_new" type="password" class="ltr"><div id="pErr" class="small" style="color:#fda4af;min-height:20px"></div><div class="row" style="justify-content:flex-end"><button class="btn p" id="pGo">تغییر</button></div>`);
  $('#pGo').onclick = async () => { try { await api('/api/password', { method: 'POST', body: { current: $('#p_cur').value, password: $('#p_new').value } }); closeModal(); toast('رمز عوض شد'); } catch (e) { $('#pErr').textContent = e.message; } };
}

/* ===================== TOOLS ===================== */
async function pageTools() {
  $('#main').innerHTML = `
  <div class="grid g2 fadein">
    <div class="card">
      <h3>📡 پینگ زنده <small>مرورگر شما ↔ این پنل (لبه‌ی کلودفلر)</small></h3>
      <div class="row"><b id="pingVal" style="font-size:26px">—</b><span class="muted small" id="pingColo"></span><div class="grow"></div><button class="btn s" onclick="livePing()">▶️ شروع</button><button class="btn s" onclick="clearInterval(state.pingTimer)">⏹</button></div>
      <div class="spark" id="pingSpark" style="height:44px;margin-top:8px"></div>
    </div>
    <div class="card">
      <h3>🌐 تست مستقیم <small>لبه‌ی کلودفلر → اینترنت</small></h3>
      <div class="row"><input id="d_host" class="ltr mono" value="www.google.com" style="max-width:220px"><input id="d_port" class="ltr" type="number" value="443" style="max-width:90px"><input id="d_out" class="ltr mono" value="direct" placeholder="outbound" style="max-width:220px"><button class="btn s p" onclick="directTest()">تست</button></div>
      <pre class="out" id="dOut" style="margin-top:8px;max-height:120px">نتیجه این‌جا نمایش داده می‌شود</pre>
      <div class="row" style="gap:6px;margin-top:6px">${['www.google.com', 'www.youtube.com', 'gemini.google.com', 'chatgpt.com', 'web.telegram.org', 'www.instagram.com', 'discord.com'].map(h => `<button class="btn s" onclick="$('#d_host').value='${h}';directTest()">${h.replace('www.', '')}</button>`).join('')}</div>
    </div>
  </div>
  <div class="grid g2" style="margin-top:12px">
    <div class="card">
      <h3>🔎 اسکنر IP تمیز <small>روی دستگاه خودت اجرا کن</small></h3>
      <p class="small muted">ورکر نمی‌تواند به IPهای کلودفلر وصل شود، پس اسکن باید از سمت کاربر باشد. اسکریپت آماده را دانلود کن؛ آدرس پنل داخلش ست شده و بهترین IPها را برمی‌گرداند.</p>
      <div class="row" style="gap:6px;margin-top:8px"><a class="btn s b" href="/tools/scanner.py" download>🐍 Python / Pydroid3</a><a class="btn s b" href="/tools/scanner.cmd" download>🪟 Windows CMD</a><a class="btn s b" href="/tools/scanner.sh" download>🐧 Linux / Termux</a></div>
      <div class="hr"></div>
      <label>اسکن سریع از داخل مرورگر (تقریبی — تأخیر TLS به هر IP از دستگاه شما)</label>
      <div class="row"><input id="sc_n" type="number" value="40" min="5" max="200" class="ltr" style="max-width:90px"><button class="btn s p" onclick="browserScan()">▶️ اسکن</button><span class="xs muted" id="scStatus"></span></div>
      <pre class="out" id="scOut" style="margin-top:8px">—</pre>
      <div class="row" style="margin-top:6px"><button class="btn s" onclick="addScanToClean()">➕ افزودن ۵ تای برتر به لیست IP تمیز</button></div>
    </div>
    <div class="card">
      <h3>🩺 سلامت مسیرهای خروجی</h3>
      <pre class="out" id="hOut">—</pre>
      <div class="row" style="margin-top:6px"><button class="btn s" onclick="loadHealth()">🔄 بروزرسانی</button></div>
      <div class="hr"></div>
      <h3>🧾 اطلاعات اتصال شما</h3>
      <pre class="out" id="ipOut">—</pre>
    </div>
  </div>`;
  loadHealth(); api('/api/tools/ipinfo').then(j => $('#ipOut').textContent = JSON.stringify(j, null, 1)).catch(() => {});
}
let pingHist = [];
function livePing() {
  clearInterval(state.pingTimer); pingHist = [];
  const tick = async () => { const t0 = performance.now(); try { const j = await api('/api/ping'); const ms = Math.round(performance.now() - t0); pingHist.push(ms); if (pingHist.length > 40) pingHist.shift(); $('#pingVal').textContent = fa(ms) + ' ms'; $('#pingColo').textContent = j.colo ? '📍 ' + j.colo : ''; const mx = Math.max(...pingHist, 50); $('#pingSpark').innerHTML = pingHist.map(v => `<i style="height:${v / mx * 100}%" data-t="${v}ms"></i>`).join(''); } catch (e) { $('#pingVal').textContent = '✖'; } };
  tick(); state.pingTimer = setInterval(tick, 1500);
}
async function directTest() { $('#dOut').textContent = '⏳ …'; const j = await api('/api/tools/direct', { method: 'POST', body: { host: $('#d_host').value.trim(), port: Number($('#d_port').value), out: $('#d_out').value.trim() } }); $('#dOut').textContent = (j.ok ? `✅ ${j.ms} ms  via ${j.via}  (${j.bytes} bytes)` : `❌ ${j.error}  (${j.ms} ms)  via ${j.via}`) + (j.note ? '\n' + j.note : ''); }
async function loadHealth() { const j = await api('/api/tools/health'); $('#hOut').textContent = j.outbounds.length ? j.outbounds.map(o => `${o.healthy ? '🟢' : '🔴'} ${o.spec}  fails=${o.fails}`).join('\n') : 'هنوز مسیر غیرمستقیمی استفاده نشده.'; }
let scanRes = [];
async function browserScan() {
  const N = Number($('#sc_n').value) || 40; const host = location.host; scanRes = [];
  const prefixes = ['104.16', '104.17', '104.18', '104.19', '104.20', '104.21', '104.22', '104.23', '104.24', '104.25', '104.26', '104.27', '172.64', '172.65', '172.66', '172.67', '162.159', '188.114', '141.101'];
  const ips = Array.from({ length: N }, () => prefixes[Math.floor(Math.random() * prefixes.length)] + '.' + Math.floor(Math.random() * 256) + '.' + (1 + Math.floor(Math.random() * 254)));
  $('#scOut').textContent = ''; let done = 0;
  const probe = async (ip) => {
    const t0 = performance.now();
    try { const c = new AbortController(); const t = setTimeout(() => c.abort(), 2500); await fetch(`https://${ip}/cdn-cgi/trace`, { mode: 'no-cors', cache: 'no-store', signal: c.signal }); clearTimeout(t); scanRes.push([Math.round(performance.now() - t0), ip]); }
    catch (e) {}
    done++; $('#scStatus').textContent = `${done}/${N}`;
  };
  const q = ips.slice(); await Promise.all(Array.from({ length: 8 }, async () => { while (q.length) await probe(q.shift()); }));
  scanRes.sort((a, b) => a[0] - b[0]);
  $('#scOut').textContent = scanRes.length ? scanRes.slice(0, 15).map(([ms, ip]) => `${ip.padEnd(16)} ${ms} ms`).join('\n') : 'هیچ IP پاسخ نداد (مرورگر ممکن است HTTPS به IP خام را مسدود کند — از اسکریپت استفاده کن)';
}
async function addScanToClean() {
  if (!scanRes.length) return toast('اول اسکن کن', 'warn');
  if (!state.settings) await loadSettings();
  const list = [...new Set([...scanRes.slice(0, 5).map(x => x[1]), ...state.settings.clean_ips])];
  const j = await api('/api/settings', { method: 'PUT', body: { clean_ips: list } }); state.settings = j.settings; toast('به لیست IP تمیز اضافه شد');
}

/* ===================== BACKUP / UPDATE ===================== */
async function pageBackup() {
  const me = state.me;
  $('#main').innerHTML = `
  <div class="grid g2 fadein">
    <div class="card">
      <h3>💾 پشتیبان‌گیری کامل</h3>
      <p class="small muted">تمام کاربران، تنظیمات و آمار در یک فایل JSON. برای انتقال به ورکر/اکانت دیگر یا بازیابی بعد از حذف.</p>
      <div class="row" style="margin-top:10px"><a class="btn p" href="/api/backup" download>⬇️ دانلود پشتیبان</a><label class="btn" style="margin:0;cursor:pointer">⬆️ بازیابی<input id="impFile" type="file" accept="application/json" class="hidden"></label></div>
      <div class="sw" style="margin-top:10px"><div><b>بازیابی تنظیمات هم انجام شود</b><small>لوکیشن‌ها، fragment، پروکسی‌ها… (مسیر پروکسی دست نمی‌خورد)</small></div><label class="switch"><input type="checkbox" id="impSettings" checked><i></i></label></div>
    </div>
    <div class="card">
      <h3>🔄 آپدیت OTA <small>از مخزن رسمی GitHub</small></h3>
      <div class="row"><span class="chip info">نسخه‌ی فعلی: v${me.version}</span><span class="chip" id="latestChip">در حال بررسی…</span></div>
      <p class="small muted" style="margin-top:8px">آپدیت بدون از دست رفتن دیتابیس انجام می‌شود. دو راه:<br>۱) از بات تلگرام (🔄 روی پنل) — بدون نیاز به توکن این‌جا.<br>۲) از همین‌جا با توکن کلودفلر (Workers Scripts:Edit). توکن فقط در D1 خودت ذخیره می‌شود.</p>
      <div class="row" style="margin-top:8px"><input id="cfTok" class="ltr mono" placeholder="${me.has_cf_token ? 'توکن ذخیره شده — برای تعویض وارد کن' : 'Cloudflare API Token (اختیاری)'}"><button class="btn g" id="updBtn" onclick="applyUpdate()">⚡ آپدیت کن</button></div>
      <label style="margin-top:6px"><input type="checkbox" id="saveTok" checked> توکن را برای آپدیت‌های بعدی ذخیره کن</label>
      <pre class="out hidden" id="updOut"></pre>
    </div>
  </div>
  <div class="card" style="margin-top:12px">
    <h3>ℹ️ درباره</h3>
    <p class="small muted" style="line-height:2">
      <b>جاویدنام</b> یک پنل کاملاً اورجینال و آزاد (GPL-3.0) برای Cloudflare Workers است — بدون تبلیغ، بدون DRM، بدون «غیرقابل فروش». هر کاری خواستی باهاش بکن؛ فقط آزاد نگهش دار.<br>
      🌷 به یاد جان‌باختگان ۱۸ و ۱۹ دی ۱۴۰۴ — نامشان جاوید.<br>
      <a href="https://github.com/amirparsa1/JavidNam" target="_blank" style="color:#fda4af">github.com/amirparsa1/JavidNam</a>
    </p>
  </div>`;
  $('#impFile').onchange = async (e) => {
    const f = e.target.files[0]; if (!f) return;
    try { const data = JSON.parse(await f.text()); if (!(await confirmBox('بازیابی', `${fa((data.users || []).length)} کاربر بازیابی شود؟ کاربران هم‌UUID به‌روزرسانی می‌شوند.`, 'بازیابی', 'g'))) return; const j = await api('/api/restore', { method: 'POST', body: { ...data, with_settings: $('#impSettings').checked } }); toast(fa(j.restored) + ' کاربر بازیابی شد'); } catch (err) { toast(err.message, 'err'); }
  };
  api('/api/update/check').then(j => { const c = $('#latestChip'); if (j.error) { c.textContent = '⚠️ ' + j.error; c.className = 'chip warn'; return; } c.textContent = j.update_available ? '🆕 نسخه‌ی جدید: v' + j.latest : '✅ آخرین نسخه'; c.className = 'chip ' + (j.update_available ? 'warn' : 'ok'); }).catch(() => {});
}
async function applyUpdate() {
  const out = $('#updOut'); out.classList.remove('hidden'); out.textContent = '⏳ در حال دریافت و آپلود نسخه‌ی جدید…'; $('#updBtn').disabled = true;
  try { const j = await api('/api/update/apply', { method: 'POST', body: { cf_token: $('#cfTok').value.trim(), save_token: $('#saveTok').checked } }); out.textContent = `✅ آپدیت شد به v${j.version}. صفحه تا چند ثانیه دیگر رفرش می‌شود…`; setTimeout(() => location.reload(), 4000); }
  catch (e) { out.textContent = '❌ ' + e.message; $('#updBtn').disabled = false; }
}

boot();
