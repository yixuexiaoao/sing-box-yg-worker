// sing-box-yg-worker：Cloudflare Worker 多服务器管理面板
// 配合 sing-box-yg 脚本的 sbagent API（主菜单19）使用：访问日志、流量统计、一键重置参数、订阅管理、审计日志与 TG 通知
// 绑定：KV 命名空间 SBYG_KV；机密变量 ADMIN_PASSWORD（面板登录密码）；Cron 触发器（wrangler.toml 已配置每5分钟）
// 与服务器通信：cloudflare:sockets 直连 IP:端口，报文 AES-256-CBC + HMAC-SHA256 加密签名，带时间戳与 nonce 防重放
import { connect } from 'cloudflare:sockets';

const VERSION = '1.1.0';
const LOGIN_MAX_FAIL = 10;
const COOKIE = '__Host-sbyg_s';
const enc = new TextEncoder();
const dec = new TextDecoder();
const READ_ACTIONS = ['ping', 'status', 'logs', 'stats', 'peers', 'rawlog', 'leakcheck', 'traffic', 'apilog'];
const ACTIONS = new Set(READ_ACTIONS.concat(['links', 'reset', 'restart', 'logon', 'logoff', 'clearlog', 'logprune',
  'logpolicy', 'schedule', 'leakconf', 'trafficon', 'trafficoff', 'trafficpurge', 'trafficconf']));
const ACTION_NAMES = {
  links: '查看节点链接', reset: '重置参数', restart: '重启Sing-box', logon: '开启连接日志', logoff: '关闭连接日志',
  clearlog: '清空日志', logprune: '按时间删除日志', logpolicy: '修改日志策略', schedule: '设置定时重置',
  leakconf: '设置泄露检测', trafficon: '开启流量统计', trafficoff: '关闭流量统计', trafficpurge: '清理流量记录',
  trafficconf: '修改流量保留天数',
};
const TG_EVENTS = {
  login_ok: '登录成功', login_fail: '登录失败/被拒绝', ops: '服务器操作（重置/重启/修改设置）',
  panel: '面板变更（设置/服务器/订阅/导出）', offline: '服务器离线', recover: '服务器恢复',
  daily: '每日流量报告', traffic: '流量超额告警', sub_ip: '订阅被新IP访问',
};
const DEFAULT_SETTINGS = {
  title: 'Sing-box-yg 管理面板',
  tz: 8,
  sessionHours: 12,
  loginAllow: [],
  totp: false,
  tg: { token: '', chat: '', events: { login_ok: true, login_fail: true, ops: true, panel: true, offline: true, recover: true, daily: false, traffic: true, sub_ip: false } },
  monitor: { enabled: true, failCount: 2 },
  reportHour: 9,
  trafficAlertGB: 0,
  auditDays: 30,
  linkCacheHours: 24,
};

export default {
  async fetch(request, env, ctx) {
    try {
      return await route(request, env, ctx);
    } catch (e) {
      return json({ ok: false, error: (e && e.message) || String(e) }, e && e.status ? e.status : 500);
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(cronTick(env).catch((e) => console.error('cron', e)));
  },
};

// ------------------------------------------------------------------ 路由
async function route(request, env, ctx) {
  const url = new URL(request.url);
  const p = url.pathname;
  const m = request.method;
  if (m === 'GET' && (p === '/' || p === '/index.html')) return page();
  if (m === 'GET' && p.startsWith('/sub/')) return serveSub(request, env, ctx, p.slice(5));
  if (!p.startsWith('/api/')) return new Response('Not Found', { status: 404 });
  if (!env.ADMIN_PASSWORD) throw httpError(500, '未设置 ADMIN_PASSWORD 机密变量，请在 Worker 设置中添加');
  if (!env.SBYG_KV) throw httpError(500, '未绑定 KV 命名空间 SBYG_KV，请在 Worker 设置中绑定');
  if (m !== 'GET') {
    // 写操作：自定义请求头 + 同源检查，防止 CSRF
    const origin = request.headers.get('origin');
    if (request.headers.get('x-sbyg') !== '1' || (origin && origin !== url.origin)) throw httpError(403, 'forbidden');
  }
  const who = { ip: clientIp(request), cc: (request.cf && request.cf.country) || '', ua: (request.headers.get('user-agent') || '').slice(0, 100) };
  const settings = await getSettings(env);

  if (p === '/api/pre') return json({ ok: true, title: settings.title, totp: !!settings.totp });
  if (p === '/api/login' && m === 'POST') return login(request, env, ctx, who, settings);
  if (p === '/api/logout' && m === 'POST') return json({ ok: true }, 200, { 'set-cookie': COOKIE + '=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' });
  if (!(await checkSession(request, env))) throw httpError(401, '未登录或登录已过期');

  const note = (kind, act, extra) => logEvent(env, ctx, settings, who, kind, act, extra);

  if (p === '/api/me') return json({ ok: true, version: VERSION, ip: who.ip, cc: who.cc, settings: publicSettings(settings), events: TG_EVENTS });
  if (p === '/api/settings' && m === 'POST') {
    const next = sanitizeSettings(await readJson(request), settings, who.ip);
    await env.SBYG_KV.put('settings', JSON.stringify(next));
    note('panel', '修改面板设置', { ok: true });
    return json({ ok: true, settings: publicSettings(next) });
  }
  if (p === '/api/settings/tgtest' && m === 'POST') {
    const r = await tgSend(settings, '✅ 测试消息：TG 通知配置正常');
    if (!r.ok) throw httpError(400, 'TG 发送失败：' + r.error);
    return json({ ok: true });
  }
  if (p === '/api/logout-all' && m === 'POST') {
    const v = parseInt((await env.SBYG_KV.get('sessver')) || '0', 10) + 1;
    await env.SBYG_KV.put('sessver', String(v));
    note('panel', '退出所有设备', { ok: true });
    return json({ ok: true }, 200, { 'set-cookie': COOKIE + '=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' });
  }
  if (p.startsWith('/api/totp/') && m === 'POST') return totpRoute(p.slice(10), request, env, settings, note);

  if (p === '/api/servers' && m === 'GET') return json({ ok: true, data: (await getServers(env)).map(publicServer) });
  if (p === '/api/servers' && m === 'POST') {
    const body = await readJson(request);
    const data = await saveServer(env, body);
    note('panel', body.id ? '修改服务器' : '添加服务器', { srv: body.name || body.host, ok: true });
    return json({ ok: true, data });
  }
  if (p === '/api/export' && m === 'POST') {
    const body = await readJson(request);
    if (!(await passwordOk(env, body && body.password))) {
      note('panel', '导出配置', { ok: false, msg: '密码错误' });
      throw httpError(403, '密码错误');
    }
    note('panel', '导出配置（含Token）', { ok: true });
    const data = { version: VERSION, time: Date.now(), servers: await getServers(env), subs: await getSubs(env) };
    return new Response(JSON.stringify(data, null, 2), {
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'content-disposition': 'attachment; filename="sbyg-backup.json"' },
    });
  }
  if (p === '/api/import' && m === 'POST') {
    const r = await importData(env, await readJson(request));
    note('panel', '导入配置', { ok: true, msg: JSON.stringify(r) });
    return json({ ok: true, data: r });
  }
  let mm = p.match(/^\/api\/servers\/([\w-]+)$/);
  if (mm && m === 'DELETE') {
    const list = await getServers(env);
    const srv = list.find((s) => s.id === mm[1]);
    await env.SBYG_KV.put('servers', JSON.stringify(list.filter((s) => s.id !== mm[1])));
    await env.SBYG_KV.delete('links:' + mm[1]);
    note('panel', '删除服务器', { srv: srv ? srv.name : mm[1], ok: true });
    return json({ ok: true });
  }
  mm = p.match(/^\/api\/servers\/([\w-]+)\/call$/);
  if (mm && m === 'POST') {
    const srv = (await getServers(env)).find((s) => s.id === mm[1]);
    if (!srv) throw httpError(404, '服务器不存在');
    const body = await readJson(request);
    if (!body || !ACTIONS.has(body.action)) throw httpError(400, '不支持的操作');
    const params = body.params && typeof body.params === 'object' && !Array.isArray(body.params) ? body.params : {};
    const t0 = Date.now();
    const audited = !READ_ACTIONS.includes(body.action);
    try {
      const data = await agentCall(env, srv, body.action, params);
      if (audited) note('op', ACTION_NAMES[body.action] || body.action, { srv: srv.name, ok: true, msg: params.items || params.mode || '' });
      return json({ ok: true, data, ms: Date.now() - t0 });
    } catch (e) {
      if (audited) note('op', ACTION_NAMES[body.action] || body.action, { srv: srv.name, ok: false, msg: e.message });
      throw e;
    }
  }
  if (p === '/api/links' && m === 'GET') return json({ ok: true, data: await linkOverview(env) });
  if (p === '/api/links/refresh' && m === 'POST') {
    const body = (await readJson(request)) || {};
    const servers = (await getServers(env)).filter((s) => !body.ids || body.ids.includes(s.id));
    const res = await mapLimit(servers, 5, async (s) => {
      try { const c = await refreshLinks(env, s); return { id: s.id, ok: true, count: c.links.length }; } catch (e) { return { id: s.id, ok: false, error: e.message }; }
    });
    return json({ ok: true, data: res });
  }

  if (p === '/api/subs' && m === 'GET') return json({ ok: true, data: await subsView(env, url.origin) });
  if (p === '/api/subs' && m === 'POST') {
    const body = await readJson(request);
    await saveSub(env, body);
    note('panel', body.id ? '修改订阅' : '新建订阅', { msg: String(body.name || '').slice(0, 40), ok: true });
    return json({ ok: true, data: await subsView(env, url.origin) });
  }
  if (p === '/api/subs/rotate-all' && m === 'POST') {
    const subs = await getSubs(env);
    subs.forEach((s) => { s.token = randHex(16); s.rotated = Date.now(); });
    await env.SBYG_KV.put('subs', JSON.stringify(subs));
    note('panel', '重置全部订阅链接', { ok: true, msg: subs.length + ' 个' });
    return json({ ok: true, data: await subsView(env, url.origin) });
  }
  mm = p.match(/^\/api\/subs\/([\w-]+)(\/rotate)?$/);
  if (mm) {
    const subs = await getSubs(env);
    const sub = subs.find((s) => s.id === mm[1]);
    if (!sub) throw httpError(404, '订阅不存在');
    if (m === 'DELETE' && !mm[2]) {
      await env.SBYG_KV.put('subs', JSON.stringify(subs.filter((s) => s.id !== sub.id)));
      await env.SBYG_KV.delete('substat:' + sub.id);
      note('panel', '删除订阅', { msg: sub.name, ok: true });
      return json({ ok: true, data: await subsView(env, url.origin) });
    }
    if (m === 'POST' && mm[2]) {
      sub.token = randHex(16);
      sub.rotated = Date.now();
      await env.SBYG_KV.put('subs', JSON.stringify(subs));
      await env.SBYG_KV.delete('substat:' + sub.id);
      note('panel', '重置订阅链接', { msg: sub.name, ok: true });
      return json({ ok: true, data: await subsView(env, url.origin) });
    }
  }

  if (p === '/api/audit' && m === 'GET') return json({ ok: true, data: await listAudit(env, url.searchParams) });
  if (p === '/api/audit/purge' && m === 'POST') {
    const r = await purgeAudit(env, (await readJson(request)) || {});
    note('panel', '清理审计日志', { ok: true, msg: '删除 ' + r.deleted + ' 条' });
    return json({ ok: true, data: r });
  }
  if (p === '/api/health' && m === 'GET') return json({ ok: true, data: await kvJson(env, 'health', {}) });
  throw httpError(404, 'not found');
}

function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...headers },
  });
}

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

async function readJson(request) {
  try {
    return await request.json();
  } catch (_) {
    throw httpError(400, '请求体不是有效的 JSON');
  }
}

async function kvJson(env, key, def) {
  const v = await env.SBYG_KV.get(key);
  if (!v) return def;
  try { return JSON.parse(v); } catch (_) { return def; }
}

function clientIp(request) {
  return request.headers.get('cf-connecting-ip') || 'unknown';
}

function randHex(n) {
  return hex(crypto.getRandomValues(new Uint8Array(n)));
}

async function mapLimit(items, limit, fn) {
  // Worker 单次请求同时打开的出站连接有限，分批并发
  const out = [];
  for (let i = 0; i < items.length; i += limit) out.push(...(await Promise.all(items.slice(i, i + limit).map(fn))));
  return out;
}

// ------------------------------------------------------------------ 设置
async function getSettings(env) {
  const s = await kvJson(env, 'settings', {});
  const out = { ...DEFAULT_SETTINGS, ...s };
  out.tg = { ...DEFAULT_SETTINGS.tg, ...(s.tg || {}) };
  out.tg.events = { ...DEFAULT_SETTINGS.tg.events, ...((s.tg && s.tg.events) || {}) };
  out.monitor = { ...DEFAULT_SETTINGS.monitor, ...(s.monitor || {}) };
  return out;
}

function publicSettings(s) {
  return { ...s, tg: { chat: s.tg.chat, events: s.tg.events, tokenSet: !!s.tg.token } };
}

function num(v, lo, hi, name) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < lo || n > hi) throw httpError(400, name + '需在 ' + lo + '~' + hi + ' 之间');
  return n;
}

function sanitizeSettings(b, cur, myIp) {
  if (!b || typeof b !== 'object') throw httpError(400, '参数错误');
  const s = JSON.parse(JSON.stringify(cur));
  if (b.title !== undefined) s.title = String(b.title).slice(0, 40) || DEFAULT_SETTINGS.title;
  if (b.tz !== undefined) s.tz = num(b.tz, -12, 14, '时区');
  if (b.sessionHours !== undefined) s.sessionHours = Math.round(num(b.sessionHours, 1, 720, '会话有效期'));
  if (b.reportHour !== undefined) s.reportHour = Math.round(num(b.reportHour, 0, 23, '报告时间'));
  if (b.trafficAlertGB !== undefined) s.trafficAlertGB = num(b.trafficAlertGB, 0, 1e6, '流量告警阈值');
  if (b.auditDays !== undefined) s.auditDays = Math.round(num(b.auditDays, 1, 3650, '审计日志保留天数'));
  if (b.linkCacheHours !== undefined) s.linkCacheHours = Math.round(num(b.linkCacheHours, 1, 720, '节点缓存刷新间隔'));
  if (b.monitor) {
    s.monitor.enabled = !!b.monitor.enabled;
    s.monitor.failCount = Math.round(num(b.monitor.failCount, 1, 20, '离线判定次数'));
  }
  if (b.loginAllow !== undefined) {
    const list = (Array.isArray(b.loginAllow) ? b.loginAllow : String(b.loginAllow).split(/[\s,，]+/)).map((x) => String(x).trim()).filter(Boolean);
    for (const c of list) if (!parseCidr(c)) throw httpError(400, 'IP/网段格式错误：' + c);
    if (list.length && !list.some((c) => ipInCidr(myIp, c))) throw httpError(400, '当前登录IP ' + myIp + ' 不在白名单内，保存后将无法登录，请先加入');
    s.loginAllow = list;
  }
  if (b.tg) {
    if (b.tg.token !== undefined && b.tg.token !== '') {
      if (!/^\d{5,}:[\w-]{20,}$/.test(b.tg.token)) throw httpError(400, 'TG Bot Token 格式错误');
      s.tg.token = b.tg.token;
    }
    if (b.tg.clearToken) s.tg.token = '';
    if (b.tg.chat !== undefined) {
      if (b.tg.chat && !/^(-?\d{3,20}|@[\w]{4,64})$/.test(String(b.tg.chat))) throw httpError(400, 'TG Chat ID 格式错误');
      s.tg.chat = String(b.tg.chat);
    }
    if (b.tg.events) for (const k of Object.keys(TG_EVENTS)) if (k in b.tg.events) s.tg.events[k] = !!b.tg.events[k];
  }
  return s;
}

// ------------------------------------------------------------------ 审计日志与通知
function auditKey(ts) {
  return 'a:' + String(9999999999999 - ts).padStart(13, '0') + ':' + randHex(3); // 倒序时间，list 时最新在前
}

function logEvent(env, ctx, settings, who, kind, act, extra = {}) {
  const ts = Date.now();
  const meta = {
    t: ts, k: kind, a: String(act).slice(0, 40), ip: who.ip, cc: who.cc, ok: extra.ok !== false,
    s: String(extra.srv || '').slice(0, 40), m: String(extra.msg || '').slice(0, 160), u: kind === 'login' ? who.ua.slice(0, 80) : '',
  };
  const ttl = Math.max(60, settings.auditDays * 86400);
  const work = [env.SBYG_KV.put(auditKey(ts), '', { metadata: meta, expirationTtl: ttl })];
  const ev = kind === 'login' ? (meta.ok ? 'login_ok' : 'login_fail') : kind === 'op' ? 'ops' : kind === 'panel' ? 'panel' : '';
  if (ev) {
    const icon = meta.ok ? (kind === 'login' ? '🔑' : '🔧') : '⚠️';
    work.push(tgEvent(settings, ev, icon + ' ' + (kind === 'login' ? '面板登录' : '操作') + '：' + meta.a + (meta.s ? '\n服务器：' + meta.s : '') +
      '\n结果：' + (meta.ok ? '成功' : '失败') + (meta.m ? '（' + meta.m + '）' : '') + '\nIP：' + who.ip + (who.cc ? ' ' + who.cc : '')));
  }
  const p = Promise.all(work).catch(() => {});
  if (ctx && ctx.waitUntil) ctx.waitUntil(p);
  return p;
}

async function tgSend(settings, text) {
  const t = settings.tg;
  if (!t.token || !t.chat) return { ok: false, error: '未设置 Bot Token 或 Chat ID' };
  try {
    const r = await fetch('https://api.telegram.org/bot' + t.token + '/sendMessage', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: t.chat, text: '[' + settings.title + ']\n' + text, disable_web_page_preview: true }),
    });
    const j = await r.json().catch(() => ({}));
    return j.ok ? { ok: true } : { ok: false, error: j.description || 'HTTP ' + r.status };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

function tgEvent(settings, ev, text) {
  return settings.tg.events[ev] ? tgSend(settings, text) : Promise.resolve();
}

async function listAudit(env, q) {
  const kind = q.get('kind') || '';
  const ip = q.get('ip') || '';
  const kw = (q.get('q') || '').toLowerCase();
  const from = Number(q.get('from')) || 0;
  const to = Number(q.get('to')) || Infinity;
  const limit = Math.min(500, Number(q.get('limit')) || 100);
  let cursor = q.get('cursor') || undefined;
  const items = [];
  for (let page = 0; page < 10 && items.length < limit; page++) {
    const r = await env.SBYG_KV.list({ prefix: 'a:', cursor, limit: 1000 });
    for (const k of r.keys) {
      const e = k.metadata;
      if (!e || e.t > to) continue;
      if (e.t < from) { cursor = undefined; r.list_complete = true; break; }
      if (kind && e.k !== kind) continue;
      if (ip && !String(e.ip).includes(ip)) continue;
      if (kw && !(e.a + ' ' + e.s + ' ' + e.m).toLowerCase().includes(kw)) continue;
      items.push(e);
      if (items.length >= limit) break;
    }
    cursor = r.list_complete ? undefined : r.cursor;
    if (!cursor) break;
  }
  return { items, cursor: cursor || null };
}

async function purgeAudit(env, b) {
  const from = Number(b.from) || 0;
  const to = Number(b.to) || 0;
  if (!to || to <= from) throw httpError(400, '请指定有效的时间范围');
  let cursor;
  let deleted = 0;
  for (let page = 0; page < 20; page++) {
    const r = await env.SBYG_KV.list({ prefix: 'a:', cursor, limit: 1000 });
    const dels = r.keys.filter((k) => k.metadata && k.metadata.t >= from && k.metadata.t < to).map((k) => k.name);
    for (let i = 0; i < dels.length; i += 50) await Promise.all(dels.slice(i, i + 50).map((n) => env.SBYG_KV.delete(n)));
    deleted += dels.length;
    if (r.list_complete) break;
    cursor = r.cursor;
  }
  return { deleted };
}

// ------------------------------------------------------------------ 登录、会话与二次验证
async function sessionKey(env) {
  const raw = await crypto.subtle.digest('SHA-256', enc.encode('sbyg-session:' + env.ADMIN_PASSWORD));
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function passwordOk(env, password) {
  const key = await sessionKey(env);
  // 两边都做 HMAC 再比较，避免时序侧信道
  const a = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode('pw:' + String(password || ''))));
  const b = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode('pw:' + env.ADMIN_PASSWORD)));
  return timingSafeEqual(a, b);
}

async function login(request, env, ctx, who, settings) {
  const note = (ok, msg) => logEvent(env, ctx, settings, who, 'login', ok ? '登录成功' : '登录失败', { ok, msg });
  if (settings.loginAllow.length && !settings.loginAllow.some((c) => ipInCidr(who.ip, c))) {
    note(false, 'IP不在登录白名单');
    throw httpError(403, '当前IP不允许登录');
  }
  const failKey = 'fail:' + who.ip;
  const fails = parseInt((await env.SBYG_KV.get(failKey)) || '0', 10);
  if (fails >= LOGIN_MAX_FAIL) throw httpError(429, '登录失败次数过多，请15分钟后再试');
  const body = (await readJson(request)) || {};
  const bad = async (msg) => {
    await env.SBYG_KV.put(failKey, String(fails + 1), { expirationTtl: 900 });
    note(false, msg);
    return httpError(401, msg);
  };
  if (!(await passwordOk(env, body.password))) throw await bad('密码错误');
  if (settings.totp) {
    if (!body.code) return json({ ok: false, needTotp: true, error: '请输入二次验证码' }, 401);
    const secret = await env.SBYG_KV.get('totp_secret');
    if (!secret || !(await totpVerify(secret, String(body.code)))) throw await bad('二次验证码错误');
  }
  const ver = (await env.SBYG_KV.get('sessver')) || '0';
  const ttl = settings.sessionHours * 3600;
  const exp = Math.floor(Date.now() / 1000) + ttl;
  const sig = b64url(await crypto.subtle.sign('HMAC', await sessionKey(env), enc.encode('sess:' + exp + ':' + ver)));
  note(true, '');
  return json({ ok: true }, 200, { 'set-cookie': COOKIE + '=' + exp + '.' + ver + '.' + sig + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=' + ttl });
}

async function checkSession(request, env) {
  const m = (request.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + COOKIE + '=(\\d+)\\.(\\d+)\\.([\\w-]+)'));
  if (!m || parseInt(m[1], 10) < Date.now() / 1000) return false;
  if (m[2] !== ((await env.SBYG_KV.get('sessver')) || '0')) return false;
  let sig;
  try {
    sig = b64urlDecode(m[3]);
  } catch (_) {
    return false;
  }
  return crypto.subtle.verify('HMAC', await sessionKey(env), sig, enc.encode('sess:' + m[1] + ':' + m[2]));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}

async function totpRoute(op, request, env, settings, note) {
  const body = (await readJson(request)) || {};
  if (op === 'setup') {
    const secret = b32encode(crypto.getRandomValues(new Uint8Array(20)));
    await env.SBYG_KV.put('totp_pending', secret, { expirationTtl: 600 });
    const label = encodeURIComponent(settings.title);
    return json({ ok: true, secret, uri: 'otpauth://totp/' + label + ':admin?secret=' + secret + '&issuer=' + label });
  }
  if (op === 'enable') {
    const secret = await env.SBYG_KV.get('totp_pending');
    if (!secret) throw httpError(400, '请先生成密钥（10分钟内有效）');
    if (!(await totpVerify(secret, String(body.code || '')))) throw httpError(400, '验证码错误，请检查手机时间');
    await env.SBYG_KV.put('totp_secret', secret);
    await env.SBYG_KV.delete('totp_pending');
    await env.SBYG_KV.put('settings', JSON.stringify({ ...settings, totp: true }));
    note('panel', '开启二次验证', { ok: true });
    return json({ ok: true });
  }
  if (op === 'disable') {
    const secret = await env.SBYG_KV.get('totp_secret');
    if (!(await passwordOk(env, body.password)) || !secret || !(await totpVerify(secret, String(body.code || '')))) {
      note('panel', '关闭二次验证', { ok: false, msg: '密码或验证码错误' });
      throw httpError(403, '密码或验证码错误');
    }
    await env.SBYG_KV.delete('totp_secret');
    await env.SBYG_KV.put('settings', JSON.stringify({ ...settings, totp: false }));
    note('panel', '关闭二次验证', { ok: true });
    return json({ ok: true });
  }
  throw httpError(404, 'not found');
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function b32encode(u8) {
  let bits = 0, val = 0, out = '';
  for (const b of u8) {
    val = (val << 8) | b;
    bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}
function b32decode(s) {
  const out = [];
  let bits = 0, val = 0;
  for (const c of s.replace(/=+$/, '').toUpperCase()) {
    const i = B32.indexOf(c);
    if (i < 0) continue;
    val = (val << 5) | i;
    bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}

export async function totpCode(secret, counter) {
  const key = await crypto.subtle.importKey('raw', b32decode(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) { msg[i] = c & 255; c = Math.floor(c / 256); }
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const o = h[19] & 15;
  const code = (((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1000000;
  return String(code).padStart(6, '0');
}

async function totpVerify(secret, code) {
  if (!/^\d{6}$/.test(code)) return false;
  const c = Math.floor(Date.now() / 30000);
  for (const d of [-1, 0, 1]) if ((await totpCode(secret, c + d)) === code) return true;
  return false;
}

// ------------------------------------------------------------------ IP / CIDR
function parseIp(ip) {
  ip = String(ip || '').trim();
  const m4 = ip.match(/^(?:::ffff:)?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/i);
  if (m4) {
    const parts = m4.slice(1).map(Number);
    if (parts.some((x) => x > 255)) return null;
    return { bits: 32, v: parts.reduce((a, x) => (a << 8n) | BigInt(x), 0n) };
  }
  if (!ip.includes(':') || !/^[0-9a-f:]+$/i.test(ip)) return null;
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const groups = head.concat(new Array(fill).fill('0'), tail);
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  return { bits: 128, v: groups.reduce((a, g) => (a << 16n) | BigInt(parseInt(g, 16)), 0n) };
}

function parseCidr(c) {
  const [net, len] = String(c).split('/');
  const n = parseIp(net);
  if (!n) return null;
  const l = len === undefined ? n.bits : Number(len);
  if (!Number.isInteger(l) || l < 0 || l > n.bits) return null;
  return { ...n, len: l };
}

export function ipInCidr(ip, cidr) {
  const a = parseIp(ip);
  const n = parseCidr(cidr);
  if (!a || !n || a.bits !== n.bits) return false;
  const shift = BigInt(n.bits - n.len);
  return a.v >> shift === n.v >> shift;
}

// ------------------------------------------------------------------ 服务器列表（KV）
async function getServers(env) {
  return kvJson(env, 'servers', []);
}

function publicServer(s) {
  return { id: s.id, name: s.name, host: s.host, port: s.port, path: s.path, group: s.group || '', note: s.note || '' };
}

function validServer(s) {
  const host = String(s.host || '').trim().replace(/^\[|\]$/g, '');
  const port = parseInt(s.port, 10);
  const path = String(s.path || '/api').trim();
  if (!/^[A-Za-z0-9.:-]{1,253}$/.test(host)) throw httpError(400, '服务器地址格式错误');
  if (!(port > 0 && port < 65536) || port === 25) throw httpError(400, '端口错误');
  if (!/^\/[A-Za-z0-9/_-]{0,64}$/.test(path)) throw httpError(400, 'API路径格式错误');
  return {
    name: String(s.name || host).slice(0, 64), host, port, path,
    group: String(s.group || '').slice(0, 32), note: String(s.note || '').slice(0, 200),
  };
}

async function saveServer(env, body) {
  const list = await getServers(env);
  const v = validServer(body || {});
  const token = String(body.token || '').trim();
  if (body.id) {
    const i = list.findIndex((s) => s.id === body.id);
    if (i < 0) throw httpError(404, '服务器不存在');
    list[i] = { ...list[i], ...v, token: token || list[i].token };
  } else {
    if (token.length < 16) throw httpError(400, 'Token 不能为空');
    list.push({ id: crypto.randomUUID().slice(0, 8), ...v, token, created: Date.now() });
  }
  await env.SBYG_KV.put('servers', JSON.stringify(list));
  return list.map(publicServer);
}

async function importData(env, data) {
  const arr = Array.isArray(data) ? data : data && Array.isArray(data.servers) ? data.servers : [data];
  const list = await getServers(env);
  let added = 0, updated = 0;
  for (const raw of arr) {
    if (!raw || typeof raw !== 'object') continue;
    const v = validServer(raw);
    const token = String(raw.token || '').trim();
    if (token.length < 16) continue;
    const i = list.findIndex((s) => s.host === v.host && s.port === v.port);
    if (i >= 0) { list[i] = { ...list[i], ...v, token }; updated++; } else { list.push({ id: crypto.randomUUID().slice(0, 8), ...v, token, created: Date.now() }); added++; }
  }
  await env.SBYG_KV.put('servers', JSON.stringify(list));
  let subs = 0;
  if (data && Array.isArray(data.subs)) {
    const cur = await getSubs(env);
    for (const s of data.subs) {
      try { cleanSub(s); } catch (_) { continue; }
      if (!cur.some((x) => x.id === s.id)) { cur.push(s); subs++; }
    }
    await env.SBYG_KV.put('subs', JSON.stringify(cur));
  }
  return { added, updated, subs };
}

// ------------------------------------------------------------------ 节点链接缓存与订阅
async function agentCall(env, srv, action, params, timeoutMs) {
  const data = await callAgent(srv, action, params, timeoutMs || (action === 'reset' ? 300000 : 60000));
  if ((action === 'links' || action === 'reset') && data && Array.isArray(data.links)) {
    await env.SBYG_KV.put('links:' + srv.id, JSON.stringify({ t: Date.now(), links: data.links, subs: data.subs || [] }));
  }
  return data;
}

async function refreshLinks(env, srv) {
  const data = await agentCall(env, srv, 'links', {}, 20000);
  return { t: Date.now(), links: data.links || [] };
}

async function linkOverview(env) {
  const servers = await getServers(env);
  return Promise.all(servers.map(async (s) => {
    const c = await kvJson(env, 'links:' + s.id, null);
    return { id: s.id, name: s.name, t: c ? c.t : 0, protos: c ? [...new Set(c.links.map(linkProto))] : [], count: c ? c.links.length : 0 };
  }));
}

export function linkProto(l) {
  const n = String((l && l.name) || '');
  if (n.startsWith('vless')) return 'vless';
  if (n.includes('argo')) return 'vmess-argo';
  if (n.startsWith('vmess')) return 'vmess';
  if (n.startsWith('hysteria2')) return 'hysteria2';
  if (n.startsWith('tuic')) return 'tuic';
  if (n.startsWith('anytls')) return 'anytls';
  return 'other';
}

export function renameLink(link, name) {
  if (link.startsWith('vmess://')) {
    try {
      const obj = JSON.parse(dec.decode(b64decode(link.slice(8).trim())));
      obj.ps = name;
      return 'vmess://' + b64(enc.encode(JSON.stringify(obj)));
    } catch (_) {
      return link;
    }
  }
  const i = link.indexOf('#');
  return (i >= 0 ? link.slice(0, i) : link) + '#' + encodeURIComponent(name);
}

async function getSubs(env) {
  return kvJson(env, 'subs', []);
}

const LINK_RE = /^(vless|vmess|hysteria2|hy2|tuic|anytls|trojan|ss|ssr|socks|wireguard|naive\+https):\/\/\S+$/i;

function cleanSub(b) {
  if (!b || typeof b !== 'object') throw httpError(400, '参数错误');
  const custom = (Array.isArray(b.custom) ? b.custom : String(b.custom || '').split(/\r?\n/)).map((x) => String(x).trim()).filter(Boolean);
  const badLink = custom.find((x) => !LINK_RE.test(x) || x.length > 4000);
  if (badLink) throw httpError(400, '无效的节点链接：' + badLink.slice(0, 60));
  if (custom.length > 500) throw httpError(400, '自定义节点最多500个');
  const protos = (Array.isArray(b.protos) ? b.protos : []).filter((x) => ['vless', 'vmess', 'vmess-argo', 'hysteria2', 'tuic', 'anytls'].includes(x));
  return {
    name: String(b.name || '订阅').slice(0, 40), servers: (Array.isArray(b.servers) ? b.servers : []).map(String).slice(0, 200),
    protos, custom, rename: !!b.rename, enabled: b.enabled !== false, note: String(b.note || '').slice(0, 200),
    expires: Number(b.expires) || 0,
  };
}

async function saveSub(env, body) {
  const subs = await getSubs(env);
  const v = cleanSub(body);
  if (body.id) {
    const i = subs.findIndex((s) => s.id === body.id);
    if (i < 0) throw httpError(404, '订阅不存在');
    subs[i] = { ...subs[i], ...v };
  } else {
    if (subs.length >= 100) throw httpError(400, '订阅最多100个');
    subs.push({ id: crypto.randomUUID().slice(0, 8), ...v, token: randHex(16), created: Date.now(), rotated: Date.now() });
  }
  await env.SBYG_KV.put('subs', JSON.stringify(subs));
}

async function subsView(env, origin) {
  const subs = await getSubs(env);
  return Promise.all(subs.map(async (s) => ({ ...s, url: origin + '/sub/' + s.token, stat: await kvJson(env, 'substat:' + s.id, null) })));
}

export async function buildSubLines(env, sub) {
  const servers = await getServers(env);
  const lines = [];
  for (const id of sub.servers) {
    const srv = servers.find((s) => s.id === id);
    if (!srv) continue;
    let cache = await kvJson(env, 'links:' + id, null);
    if (!cache) {
      try { cache = await refreshLinks(env, srv); } catch (_) { continue; }
    }
    for (const l of cache.links) {
      const proto = linkProto(l);
      if (sub.protos.length && !sub.protos.includes(proto)) continue;
      lines.push(sub.rename ? renameLink(l.link, srv.name + '-' + proto) : l.link);
    }
  }
  return lines.concat(sub.custom);
}

async function serveSub(request, env, ctx, token) {
  const notFound = () => new Response('Not Found', { status: 404 });
  if (!/^[a-f0-9]{32}$/.test(token) || !env.SBYG_KV) return notFound();
  const sub = (await getSubs(env)).find((s) => s.token === token);
  if (!sub || sub.enabled === false || (sub.expires && Date.now() > sub.expires)) return notFound();
  const lines = await buildSubLines(env, sub);
  const ip = clientIp(request);
  const statKey = 'substat:' + sub.id;
  const stat = await kvJson(env, statKey, { hits: 0, ips: [] });
  const known = stat.ips.find((x) => x.ip === ip);
  if (known) { known.last = Date.now(); known.n = (known.n || 0) + 1; } else stat.ips.unshift({ ip, cc: (request.cf && request.cf.country) || '', first: Date.now(), last: Date.now(), n: 1 });
  stat.ips = stat.ips.slice(0, 50);
  stat.hits++;
  stat.last = { t: Date.now(), ip, ua: (request.headers.get('user-agent') || '').slice(0, 100) };
  const work = [env.SBYG_KV.put(statKey, JSON.stringify(stat))];
  if (!known && stat.hits > 1) {
    const settings = await getSettings(env);
    work.push(tgEvent(settings, 'sub_ip', '📡 订阅「' + sub.name + '」被新IP访问：' + ip + ((request.cf && request.cf.country) ? ' ' + request.cf.country : '') +
      '\n累计 ' + stat.ips.length + ' 个IP。如非本人设备，请在面板中重置订阅链接与节点参数。'));
  }
  ctx.waitUntil(Promise.all(work).catch(() => {}));
  const body = lines.join('\n');
  const plain = new URL(request.url).searchParams.get('format') === 'plain';
  return new Response(plain ? body : b64(enc.encode(body)), {
    headers: {
      'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'profile-update-interval': '12',
      'content-disposition': "inline; filename*=UTF-8''" + encodeURIComponent(sub.name),
    },
  });
}

// ------------------------------------------------------------------ 定时任务：离线检测、每日报告、刷新节点缓存
export async function cronTick(env, now = Date.now()) {
  if (!env.SBYG_KV || !env.ADMIN_PASSWORD) return;
  const settings = await getSettings(env);
  const servers = await getServers(env);
  if (!servers.length) return;
  if (settings.monitor.enabled) {
    const health = await kvJson(env, 'health', {});
    let changed = false;
    const msgs = [];
    await mapLimit(servers, 5, async (s) => {
      const h = health[s.id] || { fails: 0, down: false };
      let ok = true, err = '';
      try { await callAgent(s, 'ping', {}, 15000); } catch (e) { ok = false; err = e.message; }
      if (ok) {
        if (h.down) msgs.push(['recover', '✅ 服务器恢复：' + s.name + '\n离线时长：' + Math.round((now - h.since) / 60000) + ' 分钟']);
        if (!health[s.id] || h.fails || h.down) changed = true; // 首次检测也记录，便于面板显示状态
        health[s.id] = { fails: 0, down: false, last: now };
      } else {
        h.fails = (h.fails || 0) + 1;
        if (!h.down && h.fails >= settings.monitor.failCount) {
          h.down = true;
          h.since = now;
          msgs.push(['offline', '🔴 服务器离线：' + s.name + '（' + s.host + ':' + s.port + '）\n原因：' + err]);
        }
        h.err = err.slice(0, 120);
        health[s.id] = h;
        changed = true;
      }
    });
    if (changed) await env.SBYG_KV.put('health', JSON.stringify(health));
    for (const [ev, text] of msgs) await tgEvent(settings, ev, text);
  }
  const local = new Date(now + settings.tz * 3600000);
  const day = local.toISOString().slice(0, 10);
  const wantReport = settings.tg.events.daily || (settings.tg.events.traffic && settings.trafficAlertGB > 0);
  if (wantReport && local.getUTCHours() === settings.reportHour && !(await env.SBYG_KV.get('report:' + day))) {
    await env.SBYG_KV.put('report:' + day, '1', { expirationTtl: 172800 });
    await dailyReport(env, settings, servers, local);
  }
  // 每次最多刷新一台缓存过期的服务器节点链接，供订阅使用
  const stale = [];
  for (const s of servers) {
    const c = await kvJson(env, 'links:' + s.id, null);
    if (c && now - c.t > settings.linkCacheHours * 3600000) stale.push([c.t, s]);
  }
  stale.sort((a, b) => a[0] - b[0]);
  if (stale.length) await refreshLinks(env, stale[0][1]).catch(() => {});
}

async function dailyReport(env, settings, servers, local) {
  const midnight = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate()) - settings.tz * 3600000;
  const start = (midnight - 86400000) / 1000;
  const end = midnight / 1000;
  const lines = [];
  const alerts = [];
  await mapLimit(servers, 5, async (s) => {
    try {
      const d = await callAgent(s, 'traffic', { start, end, group: 'ip', limit: 3 }, 30000);
      const total = d.total.up + d.total.down;
      const top = d.rows.map((r) => r.key + ' ' + fmtBytes(r.up + r.down)).join('，');
      lines.push('• ' + s.name + '：↑' + fmtBytes(d.total.up) + ' ↓' + fmtBytes(d.total.down) + (d.enabled ? '' : '（流量统计未开启）') + (top ? '\n  Top：' + top : ''));
      if (settings.trafficAlertGB > 0 && total > settings.trafficAlertGB * 1073741824) alerts.push('⚠️ ' + s.name + ' 昨日流量 ' + fmtBytes(total) + '，超过 ' + settings.trafficAlertGB + ' GB');
    } catch (e) {
      lines.push('• ' + s.name + '：获取失败（' + e.message + '）');
    }
  });
  const date = new Date(midnight - 86400000 + settings.tz * 3600000).toISOString().slice(0, 10);
  if (settings.tg.events.daily) await tgSend(settings, '📊 ' + date + ' 流量日报\n' + lines.join('\n'));
  if (alerts.length) await tgEvent(settings, 'traffic', alerts.join('\n'));
}

function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(2) : String(n)) + ' ' + u[i];
}

// ------------------------------------------------------------------ 与服务器 sbagent 通信
// 报文格式与 sbagent.py 一致：
//   {"v":1,"iv":b64,"ct":b64,"z":0|1,"mac":b64}
//   mac = HMAC-SHA256(SHA256("sbyg-mac:"+token), "v1|" + ("z"|"-") + iv + ct)
//   ct  = AES-256-CBC(SHA256("sbyg-enc:"+token), iv, z ? zlib(明文) : 明文)
export async function deriveKeys(token) {
  const e = await crypto.subtle.digest('SHA-256', enc.encode('sbyg-enc:' + token));
  const m = await crypto.subtle.digest('SHA-256', enc.encode('sbyg-mac:' + token));
  return {
    enc: await crypto.subtle.importKey('raw', e, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']),
    mac: await crypto.subtle.importKey('raw', m, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']),
  };
}

function macInput(iv, ct, z) {
  const head = enc.encode(z ? 'v1|z' : 'v1|-');
  const out = new Uint8Array(head.length + iv.length + ct.length);
  out.set(head, 0);
  out.set(iv, head.length);
  out.set(ct, head.length + iv.length);
  return out;
}

async function streamBytes(data, stream) {
  const res = new Response(new Blob([data]).stream().pipeThrough(stream));
  return new Uint8Array(await res.arrayBuffer());
}

export async function seal(obj, keys) {
  let pt = enc.encode(JSON.stringify(obj));
  const z = pt.length > 512;
  if (z) pt = await streamBytes(pt, new CompressionStream('deflate'));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, keys.enc, pt));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', keys.mac, macInput(iv, ct, z)));
  return { v: 1, iv: b64(iv), ct: b64(ct), z: z ? 1 : 0, mac: b64(mac) };
}

export async function unseal(env, keys) {
  const iv = b64decode(env.iv), ct = b64decode(env.ct), mac = b64decode(env.mac);
  const z = !!env.z;
  if (env.v !== 1 || iv.length !== 16 || !(await crypto.subtle.verify('HMAC', keys.mac, mac, macInput(iv, ct, z)))) {
    throw new Error('响应签名校验失败');
  }
  let pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, keys.enc, ct));
  if (z) pt = await streamBytes(pt, new DecompressionStream('deflate'));
  return JSON.parse(dec.decode(pt));
}

export async function callAgent(srv, action, params, timeoutMs = 60000, openSocket = connect) {
  const keys = await deriveKeys(srv.token);
  const nonce = hex(crypto.getRandomValues(new Uint8Array(16)));
  const req = { ts: Math.floor(Date.now() / 1000), nonce, action, params };
  const body = enc.encode(JSON.stringify(await seal(req, keys)));
  const resp = await httpPost(srv.host, srv.port, srv.path || '/api', body, timeoutMs, openSocket);
  if (resp.status === 404) throw httpError(502, '服务器拒绝请求(404)：请检查Token、API路径、IP白名单，以及VPS系统时间是否准确');
  if (resp.status !== 200) throw httpError(502, '服务器返回 HTTP ' + resp.status);
  const out = await unseal(JSON.parse(dec.decode(resp.body)), keys);
  if (out.rn !== nonce) throw httpError(502, '响应与请求不匹配');
  if (!out.ok) throw httpError(502, out.error || '服务器执行失败');
  return out.data;
}

async function httpPost(host, port, path, body, timeoutMs, openSocket) {
  const hostname = String(host).replace(/^\[|\]$/g, '');
  let timer;
  const socket = openSocket({ hostname, port: Number(port) });
  const work = (async () => {
    const w = socket.writable.getWriter();
    const hostHdr = (hostname.includes(':') ? '[' + hostname + ']' : hostname) + ':' + port;
    await w.write(enc.encode(`POST ${path} HTTP/1.1\r\nHost: ${hostHdr}\r\nUser-Agent: sbyg-worker/${VERSION}\r\n` +
      `Content-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`));
    await w.write(body);
    w.releaseLock();
    const r = socket.readable.getReader();
    const chunks = [];
    let total = 0, need = -1, headLen = -1;
    for (;;) {
      const { value, done } = await r.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
      if (total > 64 * 1024 * 1024) throw new Error('响应过大');
      if (headLen < 0) {
        const buf = concat(chunks, total);
        const i = indexOfCRLF2(buf);
        if (i >= 0) {
          headLen = i + 4;
          const cl = dec.decode(buf.subarray(0, i)).match(/\r\ncontent-length:\s*(\d+)/i);
          if (cl) need = headLen + parseInt(cl[1], 10);
        }
      }
      if (need >= 0 && total >= need) break;
    }
    const buf = concat(chunks, total);
    const i = indexOfCRLF2(buf);
    if (i < 0) throw new Error('服务器无响应或响应不完整');
    const status = parseInt(dec.decode(buf.subarray(0, i)).split(' ')[1], 10);
    return { status, body: buf.subarray(i + 4, need >= 0 ? need : buf.length) };
  })();
  const timeout = new Promise((_, rej) => {
    timer = setTimeout(() => rej(httpError(504, '连接服务器超时：请检查IP/端口与VPS防火墙')), timeoutMs);
  });
  work.catch(() => {});
  try {
    return await Promise.race([work, timeout]);
  } catch (e) {
    if (e.status) throw e;
    throw httpError(502, '连接服务器失败：' + (e.message || e));
  } finally {
    clearTimeout(timer);
    Promise.resolve().then(() => socket.close()).catch(() => { /* 已关闭 */ });
  }
}

function concat(chunks, total) {
  if (chunks.length === 1) return chunks[0];
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  chunks.length = 0;
  chunks.push(out);
  return out;
}

function indexOfCRLF2(b) {
  for (let i = 0; i + 3 < b.length; i++) {
    if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) return i;
  }
  return -1;
}

// ------------------------------------------------------------------ 编码工具
function b64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
function b64decode(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64url(buf) {
  return b64(new Uint8Array(buf)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  return b64decode(s + '='.repeat((4 - (s.length % 4)) % 4));
}
function hex(u8) {
  return Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ------------------------------------------------------------------ 前端页面
function page() {
  // 每次响应生成新的 nonce，CSP 只允许带该 nonce 的脚本执行（页面不使用任何内联事件属性）
  const nonce = b64(crypto.getRandomValues(new Uint8Array(16)));
  return new Response(PAGE.replace('<script>', '<script nonce="' + nonce + '">'), {
    headers: {
      'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store',
      'x-frame-options': 'DENY', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
      'content-security-policy': "default-src 'self'; script-src 'nonce-" + nonce + "'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    },
  });
}

// 注意：页面脚本中不使用反引号与 ${}，以便整体放在模板字符串里；不使用 onclick 等内联事件（CSP 禁止）
const PAGE = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sing-box-yg 管理面板</title>
<style>
:root{--bg:#f5f6f8;--card:#fff;--fg:#1d2330;--muted:#6b7280;--line:#e3e6ea;--accent:#2563eb;--accent-fg:#fff;--ok:#16a34a;--bad:#dc2626;--warn:#d97706;--chip:#eef2f7;--code:#f1f3f6;--bar:#93b4f5}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b23;--fg:#e6e8ec;--muted:#9aa3af;--line:#2a303b;--accent:#3b82f6;--accent-fg:#fff;--ok:#22c55e;--bad:#f87171;--warn:#fbbf24;--chip:#232a35;--code:#11151c;--bar:#2f5bb5}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
header{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between;padding:10px 16px;background:var(--card);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
header h1{font-size:16px;margin:0}
nav{display:flex;flex-wrap:wrap;gap:4px}
nav button.on{background:var(--accent);color:var(--accent-fg);border-color:var(--accent)}
main{padding:16px;max-width:1400px;margin:0 auto}
button,select,input,textarea{font:inherit;color:inherit}
button{background:var(--chip);border:1px solid var(--line);border-radius:6px;padding:5px 10px;cursor:pointer}
button:hover{border-color:var(--accent)}
button.primary{background:var(--accent);color:var(--accent-fg);border-color:var(--accent)}
button.danger{color:var(--bad)}
button:disabled{opacity:.5;cursor:default}
input,select,textarea{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:5px 8px;min-width:0}
textarea{width:100%;font-family:ui-monospace,Consolas,monospace;font-size:12px}
.bar{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.card h3{margin:0;font-size:15px;display:flex;gap:6px;align-items:center}
.section{margin-bottom:14px}
.section h3{font-size:14px;margin:0 0 8px}
.muted{color:var(--muted)}
.small{font-size:12px}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;background:var(--muted);flex:none}
.dot.ok{background:var(--ok)}.dot.bad{background:var(--bad)}.dot.warn{background:var(--warn)}
.chips{display:flex;flex-wrap:wrap;gap:4px;margin:6px 0}
.chip{background:var(--chip);border-radius:4px;padding:1px 6px;font-size:12px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:2px 10px;font-size:12px;margin:6px 0}
.kv>span:nth-child(odd){color:var(--muted)}
.actions{display:flex;flex-wrap:wrap;gap:4px;margin-top:8px}
.actions button{font-size:12px;padding:3px 8px}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:flex-start;justify-content:center;padding:24px 8px;z-index:10;overflow:auto}
.dialog{background:var(--card);border-radius:10px;width:min(1200px,100%);padding:14px;border:1px solid var(--line)}
.dialog.narrow{width:min(620px,100%)}
.dialog h2{margin:0 0 10px;font-size:16px;display:flex;justify-content:space-between;align-items:center;gap:8px}
.tablewrap{overflow:auto;max-height:65vh;border:1px solid var(--line);border-radius:6px}
table{border-collapse:collapse;width:100%;font-size:12px}
th,td{padding:4px 8px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap;vertical-align:top}
th{position:sticky;top:0;background:var(--card)}
td.wrap{white-space:normal;word-break:break-all;min-width:180px}
td.num,th.num{text-align:right}
.err{color:var(--bad)}.okc{color:var(--ok)}
a{color:var(--accent);cursor:pointer;text-decoration:none}
.link{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all;background:var(--code);padding:6px;border-radius:6px;margin:4px 0}
.login{max-width:360px;margin:12vh auto}
.toast{position:fixed;right:16px;bottom:16px;background:var(--fg);color:var(--bg);padding:8px 12px;border-radius:6px;z-index:20;max-width:80vw}
label{display:inline-flex;gap:4px;align-items:center}
.field{display:flex;flex-direction:column;gap:3px;margin-bottom:8px}
.row{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}
.stat{display:inline-block;margin-right:16px}
.stat b{font-size:18px}
.tabs button.on{background:var(--accent);color:var(--accent-fg)}
.meter{height:6px;background:var(--chip);border-radius:3px;min-width:80px}
.meter i{display:block;height:6px;border-radius:3px;background:var(--bar)}
svg text{fill:var(--muted);font-size:10px}
@media (max-width:600px){.grid{grid-template-columns:1fr}main{padding:10px}header{padding:8px 10px}}
</style>
</head>
<body>
<div id="app"></div>
<script>
(function(){
var $app=document.getElementById('app');
var S={servers:[],status:{},selected:{},me:null,tab:'servers'};
var PROTOS=[['vless','Vless-reality'],['vmess','Vmess-ws(tls)'],['vmess-argo','Vmess-Argo'],['hysteria2','Hysteria2'],['tuic','Tuic5'],['anytls','Anytls']];
function $(id){return document.getElementById(id)}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function api(path,opt){opt=opt||{};var h={'x-sbyg':'1'};if(opt.body!==undefined){h['content-type']='application/json'}
 return fetch(path,{method:opt.method||(opt.body!==undefined?'POST':'GET'),headers:h,body:opt.body!==undefined?JSON.stringify(opt.body):undefined,credentials:'same-origin'})
 .then(function(r){return r.json().catch(function(){return{ok:false,error:'HTTP '+r.status}}).then(function(j){if(r.status===401&&path!=='/api/login'){showLogin();throw new Error(j.error||'未登录')}if(!j.ok){var e=new Error(j.error||('HTTP '+r.status));e.body=j;throw e}return j})})}
function call(id,action,params){return api('/api/servers/'+id+'/call',{body:{action:action,params:params||{}}}).then(function(j){return j.data})}
function toast(msg){var t=document.createElement('div');t.className='toast';t.textContent=msg;document.body.appendChild(t);setTimeout(function(){t.remove()},3500)}
function fmtBytes(n){n=Number(n)||0;var u=['B','KB','MB','GB','TB'],i=0;while(n>=1024&&i<4){n/=1024;i++}return (i?n.toFixed(2):n)+' '+u[i]}
function fmtUp(s){s=s||0;var d=Math.floor(s/86400),h=Math.floor(s%86400/3600);return d?d+'天'+h+'时':h+'时'+Math.floor(s%3600/60)+'分'}
function fmtTime(t){if(!t)return '-';var d=new Date(t);function p(x){return (x<10?'0':'')+x}return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds())}
function copy(text){(navigator.clipboard?navigator.clipboard.writeText(text):Promise.reject()).then(function(){toast('已复制')},function(){var t=document.createElement('textarea');t.value=text;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove();toast('已复制')})}
function srvById(id){for(var i=0;i<S.servers.length;i++)if(S.servers[i].id===id)return S.servers[i]}
function val(id){var e=$(id);return e?String(e.value).trim():''}
function checked(id){var e=$(id);return !!(e&&e.checked)}
function modal(title,html,narrow){closeModal();var m=document.createElement('div');m.className='modal';m.id='modal';
 m.innerHTML='<div class="dialog'+(narrow?' narrow':'')+'"><h2><span>'+title+'</span><button data-close="1">关闭</button></h2>'+html+'</div>';
 m.addEventListener('click',function(e){if(e.target===m)closeModal()});document.body.appendChild(m);return m}
function closeModal(){var m=$('modal');if(m)m.remove()}
document.addEventListener('click',function(e){var t=e.target.closest('[data-close]');if(t)closeModal();var c=e.target.closest('[data-copy]');if(c)copy(c.getAttribute('data-copy'))});
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeModal()});
function bind(root,sel,fn){(root||document).querySelectorAll(sel).forEach(function(el){el.addEventListener('click',function(ev){ev.preventDefault();fn(el,ev)})})}
function localInput(t){var d=new Date(t);d.setMinutes(d.getMinutes()-d.getTimezoneOffset());return d.toISOString().slice(0,16)}
function inputTime(id){var v=val(id);return v?Math.floor(new Date(v).getTime()/1000):null}
function busy(el,text){el.innerHTML='<p class="muted" style="padding:8px">'+(text||'加载中…')+'</p>'}
function fail(el,e){el.innerHTML='<p class="err" style="padding:8px">'+esc(e.message||e)+'</p>'}

// ================= 登录
function showLogin(){
 closeModal();
 api('/api/pre').then(function(p){
  document.title=p.title;
  $app.innerHTML='<div class="login card"><h3>'+esc(p.title)+'</h3><p class="muted small">请输入管理密码</p><form id="lf"><div class="field"><input type="password" id="pw" autocomplete="current-password" autofocus></div>'+
  '<div class="field" id="totpf"'+(p.totp?'':' hidden')+'><input id="code" inputmode="numeric" autocomplete="one-time-code" placeholder="二次验证码 (6位)"></div><button class="primary" style="width:100%">登录</button></form><p class="err small" id="lerr"></p></div>';
  $('lf').addEventListener('submit',function(e){e.preventDefault();api('/api/login',{body:{password:$('pw').value,code:val('code')}}).then(boot).catch(function(err){if(err.body&&err.body.needTotp){$('totpf').hidden=false;$('code').focus()}$('lerr').textContent=err.message})});
 }).catch(function(e){$app.innerHTML='<div class="login card err">'+esc(e.message)+'</div>'});
}
function boot(){api('/api/me').then(function(j){S.me=j;document.title=j.settings.title;renderShell();go(S.tab)}).catch(function(){})}

var TABS=[['servers','服务器'],['traffic','流量统计'],['subs','订阅管理'],['audit','审计日志'],['settings','设置']];
function renderShell(){
 $app.innerHTML='<header><h1>'+esc(S.me.settings.title)+' <span class="muted small">v'+esc(S.me.version)+'</span></h1><nav id="nav">'+
 TABS.map(function(t){return '<button data-tab="'+t[0]+'">'+t[1]+'</button>'}).join('')+'<button id="b-logout">退出</button></nav></header><main id="view"></main>';
 bind($('nav'),'[data-tab]',function(b){go(b.getAttribute('data-tab'))});
 $('b-logout').addEventListener('click',function(){api('/api/logout',{body:{}}).then(showLogin)});
}
function go(tab){S.tab=tab;document.querySelectorAll('#nav [data-tab]').forEach(function(b){b.classList.toggle('on',b.getAttribute('data-tab')===tab)});
 ({servers:viewServers,traffic:viewTraffic,subs:viewSubs,audit:viewAudit,settings:viewSettings})[tab]()}

// ================= 服务器
function viewServers(){
 $('view').innerHTML='<div class="bar" style="margin-bottom:10px"><button class="primary" id="b-add">添加服务器</button><button id="b-refresh">全部刷新</button>'+
 '<button id="b-resetall" class="danger">一键全部重置参数</button><button id="b-batch">批量操作</button><button id="b-io">导入/导出</button><span id="summary" class="muted small"></span></div><div class="grid" id="grid"></div>';
 $('b-add').addEventListener('click',function(){editServer()});
 $('b-refresh').addEventListener('click',refreshAll);
 $('b-resetall').addEventListener('click',function(){resetDialog(S.servers.slice(),true)});
 $('b-batch').addEventListener('click',batchDialog);
 $('b-io').addEventListener('click',ioDialog);
 loadServers();
}
function loadServers(){return api('/api/servers').then(function(j){S.servers=j.data;renderGrid();refreshAll()})}
var renderPending=false;
function scheduleRender(){if(renderPending)return;renderPending=true;requestAnimationFrame(function(){renderPending=false;renderGrid()})}
function renderGrid(){
 var g=$('grid');if(!g)return;
 if(!S.servers.length){g.innerHTML='<div class="card muted">还没有服务器。在VPS上运行 <b>sb</b>，安装时开启API，或选择 <b>19 → 1</b> 安装API服务，再选择 <b>19 → 2</b> 复制对接信息，然后点击「添加服务器」粘贴。</div>';updateSummary();return}
 g.innerHTML=S.servers.map(cardHtml).join('');
 bind(g,'[data-act]',function(b){onAction(b.getAttribute('data-act'),b.getAttribute('data-id'))});
 g.querySelectorAll('input[data-sel]').forEach(function(c){c.addEventListener('change',function(){S.selected[c.getAttribute('data-sel')]=c.checked})});
 updateSummary();
}
function updateSummary(){var el=$('summary');if(!el)return;var on=0,act=0;S.servers.forEach(function(s){var st=S.status[s.id];if(st&&st.data){on++;if(st.data.active)act++}});el.textContent='共 '+S.servers.length+' 台，在线 '+on+' 台，Sing-box运行中 '+act+' 台'}
var PERM_NAMES={read:'只读',links:'节点链接',manage:'管理'};
function cardHtml(s){
 var st=S.status[s.id],d=st&&st.data,dot='',body='';
 if(!st){body='<div class="muted small">加载中…</div>'}
 else if(st.error){dot='bad';body='<div class="err small">'+esc(st.error)+'</div>'}
 else{
  dot=d.active?'ok':'warn';
  var tr=d.traffic||{},api=d.api||{};
  body='<div class="chips">'+(d.inbounds||[]).map(function(i){return '<span class="chip">'+esc(i.name)+' :'+esc(i.port)+'</span>'}).join('')+'</div>'+
  '<div class="kv"><span>系统</span><span>'+esc(d.os||'-')+' / '+esc(d.hostname)+'</span>'+
  '<span>内核</span><span>sing-box '+esc(d.version||'-')+(d.active?'':' <b class="err">未运行</b>')+' · agent '+esc(d.agent)+'</span>'+
  '<span>IP</span><span>'+esc(d.server_ip||'-')+'</span>'+
  '<span>运行</span><span>'+fmtUp(d.uptime)+'，负载 '+esc((d.load||[]).join(' '))+(d.mem&&d.mem.MemTotal?'，内存 '+fmtBytes(d.mem.MemTotal-d.mem.MemAvailable)+'/'+fmtBytes(d.mem.MemTotal):'')+'</span>'+
  '<span>日志</span><span>'+(d.log&&d.log.enabled?'已开启 '+fmtBytes(d.log.size)+(d.log.archives?'（归档'+d.log.archives+'份）':''):'<span class="err">未开启</span>')+'</span>'+
  '<span>流量</span><span>'+(tr.enabled?'统计中 '+fmtBytes(tr.db_size):'<span class="muted">未开启</span>')+'</span>'+
  '<span>API权限</span><span>'+(api.perms?api.perms.map(function(p){return PERM_NAMES[p]||p}).join('、'):'-')+(api.allow&&api.allow.length?' · IP白名单':'')+'</span>'+
  '<span>重置</span><span>'+(d.last_reset?esc(d.last_reset.time)+' ('+esc((d.last_reset.items||[]).join(','))+')':'从未')+(d.schedule?' · 已设定时':'')+(d.leak&&d.leak.enabled?' · 泄露检测':'')+'</span>'+
  (d.argo&&(d.argo.temp||d.argo.fixed)?'<span>Argo</span><span>'+esc(d.argo.fixed||d.argo.temp)+'</span>':'')+'</div>';
 }
 var b=function(act,label,cls){return '<button data-act="'+act+'" data-id="'+esc(s.id)+'"'+(cls?' class="'+cls+'"':'')+'>'+label+'</button>'};
 return '<div class="card"><h3><input type="checkbox" data-sel="'+esc(s.id)+'"'+(S.selected[s.id]?' checked':'')+'><span class="dot '+dot+'"></span>'+esc(s.name)+
 '<span class="muted small" style="margin-left:auto">'+esc(s.host)+':'+esc(s.port)+(st&&st.ms?' · '+st.ms+'ms':'')+'</span></h3>'+body+
 '<div class="actions">'+b('logs','访问日志')+b('stats','IP统计')+b('traffic','流量')+b('peers','在线IP')+b('links','节点链接')+b('reset','重置参数','danger')+
 b('settings','日志/流量/定时')+b('apilog','API日志')+b('refresh','刷新')+b('restart','重启')+b('edit','编辑')+b('del','删除','danger')+'</div></div>';
}
function refreshOne(id){var t0=Date.now();return call(id,'status').then(function(d){S.status[id]={data:d,ms:Date.now()-t0}},function(e){S.status[id]={error:e.message}}).then(scheduleRender)}
function refreshAll(){S.status={};renderGrid();return Promise.all(S.servers.map(function(s){return refreshOne(s.id)}))}
function onAction(act,id){
 var s=srvById(id);
 if(act==='refresh')return refreshOne(id);
 if(act==='edit')return editServer(s);
 if(act==='del'){if(confirm('删除服务器「'+s.name+'」？(仅从面板移除，不影响VPS)'))api('/api/servers/'+id,{method:'DELETE'}).then(loadServers).catch(function(e){toast(e.message)});return}
 if(act==='restart'){if(confirm('重启「'+s.name+'」的 Sing-box？'))call(id,'restart').then(function(d){toast(d.active?'重启成功':'重启后未运行，请检查');refreshOne(id)}).catch(function(e){toast(e.message)});return}
 if(act==='traffic'){S.trafficServer=id;return go('traffic')}
 ({logs:logsDialog,stats:statsDialog,peers:peersDialog,links:linksDialog,settings:settingsDialog,apilog:apilogDialog})[act]?({logs:logsDialog,stats:statsDialog,peers:peersDialog,links:linksDialog,settings:settingsDialog,apilog:apilogDialog})[act](s):act==='reset'&&resetDialog([s]);
}
function editServer(s){
 s=s||{};
 modal(s.id?'编辑服务器':'添加服务器',
 (s.id?'':'<div class="field"><span class="small muted">粘贴VPS上 sb → 19 → 2 输出的对接JSON，自动填写</span><textarea id="f-json" rows="3"></textarea></div>')+
 '<div class="row"><div class="field"><span class="small muted">名称</span><input id="f-name" value="'+esc(s.name||'')+'"></div>'+
 '<div class="field"><span class="small muted">服务器IP或域名</span><input id="f-host" value="'+esc(s.host||'')+'"></div>'+
 '<div class="field"><span class="small muted">API端口</span><input id="f-port" type="number" value="'+esc(s.port||'')+'"></div>'+
 '<div class="field"><span class="small muted">API路径</span><input id="f-path" value="'+esc(s.path||'/api')+'"></div></div>'+
 '<div class="field"><span class="small muted">Token'+(s.id?' (留空表示不修改)':'')+'</span><input id="f-token" type="password" autocomplete="off"></div>'+
 '<div class="field"><span class="small muted">备注</span><input id="f-note" value="'+esc(s.note||'')+'"></div>'+
 '<div class="bar"><button class="primary" id="f-save">保存并测试</button><span class="err small" id="f-err"></span></div>',true);
 var js=$('f-json');
 if(js)js.addEventListener('input',function(){try{var o=JSON.parse(js.value);['name','host','port','path','token'].forEach(function(k){if(o[k]!=null)$('f-'+k).value=o[k]})}catch(e){}});
 $('f-save').addEventListener('click',function(){
  var body={id:s.id,name:val('f-name'),host:val('f-host'),port:val('f-port'),path:val('f-path'),token:val('f-token'),note:val('f-note')};
  api('/api/servers',{body:body}).then(function(j){S.servers=j.data;var ns=s.id?srvById(s.id):S.servers[S.servers.length-1];closeModal();renderGrid();return refreshOne(ns.id).then(function(){var st=S.status[ns.id];toast(st.error?'已保存，但连接失败：'+st.error:'已保存，连接成功')})})
  .catch(function(e){$('f-err').textContent=e.message});
 });
}

// ---------- 访问日志
function logsDialog(s,preset){
 preset=preset||{};
 var m=modal('访问日志 · '+esc(s.name),
 '<div class="bar" style="margin-bottom:8px"><input id="l-ip" placeholder="源IP" size="16" value="'+esc(preset.ip||'')+'"><input id="l-q" placeholder="访问目标/关键字" size="18" value="'+esc(preset.q||'')+'">'+
 '<select id="l-proto"><option value="">全部协议</option>'+PROTOS.filter(function(p){return p[0]!=='vmess-argo'}).map(function(p){return '<option value="'+p[0]+'">'+p[1]+'</option>'}).join('')+'</select>'+
 '<select id="l-hours"><option value="1">1小时</option><option value="6">6小时</option><option value="24" selected>24小时</option><option value="72">3天</option><option value="">全部</option></select>'+
 '<select id="l-limit"><option>100</option><option selected>300</option><option>1000</option><option>3000</option></select>'+
 '<label><input type="checkbox" id="l-err">只看失败/探测</label><label><input type="checkbox" id="l-local">隐藏Argo/本地</label>'+
 '<button class="primary" id="l-go">查询</button><button id="l-raw">原始日志</button></div><div id="l-info" class="small muted"></div><div class="tablewrap" id="l-out"></div>');
 function q(){
  var out=$('l-out');busy(out);
  call(s.id,'logs',{ip:val('l-ip'),q:val('l-q'),proto:val('l-proto'),hours:val('l-hours')?Number(val('l-hours')):null,limit:Number(val('l-limit')),err:checked('l-err'),hidelocal:checked('l-local')})
  .then(function(d){
   $('l-info').textContent=(d.enabled?'':'⚠ 连接日志未开启（在「日志/流量/定时」中开启）。 ')+'日志 '+fmtBytes(d.size)+'，记录范围 '+(d.first||'-')+' ~ '+(d.last||'-')+'，显示 '+d.matched+' 条 / 共 '+d.total+' 条';
   if(!d.records.length){out.innerHTML='<p class="muted" style="padding:8px">没有匹配的记录</p>';return}
   out.innerHTML='<table><thead><tr><th>时间</th><th>协议</th><th>源IP</th><th>端口</th><th>访问目标</th><th>网络</th><th>出站</th><th>备注</th></tr></thead><tbody>'+
   d.records.map(function(r){var tgt=r.domain||r.dst||'';var note=(r.domain&&r.dst&&r.domain!==r.dst?'原始目标 '+r.dst+' ':'')+(r.odst?'出站目标 '+r.odst+' ':'')+(r.user?'用户 '+r.user+' ':'');
    return '<tr><td>'+esc(r.time)+'</td><td>'+esc(r.proto||'')+'</td><td><a data-ip="'+esc(r.src)+'">'+esc(r.src)+'</a>'+(isLocal(r.src)?' <span class="chip">Argo/CDN</span>':'')+'</td><td>'+esc(r.sport)+'</td>'+
    '<td class="wrap">'+(tgt?'<a data-q="'+esc(tgt.replace(/:\\d+$/,''))+'">'+esc(tgt)+'</a>':'')+'</td><td>'+esc(r.net)+'</td><td>'+esc(r.out||'')+'</td><td class="wrap'+(r.err?' err':'')+'">'+esc(r.err||note)+'</td></tr>'}).join('')+'</tbody></table>';
   bind(out,'a[data-ip]',function(a){$('l-ip').value=a.getAttribute('data-ip');q()});
   bind(out,'a[data-q]',function(a){$('l-q').value=a.getAttribute('data-q');q()});
  }).catch(function(e){fail(out,e)});
 }
 $('l-go').addEventListener('click',q);
 m.querySelectorAll('input').forEach(function(i){i.addEventListener('keydown',function(e){if(e.key==='Enter')q()})});
 $('l-raw').addEventListener('click',function(){var out=$('l-out');busy(out);call(s.id,'rawlog',{lines:500}).then(function(d){out.innerHTML='<pre class="link" style="margin:0;white-space:pre-wrap">'+esc(d.lines.join('\\n'))+'</pre>'}).catch(function(e){fail(out,e)})});
 q();
}
function isLocal(ip){return ip==='::1'||/^127\\./.test(ip||'')}

// ---------- 连接统计
function statsDialog(s){
 modal('源IP与访问目标统计 · '+esc(s.name),
 '<div class="bar" style="margin-bottom:8px"><select id="s-hours"><option value="1">1小时</option><option value="6">6小时</option><option value="24" selected>24小时</option><option value="72">3天</option><option value="168">7天</option></select>'+
 '<span class="tabs bar"><button class="on" data-st="ip">按源IP</button><button data-st="dest">按访问目标</button></span></div><div id="s-sum" style="margin-bottom:8px"></div><div class="tablewrap" id="s-out"></div>');
 var data=null,tab='ip';
 function draw(){
  var out=$('s-out');if(!data)return;
  if(tab==='ip'){out.innerHTML='<table><thead><tr><th>源IP</th><th>连接数</th><th>失败</th><th>首次</th><th>最近</th><th>协议</th><th>常访问目标</th><th></th></tr></thead><tbody>'+
   data.ips.map(function(x){return '<tr><td>'+esc(x.ip)+(x.local?' <span class="chip">Argo/CDN</span>':'')+'</td><td>'+x.count+'</td><td'+(x.err?' class="err"':'')+'>'+x.err+'</td><td>'+esc(x.first)+'</td><td>'+esc(x.last)+'</td><td>'+esc(x.protos.join(','))+'</td>'+
   '<td class="wrap">'+x.top.map(function(t){return esc(t[0])+' ('+t[1]+')'}).join('，')+'</td><td><a data-ip="'+esc(x.ip)+'">明细</a></td></tr>'}).join('')+'</tbody></table>';
   bind(out,'a[data-ip]',function(a){logsDialog(s,{ip:a.getAttribute('data-ip')})});
  }else{out.innerHTML='<table><thead><tr><th>访问目标</th><th>次数</th><th>来源IP数</th><th>最近访问</th><th></th></tr></thead><tbody>'+
   data.dests.map(function(x){return '<tr><td class="wrap">'+esc(x.host)+'</td><td>'+x.count+'</td><td>'+x.ips+'</td><td>'+esc(x.last)+'</td><td><a data-q="'+esc(x.host)+'">明细</a></td></tr>'}).join('')+'</tbody></table>';
   bind(out,'a[data-q]',function(a){logsDialog(s,{q:a.getAttribute('data-q')})});
  }
 }
 function load(){
  busy($('s-out'));
  call(s.id,'stats',{hours:Number(val('s-hours')),top:300}).then(function(d){data=d;
   $('s-sum').innerHTML='<span class="stat"><b>'+d.conns+'</b> 连接</span><span class="stat"><b>'+d.unique_ips+'</b> 个源IP</span><span class="stat"><b>'+d.unique_dests+'</b> 个访问目标</span><span class="stat"><b class="'+(d.errors?'err':'')+'">'+d.errors+'</b> 失败/探测</span>';draw()})
  .catch(function(e){fail($('s-out'),e)});
 }
 $('s-hours').addEventListener('change',load);
 bind(null,'[data-st]',function(b){tab=b.getAttribute('data-st');document.querySelectorAll('[data-st]').forEach(function(x){x.classList.toggle('on',x===b)});draw()});
 load();
}

// ---------- 在线IP
function peersDialog(s){
 modal('当前在线客户端 · '+esc(s.name),'<p class="small muted">TCP连接取自 ss，Hysteria2/Tuic(UDP) 取自 conntrack（需系统已加载 nf_conntrack）</p><div class="tablewrap" id="p-out"></div>');
 busy($('p-out'));
 call(s.id,'peers').then(function(d){
  $('p-out').innerHTML=d.peers.length?'<table><thead><tr><th>源IP</th><th>协议</th><th>连接数</th><th></th></tr></thead><tbody>'+d.peers.map(function(p){return '<tr><td>'+esc(p.ip)+(p.local?' <span class="chip">Argo/CDN</span>':'')+'</td><td>'+esc(p.proto)+'</td><td>'+p.conns+'</td><td><a data-ip="'+esc(p.ip)+'">访问记录</a></td></tr>'}).join('')+'</tbody></table>':'<p class="muted" style="padding:8px">当前没有在线客户端</p>';
  bind($('p-out'),'a[data-ip]',function(a){logsDialog(s,{ip:a.getAttribute('data-ip')})});
 }).catch(function(e){fail($('p-out'),e)});
}

// ---------- 节点链接
function linksHtml(d){
 return (d.links||[]).concat(d.subs||[]).map(function(x){return '<div><b class="small">'+esc(x.name)+'</b> <a data-copy="'+esc(x.link)+'">复制</a><div class="link">'+esc(x.link)+'</div></div>'}).join('')||'<p class="muted">暂无节点链接</p>';
}
function linksDialog(s){
 modal('节点与订阅链接 · '+esc(s.name),'<p class="small err">链接即节点访问权限，请勿在不可信环境展示或分享（查看操作会记入审计日志）</p><div id="k-out"></div>');
 busy($('k-out'));
 call(s.id,'links').then(function(d){var o=$('k-out');o.innerHTML=linksHtml(d)+'<button id="k-all">复制全部节点链接</button>';
  $('k-all').addEventListener('click',function(){copy((d.links||[]).map(function(x){return x.link}).join('\\n'))})})
 .catch(function(e){fail($('k-out'),e)});
}

// ---------- 重置参数（单台/批量/全部）
function resetDialog(list,all){
 if(!list.length)return toast('没有服务器');
 modal((all?'一键全部重置参数':'防泄露参数重置')+' · '+esc(list.length===1?list[0].name:list.length+' 台服务器'),
 '<p class="small">重置后旧的节点链接与订阅链接<b class="err">立即失效</b>，客户端需重新导入。服务器会自动重新生成本地订阅、同步Gitlab订阅并推送TG（如已设置）；面板中的订阅会自动使用新参数。</p>'+
 (list.length>1?'<p class="small muted">对象：'+esc(list.map(function(s){return s.name}).join('、'))+'</p>':'')+
 '<div class="field"><label><input type="checkbox" id="r-uuid" checked>UUID(密码) + Vmess路径</label><label><input type="checkbox" id="r-reality" checked>Reality 密钥对与 short_id</label>'+
 '<label><input type="checkbox" id="r-subtoken" checked>服务器本地订阅链接路径</label><label><input type="checkbox" id="r-ports">Vless/Hy2/Tuic/Anytls 端口（需VPS防火墙放行全部端口；Vmess端口不变）</label>'+
 '<label><input type="checkbox" id="r-subs"'+(all?' checked':'')+'>同时重置面板中全部订阅链接（旧订阅地址失效）</label></div>'+
 '<div class="bar"><button class="primary" id="r-go">确认重置</button><span class="small muted" id="r-st"></span></div><div id="r-out" style="margin-top:10px"></div>');
 $('r-go').addEventListener('click',function(){
  var items=[];['uuid','reality','subtoken','ports'].forEach(function(k){if(checked('r-'+k))items.push(k==='uuid'?'uuid,path':k)});
  if(!items.length&&!checked('r-subs'))return toast('请至少选择一项');
  if(!confirm('确认重置 '+list.length+' 台服务器的参数？'))return;
  var btn=$('r-go');btn.disabled=true;$('r-st').textContent='重置中，每台约需10~60秒…';
  var out=$('r-out');out.innerHTML='';
  var jobs=items.length?list.map(function(s){
   var box=document.createElement('div');box.className='card';box.style.marginBottom='8px';box.innerHTML='<b>'+esc(s.name)+'</b> <span class="muted small">进行中…</span>';out.appendChild(box);
   return call(s.id,'reset',{items:items.join(',')}).then(function(d){
    var ch=d.changed||{};
    box.innerHTML='<b>'+esc(s.name)+'</b> <span class="small okc">✔ 已重置 '+esc(Object.keys(ch).join(','))+(d.active?'':'，<b class="err">但Sing-box未运行</b>')+'</span>'+
    (ch.ports?'<div class="small">新端口：'+esc(JSON.stringify(ch.ports))+'</div>':'')+(list.length===1?linksHtml(d):'');refreshOne(s.id);return true;
   },function(e){box.innerHTML='<b>'+esc(s.name)+'</b> <span class="err small">✘ '+esc(e.message)+'</span>';return false});
  }):[];
  Promise.all(jobs).then(function(rs){
   if(!checked('r-subs'))return rs;
   return api('/api/subs/rotate-all',{body:{}}).then(function(j){var box=document.createElement('div');box.className='card';
    box.innerHTML='<b>订阅链接已全部重置</b>'+j.data.map(function(x){return '<div class="small">'+esc(x.name)+' <a data-copy="'+esc(x.url)+'">复制</a><div class="link">'+esc(x.url)+'</div></div>'}).join('');out.appendChild(box);return rs});
  }).then(function(rs){var okn=rs.filter(Boolean).length;$('r-st').textContent=items.length?'完成：成功 '+okn+' 台，失败 '+(rs.length-okn)+' 台':'完成';btn.disabled=false})
  .catch(function(e){$('r-st').textContent=e.message;btn.disabled=false});
 });
}

// ---------- 日志/流量/定时 设置
function settingsDialog(s){
 modal('日志 / 流量 / 定时 · '+esc(s.name),'<div id="g-out"></div>',true);
 busy($('g-out'));
 call(s.id,'status').then(function(d){
  var lk=d.leak||{},pol=(d.log&&d.log.policy)||{},tr=d.traffic||{};
  var now=Date.now();
  $('g-out').innerHTML=
  '<div class="section"><h3>连接访问日志</h3><p class="small">状态：'+(d.log.enabled?'已开启，共 '+fmtBytes(d.log.size)+'（当前 '+fmtBytes(d.log.current)+'，归档 '+d.log.archives+' 份 '+fmtBytes(d.log.archive_size)+'）':'<span class="err">未开启</span>')+'</p>'+
  '<div class="bar"><button data-do="logon">开启</button><button data-do="logoff">关闭</button><button data-do="clearlog" class="danger">清空全部日志</button></div>'+
  '<div class="row" style="margin-top:8px"><div class="field"><span class="small muted">单文件上限(MB)</span><input id="g-mb" type="number" value="'+esc(pol.max_mb)+'"></div><div class="field"><span class="small muted">保留归档份数</span><input id="g-keep" type="number" value="'+esc(pol.keep)+'"></div>'+
  '<div class="field"><span class="small muted">归档保留天数(0不限)</span><input id="g-rd" type="number" value="'+esc(pol.retain_days)+'"></div><div class="field"><span class="small muted">&nbsp;</span><label><input type="checkbox" id="g-gz"'+(pol.compress?' checked':'')+'>gzip压缩归档</label></div></div>'+
  '<button id="g-pol" class="primary">保存日志策略</button>'+
  '<div class="bar small" style="margin-top:8px">按时间段删除日志：<input type="datetime-local" id="g-ls" value="'+localInput(now-30*86400000)+'"> 至 <input type="datetime-local" id="g-le" value="'+localInput(now-7*86400000)+'"><button id="g-lprune" class="danger">删除</button></div></div>'+
  '<div class="section"><h3>流量统计</h3><p class="small">状态：'+(tr.enabled?'统计中，数据库 '+fmtBytes(tr.db_size)+'，保留 '+esc(tr.retain_days)+' 天'+(tr.collector&&tr.collector!=='ok'?' <span class="err">采集异常：'+esc(tr.collector)+'</span>':''):'<span class="muted">未开启</span>')+(tr.available===false?' <span class="err">（缺少sqlite3）</span>':'')+'</p>'+
  '<div class="bar"><button data-do="trafficon">开启</button><button data-do="trafficoff">关闭</button>保留天数 <input id="g-tr" type="number" style="width:80px" value="'+esc(tr.retain_days||90)+'"><button id="g-trs">保存</button></div>'+
  '<div class="bar small" style="margin-top:8px">按时间段删除流量记录：<input type="datetime-local" id="g-ts" value="'+localInput(now-90*86400000)+'"> 至 <input type="datetime-local" id="g-te" value="'+localInput(now-30*86400000)+'"><button id="g-tprune" class="danger">删除</button></div></div>'+
  '<div class="section"><h3>定时自动重置（UUID+Reality+订阅路径）</h3><p class="small muted">'+esc(d.schedule||'未设置')+'</p><div class="bar"><button data-sch="daily">每天04:00</button><button data-sch="weekly">每周一04:00</button><button data-sch="off">关闭</button></div></div>'+
  '<div class="section"><h3>泄露检测（每小时一次）</h3>'+
  '<div class="bar small"><label><input type="checkbox" id="g-len"'+(lk.enabled?' checked':'')+'>开启</label> 最近 <input id="g-lh" type="number" style="width:70px" value="'+esc(lk.hours||24)+'"> 小时内，不同源IP超过 <input id="g-lt" type="number" style="width:70px" value="'+esc(lk.threshold||10)+'"> 个时'+
  '<select id="g-la"><option value="notify"'+(lk.action!=='reset'?' selected':'')+'>仅TG通知</option><option value="reset"'+(lk.action==='reset'?' selected':'')+'>自动重置并TG推送</option></select><button id="g-lsave" class="primary">保存</button><button id="g-lcheck">立即检测</button></div><div id="g-lres" class="small" style="margin-top:6px"></div></div>'+
  '<p class="small muted">API权限：'+(d.api&&d.api.perms?d.api.perms.map(function(p){return PERM_NAMES[p]||p}).join('、'):'-')+(d.api&&d.api.allow&&d.api.allow.length?'；IP白名单：'+esc(d.api.allow.join(', ')):'')+'。权限与白名单只能在VPS上通过 sb → 19 修改。</p>';
  function act(a,p,msg,reload){return call(s.id,a,p).then(function(r){toast(msg);refreshOne(s.id);if(reload)settingsDialog(s);return r}).catch(function(e){toast(e.message)})}
  bind($('g-out'),'[data-do]',function(b){var a=b.getAttribute('data-do');if(a==='clearlog'&&!confirm('清空全部日志（含归档）？'))return;act(a,{},'已完成',true)});
  bind($('g-out'),'[data-sch]',function(b){act('schedule',{mode:b.getAttribute('data-sch'),items:'all'},'已保存',true)});
  $('g-pol').addEventListener('click',function(){act('logpolicy',{max_mb:Number(val('g-mb')),keep:Number(val('g-keep')),retain_days:Number(val('g-rd')),compress:checked('g-gz')},'日志策略已保存',true)});
  $('g-lprune').addEventListener('click',function(){if(confirm('删除该时间段的日志？'))act('logprune',{start:inputTime('g-ls'),end:inputTime('g-le')},'已删除',true).then(function(r){if(r)toast('删除 '+r.removed_lines+' 行')})});
  $('g-trs').addEventListener('click',function(){act('trafficconf',{retain_days:Number(val('g-tr'))},'已保存',true)});
  $('g-tprune').addEventListener('click',function(){if(confirm('删除该时间段的流量记录？'))act('trafficpurge',{start:inputTime('g-ts'),end:inputTime('g-te')},'已删除',true)});
  $('g-lsave').addEventListener('click',function(){act('leakconf',{enabled:checked('g-len'),hours:Number(val('g-lh')),threshold:Number(val('g-lt')),action:val('g-la'),items:'all'},'已保存')});
  $('g-lcheck').addEventListener('click',function(){call(s.id,'leakcheck').then(function(r){$('g-lres').innerHTML='最近 '+esc(r.hours)+' 小时：'+r.unique_ips+' 个源IP（阈值 '+r.threshold+'）'+(r.exceeded?' <b class="err">已超过阈值</b>':' 正常')+'<br>'+r.ips.slice(0,20).map(function(x){return esc(x[0])+'('+x[1]+')'}).join('，')}).catch(function(e){toast(e.message)})});
 }).catch(function(e){fail($('g-out'),e)});
}

// ---------- API 审计日志（服务器端）
function apilogDialog(s){
 modal('API访问审计日志 · '+esc(s.name),'<p class="small muted">记录服务器API收到的修改操作、权限拒绝、认证失败封禁等（高频只读查询不记录）</p><div class="tablewrap" id="al-out"></div>');
 busy($('al-out'));
 call(s.id,'apilog',{lines:500}).then(function(d){
  $('al-out').innerHTML=d.entries.length?'<table><thead><tr><th>时间</th><th>来源IP</th><th>操作</th><th>结果</th><th>参数/错误</th></tr></thead><tbody>'+d.entries.map(function(e){return '<tr><td>'+esc(e.time)+'</td><td>'+esc(e.ip)+'</td><td>'+esc(e.action)+'</td><td class="'+(e.ok?'okc':'err')+'">'+(e.ok?'成功':'失败')+'</td><td class="wrap">'+esc(e.error||JSON.stringify(e.params||{}))+'</td></tr>'}).join('')+'</tbody></table>':'<p class="muted" style="padding:8px">暂无记录</p>';
 }).catch(function(e){fail($('al-out'),e)});
}

// ---------- 批量操作
function batchDialog(){
 var ids=Object.keys(S.selected).filter(function(k){return S.selected[k]&&srvById(k)});
 var list=ids.length?ids.map(srvById):S.servers.slice();
 modal('批量操作','<p class="small">对象：'+(ids.length?'已勾选的 ':'全部 ')+list.length+' 台 —— '+esc(list.map(function(s){return s.name}).join('、'))+'</p>'+
 '<div class="bar"><button id="x-reset" class="danger">批量重置参数</button><button id="x-restart">批量重启</button><button id="x-logon">批量开启日志</button><button id="x-tron">批量开启流量统计</button><button id="x-stats">汇总24小时源IP</button></div><div id="x-out" style="margin-top:10px"></div>',true);
 $('x-reset').addEventListener('click',function(){resetDialog(list)});
 function each(action,params,label){
  var out=$('x-out');out.innerHTML='';
  list.forEach(function(s){var d=document.createElement('div');d.className='small';d.textContent=s.name+'：'+label+'中…';out.appendChild(d);
   call(s.id,action,params).then(function(){d.textContent=s.name+'：✔ 完成';refreshOne(s.id)},function(e){d.textContent=s.name+'：✘ '+e.message;d.className='small err'})});
 }
 $('x-restart').addEventListener('click',function(){if(confirm('重启 '+list.length+' 台服务器的 Sing-box？'))each('restart',{},'重启')});
 $('x-logon').addEventListener('click',function(){each('logon',{},'开启日志')});
 $('x-tron').addEventListener('click',function(){each('trafficon',{},'开启流量统计')});
 $('x-stats').addEventListener('click',function(){
  var out=$('x-out');busy(out,'汇总中…');
  Promise.all(list.map(function(s){return call(s.id,'stats',{hours:24,top:1000}).then(function(d){return{s:s,d:d}},function(e){return{s:s,e:e}})})).then(function(rs){
   var ipm={};rs.forEach(function(r){if(!r.d)return;r.d.ips.forEach(function(x){var o=ipm[x.ip]||(ipm[x.ip]={ip:x.ip,count:0,servers:[]});o.count+=x.count;o.servers.push(r.s.name)})});
   var arr=Object.keys(ipm).map(function(k){return ipm[k]}).sort(function(a,b){return b.count-a.count});
   out.innerHTML=rs.filter(function(r){return r.e}).map(function(r){return '<div class="err small">'+esc(r.s.name)+'：'+esc(r.e.message)+'</div>'}).join('')+
   '<div class="tablewrap"><table><thead><tr><th>源IP</th><th>连接数</th><th>访问的服务器</th></tr></thead><tbody>'+arr.map(function(x){return '<tr><td>'+esc(x.ip)+'</td><td>'+x.count+'</td><td class="wrap">'+esc(x.servers.join('、'))+'</td></tr>'}).join('')+'</tbody></table></div>';
  });
 });
}

// ---------- 导入导出
function ioDialog(){
 modal('导入 / 导出','<div class="section"><h3>导出备份（服务器含Token、订阅）</h3><div class="bar"><input type="password" id="i-pw" placeholder="请输入管理密码确认"><button id="i-exp">导出为JSON</button></div></div>'+
 '<div class="section"><h3>导入</h3><div class="field"><span class="small muted">粘贴导出的备份JSON，或一台/多台服务器的对接JSON（同IP+端口会被覆盖）</span><textarea id="i-json" rows="8"></textarea></div><button class="primary" id="i-go">导入</button> <span id="i-res" class="small"></span></div>',true);
 $('i-exp').addEventListener('click',function(){
  fetch('/api/export',{method:'POST',headers:{'x-sbyg':'1','content-type':'application/json'},body:JSON.stringify({password:$('i-pw').value}),credentials:'same-origin'}).then(function(r){
   if(!r.ok)return r.json().then(function(j){throw new Error(j.error||'导出失败')});
   return r.blob().then(function(b){var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='sbyg-backup.json';a.click();setTimeout(function(){URL.revokeObjectURL(a.href)},5000)});
  }).catch(function(e){toast(e.message)});
 });
 $('i-go').addEventListener('click',function(){
  var v;try{v=JSON.parse(val('i-json'))}catch(e){return toast('JSON格式错误')}
  api('/api/import',{body:v}).then(function(j){$('i-res').textContent='新增服务器 '+j.data.added+' 台，更新 '+j.data.updated+' 台，新增订阅 '+j.data.subs+' 个';loadServers()}).catch(function(e){toast(e.message)});
 });
}

// ================= 流量统计
var GROUPS=[['ip','按源IP'],['host','按访问地址'],['day','按日期'],['hour','按小时'],['inbound','按协议'],['outbound','按出站'],['ip_host','源IP+访问地址']];
function viewTraffic(){
 var now=Date.now();
 if(!S.servers.length){api('/api/servers').then(function(j){S.servers=j.data;if(j.data.length)viewTraffic();else $('view').innerHTML='<div class="card muted">请先添加服务器</div>'});return}
 $('view').innerHTML='<div class="card" style="margin-bottom:10px"><div class="bar">'+
 '<select id="t-srv"><option value="">全部服务器</option>'+S.servers.map(function(s){return '<option value="'+esc(s.id)+'"'+(S.trafficServer===s.id?' selected':'')+'>'+esc(s.name)+'</option>'}).join('')+'</select>'+
 '<select id="t-range"><option value="today">今天</option><option value="yesterday">昨天</option><option value="24h" selected>最近24小时</option><option value="7d">最近7天</option><option value="30d">最近30天</option><option value="custom">自定义</option></select>'+
 '<span id="t-custom" hidden><input type="datetime-local" id="t-start" value="'+localInput(now-86400000)+'"> 至 <input type="datetime-local" id="t-end" value="'+localInput(now)+'"></span>'+
 '<select id="t-group">'+GROUPS.map(function(g){return '<option value="'+g[0]+'">'+g[1]+'</option>'}).join('')+'</select>'+
 '<input id="t-ip" placeholder="源IP筛选" size="14"><input id="t-host" placeholder="访问地址筛选" size="16"><input id="t-in" placeholder="协议筛选(如 vless)" size="12">'+
 '<select id="t-limit"><option>50</option><option selected>200</option><option>1000</option></select>'+
 '<button class="primary" id="t-go">查询</button><button id="t-csv">导出CSV</button></div>'+
 '<p class="small muted" style="margin:6px 0 0">数据来自各服务器 sing-box 的连接计数（需在服务器「日志/流量/定时」中开启流量统计），按小时聚合；时间按浏览器本地时间。点击分组项可下钻。</p></div>'+
 '<div id="t-sum" style="margin-bottom:10px"></div><div id="t-chart"></div><div class="tablewrap" id="t-out"></div>';
 $('t-range').addEventListener('change',function(){$('t-custom').hidden=val('t-range')!=='custom'});
 $('t-go').addEventListener('click',loadTraffic);
 $('t-csv').addEventListener('click',exportCsv);
 ['t-ip','t-host','t-in'].forEach(function(id){$(id).addEventListener('keydown',function(e){if(e.key==='Enter')loadTraffic()})});
 S.trafficServer=null;
 loadTraffic();
}
function trafficRange(){
 var r=val('t-range'),now=new Date(),d0=new Date(now.getFullYear(),now.getMonth(),now.getDate()).getTime()/1000,t=Math.floor(now.getTime()/1000);
 if(r==='today')return[d0,t];if(r==='yesterday')return[d0-86400,d0];if(r==='7d')return[t-7*86400,t];if(r==='30d')return[t-30*86400,t];
 if(r==='custom')return[inputTime('t-start'),inputTime('t-end')];return[t-86400,t];
}
var TR=null;
function loadTraffic(){
 var range=trafficRange(),group=val('t-group'),sid=val('t-srv');
 var list=sid?[srvById(sid)]:S.servers.slice();
 var params={start:range[0],end:range[1],group:group,ip:val('t-ip'),host:val('t-host'),inbound:val('t-in'),limit:Number(val('t-limit'))};
 busy($('t-out'),'查询中…');$('t-sum').innerHTML='';$('t-chart').innerHTML='';
 Promise.all(list.map(function(s){return call(s.id,'traffic',params).then(function(d){return{s:s,d:d}},function(e){return{s:s,e:e}})})).then(function(rs){
  var rows={},tot={up:0,down:0},mt={up:0,down:0,conns:0},errs=[],off=[];
  rs.forEach(function(r){
   if(r.e){errs.push(r.s.name+'：'+r.e.message);return}
   if(!r.d.enabled)off.push(r.s.name);
   tot.up+=r.d.total.up;tot.down+=r.d.total.down;mt.up+=r.d.matched.up;mt.down+=r.d.matched.down;mt.conns+=r.d.matched.conns;
   r.d.rows.forEach(function(x){var o=rows[x.key]||(rows[x.key]={key:x.key,up:0,down:0,conns:0,ips:0,hosts:0,servers:[]});o.up+=x.up;o.down+=x.down;o.conns+=x.conns;o.ips=Math.max(o.ips,x.ips);o.hosts=Math.max(o.hosts,x.hosts);o.servers.push(r.s.name)});
  });
  var arr=Object.keys(rows).map(function(k){return rows[k]});
  if(group==='day'||group==='hour')arr.sort(function(a,b){return a.key<b.key?-1:1});else arr.sort(function(a,b){return (b.up+b.down)-(a.up+a.down)});
  TR={rows:arr,group:group};
  $('t-sum').innerHTML='<div class="card"><span class="stat">服务器总流量 <b>'+fmtBytes(tot.up+tot.down)+'</b></span><span class="stat">上行 <b>'+fmtBytes(tot.up)+'</b></span><span class="stat">下行 <b>'+fmtBytes(tot.down)+'</b></span>'+
  '<span class="stat">筛选结果 <b>'+fmtBytes(mt.up+mt.down)+'</b></span><span class="stat">连接 <b>'+mt.conns+'</b></span>'+
  (errs.length?'<div class="err small">'+esc(errs.join('；'))+'</div>':'')+(off.length?'<div class="small muted">未开启流量统计：'+esc(off.join('、'))+'</div>':'')+'</div>';
  if((group==='day'||group==='hour')&&arr.length)$('t-chart').innerHTML=chart(arr);
  var max=arr.reduce(function(m,x){return Math.max(m,x.up+x.down)},0)||1;
  var label=GROUPS.filter(function(g){return g[0]===group})[0][1].replace('按','');
  $('t-out').innerHTML=arr.length?'<table><thead><tr><th>'+esc(label)+'</th><th class="num">上行</th><th class="num">下行</th><th class="num">合计</th><th>占比</th><th class="num">连接</th><th class="num">IP数</th><th class="num">地址数</th>'+(list.length>1?'<th>服务器</th>':'')+'</tr></thead><tbody>'+
  arr.map(function(x){var t=x.up+x.down;var drill=(group==='ip'||group==='host'||group==='inbound')?'<a data-k="'+esc(x.key)+'">'+esc(x.key)+'</a>':esc(x.key);
   return '<tr><td class="wrap">'+drill+'</td><td class="num">'+fmtBytes(x.up)+'</td><td class="num">'+fmtBytes(x.down)+'</td><td class="num"><b>'+fmtBytes(t)+'</b></td><td><div class="meter"><i style="width:'+Math.max(1,Math.round(t/max*100))+'%"></i></div></td><td class="num">'+x.conns+'</td><td class="num">'+x.ips+'</td><td class="num">'+x.hosts+'</td>'+(list.length>1?'<td class="small">'+esc(x.servers.join('、'))+'</td>':'')+'</tr>'}).join('')+'</tbody></table>':'<p class="muted" style="padding:8px">没有数据</p>';
  bind($('t-out'),'a[data-k]',function(a){var k=a.getAttribute('data-k');if(group==='ip'){$('t-ip').value=k;$('t-group').value='host'}else if(group==='host'){$('t-host').value=k;$('t-group').value='ip'}else{$('t-in').value=k.split('/').pop();$('t-group').value='ip'}loadTraffic()});
 });
}
function chart(arr){
 var w=Math.max(600,arr.length*14),h=160,pad=30,max=arr.reduce(function(m,x){return Math.max(m,x.up+x.down)},0)||1,bw=(w-pad)/arr.length;
 var bars=arr.map(function(x,i){var bh=Math.round((x.up+x.down)/max*(h-30)),uh=Math.round(x.up/max*(h-30));var X=pad+i*bw;
  return '<rect x="'+X.toFixed(1)+'" y="'+(h-20-bh)+'" width="'+Math.max(2,bw-2).toFixed(1)+'" height="'+bh+'" fill="var(--bar)"><title>'+esc(x.key)+' 合计 '+fmtBytes(x.up+x.down)+'</title></rect>'+
  '<rect x="'+X.toFixed(1)+'" y="'+(h-20-uh)+'" width="'+Math.max(2,bw-2).toFixed(1)+'" height="'+uh+'" fill="var(--accent)" opacity=".8"><title>'+esc(x.key)+' 上行 '+fmtBytes(x.up)+'</title></rect>'+
  ((i%Math.ceil(arr.length/10)===0)?'<text x="'+X.toFixed(1)+'" y="'+(h-6)+'">'+esc(String(x.key).slice(5))+'</text>':'')});
 return '<div class="card" style="margin-bottom:10px;overflow:auto"><div class="small muted">深色：上行　浅色：合计　最高 '+fmtBytes(max)+'</div><svg width="'+w+'" height="'+h+'" role="img" aria-label="流量柱状图">'+bars.join('')+'</svg></div>';
}
function exportCsv(){
 if(!TR||!TR.rows.length)return toast('请先查询');
 var lines=['key,upload,download,total,conns,ips,hosts'].concat(TR.rows.map(function(x){return ['"'+String(x.key).replace(/"/g,'""')+'"',x.up,x.down,x.up+x.down,x.conns,x.ips,x.hosts].join(',')}));
 var a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['\\ufeff'+lines.join('\\n')],{type:'text/csv'}));a.download='traffic-'+TR.group+'.csv';a.click();
}

// ================= 订阅管理
function viewSubs(){
 $('view').innerHTML='<div class="bar" style="margin-bottom:10px"><button class="primary" id="u-new">新建订阅</button><button id="u-refresh">刷新全部节点缓存</button><button id="u-rot" class="danger">重置全部订阅链接</button>'+
 '<span class="small muted">订阅内容来自各服务器节点链接的缓存（重置参数后自动更新，并按设置定期刷新）+ 自定义节点</span></div><div id="u-cache" class="small muted" style="margin-bottom:8px"></div><div class="grid" id="u-list"></div>';
 $('u-new').addEventListener('click',function(){editSub()});
 $('u-refresh').addEventListener('click',function(){$('u-cache').textContent='刷新中…';api('/api/links/refresh',{body:{}}).then(function(j){var bad=j.data.filter(function(x){return !x.ok});toast('已刷新 '+(j.data.length-bad.length)+' 台'+(bad.length?'，失败 '+bad.length+' 台':''));loadSubs()}).catch(function(e){toast(e.message)})});
 $('u-rot').addEventListener('click',function(){if(confirm('重置全部订阅链接？旧订阅地址将立即失效。'))api('/api/subs/rotate-all',{body:{}}).then(function(j){toast('已重置');drawSubs(j.data)}).catch(function(e){toast(e.message)})});
 loadSubs();
}
function loadSubs(){
 Promise.all([api('/api/subs'),api('/api/links'),api('/api/servers')]).then(function(r){S.links=r[1].data;S.servers=r[2].data;
  $('u-cache').innerHTML='节点缓存：'+(S.links.map(function(x){return esc(x.name)+' '+(x.t?x.count+'个 / '+fmtTime(x.t):'<span class="err">无缓存</span>')}).join('；')||'无服务器');drawSubs(r[0].data)}).catch(function(e){fail($('u-list'),e)});
}
function drawSubs(list){
 var el=$('u-list');if(!el)return;S.subs=list;
 if(!list.length){el.innerHTML='<div class="card muted">还没有订阅。新建订阅后，可把多台服务器的节点和自定义节点合并为一个订阅链接（Base64格式，适用于 v2rayN/NekoBox/小火箭等）。</div>';return}
 el.innerHTML=list.map(function(s){var st=s.stat||{hits:0,ips:[]};
  var names=s.servers.map(function(id){var x=srvById(id);return x?x.name:'(已删除)'});
  return '<div class="card"><h3><span class="dot '+(s.enabled?'ok':'')+'"></span>'+esc(s.name)+(s.expires&&s.expires<Date.now()?' <span class="chip err">已过期</span>':'')+'</h3>'+
  '<div class="link">'+esc(s.url)+'</div><div class="bar small"><a data-copy="'+esc(s.url)+'">复制订阅链接</a><a data-copy="'+esc(s.url+'?format=plain')+'">复制明文格式链接</a></div>'+
  '<div class="kv"><span>服务器</span><span>'+(names.length?esc(names.join('、')):'无')+'</span><span>协议</span><span>'+(s.protos.length?esc(s.protos.join('、')):'全部')+'</span>'+
  '<span>自定义节点</span><span>'+s.custom.length+' 个</span><span>访问</span><span>'+st.hits+' 次，'+st.ips.length+' 个IP'+(st.last?'，最近 '+fmtTime(st.last.t)+' '+esc(st.last.ip):'')+'</span>'+
  '<span>链接重置</span><span>'+fmtTime(s.rotated)+'</span>'+(s.expires?'<span>到期</span><span>'+fmtTime(s.expires)+'</span>':'')+(s.note?'<span>备注</span><span>'+esc(s.note)+'</span>':'')+'</div>'+
  '<div class="actions"><button data-su="edit" data-id="'+esc(s.id)+'">编辑</button><button data-su="preview" data-id="'+esc(s.id)+'">预览节点</button><button data-su="ips" data-id="'+esc(s.id)+'">访问IP</button>'+
  '<button data-su="rotate" data-id="'+esc(s.id)+'" class="danger">重置链接</button><button data-su="del" data-id="'+esc(s.id)+'" class="danger">删除</button></div></div>'}).join('');
 bind(el,'[data-su]',function(b){var id=b.getAttribute('data-id'),a=b.getAttribute('data-su'),s=list.filter(function(x){return x.id===id})[0];
  if(a==='edit')return editSub(s);
  if(a==='rotate'){if(confirm('重置「'+s.name+'」的订阅链接？旧链接立即失效。'))api('/api/subs/'+id+'/rotate',{body:{}}).then(function(j){toast('已重置');drawSubs(j.data)}).catch(function(e){toast(e.message)});return}
  if(a==='del'){if(confirm('删除订阅「'+s.name+'」？'))api('/api/subs/'+id,{method:'DELETE'}).then(function(j){drawSubs(j.data)}).catch(function(e){toast(e.message)});return}
  if(a==='ips'){var st=s.stat||{ips:[]};modal('订阅访问IP · '+esc(s.name),'<p class="small muted">如出现陌生IP，说明订阅链接可能已泄露，请重置订阅链接，并对相关服务器重置参数。</p><div class="tablewrap"><table><thead><tr><th>IP</th><th>地区</th><th>次数</th><th>首次</th><th>最近</th></tr></thead><tbody>'+st.ips.map(function(x){return '<tr><td>'+esc(x.ip)+'</td><td>'+esc(x.cc)+'</td><td>'+(x.n||1)+'</td><td>'+fmtTime(x.first)+'</td><td>'+fmtTime(x.last)+'</td></tr>'}).join('')+'</tbody></table></div>'+(st.last?'<p class="small muted">最近客户端：'+esc(st.last.ua)+'</p>':''),true);return}
  if(a==='preview'){modal('节点预览 · '+esc(s.name),'<div id="pv"></div>',true);busy($('pv'));fetch(s.url+'?format=plain',{credentials:'omit'}).then(function(r){return r.text()}).then(function(t){var ls=t.split('\\n').filter(Boolean);$('pv').innerHTML='<p class="small">共 '+ls.length+' 个节点（预览也会计入访问统计）</p>'+ls.map(function(l){return '<div class="link">'+esc(l)+'</div>'}).join('')}).catch(function(e){fail($('pv'),e)})}
 });
}
function editSub(s){
 s=s||{servers:[],protos:[],custom:[],enabled:true,rename:true};
 var ex=s.expires?localInput(s.expires):'';
 modal(s.id?'编辑订阅':'新建订阅',
 '<div class="row"><div class="field"><span class="small muted">名称</span><input id="e-name" value="'+esc(s.name||'')+'"></div><div class="field"><span class="small muted">到期时间（可选）</span><input type="datetime-local" id="e-exp" value="'+ex+'"></div></div>'+
 '<div class="field"><span class="small muted">包含的服务器节点</span><div class="bar">'+S.servers.map(function(x){var c=(S.links||[]).filter(function(l){return l.id===x.id})[0];return '<label><input type="checkbox" data-es="'+esc(x.id)+'"'+(s.servers.indexOf(x.id)>=0?' checked':'')+'>'+esc(x.name)+(c&&c.t?'':' <span class="small err">(无缓存)</span>')+'</label>'}).join('')+'</div></div>'+
 '<div class="field"><span class="small muted">协议（不选表示全部）</span><div class="bar">'+PROTOS.map(function(p){return '<label><input type="checkbox" data-ep="'+p[0]+'"'+(s.protos.indexOf(p[0])>=0?' checked':'')+'>'+p[1]+'</label>'}).join('')+'</div></div>'+
 '<div class="field"><label><input type="checkbox" id="e-ren"'+(s.rename?' checked':'')+'>节点名改为「服务器名-协议」</label><label><input type="checkbox" id="e-en"'+(s.enabled?' checked':'')+'>启用</label></div>'+
 '<div class="field"><span class="small muted">自定义节点链接（每行一个，支持 vless/vmess/hysteria2/tuic/anytls/trojan/ss 等）</span><textarea id="e-custom" rows="6">'+esc(s.custom.join('\\n'))+'</textarea></div>'+
 '<div class="field"><span class="small muted">备注</span><input id="e-note" value="'+esc(s.note||'')+'"></div>'+
 '<div class="bar"><button class="primary" id="e-save">保存</button><span class="err small" id="e-err"></span></div>',true);
 $('e-save').addEventListener('click',function(){
  var body={id:s.id,name:val('e-name'),expires:val('e-exp')?new Date(val('e-exp')).getTime():0,rename:checked('e-ren'),enabled:checked('e-en'),custom:$('e-custom').value,note:val('e-note'),
   servers:Array.prototype.map.call(document.querySelectorAll('[data-es]:checked'),function(c){return c.getAttribute('data-es')}),
   protos:Array.prototype.map.call(document.querySelectorAll('[data-ep]:checked'),function(c){return c.getAttribute('data-ep')})};
  api('/api/subs',{body:body}).then(function(j){closeModal();drawSubs(j.data);toast('已保存')}).catch(function(e){$('e-err').textContent=e.message});
 });
}

// ================= 审计日志
var KINDS={login:'登录',op:'服务器操作',panel:'面板变更'};
function viewAudit(){
 var now=Date.now();
 $('view').innerHTML='<div class="card" style="margin-bottom:10px"><div class="bar"><select id="a-kind"><option value="">全部类型</option><option value="login">登录</option><option value="op">服务器操作</option><option value="panel">面板变更</option></select>'+
 '<input id="a-ip" placeholder="IP" size="14"><input id="a-q" placeholder="关键字（操作/服务器/详情）" size="20"><input type="datetime-local" id="a-from"> 至 <input type="datetime-local" id="a-to">'+
 '<button class="primary" id="a-go">查询</button></div><div class="bar small" style="margin-top:8px">清理：删除 <input type="datetime-local" id="a-pf" value="'+localInput(now-365*86400000)+'"> 至 <input type="datetime-local" id="a-pt" value="'+localInput(now-7*86400000)+'"> 的记录<button id="a-purge" class="danger">删除</button>'+
 '<span class="muted">（审计日志按「设置」中的保留天数自动过期）</span></div></div><div class="tablewrap" id="a-out"></div><div style="margin-top:8px"><button id="a-more" hidden>加载更多</button></div>';
 var cursor=null,items=[];
 function q(more){
  if(!more){items=[];cursor=null;busy($('a-out'))}
  var qs='kind='+encodeURIComponent(val('a-kind'))+'&ip='+encodeURIComponent(val('a-ip'))+'&q='+encodeURIComponent(val('a-q'))+'&limit=200'+
   (val('a-from')?'&from='+new Date(val('a-from')).getTime():'')+(val('a-to')?'&to='+new Date(val('a-to')).getTime():'')+(more&&cursor?'&cursor='+encodeURIComponent(cursor):'');
  api('/api/audit?'+qs).then(function(j){items=items.concat(j.data.items);cursor=j.data.cursor;$('a-more').hidden=!cursor;
   $('a-out').innerHTML=items.length?'<table><thead><tr><th>时间</th><th>类型</th><th>操作</th><th>服务器</th><th>IP</th><th>结果</th><th>详情</th></tr></thead><tbody>'+items.map(function(e){
    return '<tr><td>'+fmtTime(e.t)+'</td><td>'+esc(KINDS[e.k]||e.k)+'</td><td>'+esc(e.a)+'</td><td>'+esc(e.s)+'</td><td>'+esc(e.ip)+' '+esc(e.cc||'')+'</td><td class="'+(e.ok?'okc':'err')+'">'+(e.ok?'成功':'失败')+'</td><td class="wrap">'+esc(e.m)+(e.u?' <span class="muted">'+esc(e.u)+'</span>':'')+'</td></tr>'}).join('')+'</tbody></table>':'<p class="muted" style="padding:8px">没有记录</p>';
  }).catch(function(e){fail($('a-out'),e)});
 }
 $('a-go').addEventListener('click',function(){q(false)});
 $('a-more').addEventListener('click',function(){q(true)});
 $('a-purge').addEventListener('click',function(){if(confirm('删除该时间段的审计日志？'))api('/api/audit/purge',{body:{from:new Date(val('a-pf')).getTime(),to:new Date(val('a-pt')).getTime()}}).then(function(j){toast('已删除 '+j.data.deleted+' 条');q(false)}).catch(function(e){toast(e.message)})});
 q(false);
}

// ================= 设置
function viewSettings(){
 api('/api/me').then(function(j){S.me=j;var st=j.settings,ev=j.events;
  $('view').innerHTML=
  '<div class="card section"><h3>基本</h3><div class="row"><div class="field"><span class="small muted">面板标题</span><input id="c-title" value="'+esc(st.title)+'"></div>'+
  '<div class="field"><span class="small muted">时区（UTC偏移小时，用于报告）</span><input id="c-tz" type="number" value="'+esc(st.tz)+'"></div>'+
  '<div class="field"><span class="small muted">登录有效期（小时）</span><input id="c-sess" type="number" value="'+esc(st.sessionHours)+'"></div>'+
  '<div class="field"><span class="small muted">审计日志保留天数</span><input id="c-ad" type="number" value="'+esc(st.auditDays)+'"></div>'+
  '<div class="field"><span class="small muted">节点缓存刷新间隔（小时）</span><input id="c-lc" type="number" value="'+esc(st.linkCacheHours)+'"></div></div></div>'+
  '<div class="card section"><h3>安全</h3><div class="field"><span class="small muted">登录IP白名单（IP或网段，逗号/换行分隔，留空不限制）。当前IP：'+esc(j.ip)+' '+esc(j.cc)+'</span><textarea id="c-allow" rows="2">'+esc((st.loginAllow||[]).join('\\n'))+'</textarea>'+
  '<span class="small muted">如被锁在外面：在 Cloudflare 后台 KV 中删除 settings 键即可恢复默认设置。</span></div>'+
  '<div class="bar"><span>二次验证（TOTP）：'+(st.totp?'<b class="okc">已开启</b>':'<span class="muted">未开启</span>')+'</span>'+(st.totp?'<button id="c-totpoff" class="danger">关闭二次验证</button>':'<button id="c-totpon">开启二次验证</button>')+
  '<button id="c-out" class="danger">退出所有设备</button></div></div>'+
  '<div class="card section"><h3>Telegram 通知</h3><div class="row"><div class="field"><span class="small muted">Bot Token'+(st.tg.tokenSet?'（已设置，留空不修改）':'')+'</span><input id="c-tgt" type="password" autocomplete="off" placeholder="123456789:AA..."></div>'+
  '<div class="field"><span class="small muted">Chat ID（用户/群组ID或 @频道）</span><input id="c-tgc" value="'+esc(st.tg.chat)+'"></div></div>'+
  '<div class="field"><span class="small muted">通知事件</span><div class="bar">'+Object.keys(ev).map(function(k){return '<label><input type="checkbox" data-ev="'+k+'"'+(st.tg.events[k]?' checked':'')+'>'+esc(ev[k])+'</label>'}).join('')+'</div></div>'+
  '<div class="bar"><button id="c-tgtest">发送测试消息</button>'+(st.tg.tokenSet?'<label><input type="checkbox" id="c-tgclr">清除已保存的Token</label>':'')+'</div></div>'+
  '<div class="card section"><h3>监控与报告（由 Cron 每5分钟执行）</h3><div class="row"><div class="field"><label><input type="checkbox" id="c-mon"'+(st.monitor.enabled?' checked':'')+'>离线检测</label></div>'+
  '<div class="field"><span class="small muted">连续失败几次判定离线</span><input id="c-fc" type="number" value="'+esc(st.monitor.failCount)+'"></div>'+
  '<div class="field"><span class="small muted">每日报告时间（0-23点）</span><input id="c-rh" type="number" value="'+esc(st.reportHour)+'"></div>'+
  '<div class="field"><span class="small muted">单台服务器日流量告警阈值（GB，0关闭）</span><input id="c-ta" type="number" value="'+esc(st.trafficAlertGB)+'"></div></div><div id="c-health" class="small muted"></div></div>'+
  '<button class="primary" id="c-save">保存设置</button> <span id="c-err" class="err small"></span>';
  api('/api/health').then(function(h){var ids=Object.keys(h.data);$('c-health').textContent=ids.length?'检测状态：'+ids.map(function(id){var x=h.data[id],s=srvById(id);return (s?s.name:id)+(x.down?' 离线':' 正常')+(x.fails?'(失败'+x.fails+'次)':'')}).join('；'):'尚未运行检测（部署后Cron每5分钟执行）'}).catch(function(){});
  $('c-save').addEventListener('click',function(){
   var events={};document.querySelectorAll('[data-ev]').forEach(function(c){events[c.getAttribute('data-ev')]=c.checked});
   var body={title:val('c-title'),tz:Number(val('c-tz')),sessionHours:Number(val('c-sess')),auditDays:Number(val('c-ad')),linkCacheHours:Number(val('c-lc')),loginAllow:$('c-allow').value,
    tg:{token:val('c-tgt'),chat:val('c-tgc'),events:events,clearToken:checked('c-tgclr')},monitor:{enabled:checked('c-mon'),failCount:Number(val('c-fc'))},reportHour:Number(val('c-rh')),trafficAlertGB:Number(val('c-ta'))};
   api('/api/settings',{body:body}).then(function(){toast('已保存');$('c-err').textContent='';boot()}).catch(function(e){$('c-err').textContent=e.message});
  });
  $('c-tgtest').addEventListener('click',function(){api('/api/settings/tgtest',{body:{}}).then(function(){toast('测试消息已发送')}).catch(function(e){toast(e.message)})});
  $('c-out').addEventListener('click',function(){if(confirm('退出所有已登录的设备（包括当前）？'))api('/api/logout-all',{body:{}}).then(showLogin)});
  if($('c-totpon'))$('c-totpon').addEventListener('click',totpSetup);
  if($('c-totpoff'))$('c-totpoff').addEventListener('click',function(){
   modal('关闭二次验证','<div class="field"><input type="password" id="t-pw" placeholder="管理密码"></div><div class="field"><input id="t-code" placeholder="当前6位验证码"></div><button class="primary" id="t-off">确认关闭</button> <span class="err small" id="t-err"></span>',true);
   $('t-off').addEventListener('click',function(){api('/api/totp/disable',{body:{password:$('t-pw').value,code:val('t-code')}}).then(function(){closeModal();toast('已关闭');viewSettings()}).catch(function(e){$('t-err').textContent=e.message})});
  });
 }).catch(function(e){fail($('view'),e)});
}
function totpSetup(){
 api('/api/totp/setup',{body:{}}).then(function(j){
  modal('开启二次验证','<p class="small">在 Google Authenticator / Microsoft Authenticator / 1Password 等应用中添加账户，手动输入以下密钥（基于时间）：</p><div class="link" style="font-size:16px;letter-spacing:2px">'+esc(j.secret)+'</div>'+
  '<p class="small muted">或复制配置链接：<a data-copy="'+esc(j.uri)+'">复制 otpauth 链接</a></p><div class="bar"><input id="t-code" placeholder="输入应用中显示的6位验证码"><button class="primary" id="t-on">验证并开启</button></div><p class="err small" id="t-err"></p>',true);
  $('t-on').addEventListener('click',function(){api('/api/totp/enable',{body:{code:val('t-code')}}).then(function(){closeModal();toast('二次验证已开启');viewSettings()}).catch(function(e){$('t-err').textContent=e.message})});
 }).catch(function(e){toast(e.message)});
}

boot();
})();
</script>
</body>
</html>`;
