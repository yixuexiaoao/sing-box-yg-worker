// sing-box-yg-worker：Cloudflare Worker 多服务器管理面板
// 配合 sing-box-yg 脚本的 sbagent API（主菜单19）使用：访问日志、流量统计、一键重置参数、订阅管理、审计日志与 TG 通知
// 绑定：KV 命名空间 SBYG_KV；机密变量 ADMIN_PASSWORD（面板登录密码）；Cron 触发器（wrangler.toml 已配置每5分钟）
// 与服务器通信：cloudflare:sockets 直连 IP:端口，报文 AES-256-CBC + HMAC-SHA256 加密签名，带时间戳与 nonce 防重放
import { connect } from 'cloudflare:sockets';

const VERSION = '1.5.4';
// 服务器升级以此仓库为准（与 sbagent 内置的升级地址一致）
const UPSTREAM = 'https://raw.githubusercontent.com/yixuexiaoao/sing-box-yg/main';
const GB = 1073741824;
const LOGIN_MAX_FAIL = 10;
const COOKIE = '__Host-sbyg_s';
const enc = new TextEncoder();
const dec = new TextDecoder();
const READ_ACTIONS = ['ping', 'status', 'logs', 'stats', 'peers', 'rawlog', 'leakcheck', 'traffic', 'apilog'];
const ACTIONS = new Set(READ_ACTIONS.concat(['links', 'reset', 'restart', 'logon', 'logoff', 'clearlog', 'logprune',
  'logpolicy', 'schedule', 'leakconf', 'trafficon', 'trafficoff', 'trafficpurge', 'trafficconf', 'upgrade', 'coreupgrade']));
const ACTION_NAMES = {
  links: '查看节点链接', reset: '重置参数', restart: '重启Sing-box', logon: '开启连接日志', logoff: '关闭连接日志',
  clearlog: '清空日志', logprune: '按时间删除日志', logpolicy: '修改日志策略', schedule: '设置定时重置',
  leakconf: '设置泄露检测', trafficon: '开启流量统计', trafficoff: '关闭流量统计', trafficpurge: '清理流量记录',
  trafficconf: '修改流量保留天数', upgrade: '升级 sing-box-yg', coreupgrade: '升级/切换 sing-box 内核',
};
const TG_EVENTS = {
  login_ok: '登录成功', login_fail: '登录失败/被拒绝', ops: '服务器操作（重置/重启/修改设置）',
  panel: '面板变更（设置/服务器/订阅/导出）', offline: '服务器离线', recover: '服务器恢复',
  daily: '每日流量报告', traffic: '流量超额告警', cycle: '流量周期结算/配额告警', sub_ip: '订阅被新IP访问',
};
const DEFAULT_SETTINGS = {
  title: 'Sing-box-yg 管理面板',
  tz: 8,
  sessionHours: 12,
  loginAllow: [],
  totp: false,
  tg: { token: '', chat: '', events: { login_ok: true, login_fail: true, ops: true, panel: true, offline: true, recover: true, daily: false, traffic: true, cycle: true, sub_ip: false } },
  geo: 'ipwhois',
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
  if (m === 'GET' && /^\/app\.[0-9a-f]{8}\.js$/.test(p)) return appScript(p);
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
  // 设置与会话校验各需读取一次 KV：并行进行
  const [settings, authed] = await Promise.all([getSettings(env), checkSession(request, env)]);

  if (p === '/api/pre') return json({ ok: true, title: settings.title, totp: !!settings.totp });
  if (p === '/api/login' && m === 'POST') return login(request, env, ctx, who, settings);
  if (p === '/api/logout' && m === 'POST') return json({ ok: true }, 200, { 'set-cookie': COOKIE + '=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' });
  if (!authed) throw httpError(401, '未登录或登录已过期');

  const note = (kind, act, extra) => logEvent(env, ctx, settings, who, kind, act, extra);

  if (p === '/api/me') return json({ ok: true, version: VERSION, ip: who.ip, cc: who.cc, settings: publicSettings(settings), events: TG_EVENTS, weakPassword: String(env.ADMIN_PASSWORD).length < 12, dataEncrypted: !!env.DATA_KEY, secretError: await secretProblem(env, settings) });
  if (p === '/api/latest') return json({ ok: true, data: await latestVersions(env, url.searchParams.get('refresh') === '1', ctx) });
  if (p === '/api/settings' && m === 'POST') {
    const body = await readJson(request);
    const next = sanitizeSettings(body, settings, who.ip);
    if (next.auditDays < settings.auditDays) await requireTotp(env, settings, body && body.totpCode, '缩短审计日志保留天数');
    await putSettings(env, next);
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

  if (p === '/api/servers' && m === 'GET') return json({ ok: true, data: (await getServers(env, false)).map(publicServer) });
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
    const data = { version: VERSION, time: Date.now(), servers: (await getServers(env)).map(({ _enc, tokenError, ...x }) => x), subs: await getSubs(env) };
    return new Response(JSON.stringify(data, null, 2), {
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'content-disposition': 'attachment; filename="sbyg-backup.json"' },
    });
  }
  if (p === '/api/import' && m === 'POST') {
    const r = await importData(env, await readJson(request));
    note('panel', '导入配置', { ok: true, msg: JSON.stringify(r) });
    return json({ ok: true, data: r });
  }
  if (p === '/api/servers/group' && m === 'POST') {
    const body = (await readJson(request)) || {};
    const group = String(body.group || '').trim().slice(0, 32);
    const ids = Array.isArray(body.ids) ? body.ids : [];
    const list = await getServers(env, false);
    list.forEach((s) => { if (ids.includes(s.id)) s.group = group; });
    await putServers(env, list);
    note('panel', '设置服务器分组', { ok: true, msg: (group || '未分组') + ' · ' + ids.length + ' 台' });
    return json({ ok: true, data: list.map(publicServer) });
  }
  if (p === '/api/groups/rename' && m === 'POST') {
    const body = (await readJson(request)) || {};
    const from = String(body.from || ''), to = String(body.to || '').trim().slice(0, 32);
    const list = await getServers(env, false);
    list.forEach((s) => { if ((s.group || '') === from) s.group = to; });
    await putServers(env, list);
    note('panel', '重命名分组', { ok: true, msg: (from || '未分组') + ' → ' + (to || '未分组') });
    return json({ ok: true, data: list.map(publicServer) });
  }
  if (p === '/api/geo' && m === 'POST') {
    const body = (await readJson(request)) || {};
    return json({ ok: true, data: await geoLookup(env, ctx, settings, Array.isArray(body.ips) ? body.ips : []) });
  }
  if (p === '/api/subs/nodes' && m === 'GET') {
    const ids = (url.searchParams.get('ids') || '').split(',').filter(Boolean);
    return json({ ok: true, data: await subNodes(env, ids) });
  }
  let mm = p.match(/^\/api\/servers\/([\w-]+)\/cycle$/);
  if (mm && m === 'POST') {
    return json({ ok: true, data: await serverCycle(await getServer(env, mm[1]), settings, Date.now()) });
  }
  mm = p.match(/^\/api\/servers\/([\w-]+)$/);
  if (mm && m === 'DELETE') {
    const list = await getServers(env, false);
    const srv = list.find((s) => s.id === mm[1]);
    await putServers(env, list.filter((s) => s.id !== mm[1]));
    await env.SBYG_KV.delete('links:' + mm[1]);
    note('panel', '删除服务器', { srv: srv ? srv.name : mm[1], ok: true });
    return json({ ok: true });
  }
  mm = p.match(/^\/api\/servers\/([\w-]+)\/call$/);
  if (mm && m === 'POST') {
    const srv = await getServer(env, mm[1]);
    const body = await readJson(request);
    if (!body || !ACTIONS.has(body.action)) throw httpError(400, '不支持的操作');
    const params = body.params && typeof body.params === 'object' && !Array.isArray(body.params) ? body.params : {};
    const t0 = Date.now();
    const audited = !READ_ACTIONS.includes(body.action);
    try {
      const data = await agentCall(env, srv, body.action, params, ['reset', 'coreupgrade'].includes(body.action) ? 300000 : 60000);
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
    const body = (await readJson(request)) || {};
    await requireTotp(env, settings, body.code, '删除审计日志', note);
    const r = await purgeAudit(env, body);
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
  // Worker 单次请求同时打开的出站连接有限：最多 limit 个同时进行，完成一个立即开始下一个
  // （原先按批等待：一批中有一台慢或超时，同批其余连接空闲也要等它结束）
  const out = new Array(items.length);
  let next = 0;
  const run = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run));
  return out;
}

// ------------------------------------------------------------------ 设置
async function getSettings(env) {
  const s = await kvJson(env, 'settings', {});
  const out = { ...DEFAULT_SETTINGS, ...s };
  out.tg = { ...DEFAULT_SETTINGS.tg, ...(s.tg || {}) };
  // 解密失败（DATA_KEY 丢失/被修改）不能让整个面板不可用：Token 视为未设置，保留密文，页面提示原因
  try { out.tg.token = await decSecret(env, out.tg.token); } catch (e) { out._tgEnc = out.tg.token; out.tg.token = ''; out._secretErr = e.message; }
  out.tg.events = { ...DEFAULT_SETTINGS.tg.events, ...((s.tg && s.tg.events) || {}) };
  out.monitor = { ...DEFAULT_SETTINGS.monitor, ...(s.monitor || {}) };
  return out;
}

function publicSettings(s) {
  const { _tgEnc, _secretErr, ...rest } = s;
  return { ...rest, tg: { chat: s.tg.chat, events: s.tg.events, tokenSet: !!(s.tg.token || _tgEnc) } };
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
  if (b.geo !== undefined) {
    if (!['ipapi', 'ipwhois', 'off'].includes(b.geo)) throw httpError(400, 'IP归属地数据源错误');
    s.geo = b.geo;
  }
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
  while (enc.encode(JSON.stringify(meta)).length > 1000 && (meta.m || meta.u)) {
    if (meta.u) meta.u = meta.u.slice(0, Math.floor(meta.u.length / 2));
    else meta.m = meta.m.slice(0, Math.floor(meta.m.length / 2));
  }
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
let SESSION_KEY_CACHE = null;
async function sessionKey(env) {
  // 同一 isolate 内复用（ADMIN_PASSWORD 改变后自动重新生成）
  if (!SESSION_KEY_CACHE || SESSION_KEY_CACHE.src !== env.ADMIN_PASSWORD) {
    const raw = await crypto.subtle.digest('SHA-256', enc.encode('sbyg-session:' + env.ADMIN_PASSWORD));
    SESSION_KEY_CACHE = { src: env.ADMIN_PASSWORD, key: await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']) };
  }
  return SESSION_KEY_CACHE.key;
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
    const secret = await getSecret(env, 'totp_secret');
    if (!secret || !(await totpVerify(secret, String(body.code), env))) throw await bad('二次验证码错误或已使用');
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
  if (b64url(sig) !== m[3]) return false; // 只接受规范编码，避免同一签名存在多种写法
  return crypto.subtle.verify('HMAC', await sessionKey(env), sig, enc.encode('sess:' + m[1] + ':' + m[2]));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}

async function requireTotp(env, settings, code, what, note) {
  // 审计日志等敏感数据的删除：必须已开启二次验证且本次提供正确验证码
  if (!settings.totp) throw httpError(403, what + '需要二次验证，请先在「设置 → 安全」中开启二次验证');
  const secret = await getSecret(env, 'totp_secret');
  if (!secret || !(await totpVerify(secret, String(code || ''), env))) {
    if (note) note('panel', what, { ok: false, msg: '二次验证码错误' });
    throw httpError(403, '二次验证码错误');
  }
}

async function totpRoute(op, request, env, settings, note) {
  const body = (await readJson(request)) || {};
  if (op === 'setup') {
    const secret = b32encode(crypto.getRandomValues(new Uint8Array(20)));
    await env.SBYG_KV.put('totp_pending', await encSecret(env, secret), { expirationTtl: 600 });
    const label = encodeURIComponent(settings.title);
    return json({ ok: true, secret, uri: 'otpauth://totp/' + label + ':admin?secret=' + secret + '&issuer=' + label });
  }
  if (op === 'enable') {
    const secret = await getSecret(env, 'totp_pending');
    if (!secret) throw httpError(400, '请先生成密钥（10分钟内有效）');
    if (!(await totpVerify(secret, String(body.code || ''), env))) throw httpError(400, '验证码错误，请检查手机时间');
    await env.SBYG_KV.put('totp_secret', await encSecret(env, secret));
    await env.SBYG_KV.delete('totp_pending');
    await putSettings(env, { ...settings, totp: true });
    note('panel', '开启二次验证', { ok: true });
    return json({ ok: true });
  }
  if (op === 'disable') {
    const secret = await getSecret(env, 'totp_secret');
    if (!(await passwordOk(env, body.password)) || !secret || !(await totpVerify(secret, String(body.code || ''), env))) {
      note('panel', '关闭二次验证', { ok: false, msg: '密码或验证码错误' });
      throw httpError(403, '密码或验证码错误');
    }
    await env.SBYG_KV.delete('totp_secret');
    await putSettings(env, { ...settings, totp: false });
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

// 传入 env 时防重放：同一个验证码（时间片）只能使用一次，被他人看到的验证码在有效期内也无法再用
async function totpVerify(secret, code, env) {
  if (!/^\d{6}$/.test(code)) return false;
  const c = Math.floor(Date.now() / 30000);
  for (const d of [-1, 0, 1]) {
    if ((await totpCode(secret, c + d)) !== code) continue;
    if (env) {
      const used = parseInt((await env.SBYG_KV.get('totp_used')) || '0', 10);
      if (c + d <= used) return false;
      await env.SBYG_KV.put('totp_used', String(c + d));
    }
    return true;
  }
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
// decrypt=false：只需名称/地址/分组等字段时（列表、分组、订阅缓存命中）不解密 Token，避免每个请求解密全部服务器
async function getServers(env, decrypt = true) {
  const list = await kvJson(env, 'servers', []);
  if (decrypt) for (const s of list) await openToken(env, s);
  return list;
}

// 单台解密失败只影响该服务器（连接时报出原因），列表与面板其余功能照常可用
async function openToken(env, s) {
  if (s._open) return s;
  try { s.token = await decSecret(env, s.token); } catch (e) { s._enc = s.token; s.token = ''; s.tokenError = e.message; }
  Object.defineProperty(s, '_open', { value: true }); // 不可枚举：不会写入 KV 或导出
  return s;
}

// 按 ID 取一台服务器，只解密这一台（面板刷新时每台服务器各一个请求，原先每个请求都要解密全部服务器）
async function getServer(env, id) {
  const srv = (await getServers(env, false)).find((s) => s.id === id);
  if (!srv) throw httpError(404, '服务器不存在');
  return openToken(env, srv);
}

async function putServers(env, list) {
  const out = [];
  for (const s of list) {
    const { _enc, tokenError, ...rest } = s;
    // 无法解密且未重新填写 Token 的服务器，原样保留密文，恢复 DATA_KEY 后即可继续使用
    out.push({ ...rest, token: _enc && !s.token ? _enc : await encSecret(env, s.token) });
  }
  await env.SBYG_KV.put('servers', JSON.stringify(out));
}

async function putSettings(env, settings) {
  const { _tgEnc, _secretErr, ...rest } = settings;
  const out = JSON.parse(JSON.stringify(rest));
  out.tg.token = _tgEnc && !out.tg.token ? _tgEnc : await encSecret(env, out.tg.token);
  await env.SBYG_KV.put('settings', JSON.stringify(out));
}

// 加密数据无法解密时的提示（显示在面板顶部），不含任何密文
async function secretProblem(env, settings) {
  const [raw, t] = await Promise.all([kvJson(env, 'servers', []), env.SBYG_KV.get('totp_secret')]);
  const encd = raw.filter((s) => String(s.token || '').startsWith('enc:v1:'));
  const anyEnc = encd.length || settings._tgEnc || String(settings.tg.token || '').startsWith('enc:v1:') || (t && t.startsWith('enc:v1:'));
  if (!anyEnc) return '';
  let err = settings._secretErr || '';
  // 只解密带密文的服务器，遇到第一个错误即停止（原先另读一次 KV 并解密全部服务器）
  for (const s of encd) {
    if (err) break;
    err = (await openToken(env, s)).tokenError || '';
  }
  if (!err && t && t.startsWith('enc:v1:')) { try { await decSecret(env, t); } catch (e) { err = e.message; } }
  return err;
}

// ------------------------------------------------------------------ 敏感数据加密存储（可选 DATA_KEY 机密）
// 设置 DATA_KEY 后，服务器 Token、TG Bot Token、TOTP 密钥在 KV 中以 AES-256-GCM 加密保存：
// 仅能读取 KV 的人（KV 导出、只读 API 令牌等）拿不到可用的服务器管理凭据。旧的明文数据由 Cron 自动迁移。
let DATA_KEY_CACHE = null;
async function dataKey(env) {
  if (!env.DATA_KEY) return null;
  if (!DATA_KEY_CACHE || DATA_KEY_CACHE.src !== env.DATA_KEY) {
    const raw = await crypto.subtle.digest('SHA-256', enc.encode('sbyg-data:' + env.DATA_KEY));
    DATA_KEY_CACHE = { src: env.DATA_KEY, key: await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']) };
  }
  return DATA_KEY_CACHE.key;
}

export async function encSecret(env, v) {
  const key = await dataKey(env);
  if (!key || !v || String(v).startsWith('enc:v1:')) return v;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(String(v))));
  return 'enc:v1:' + b64(iv) + ':' + b64(ct);
}

export async function decSecret(env, v) {
  if (typeof v !== 'string' || !v.startsWith('enc:v1:')) return v;
  const key = await dataKey(env);
  if (!key) throw httpError(500, '数据已加密保存，但未设置 DATA_KEY 机密（或已被修改），无法解密');
  const [, , iv, ct] = v.split(':');
  try {
    return dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64decode(iv) }, key, b64decode(ct)));
  } catch (_) {
    throw httpError(500, 'DATA_KEY 与加密数据不匹配，无法解密（请恢复原来的 DATA_KEY）');
  }
}

async function getSecret(env, name) {
  return decSecret(env, await env.SBYG_KV.get(name));
}

async function migrateSecrets(env) {
  if (!env.DATA_KEY) return;
  const raw = await kvJson(env, 'servers', []);
  if (raw.some((s) => s.token && !String(s.token).startsWith('enc:v1:'))) await putServers(env, await getServers(env));
  const st = await kvJson(env, 'settings', null);
  if (st && st.tg && st.tg.token && !String(st.tg.token).startsWith('enc:v1:')) await putSettings(env, await getSettings(env));
  const t = await env.SBYG_KV.get('totp_secret');
  if (t && !t.startsWith('enc:v1:')) await env.SBYG_KV.put('totp_secret', await encSecret(env, t));
}

function publicServer(s) {
  return { id: s.id, name: s.name, host: s.host, port: s.port, path: s.path, group: s.group || '', note: s.note || '', cycle: s.cycle || { mode: 'off' } };
}

function validCycle(c) {
  if (!c || !c.mode || c.mode === 'off') return { mode: 'off' };
  const mode = c.mode === 'days' ? 'days' : 'month';
  const out = {
    mode, quotaGB: num(c.quotaGB || 0, 0, 1e6, '流量配额'), alertPct: Math.round(num(c.alertPct || 90, 1, 100, '告警百分比')),
    count: ['both', 'up', 'down', 'max'].includes(c.count) ? c.count : 'both', source: c.source === 'proxy' ? 'proxy' : 'nic',
  };
  if (mode === 'month') out.day = Math.round(num(c.day || 1, 1, 31, '每月重置日'));
  else {
    out.len = Math.round(num(c.len || 30, 1, 366, '周期天数'));
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(c.start || ''))) throw httpError(400, '周期起始日期格式应为 YYYY-MM-DD');
    out.start = c.start;
  }
  return out;
}

// 流量周期（按面板时区）：month = 每月第 day 天 00:00 重置（该月没有这一天时取月末）；days = 从 start 起每 len 天一个周期
export function cyclePeriods(cycle, nowMs, tz) {
  const off = tz * 3600000;
  if (cycle.mode === 'month') {
    const at = (y, m) => {
      const first = new Date(Date.UTC(y, m, 1));
      const dim = new Date(Date.UTC(first.getUTCFullYear(), first.getUTCMonth() + 1, 0)).getUTCDate();
      return Date.UTC(first.getUTCFullYear(), first.getUTCMonth(), Math.min(cycle.day, dim)) - off;
    };
    const local = new Date(nowMs + off);
    let y = local.getUTCFullYear(), mo = local.getUTCMonth();
    if (at(y, mo) > nowMs) mo -= 1;
    return { cur: [at(y, mo), at(y, mo + 1)], prev: [at(y, mo - 1), at(y, mo)] };
  }
  const [Y, M, D] = cycle.start.split('-').map(Number);
  const s0 = Date.UTC(Y, M - 1, D) - off;
  const L = cycle.len * 86400000;
  const start = s0 + Math.floor((nowMs - s0) / L) * L;
  return { cur: [start, start + L], prev: [start - L, start] };
}

function cycleUsage(d, cycle) {
  const useNic = cycle.source !== 'proxy' && d.nic && d.nic.since;
  const up = useNic ? d.nic.tx : d.total.up;
  const down = useNic ? d.nic.rx : d.total.down;
  const used = cycle.count === 'up' ? up : cycle.count === 'down' ? down : cycle.count === 'max' ? Math.max(up, down) : up + down;
  return { up, down, used, source: useNic ? 'nic' : 'proxy', since: (d.nic && d.nic.since) || '' };
}

async function serverCycle(srv, settings, now) {
  const c = srv.cycle;
  if (!c || c.mode === 'off') return null;
  const p = cyclePeriods(c, now, settings.tz);
  const q = (r) => callAgent(srv, 'traffic', { start: Math.floor(r[0] / 1000), end: Math.floor(Math.min(r[1], now) / 1000), group: 'day', limit: 400 }, 30000);
  const [cur, prev] = await Promise.all([q(p.cur), q(p.prev)]);
  const quota = c.quotaGB * GB;
  const pack = (d, r) => {
    const u = cycleUsage(d, c);
    return { ...u, start: r[0], end: r[1], quota, pct: quota ? Math.round((u.used / quota) * 1000) / 10 : null };
  };
  return { cycle: c, cur: pack(cur, p.cur), prev: pack(prev, p.prev), days: cur.rows };
}

function validServer(s) {
  const host = String(s.host || '').trim().replace(/^\[|\]$/g, '');
  const port = parseInt(s.port, 10);
  const path = String(s.path || '/api').trim();
  if (!/^[A-Za-z0-9.:-]{1,253}$/.test(host)) throw httpError(400, '服务器地址格式错误：请填写服务器的公网IP或域名');
  // Worker 只能连接公网地址：IPv4/IPv6 或带点的域名。不带点的主机名（如 VM 名称 free-e2micro）与内网地址在公网上无法连接
  const v4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host), v6 = host.includes(':');
  if (!globalThis.__SBYG_ALLOW_PRIVATE && !v4 && !v6 && !host.includes('.')) throw httpError(400, '服务器地址「' + host + '」是主机名，Worker 无法连接：请填写服务器的公网IP或域名（谷歌云在控制台「外部IP」一栏查看）');
  if (!globalThis.__SBYG_ALLOW_PRIVATE && v4 && /^(10|127|0|169\.254|192\.168|172\.(1[6-9]|2\d|3[01]))\./.test(host)) throw httpError(400, '「' + host + '」是内网IP，Worker 无法连接：请填写服务器的公网IP（谷歌云/AWS 等网卡上只有内网IP，公网IP在控制台查看）');
  if (!globalThis.__SBYG_ALLOW_PRIVATE && v6 && /^(fe80|fc|fd)|^::1?$/i.test(host)) throw httpError(400, '「' + host + '」不是公网IPv6地址');
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
  if (body.cycle !== undefined) v.cycle = validCycle(body.cycle);
  const token = String(body.token || '').trim();
  if (body.id) {
    const i = list.findIndex((s) => s.id === body.id);
    if (i < 0) throw httpError(404, '服务器不存在');
    list[i] = { ...list[i], ...v, token: token || list[i].token };
  } else {
    if (token.length < 16) throw httpError(400, 'Token 不能为空');
    list.push({ id: crypto.randomUUID().slice(0, 8), ...v, token, created: Date.now() });
  }
  await putServers(env, list);
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
  await putServers(env, list);
  let subs = 0;
  if (data && Array.isArray(data.subs)) {
    const cur = await getSubs(env);
    for (const raw of data.subs.slice(0, 100)) {
      let v;
      try { v = cleanSub(raw); } catch (_) { continue; }
      const id = /^[\w-]{1,36}$/.test(String(raw.id || '')) ? String(raw.id) : crypto.randomUUID().slice(0, 8);
      if (cur.some((x) => x.id === id) || cur.length >= 100) continue;
      cur.push({ ...v, id, token: /^[a-f0-9]{32}$/.test(String(raw.token || '')) ? raw.token : randHex(16), created: Number(raw.created) || Date.now(), rotated: Date.now() });
      subs++;
    }
    await env.SBYG_KV.put('subs', JSON.stringify(cur));
  }
  return { added, updated, subs };
}

// ------------------------------------------------------------------ 最新版本
// 版本信息缓存30分钟；过期后先返回旧数据并在后台刷新（打开面板不再等待 GitHub 的3个请求）
let LATEST_PENDING = null;
async function latestVersions(env, refresh, ctx) {
  const cached = refresh ? null : await kvJson(env, 'latest', null);
  if (cached && Date.now() - cached.t < 1800000) return cached;
  if (cached && ctx && ctx.waitUntil) {
    if (!LATEST_PENDING) {
      LATEST_PENDING = fetchLatest(env).catch(() => null).finally(() => { LATEST_PENDING = null; });
      ctx.waitUntil(LATEST_PENDING);
    }
    return cached;
  }
  return fetchLatest(env);
}

async function fetchLatest(env) {
  const get = async (f, upto) => {
    const r = await fetch(UPSTREAM + '/' + f, { headers: { 'user-agent': 'sbyg-worker/' + VERSION, ...(upto ? { range: 'bytes=0-' + upto } : {}) } });
    if (!r.ok) throw httpError(502, '获取 GitHub 版本失败：HTTP ' + r.status);
    return r.text();
  };
  // sbagent.py 约 100KB，而版本号在文件开头：只取前 8KB（服务器不支持 Range 时返回整个文件，结果相同）
  const [ver, agent, core] = await Promise.all([get('version'), get('sbagent.py', 8191), coreVersions().catch(() => ({}))]);
  const line = (ver.split('\n')[0] || '');
  const notes = ver.split(/\n(?=v\d)/)[0].split('\n').slice(1).filter((x) => x.trim()).slice(0, 12);
  const m = agent.match(/^VERSION = "([^"]+)"/m);
  const out = { t: Date.now(), script: line.split('更新内容')[0].trim(), agent: m ? m[1] : '', notes, core: core.latest || '', corePre: core.prerelease || '' };
  await env.SBYG_KV.put('latest', JSON.stringify(out));
  return out;
}

const CORE_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}(-(alpha|beta|rc)\.\d{1,3})?$/;
function coreKey(v) {
  const [main, pre] = v.split('-');
  const n = main.split('.').map(Number);
  if (!pre) return n.concat([1, 0]);
  const [kind, num] = pre.split('.');
  return n.concat([0, ({ alpha: 0, beta: 1, rc: 2 }[kind] || 0) * 1000 + Number(num || 0)]);
}
function cmpKey(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) - (b[i] || 0);
  return 0;
}
async function coreVersions() {
  let vers = [];
  try {
    const r = await fetch('https://data.jsdelivr.com/v1/package/gh/SagerNet/sing-box');
    if (r.ok) vers = (await r.json()).versions || [];
  } catch (_) { /* 改用 GitHub API */ }
  if (!vers.length) {
    const r = await fetch('https://api.github.com/repos/SagerNet/sing-box/releases?per_page=30', { headers: { 'user-agent': 'sbyg-worker/' + VERSION } });
    if (r.ok) vers = (await r.json()).map((x) => String(x.tag_name || '').replace(/^v/, ''));
  }
  vers = [...new Set(vers.filter((v) => CORE_RE.test(v)))].sort((a, b) => cmpKey(coreKey(b), coreKey(a)));
  const stable = vers.filter((v) => !v.includes('-'));
  return { latest: stable[0] || '', prerelease: vers[0] && vers[0].includes('-') ? vers[0] : '' };
}

// ------------------------------------------------------------------ IP 归属地（公开IP库，结果缓存30天）
export function isPublicIp(ip) {
  const a = parseIp(ip);
  if (!a) return false;
  const priv = a.bits === 32
    ? ['10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '0.0.0.0/8', '224.0.0.0/4']
    : ['::1/128', 'fc00::/7', 'fe80::/10', '::/128', 'ff00::/8'];
  return !priv.some((c) => ipInCidr(ip, c));
}

async function geoLookup(env, ctx, settings, ips) {
  const out = {};
  const miss = [];
  const uniq = [...new Set(ips.map((x) => String(x).trim()).filter(Boolean))].slice(0, 300);
  await Promise.all(uniq.map(async (ip) => {
    if (!parseIp(ip)) return; // 非法输入直接忽略
    if (!isPublicIp(ip)) { out[ip] = { local: true }; return; }
    const c = await kvJson(env, 'geo:' + ip, null);
    if (c) out[ip] = c; else miss.push(ip);
  }));
  if (!miss.length || settings.geo === 'off') return out;
  const found = {};
  if (settings.geo === 'ipwhois') {
    // Worker 单次请求的外部子请求数有限（免费版50），每次最多查询40个，其余由前端分批再请求
    await mapLimit(miss.slice(0, 40), 8, async (ip) => {
      try {
        const j = await (await fetch('https://ipwho.is/' + encodeURIComponent(ip) + '?lang=zh-CN&fields=success,country,country_code,region,city,connection')).json();
        const c = j.connection || {};
        if (j.success) found[ip] = { country: j.country, cc: j.country_code, region: j.region, city: j.city, isp: c.isp, org: c.org, as: c.asn ? 'AS' + c.asn : '' };
      } catch (_) { /* 查询失败不影响结果 */ }
    });
  } else {
    // ip-api.com 批量接口：每次最多100个IP（免费版仅 http，限非商业用途）
    for (let i = 0; i < miss.length; i += 100) {
      try {
        const r = await fetch('http://ip-api.com/batch?lang=zh-CN&fields=status,query,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting', {
          method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(miss.slice(i, i + 100)),
        });
        for (const j of await r.json()) {
          if (j.status === 'success') found[j.query] = { country: j.country, cc: j.countryCode, region: j.regionName, city: j.city, isp: j.isp, org: j.org, as: j.as, mobile: j.mobile, proxy: j.proxy, hosting: j.hosting };
        }
      } catch (_) { /* 查询失败不影响结果 */ }
    }
  }
  Object.assign(out, found);
  const p = Promise.all(Object.entries(found).map(([ip, v]) => env.SBYG_KV.put('geo:' + ip, JSON.stringify(v), { expirationTtl: 30 * 86400 }))).catch(() => {});
  if (ctx && ctx.waitUntil) ctx.waitUntil(p);
  return out;
}

// ------------------------------------------------------------------ 节点链接缓存与订阅
async function agentCall(env, srv, action, params, timeoutMs) {
  const data = await callAgent(srv, action, params, timeoutMs || (action === 'reset' ? 300000 : 60000));
  if ((action === 'links' || action === 'reset') && data && Array.isArray(data.links)) {
    // rev：节点参数版本（sbagent 1.4.1 起随链接返回），Cron 据此判断缓存是否需要刷新
    await env.SBYG_KV.put('links:' + srv.id, JSON.stringify({ t: Date.now(), links: data.links, subs: data.subs || [], rev: data.rev || '' }));
  }
  return data;
}

async function refreshLinks(env, srv, rev) {
  const data = await callAgent(srv, 'links', {}, 20000);
  const c = { t: Date.now(), links: data.links || [], subs: data.subs || [], rev: data.rev || rev || '' };
  await env.SBYG_KV.put('links:' + srv.id, JSON.stringify(c));
  return c;
}

async function linkOverview(env) {
  const servers = await getServers(env, false);
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

export function linkName(link) {
  if (link.startsWith('vmess://')) {
    try { return JSON.parse(dec.decode(b64decode(link.slice(8).trim()))).ps || ''; } catch (_) { return ''; }
  }
  const i = link.indexOf('#');
  if (i < 0) return '';
  try { return decodeURIComponent(link.slice(i + 1)); } catch (_) { return link.slice(i + 1); }
}

const PROTO_LABEL = { vless: 'Vless', vmess: 'Vmess', 'vmess-argo': 'Vmess-Argo', hysteria2: 'Hy2', tuic: 'Tuic', anytls: 'Anytls', other: '节点' };

export function applyTpl(tpl, v) {
  return String(tpl || '{server}-{proto}').replace(/\{(\w+)\}/g, (all, k) => (v[k] !== undefined && v[k] !== null ? String(v[k]) : all)).slice(0, 64);
}

function dedupeName(name, used) {
  let n = name, i = 2;
  while (used.has(n)) n = name + '-' + i++;
  used.add(n);
  return n;
}

async function subNodes(env, ids) {
  const [servers, caches] = await Promise.all([getServers(env, false), Promise.all(ids.map((id) => kvJson(env, 'links:' + id, null)))]);
  const out = [];
  for (const [i, id] of ids.entries()) {
    const srv = servers.find((s) => s.id === id);
    if (!srv) continue;
    const c = caches[i];
    for (const l of (c && c.links) || []) {
      out.push({ key: id + '|' + l.name, serverId: id, server: srv.name, group: srv.group || '', proto: linkProto(l), label: l.name, orig: linkName(l.link) });
    }
  }
  return out;
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
  const names = {};
  if (b.names && typeof b.names === 'object') {
    for (const [k, v] of Object.entries(b.names).slice(0, 2000)) {
      const name = String(v || '').trim().slice(0, 64);
      if (name) names[String(k).slice(0, 120)] = name;
    }
  }
  return {
    name: String(b.name || '订阅').slice(0, 40), servers: (Array.isArray(b.servers) ? b.servers : []).map(String).slice(0, 200),
    protos, custom, rename: !!b.rename, tpl: String(b.tpl || '{server}-{proto}').slice(0, 64), names,
    exclude: (Array.isArray(b.exclude) ? b.exclude : []).map((x) => String(x).slice(0, 120)).slice(0, 2000),
    enabled: b.enabled !== false, note: String(b.note || '').slice(0, 200), expires: Number(b.expires) || 0,
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

// 节点名优先级：单独设置的名称 > 命名模板（开启时）> 原名称；重名自动加序号
// 节点键 = 服务器ID|链接类型（如 vless-reality），重置参数后不变，因此自定义名称在重置后依然有效
export async function buildSubLines(env, sub) {
  const servers = await getServers(env, false);
  const names = sub.names || {};
  const exclude = new Set(sub.exclude || []);
  const used = new Set();
  const lines = [];
  let n = 0;
  const emit = (link, key, vars, useTpl) => {
    if (exclude.has(key)) return;
    n += 1;
    let name = names[key] || (sub.rename && useTpl ? applyTpl(sub.tpl, { ...vars, n, orig: linkName(link) }) : '');
    if (name) lines.push(renameLink(link, dedupeName(name, used)));
    else lines.push(link);
  };
  // 各服务器的节点缓存并行读取（缺缓存的并行向服务器获取），再按订阅中的顺序输出
  const caches = await Promise.all(sub.servers.map(async (id) => {
    const srv = servers.find((s) => s.id === id);
    if (!srv) return null;
    const cache = await kvJson(env, 'links:' + id, null);
    // 只有缓存缺失、需要向服务器获取时才解密该服务器的 Token
    return [srv, cache || await refreshLinks(env, await openToken(env, srv)).catch(() => null)];
  }));
  for (const item of caches) {
    if (!item || !item[1]) continue;
    const [srv, cache] = item, id = srv.id;
    for (const l of cache.links) {
      const proto = linkProto(l);
      if (sub.protos.length && !sub.protos.includes(proto)) continue;
      emit(l.link, id + '|' + l.name, { server: srv.name, group: srv.group || '', proto: PROTO_LABEL[proto] || proto, type: l.name, host: srv.host }, true);
    }
  }
  // 自定义节点保留自己的名称，只有单独命名时才修改
  sub.custom.forEach((link, i) => emit(link, 'c|' + i, {}, false));
  return lines;
}

async function serveSub(request, env, ctx, token) {
  const notFound = () => new Response('Not Found', { status: 404 });
  if (!/^[a-f0-9]{32}$/.test(token) || !env.SBYG_KV) return notFound();
  const sub = (await getSubs(env)).find((s) => s.token === token);
  if (!sub || sub.enabled === false || (sub.expires && Date.now() > sub.expires)) return notFound();
  const ip = clientIp(request);
  const statKey = 'substat:' + sub.id;
  const [lines, stat] = await Promise.all([buildSubLines(env, sub), kvJson(env, statKey, { hits: 0, ips: [] })]);
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
  await migrateSecrets(env);
  const settings = await getSettings(env);
  const servers = await getServers(env);
  if (!servers.length) return;
  const cacheT = {}; // 本轮读到的节点缓存时间（0 = 无缓存），避免下面再逐台读取 KV
  {
    const health = await kvJson(env, 'health', {});
    let changed = false;
    const msgs = [];
    await mapLimit(servers, 5, async (s) => {
      const h = health[s.id] || { fails: 0, down: false };
      let ok = true, err = '';
      try {
        const [pong, cache] = await Promise.all([callAgent(s, 'ping', {}, 15000), kvJson(env, 'links:' + s.id, null)]);
        cacheT[s.id] = cache ? cache.t : 0;
        // 参数版本变化（VPS 上重置/定时重置/泄露自动重置/改端口等）→ 立即刷新订阅使用的节点缓存
        if (pong.rev && (!cache || cache.rev !== pong.rev)) {
          const c = await refreshLinks(env, s, pong.rev).catch(() => null);
          if (c) cacheT[s.id] = c.t;
        }
      } catch (e) { ok = false; err = e.message; }
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
    if (settings.monitor.enabled) for (const [ev, text] of msgs) await tgEvent(settings, ev, text);
  }
  const hourKey = 'cyc:' + Math.floor(now / 3600000);
  if (servers.some((s) => s.cycle && s.cycle.mode !== 'off') && !(await env.SBYG_KV.get(hourKey))) {
    await env.SBYG_KV.put(hourKey, '1', { expirationTtl: 7200 });
    await cycleCheck(env, settings, servers, now);
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
    const t = cacheT[s.id]; // 只刷新在线（本轮 ping 成功）且已有缓存的服务器
    if (t && now - t > settings.linkCacheHours * 3600000) stale.push([t, s]);
  }
  stale.sort((a, b) => a[0] - b[0]);
  if (stale.length) await refreshLinks(env, stale[0][1]).catch(() => {});
}

async function cycleCheck(env, settings, servers, now) {
  await mapLimit(servers.filter((s) => s.cycle && s.cycle.mode !== 'off'), 3, async (s) => {
    let d;
    try { d = await serverCycle(s, settings, now); } catch (_) { return; }
    const day = (t) => new Date(t + settings.tz * 3600000).toISOString().slice(0, 10);
    const span = (x) => day(x.start) + ' ~ ' + day(x.end - 1);
    const fmtq = (x) => fmtBytes(x.used) + (x.quota ? ' / ' + fmtBytes(x.quota) + '（' + x.pct + '%）' : '');
    // 上一周期结算：每个周期只发送一次
    const pk = 'cs:' + s.id + ':' + d.prev.start;
    if (!(await env.SBYG_KV.get(pk))) {
      await env.SBYG_KV.put(pk, '1', { expirationTtl: 400 * 86400 });
      await tgEvent(settings, 'cycle', '🧾 ' + s.name + ' 上一流量周期结算\n' + span(d.prev) + '：' + fmtq(d.prev) + '\n（↑' + fmtBytes(d.prev.up) + ' ↓' + fmtBytes(d.prev.down) + '，' + (d.prev.source === 'nic' ? '网卡流量' : '代理流量') + '）');
    }
    if (d.cur.quota && d.cur.pct >= s.cycle.alertPct) {
      const ak = 'qa:' + s.id + ':' + d.cur.start + ':' + (d.cur.pct >= 100 ? 100 : s.cycle.alertPct);
      if (!(await env.SBYG_KV.get(ak))) {
        await env.SBYG_KV.put(ak, '1', { expirationTtl: 400 * 86400 });
        await tgEvent(settings, 'cycle', (d.cur.pct >= 100 ? '⛔ ' : '⚠️ ') + s.name + ' 本周期流量已用 ' + fmtq(d.cur) + '\n周期：' + span(d.cur));
      }
    }
  });
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
  if (srv.tokenError) throw httpError(500, srv.tokenError);
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
    const msg = String((e && e.message) || e);
    // Cloudflare 的套接字在 TCP 连不上（端口未放行、IP不对、主机名无法解析）时只报这些笼统的错误
    if (/stream was cancelled|network connection lost|connection refused|connect|socket/i.test(msg)) {
      throw httpError(502, '无法连接 ' + hostname + ':' + port + '（' + msg + '）：请确认地址是服务器公网IP，VPS防火墙与云平台安全组已放行该TCP端口（谷歌云需在「VPC网络 → 防火墙」放行），且 sbagent 正在运行');
    }
    throw httpError(502, '连接服务器失败：' + msg);
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
// 页面脚本（约 150KB）单独作为 /app.<内容hash>.js 提供，浏览器长期缓存，内容变化后 hash 随之改变；
// HTML 只剩样式与外壳（约 5KB），仍每次生成新的 nonce。原先整页内联且 no-store，每次打开都要重新下载并解析全部脚本
let PAGE_PARTS = null;
function pageParts() {
  if (!PAGE_PARTS) {
    const a = PAGE.indexOf('<script>'), b = PAGE.lastIndexOf('</script>');
    const js = PAGE.slice(a + 8, b);
    let h = 0x811c9dc5; // FNV-1a 32位
    for (let i = 0; i < js.length; i++) { h ^= js.charCodeAt(i); h = Math.imul(h, 0x01000193); }
    PAGE_PARTS = { head: PAGE.slice(0, a), tail: PAGE.slice(b + 9), js, src: '/app.' + (h >>> 0).toString(16).padStart(8, '0') + '.js' };
  }
  return PAGE_PARTS;
}

function appScript(p) {
  const P = pageParts();
  // 部署切换期间请求到旧 hash：返回当前脚本但不缓存
  return new Response(P.js, {
    headers: {
      'content-type': 'text/javascript; charset=utf-8', 'x-content-type-options': 'nosniff',
      'cache-control': p === P.src ? 'public, max-age=31536000, immutable' : 'no-store',
    },
  });
}

function page() {
  // 每次响应生成新的 nonce，CSP 只允许带该 nonce 的脚本执行（页面不使用任何内联事件属性）
  const nonce = b64(crypto.getRandomValues(new Uint8Array(16)));
  const P = pageParts();
  return new Response(P.head + '<script nonce="' + nonce + '" src="' + P.src + '"></script>' + P.tail, {
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
<meta name="color-scheme" content="light dark">
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
<div id="app"><p class="muted" style="padding:16px">加载中…</p></div>
<script>
(function(){
var $app=document.getElementById('app');
var S={servers:[],status:{},selected:{},cycles:{},me:null,tab:'servers',groupFilter:null};
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

// ================= IP 归属地（所有出现IP的地方共用）
var GEO={};
function flag(cc){return cc&&/^[A-Z]{2}$/.test(cc)?String.fromCodePoint(cc.charCodeAt(0)+127397,cc.charCodeAt(1)+127397)+' ':''}
function geoText(g){if(!g)return '';if(g.local)return '内网/本机';return flag(g.cc)+[g.country,g.region,g.city].filter(function(x,i,a){return x&&a.indexOf(x)===i}).join(' ')}
function geoIsp(g){return g&&!g.local?(g.isp||g.org||'')+(g.as?' · '+String(g.as).split(' ')[0]:''):''}
function geoTags(g){if(!g)return '';var t=[];if(g.mobile)t.push('<span class="chip">移动网络</span>');if(g.hosting)t.push('<span class="chip err" title="机房/服务器IP，通常不是个人设备，可能是节点被转用或泄露">机房IP</span>');if(g.proxy)t.push('<span class="chip err">代理/VPN</span>');if(g.local)t.push('<span class="chip">内网/本机</span>');return t.join(' ')}
// 分批查询（每批100个），已查过的IP不重复请求
function loadGeo(ips){
 var need=[];ips.forEach(function(ip){if(ip&&!(ip in GEO)&&need.indexOf(ip)<0)need.push(ip)});
 need=need.slice(0,1000);
 var chain=Promise.resolve();
 for(var i=0;i<need.length;i+=100)(function(part){chain=chain.then(function(){return api('/api/geo',{body:{ips:part}}).then(function(j){Object.keys(j.data).forEach(function(k){GEO[k]=j.data[k]});part.forEach(function(ip){if(!(ip in GEO))GEO[ip]=null})}).catch(function(){})})})(need.slice(i,i+100));
 return chain;
}
function geoSpan(ip){return ip?' <span class="small muted" data-gfor="'+esc(ip)+'"></span>':''}
function geoFill(root){
 var els=(root||document).querySelectorAll('[data-gfor]');if(!els.length)return;
 var ips=Array.prototype.map.call(els,function(e){return e.getAttribute('data-gfor')});
 loadGeo(ips).then(function(){els.forEach(function(e){var g=GEO[e.getAttribute('data-gfor')];if(!g)return;var t=geoText(g),i=geoIsp(g);e.innerHTML=esc(t)+(i?' · '+esc(i):'')+(g.local?'':' '+geoTags(g))})});
}

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
function bootError(e){if(/未登录/.test(e&&e.message||''))return;$app.innerHTML='<div class="login card"><h3>面板加载失败</h3><p class="err">'+esc(e&&e.message||String(e))+'</p><p class="small muted">若提示与 DATA_KEY 有关：DATA_KEY 必须以「机密(Secret)」添加并保持原值；以「文本变量」添加时，下次从 Git/wrangler 部署会被删除。恢复原值后刷新即可。</p><button class="primary" id="b-retry">重试</button></div>';$('b-retry').addEventListener('click',function(){location.reload()})}
// 服务器列表与 /api/me 同时请求（原先等 /api/me 返回、渲染完外壳后才开始请求列表）；未登录时预取结果被忽略
var PRE=null;
function boot(){
 PRE=fetch('/api/servers',{headers:{'x-sbyg':'1'},credentials:'same-origin'}).then(function(r){return r.ok?r.json():null}).catch(function(){return null});
 api('/api/me').then(function(j){S.me=j;document.title=j.settings.title;renderShell();go(S.tab)}).catch(function(e){PRE=null;bootError(e)})}

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
function groupNames(){var g={};S.servers.forEach(function(s){g[s.group||'']=(g[s.group||'']||0)+1});return Object.keys(g).sort(function(a,b){return a===''?1:b===''?-1:(a<b?-1:1)}).map(function(k){return [k,g[k]]})}
function viewServers(){
 $('view').innerHTML='<div class="bar" style="margin-bottom:8px"><button class="primary" id="b-add">添加服务器</button><button id="b-refresh">全部刷新</button>'+
 '<button id="b-resetall" class="danger">一键全部重置参数</button><button id="b-batch">批量操作</button><button id="b-groups">分组管理</button><button id="b-upg">检查更新</button><button id="b-io">导入/导出</button><span id="summary" class="muted small"></span></div><div id="b-notice"></div>'+
 '<div class="bar tabs" id="gchips" style="margin-bottom:10px"></div><div id="grid"></div>';
 $('b-add').addEventListener('click',function(){editServer()});
 $('b-refresh').addEventListener('click',refreshAll);
 $('b-resetall').addEventListener('click',function(){resetDialog(visibleServers(),true)});
 $('b-batch').addEventListener('click',batchDialog);
 $('b-groups').addEventListener('click',groupsDialog);
 $('b-upg').addEventListener('click',function(){upgradeDialog()});
 var nt=[];
 if(S.me&&S.me.weakPassword)nt.push('⚠ 当前面板密码 ADMIN_PASSWORD 少于12位，建议在 Cloudflare 后台改为更长的随机密码，并在「设置 → 安全」开启二次验证。');
 if(S.me&&S.me.secretError)nt.push('⛔ 加密数据无法解密：'+S.me.secretError+'。服务器 Token / TG Token / 二次验证密钥暂不可用（数据未被修改）。请在 Worker 设置中把 DATA_KEY 以「机密(Secret)」恢复为原来的值后刷新；以「文本变量」添加的会在下次 Git/wrangler 部署时被删除。');
 else if(S.me&&!S.me.dataEncrypted)nt.push('⚠ 未设置 DATA_KEY 机密：服务器 Token 以明文保存在 KV 中，能读取 KV 的人即可管理这些服务器。建议在 Worker 设置中添加机密 DATA_KEY（长随机字符串，设置后不要修改），Cron 会自动加密已有数据。');
 if(nt.length)$('b-notice').innerHTML='<div class="card err small" style="margin-bottom:10px">'+nt.map(esc).join('<br>')+'</div>';
 loadLatest().catch(function(){});
 $('b-io').addEventListener('click',ioDialog);
 loadServers();
}
function verCmp(a,b){a=String(a||'').replace(/^v/,'').split(/[.-]/).map(Number);b=String(b||'').replace(/^v/,'').split(/[.-]/).map(Number);for(var i=0;i<Math.max(a.length,b.length);i++){var x=a[i]||0,y=b[i]||0;if(x!==y)return x<y?-1:1}return 0}
function needUpgrade(d){var L=S.latest;return !!(L&&d&&((L.agent&&verCmp(d.agent,L.agent)<0)||(L.script&&d.script_version&&verCmp(d.script_version,L.script)<0)))}
function loadLatest(force){return api('/api/latest'+(force?'?refresh=1':'')).then(function(j){S.latest=j.data;scheduleRender();return j.data})}
function visibleServers(){return S.groupFilter==null?S.servers.slice():S.servers.filter(function(s){return (s.group||'')===S.groupFilter})}
function loadServers(){var pre=PRE;PRE=null;
 return (pre?pre.then(function(j){return j&&j.ok?j:api('/api/servers')}):api('/api/servers')).then(function(j){S.servers=j.data;renderGrid();refreshAll()})}
var renderPending=false;
function scheduleRender(){if(renderPending)return;renderPending=true;requestAnimationFrame(function(){renderPending=false;renderGrid()})}
function renderGrid(){
 var g=$('grid');if(!g)return;
 var groups=groupNames();
 if(S.groupFilter!=null&&!groups.some(function(x){return x[0]===S.groupFilter}))S.groupFilter=null;
 $('gchips').innerHTML=groups.length>1||(groups[0]&&groups[0][0])?'<button data-g="*"'+(S.groupFilter==null?' class="on"':'')+'>全部 ('+S.servers.length+')</button>'+groups.map(function(x){return '<button data-g="'+esc(x[0])+'"'+(S.groupFilter===x[0]?' class="on"':'')+'>'+esc(x[0]||'未分组')+' ('+x[1]+')</button>'}).join(''):'';
 bind($('gchips'),'[data-g]',function(b){var v=b.getAttribute('data-g');S.groupFilter=v==='*'?null:v;renderGrid()});
 if(!S.servers.length){g.innerHTML='<div class="card muted">还没有服务器。在VPS上运行 <b>sb</b>，安装时开启API，或选择 <b>19 → 1</b> 安装API服务，再选择 <b>19 → 2</b> 复制对接信息，然后点击「添加服务器」粘贴。</div>';updateSummary();return}
 var list=visibleServers();
 if(S.groupFilter==null&&groups.length>1){
  g.innerHTML=groups.map(function(x){var ss=list.filter(function(s){return (s.group||'')===x[0]});return '<div class="section"><h3>'+esc(x[0]||'未分组')+' <span class="muted small">'+ss.length+' 台</span></h3><div class="grid">'+ss.map(cardHtml).join('')+'</div></div>'}).join('');
 }else g.innerHTML='<div class="grid">'+list.map(cardHtml).join('')+'</div>';
 bind(g,'[data-act]',function(b){onAction(b.getAttribute('data-act'),b.getAttribute('data-id'))});
 g.querySelectorAll('input[data-sel]').forEach(function(c){c.addEventListener('change',function(){S.selected[c.getAttribute('data-sel')]=c.checked})});
 updateSummary();
}
function updateSummary(){var el=$('summary');if(!el)return;var on=0,act=0;S.servers.forEach(function(s){var st=S.status[s.id];if(st&&st.data){on++;if(st.data.active)act++}});el.textContent='共 '+S.servers.length+' 台，在线 '+on+' 台，Sing-box运行中 '+act+' 台'}
var PERM_NAMES={read:'只读',links:'节点链接',manage:'管理',upgrade:'远程升级'};
function day(t){return fmtTime(t).slice(0,10)}
function cycleHtml(s){
 var c=S.cycles[s.id];if(!s.cycle||s.cycle.mode==='off')return '';
 if(!c)return '<span>周期</span><span class="muted">计算中…</span>';
 if(c.error)return '<span>周期</span><span class="err">'+esc(c.error)+'</span>';
 var cur=c.cur,pct=cur.pct==null?null:Math.min(100,cur.pct);
 return '<span>本周期</span><span>'+day(cur.start)+' ~ '+day(cur.end-1)+'：<b>'+fmtBytes(cur.used)+'</b>'+(cur.quota?' / '+fmtBytes(cur.quota)+' <b class="'+(cur.pct>=s.cycle.alertPct?'err':'')+'">'+cur.pct+'%</b>':'')+
  (pct!=null?'<div class="meter" style="margin-top:2px"><i style="width:'+Math.max(1,pct)+'%;'+(cur.pct>=s.cycle.alertPct?'background:var(--bad)':'')+'"></i></div>':'')+'</span>'+
  '<span>上周期</span><span>'+day(c.prev.start)+' ~ '+day(c.prev.end-1)+'：'+fmtBytes(c.prev.used)+(c.prev.quota?'（'+c.prev.pct+'%）':'')+' <span class="muted">'+(cur.source==='nic'?'网卡流量':'代理流量')+(cur.since?'，网卡数据自 '+esc(cur.since.slice(0,10)):'')+'</span></span>';
}
function cardHtml(s){
 var st=S.status[s.id],d=st&&st.data,dot='',body='';
 if(!st){body='<div class="muted small">加载中…</div>'}
 else if(st.error){dot='bad';body='<div class="err small">'+esc(st.error)+'</div>'}
 else{
  dot=d.active?'ok':'warn';
  var tr=d.traffic||{},ap=d.api||{};
  body='<div class="chips">'+(d.inbounds||[]).map(function(i){return '<span class="chip">'+esc(i.name)+' :'+esc(i.port)+'</span>'}).join('')+'</div>'+
  '<div class="kv"><span>系统</span><span>'+esc(d.os||'-')+' / '+esc(d.hostname)+'</span>'+
  '<span>内核</span><span>sing-box '+esc(d.version||'-')+(d.active?'':' <b class="err">未运行</b>')+(needCore(d)?' <span class="chip">有新内核 '+esc(S.latest.core)+'</span>':'')+'</span>'+
  '<span>版本</span><span>脚本 '+esc(d.script_version||'-')+' · agent '+esc(d.agent)+(needUpgrade(d)?' <span class="chip err">可升级</span> <a data-act="upgrade" data-id="'+esc(s.id)+'">升级</a>':'')+'</span>'+
  '<span>IP</span><span>'+esc(d.server_ip||'-')+'</span>'+
  '<span>运行</span><span>'+fmtUp(d.uptime)+'，负载 '+esc((d.load||[]).join(' '))+(d.mem&&d.mem.MemTotal?'，内存 '+fmtBytes(d.mem.MemTotal-d.mem.MemAvailable)+'/'+fmtBytes(d.mem.MemTotal):'')+'</span>'+
  '<span>日志</span><span>'+(d.log&&d.log.enabled?'已开启 '+fmtBytes(d.log.size)+(d.log.archives?'（归档'+d.log.archives+'份）':''):'<span class="err">未开启</span>')+'</span>'+
  '<span>流量</span><span>'+(tr.enabled?'统计中 '+fmtBytes(tr.db_size):'<span class="muted">未开启</span>')+'</span>'+cycleHtml(s)+
  '<span>API权限</span><span>'+(ap.perms?ap.perms.map(function(p){return PERM_NAMES[p]||p}).join('、'):'-')+(ap.allow&&ap.allow.length?' · IP白名单':'')+'</span>'+
  '<span>重置</span><span>'+(d.last_reset?esc(d.last_reset.time)+' ('+esc((d.last_reset.items||[]).join(','))+')':'从未')+(d.schedule?' · 已设定时':'')+(d.leak&&d.leak.enabled?' · 泄露检测':'')+'</span>'+
  (d.argo&&(d.argo.temp||d.argo.fixed)?'<span>Argo</span><span>'+esc(d.argo.fixed||d.argo.temp)+'</span>':'')+'</div>';
 }
 var b=function(act,label,cls){return '<button data-act="'+act+'" data-id="'+esc(s.id)+'"'+(cls?' class="'+cls+'"':'')+'>'+label+'</button>'};
 return '<div class="card"><h3><input type="checkbox" data-sel="'+esc(s.id)+'"'+(S.selected[s.id]?' checked':'')+'><span class="dot '+dot+'"></span>'+esc(s.name)+(s.group?' <span class="chip">'+esc(s.group)+'</span>':'')+
 '<span class="muted small" style="margin-left:auto">'+esc(s.host)+':'+esc(s.port)+(st&&st.ms?' · '+st.ms+'ms':'')+'</span></h3>'+body+
 '<div class="actions">'+b('logs','访问日志')+b('stats','IP统计')+b('traffic','流量')+b('peers','在线IP')+b('links','节点链接')+b('reset','重置参数','danger')+
 b('settings','日志/流量/定时')+b('apilog','API日志')+b('refresh','刷新')+b('restart','重启')+b('edit','编辑')+b('del','删除','danger')+'</div></div>';
}
function refreshOne(id){var t0=Date.now(),s=srvById(id);
 return call(id,'status').then(function(d){S.status[id]={data:d,ms:Date.now()-t0};
  if(s&&s.cycle&&s.cycle.mode!=='off'){delete S.cycles[id];api('/api/servers/'+id+'/cycle',{body:{}}).then(function(j){S.cycles[id]=j.data},function(e){S.cycles[id]={error:e.message}}).then(scheduleRender)}
 },function(e){S.status[id]={error:e.message}}).then(scheduleRender)}
function refreshAll(){S.status={};renderGrid();return Promise.all(visibleServers().map(function(s){return refreshOne(s.id)}))}
function onAction(act,id){
 var s=srvById(id);
 if(act==='refresh')return refreshOne(id);
 if(act==='edit')return editServer(s);
 if(act==='del'){if(confirm('删除服务器「'+s.name+'」？(仅从面板移除，不影响VPS)'))api('/api/servers/'+id,{method:'DELETE'}).then(loadServers).catch(function(e){toast(e.message)});return}
 if(act==='restart'){if(confirm('重启「'+s.name+'」的 Sing-box？'))call(id,'restart').then(function(d){toast(d.active?'重启成功':'重启后未运行，请检查');refreshOne(id)}).catch(function(e){toast(e.message)});return}
 if(act==='traffic'){S.trafficScope='s:'+id;return go('traffic')}
 if(act==='reset')return resetDialog([s]);
 if(act==='upgrade')return upgradeDialog([id]);
 var f={logs:logsDialog,stats:statsDialog,peers:peersDialog,links:linksDialog,settings:settingsDialog,apilog:apilogDialog}[act];if(f)f(s);
}
function editServer(s){
 s=s||{cycle:{mode:'off'}};var c=s.cycle||{mode:'off'};
 modal(s.id?'编辑服务器':'添加服务器',
 (s.id?'':'<div class="field"><span class="small muted">粘贴VPS上 sb → 19 → 2 输出的对接JSON，自动填写</span><textarea id="f-json" rows="3"></textarea></div>')+
 '<div class="row"><div class="field"><span class="small muted">名称</span><input id="f-name" value="'+esc(s.name||'')+'"></div>'+
 '<div class="field"><span class="small muted">分组（可新建）</span><input id="f-group" list="f-groups" value="'+esc(s.group||'')+'"><datalist id="f-groups">'+groupNames().filter(function(x){return x[0]}).map(function(x){return '<option value="'+esc(x[0])+'">'}).join('')+'</datalist></div>'+
 '<div class="field"><span class="small muted">服务器IP或域名</span><input id="f-host" value="'+esc(s.host||'')+'"></div>'+
 '<div class="field"><span class="small muted">API端口</span><input id="f-port" type="number" value="'+esc(s.port||'')+'"></div>'+
 '<div class="field"><span class="small muted">API路径</span><input id="f-path" value="'+esc(s.path||'/api')+'"></div></div>'+
 '<div class="field"><span class="small muted">Token'+(s.id?' (留空表示不修改)':'')+'</span><input id="f-token" type="password" autocomplete="off"></div>'+
 '<div class="field"><span class="small muted">备注</span><input id="f-note" value="'+esc(s.note||'')+'"></div>'+
 '<div class="section card"><h3>流量周期与配额</h3><div class="row"><div class="field"><span class="small muted">周期</span><select id="f-cm"><option value="off">不启用</option><option value="month">每月固定日重置</option><option value="days">固定天数为一个周期</option></select></div>'+
 '<div class="field" data-cm="month"><span class="small muted">每月重置日（1-31，月份没有该日时取月末）</span><input id="f-cday" type="number" value="'+esc(c.day||1)+'"></div>'+
 '<div class="field" data-cm="days"><span class="small muted">周期起始日期</span><input id="f-cstart" type="date" value="'+esc(c.start||fmtTime(Date.now()).slice(0,8)+'01')+'"></div>'+
 '<div class="field" data-cm="days"><span class="small muted">每个周期天数</span><input id="f-clen" type="number" value="'+esc(c.len||30)+'"></div>'+
 '<div class="field" data-cm="on"><span class="small muted">流量配额 GB（0 不限）</span><input id="f-cq" type="number" value="'+esc(c.quotaGB||0)+'"></div>'+
 '<div class="field" data-cm="on"><span class="small muted">达到配额百分之几时告警</span><input id="f-ca" type="number" value="'+esc(c.alertPct||90)+'"></div>'+
 '<div class="field" data-cm="on"><span class="small muted">计算方式</span><select id="f-cc"><option value="both">上行+下行</option><option value="up">仅上行(出站)</option><option value="down">仅下行(入站)</option><option value="max">取上下行较大值</option></select></div>'+
 '<div class="field" data-cm="on"><span class="small muted">数据来源</span><select id="f-cs"><option value="nic">网卡总流量（与运营商计费接近）</option><option value="proxy">代理流量（sing-box）</option></select></div></div>'+
 '<p class="small muted" data-cm="days">例：起始 2026-11-01、周期 30 天 → 11-01~11-30 为一个周期，12-01 重新计算。时间按「设置」中的时区。</p></div>'+
 '<div class="bar"><button class="primary" id="f-save">保存并测试</button><span class="err small" id="f-err"></span></div>',true);
 $('f-cm').value=c.mode||'off';$('f-cc').value=c.count||'both';$('f-cs').value=c.source||'nic';
 function cm(){var m=val('f-cm');document.querySelectorAll('[data-cm]').forEach(function(el){var k=el.getAttribute('data-cm');el.hidden=!(k===m||(k==='on'&&m!=='off'))})}
 $('f-cm').addEventListener('change',cm);cm();
 var js=$('f-json');
 if(js)js.addEventListener('input',function(){try{var o=JSON.parse(js.value);['name','host','port','path','token'].forEach(function(k){if(o[k]!=null)$('f-'+k).value=o[k]})}catch(e){}});
 $('f-save').addEventListener('click',function(){
  var cycle={mode:val('f-cm'),day:Number(val('f-cday')),start:val('f-cstart'),len:Number(val('f-clen')),quotaGB:Number(val('f-cq')),alertPct:Number(val('f-ca')),count:val('f-cc'),source:val('f-cs')};
  var body={id:s.id,name:val('f-name'),group:val('f-group'),host:val('f-host'),port:val('f-port'),path:val('f-path'),token:val('f-token'),note:val('f-note'),cycle:cycle};
  api('/api/servers',{body:body}).then(function(j){S.servers=j.data;var ns=s.id?srvById(s.id):S.servers[S.servers.length-1];closeModal();renderGrid();return refreshOne(ns.id).then(function(){var st=S.status[ns.id];toast(st.error?'已保存，但连接失败：'+st.error:'已保存，连接成功')})})
  .catch(function(e){$('f-err').textContent=e.message});
 });
}
// ---------- 升级 sing-box-yg（脚本 sb.sh 与 sbagent）与 sing-box 内核
function coreOf(d){return d&&d.version?String(d.version).trim():''}
function needCore(d,target){var L=S.latest;target=target||(L&&L.core);return !!(target&&coreOf(d)&&coreOf(d)!==target)}
function upgradeDialog(preset){
 modal('检查更新 / 升级','<div id="u-latest" class="small"></div>'+
 '<div class="bar" style="margin:8px 0"><span class="small">升级内容：</span><select id="u-what"><option value="script">sing-box-yg 脚本与 agent</option><option value="core">sing-box 内核：最新正式版</option><option value="corepre">sing-box 内核：最新测试版</option><option value="corever">sing-box 内核：指定版本</option><option value="both">脚本与 agent + 内核最新正式版</option></select>'+
 '<input id="u-ver" placeholder="如 1.12.10 或 1.13.0-rc.1" size="20" hidden></div>'+
 '<div class="tablewrap" style="margin:8px 0"><table><thead><tr><th><input type="checkbox" id="u-all"></th><th>服务器</th><th>当前脚本</th><th>当前agent</th><th>当前内核</th><th>状态</th></tr></thead><tbody id="u-rows"></tbody></table></div>'+
 '<div class="bar"><button class="primary" id="u-go">升级所选</button><button id="u-outdated">一键升级全部需要升级的</button><button id="u-refresh">重新检查</button><span id="u-st" class="small muted"></span></div>'+
 '<p class="small muted">脚本升级：服务器从其内置的 GitHub 仓库地址下载 sb.sh 与 sbagent.py（HTTPS），校验语法后替换并重启 agent，失败自动回滚，不影响节点。<br>内核升级：服务器从 SagerNet 官方 GitHub Releases 下载对应架构的 sing-box，确认能运行且通过当前配置的 sing-box check 后才替换，重启后不能稳定运行则自动恢复旧内核（切换期间节点会中断几秒）。面板只传递版本号，不传递任何代码或下载地址。<br>出于安全考虑，服务器默认不允许远程升级（这是仅有的会让服务器运行新代码的操作），需在VPS上 sb → 19 → 6 选择 4 单独开启；agent 1.4.0 以下不支持内核升级，需先升级脚本。</p>');
 var st={};
 function what(){return val('u-what')}
 function coreTarget(){var w=what(),L=S.latest||{};return w==='core'||w==='both'?L.core:w==='corepre'?L.corePre:w==='corever'?val('u-ver'):''}
 function needs(d){var w=what();if(!d)return false;if(w==='script')return needUpgrade(d);if(w==='both')return needUpgrade(d)||needCore(d,coreTarget());return needCore(d,coreTarget())}
 function rowState(s){var x=S.status[s.id];if(!x)return '<span class="muted">未知</span>';if(x.error)return '<span class="err">'+esc(x.error)+'</span>';return needs(x.data)?'<span class="err">需要升级</span>':'<span class="okc">已是目标版本</span>'}
 function draw(){var L=S.latest||{};
  $('u-ver').hidden=what()!=='corever';
  $('u-latest').innerHTML=L.script?'GitHub 最新：脚本 <b>'+esc(L.script)+'</b> · agent <b>'+esc(L.agent)+'</b>　sing-box 正式版 <b>'+esc(L.core||'-')+'</b> · 测试版 <b>'+esc(L.corePre||'-')+'</b>'+(L.notes&&L.notes.length?'<details><summary>脚本更新内容</summary><pre class="link" style="white-space:pre-wrap">'+esc(L.notes.join('\\n'))+'</pre></details>':''):'<span class="muted">正在获取最新版本…</span>';
  $('u-rows').innerHTML=S.servers.map(function(s){var x=S.status[s.id],d=x&&x.data;var chk=preset?preset.indexOf(s.id)>=0:needs(d);
   return '<tr><td><input type="checkbox" data-u="'+esc(s.id)+'"'+(chk?' checked':'')+'></td><td>'+esc(s.name)+(s.group?' <span class="small muted">'+esc(s.group)+'</span>':'')+'</td><td>'+esc(d?d.script_version||'-':'-')+'</td><td>'+esc(d?d.agent:'-')+'</td><td>'+esc(coreOf(d)||'-')+'</td><td id="u-s-'+esc(s.id)+'">'+(st[s.id]||rowState(s))+'</td></tr>'}).join('');
 }
 function refresh(force){$('u-st').textContent='检查中…';st={};return Promise.all([loadLatest(force).catch(function(e){$('u-latest').innerHTML='<span class="err">'+esc(e.message)+'</span>'})].concat(S.servers.map(function(s){return refreshOne(s.id)}))).then(function(){$('u-st').textContent='';draw()})}
 function errText(e){return /未知操作/.test(e.message)?'agent 版本过旧，不支持此操作：请在VPS上运行 sb 选择 7 升级脚本':/upgrade/.test(e.message)?'该服务器未允许远程升级（安全默认）：如需开启，在VPS上运行 sb → 19 → 6 选择 4':e.message}
 function cellOf(s){return function(h){st[s.id]=h;var el=$('u-s-'+s.id);if(el)el.innerHTML=h}}
 function scriptOne(s){
  var cell=cellOf(s);cell('升级脚本中…');
  return call(s.id,'upgrade').then(function(r){
   var target=r.to.agent;cell('已替换为 '+esc(r.to.script)+' / agent '+esc(target)+'，等待重启…');
   var t0=Date.now();
   return new Promise(function(done){(function poll(){setTimeout(function(){call(s.id,'status').then(function(d){
     if(d.agent===target){S.status[s.id]={data:d};cell('<span class="okc">✔ 脚本已升级到 '+esc(d.script_version)+' / agent '+esc(d.agent)+'</span>');done(true)}
     else if(Date.now()-t0>90000){cell('<span class="err">重启后版本仍为 '+esc(d.agent)+'，可能已自动回滚，请在VPS上查看</span>');done(false)}else poll();
    },function(){if(Date.now()-t0>90000){cell('<span class="err">升级后无法连接，请在VPS上检查 sbagent 服务</span>');done(false)}else poll()})},3000)})()});
  },function(e){cell('<span class="err">'+esc(errText(e))+'</span>');return false});
 }
 function coreOne(s,ver){
  var cell=cellOf(s);cell('下载并切换内核 '+esc(ver)+' 中…（约需 10~60 秒）');
  return call(s.id,'coreupgrade',{version:ver}).then(function(r){
   cell(r.changed?'<span class="okc">✔ 内核 '+esc(r.from)+' → '+esc(r.to)+(r.active?'':'（未运行，请检查）')+'</span>':'<span class="okc">内核已是 '+esc(r.to)+'</span>');return refreshOne(s.id).then(function(){return true});
  },function(e){cell('<span class="err">'+esc(errText(e))+'</span>');return false});
 }
 function run(ids){
  var list=ids.map(srvById).filter(Boolean),w=what(),ver=coreTarget();
  if(!list.length)return toast('没有需要升级的服务器');
  if(w!=='script'&&!/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(-(alpha|beta|rc)\\.\\d{1,3})?$/.test(ver||''))return toast('内核版本格式错误');
  var label=w==='script'?'sing-box-yg 脚本':w==='both'?'脚本与 sing-box 内核 '+ver:'sing-box 内核 '+ver;
  if(!confirm('将 '+list.length+' 台服务器升级为：'+label+'？'+(w!=='script'?'\\n内核切换期间节点会中断几秒。':'')))return;
  $('u-st').textContent='升级中…';
  var one=function(s){if(w==='script')return scriptOne(s);if(w==='both')return scriptOne(s).then(function(ok){return ok?coreOne(s,ver):false});return coreOne(s,ver)};
  // 分批进行，每批3台，避免同时大量下载与重启
  var chain=Promise.resolve(),res=[];
  for(var i=0;i<list.length;i+=3)(function(part){chain=chain.then(function(){return Promise.all(part.map(one)).then(function(r){res=res.concat(r)})})})(list.slice(i,i+3));
  chain.then(function(){var ok=res.filter(Boolean).length;$('u-st').textContent='完成：成功 '+ok+' 台，失败 '+(res.length-ok)+' 台';scheduleRender()});
 }
 $('u-what').addEventListener('change',function(){st={};draw()});
 $('u-ver').addEventListener('input',function(){st={};draw()});
 $('u-all').addEventListener('change',function(){document.querySelectorAll('[data-u]').forEach(function(c){c.checked=checked('u-all')})});
 $('u-go').addEventListener('click',function(){run(Array.prototype.map.call(document.querySelectorAll('[data-u]:checked'),function(c){return c.getAttribute('data-u')}))});
 $('u-outdated').addEventListener('click',function(){run(S.servers.filter(function(s){var x=S.status[s.id];return x&&x.data&&needs(x.data)}).map(function(s){return s.id}))});
 $('u-refresh').addEventListener('click',function(){refresh(true)});
 draw();refresh(false);
}
function groupsDialog(){
 var groups=groupNames();
 modal('分组管理','<p class="small muted">服务器的分组在「编辑」中设置，或在「批量操作」中给勾选的服务器统一设置。这里可以重命名分组（改为空即取消分组）。</p>'+
 (groups.length?'<table><thead><tr><th>分组</th><th>服务器</th><th>重命名为</th><th></th></tr></thead><tbody>'+groups.map(function(x,i){return '<tr><td>'+esc(x[0]||'未分组')+'</td><td>'+x[1]+' 台</td><td><input id="gr-'+i+'" value="'+esc(x[0])+'"></td><td><button data-gi="'+i+'">保存</button></td></tr>'}).join('')+'</tbody></table>':'<p class="muted">暂无服务器</p>'),true);
 bind(null,'[data-gi]',function(b){var i=Number(b.getAttribute('data-gi'));api('/api/groups/rename',{body:{from:groups[i][0],to:val('gr-'+i)}}).then(function(j){S.servers=j.data;toast('已保存');closeModal();renderGrid()}).catch(function(e){toast(e.message)})});
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
    return '<tr><td>'+esc(r.time)+'</td><td>'+esc(r.proto||'')+'</td><td><a data-ip="'+esc(r.src)+'">'+esc(r.src)+'</a>'+(isLocal(r.src)?' <span class="chip">Argo/CDN</span>':geoSpan(r.src))+'</td><td>'+esc(r.sport)+'</td>'+
    '<td class="wrap">'+(tgt?'<a data-q="'+esc(tgt.replace(/:\\d+$/,''))+'">'+esc(tgt)+'</a>':'')+'</td><td>'+esc(r.net)+'</td><td>'+esc(r.out||'')+'</td><td class="wrap'+(r.err?' err':'')+'">'+esc(r.err||note)+'</td></tr>'}).join('')+'</tbody></table>';
   geoFill(out);
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
   data.ips.map(function(x){return '<tr><td>'+esc(x.ip)+(x.local?' <span class="chip">Argo/CDN</span>':geoSpan(x.ip))+'</td><td>'+x.count+'</td><td'+(x.err?' class="err"':'')+'>'+x.err+'</td><td>'+esc(x.first)+'</td><td>'+esc(x.last)+'</td><td>'+esc(x.protos.join(','))+'</td>'+
   '<td class="wrap">'+x.top.map(function(t){return esc(t[0])+' ('+t[1]+')'}).join('，')+'</td><td><a data-ip="'+esc(x.ip)+'">明细</a></td></tr>'}).join('')+'</tbody></table>';
   bind(out,'a[data-ip]',function(a){logsDialog(s,{ip:a.getAttribute('data-ip')})});
   geoFill(out);
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
  $('p-out').innerHTML=d.peers.length?'<table><thead><tr><th>源IP</th><th>协议</th><th>连接数</th><th></th></tr></thead><tbody>'+d.peers.map(function(p){return '<tr><td>'+esc(p.ip)+(p.local?' <span class="chip">Argo/CDN</span>':geoSpan(p.ip))+'</td><td>'+esc(p.proto)+'</td><td>'+p.conns+'</td><td><a data-ip="'+esc(p.ip)+'">访问记录</a></td></tr>'}).join('')+'</tbody></table>':'<p class="muted" style="padding:8px">当前没有在线客户端</p>';
  bind($('p-out'),'a[data-ip]',function(a){logsDialog(s,{ip:a.getAttribute('data-ip')})});
  geoFill($('p-out'));
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
  $('al-out').innerHTML=d.entries.length?'<table><thead><tr><th>时间</th><th>来源IP</th><th>操作</th><th>结果</th><th>参数/错误</th></tr></thead><tbody>'+d.entries.map(function(e){return '<tr><td>'+esc(e.time)+'</td><td>'+esc(e.ip)+geoSpan(e.ip)+'</td><td>'+esc(e.action)+'</td><td class="'+(e.ok?'okc':'err')+'">'+(e.ok?'成功':'失败')+'</td><td class="wrap">'+esc(e.error||JSON.stringify(e.params||{}))+'</td></tr>'}).join('')+'</tbody></table>':'<p class="muted" style="padding:8px">暂无记录</p>';
  geoFill($('al-out'));
 }).catch(function(e){fail($('al-out'),e)});
}

// ---------- 批量操作
function batchDialog(){
 var ids=Object.keys(S.selected).filter(function(k){return S.selected[k]&&srvById(k)});
 var list=ids.length?ids.map(srvById):visibleServers();
 modal('批量操作','<p class="small">对象：'+(ids.length?'已勾选的 ':S.groupFilter!=null?'分组「'+esc(S.groupFilter||'未分组')+'」的 ':'全部 ')+list.length+' 台 —— '+esc(list.map(function(s){return s.name}).join('、'))+'</p>'+
 '<div class="bar"><button id="x-reset" class="danger">批量重置参数</button><button id="x-restart">批量重启</button><button id="x-logon">批量开启日志</button><button id="x-tron">批量开启流量统计</button><button id="x-stats">汇总24小时源IP</button>'+
 '<input id="x-group" list="x-groups" placeholder="分组名（留空=取消分组）" size="16"><datalist id="x-groups">'+groupNames().filter(function(g){return g[0]}).map(function(g){return '<option value="'+esc(g[0])+'">'}).join('')+'</datalist><button id="x-setg">设置分组</button></div><div id="x-out" style="margin-top:10px"></div>',true);
 $('x-setg').addEventListener('click',function(){api('/api/servers/group',{body:{ids:list.map(function(s){return s.id}),group:val('x-group')}}).then(function(j){S.servers=j.data;S.selected={};closeModal();toast('已设置分组');renderGrid()}).catch(function(e){toast(e.message)})});
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
   '<div class="tablewrap"><table><thead><tr><th>源IP</th><th>连接数</th><th>访问的服务器</th></tr></thead><tbody>'+arr.map(function(x){return '<tr><td>'+esc(x.ip)+geoSpan(x.ip)+'</td><td>'+x.count+'</td><td class="wrap">'+esc(x.servers.join('、'))+'</td></tr>'}).join('')+'</tbody></table></div>';
   geoFill(out);
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
var DIMS=[['ip','源IP'],['host','访问地址'],['domain','主域名'],['country','IP归属地'],['isp','运营商/ASN'],['server','服务器'],['day','日期'],['hour','小时'],['month','月份'],['inbound','入站协议'],['outbound','出站'],['ip_host','源IP+访问地址'],['ip_inbound','源IP+协议']];
var RANGES=[['today','今天'],['yesterday','昨天'],['24h','最近24小时'],['7d','最近7天'],['30d','最近30天'],['month','本月'],['lastmonth','上月'],['cycle','本流量周期'],['pcycle','上流量周期'],['custom','自定义']];
var MB=1048576;
function scopeServers(scope){if(!scope)return S.servers.slice();if(scope.indexOf('g:')===0){var g=scope.slice(2);return S.servers.filter(function(s){return (s.group||'')===g})}var s=srvById(scope.slice(2));return s?[s]:[]}
function viewTraffic(){
 if(!S.servers.length){api('/api/servers').then(function(j){S.servers=j.data;if(j.data.length)viewTraffic();else $('view').innerHTML='<div class="card muted">请先添加服务器</div>'});return}
 var now=Date.now(),groups=groupNames();
 $('view').innerHTML='<div class="card" style="margin-bottom:10px"><div class="bar">'+
 '<select id="t-scope" title="统计范围"><option value="">全部服务器</option>'+(groups.length>1?groups.map(function(g){return '<option value="g:'+esc(g[0])+'">分组：'+esc(g[0]||'未分组')+'</option>'}).join(''):'')+
 S.servers.map(function(s){return '<option value="s:'+esc(s.id)+'">'+esc(s.name)+'</option>'}).join('')+'</select>'+
 '<select id="t-range">'+RANGES.map(function(r){return '<option value="'+r[0]+'">'+r[1]+'</option>'}).join('')+'</select>'+
 '<span id="t-custom" hidden><input type="datetime-local" id="t-start" value="'+localInput(now-86400000)+'"> 至 <input type="datetime-local" id="t-end" value="'+localInput(now)+'"></span>'+
 '<select id="t-group">'+DIMS.map(function(g){return '<option value="'+g[0]+'">按'+g[1]+'</option>'}).join('')+'</select>'+
 '<select id="t-sort"><option value="bytes">按合计排序</option><option value="up">按上行排序</option><option value="down">按下行排序</option><option value="conns">按连接数排序</option></select>'+
 '<select id="t-limit"><option>50</option><option selected>200</option><option>1000</option></select></div>'+
 '<div class="bar" style="margin-top:6px"><input id="t-ip" placeholder="源IP" size="16"><input id="t-host" placeholder="访问地址/域名" size="18"><label class="small"><input type="checkbox" id="t-exact">精确匹配</label>'+
 '<select id="t-in"><option value="">全部协议</option>'+PROTOS.filter(function(p){return p[0]!=='vmess-argo'}).map(function(p){return '<option value="'+p[0]+'">'+p[1]+'</option>'}).join('')+'</select>'+
 '<select id="t-outb"><option value="">全部出站</option><option value="direct">直连 direct</option><option value="warp">WARP</option><option value="socks">Socks5</option></select>'+
 '<input id="t-loc" placeholder="归属地/运营商筛选" size="14" title="作用于源IP类结果，如 日本、移动、Google"><input id="t-min" type="number" min="0" placeholder="最少MB" style="width:80px">'+
 '<label class="small"><input type="checkbox" id="t-split" checked>按服务器分别显示</label>'+
 '<button class="primary" id="t-go">查询</button><button id="t-reset">重置条件</button><button id="t-csv">导出CSV</button></div>'+
 '<p class="small muted" style="margin:6px 0 0">点击表格中的项目逐级下钻，用路径或「返回上一级」回退；多台服务器时默认按服务器分别列出，可明确看到同一IP经过哪台服务器访问了哪些地址。IP归属地来自公开IP库，缓存30天。</p></div>'+
 '<div class="bar" id="t-crumb" style="margin-bottom:8px"></div><div id="t-sum" style="margin-bottom:10px"></div><div id="t-srvsum"></div><div id="t-chart"></div><div class="tablewrap" id="t-out"></div>';
 $('t-range').addEventListener('change',function(){$('t-custom').hidden=val('t-range')!=='custom'});
 $('t-go').addEventListener('click',function(){TS.stack=[{label:'查询',q:readControls()}];runTraffic()});
 $('t-reset').addEventListener('click',function(){S.lastTrafficQ=null;viewTraffic()});
 $('t-csv').addEventListener('click',exportCsv);
 ['t-ip','t-host','t-loc','t-min'].forEach(function(id){$(id).addEventListener('keydown',function(e){if(e.key==='Enter')$('t-go').click()})});
 var q=S.lastTrafficQ?JSON.parse(JSON.stringify(S.lastTrafficQ)):{scope:'',range:'24h',group:'ip',sort:'bytes',limit:200,split:true};
 if(S.trafficScope){q.scope=S.trafficScope;S.trafficScope=null}
 TS.stack=[{label:'查询',q:q}];
 runTraffic();
}
var TS={stack:[],rows:null};
function readControls(){return {scope:val('t-scope'),range:val('t-range'),cstart:inputTime('t-start'),cend:inputTime('t-end'),group:val('t-group'),sort:val('t-sort'),limit:Number(val('t-limit')),
 ip:val('t-ip'),host:val('t-host'),exact:checked('t-exact'),inbound:val('t-in'),outbound:val('t-outb'),loc:val('t-loc'),minmb:Number(val('t-min'))||0,split:checked('t-split')}}
function writeControls(q){$('t-scope').value=q.scope||'';$('t-range').value=q.range||'24h';$('t-custom').hidden=q.range!=='custom';if(q.range==='custom'&&q.cstart){$('t-start').value=localInput(q.cstart*1000);$('t-end').value=localInput(q.cend*1000)}
 $('t-group').value=q.group;$('t-sort').value=q.sort||'bytes';$('t-limit').value=String(q.limit||200);$('t-ip').value=q.ip||'';$('t-host').value=q.host||'';$('t-exact').checked=!!q.exact;
 $('t-in').value=q.inbound&&PROTOS.some(function(p){return p[0]===q.inbound})?q.inbound:'';$('t-outb').value=q.outbound&&['direct','warp','socks'].indexOf(q.outbound)>=0?q.outbound:'';$('t-loc').value=q.loc||'';$('t-min').value=q.minmb||'';$('t-split').checked=q.split!==false}
function rangeOf(q){
 var now=new Date(),t=Math.floor(now.getTime()/1000),d0=new Date(now.getFullYear(),now.getMonth(),now.getDate()).getTime()/1000;
 var m0=new Date(now.getFullYear(),now.getMonth(),1).getTime()/1000,lm0=new Date(now.getFullYear(),now.getMonth()-1,1).getTime()/1000;
 var r={today:[d0,t],yesterday:[d0-86400,d0],'24h':[t-86400,t],'7d':[t-7*86400,t],'30d':[t-30*86400,t],month:[m0,t],lastmonth:[lm0,m0],custom:[q.cstart,q.cend]}[q.range||'24h'];
 if(r){if(!r[0]||!r[1]||r[0]>=r[1])return Promise.reject(new Error('请选择有效的时间范围'));return Promise.resolve(r)}
 var list=scopeServers(q.scope);
 if(list.length!==1||!list[0].cycle||list[0].cycle.mode==='off')return Promise.reject(new Error('「流量周期」需选择单台已设置周期的服务器（在服务器「编辑」中设置）'));
 return api('/api/servers/'+list[0].id+'/cycle',{body:{}}).then(function(j){var p=q.range==='cycle'?j.data.cur:j.data.prev;return [Math.floor(p.start/1000),Math.floor(Math.min(p.end,Date.now())/1000)]});
}
// agent 1.2.0 起支持精确筛选与新维度；旧版会忽略这些参数并返回全部数据，必须识别出来，避免把别人的流量算到所选IP上
var OLD_AGENT='该服务器 sbagent 版本过旧，不支持此查询，请在VPS上运行 sb 选择 7 更新脚本';
function oldAgent(d,needNew){return needNew&&d&&!('nic' in d)}
function ipOf(key,group){if(group==='ip')return key;if(group==='ip_host')return key.split(' -> ')[0];if(group==='ip_inbound')return key.split(' · ')[0];return null}
function agentParams(q,range,group,limit){
 var p={start:range[0],end:range[1],group:group,sort:q.sort,limit:limit,inbound:q.inbound,outbound:q.outbound,ip_exact:q.ip_exact,host_exact:q.host_exact,domain_exact:q.domain_exact};
 if(q.exact){if(q.ip&&!p.ip_exact)p.ip_exact=q.ip;if(q.host&&!p.host_exact)p.host_exact=q.host}else{p.ip=q.ip;p.host=q.host}
 return p;
}
function runTraffic(){
 var top=TS.stack[TS.stack.length-1],q=top.q;
 S.lastTrafficQ=TS.stack[0].q;
 writeControls(q);
 $('t-crumb').innerHTML=(TS.stack.length>1?'<button id="t-back">← 返回上一级</button>':'')+TS.stack.map(function(x,i){return i===TS.stack.length-1?'<b>'+esc(x.label)+'</b>':'<a data-ci="'+i+'">'+esc(x.label)+'</a> ›'}).join(' ');
 if($('t-back'))$('t-back').addEventListener('click',function(){TS.stack.pop();runTraffic()});
 bind($('t-crumb'),'[data-ci]',function(a){TS.stack=TS.stack.slice(0,Number(a.getAttribute('data-ci'))+1);runTraffic()});
 busy($('t-out'),'查询中…');$('t-sum').innerHTML='';$('t-srvsum').innerHTML='';$('t-chart').innerHTML='';
 var list=scopeServers(q.scope),geoDim=q.group==='country'||q.group==='isp'||!!q.country||!!q.isp;
 var split=q.split!==false&&list.length>1&&q.group!=='server';
 var agroup=q.group==='server'?'ip':geoDim?'ip':q.group,alimit=q.group==='server'?1:geoDim?5000:Math.max(q.limit,q.minmb||q.loc?1000:0);
 rangeOf(q).then(function(range){
  var params=agentParams(q,range,agroup,alimit);
  var needNew=params.ip_exact||params.host_exact||params.domain_exact||['domain','month','ip_inbound'].indexOf(agroup)>=0;
  return Promise.all(list.map(function(s){return call(s.id,'traffic',params).then(function(d){return oldAgent(d,needNew)?{s:s,e:new Error(OLD_AGENT)}:{s:s,d:d}},function(e){return{s:s,e:e}})})).then(function(rs){return{rs:rs,range:range}});
 }).then(function(res){
  var tot={up:0,down:0},nic={rx:0,tx:0},mt={up:0,down:0,conns:0},errs=[],off=[],per=[];
  var rows=[],merged={};
  res.rs.forEach(function(r){
   if(r.e){errs.push(r.s.name+'：'+r.e.message);per.push({s:r.s,e:r.e});return}
   var d=r.d;per.push({s:r.s,d:d});
   if(!d.enabled)off.push(r.s.name);
   tot.up+=d.total.up;tot.down+=d.total.down;if(d.nic){nic.rx+=d.nic.rx;nic.tx+=d.nic.tx}
   mt.up+=d.matched.up;mt.down+=d.matched.down;mt.conns+=d.matched.conns;
   if(q.group==='server'){rows.push({key:r.s.name,srv:r.s,up:d.matched.up,down:d.matched.down,conns:d.matched.conns,ips:'-',hosts:'-',servers:[r.s.name],tzoff:d.tzoff});return}
   d.rows.forEach(function(x){
    if(split){rows.push({key:x.key,srv:r.s,up:x.up,down:x.down,conns:x.conns,ips:x.ips,hosts:x.hosts,servers:[r.s.name],first:x.first,last:x.last,tzoff:d.tzoff});return}
    var o=merged[x.key]||(merged[x.key]={key:x.key,up:0,down:0,conns:0,ips:0,hosts:0,servers:[],tzoff:d.tzoff});o.up+=x.up;o.down+=x.down;o.conns+=x.conns;o.ips=Math.max(o.ips,x.ips);o.hosts=Math.max(o.hosts,x.hosts);o.servers.push(r.s.name);
   });
  });
  if(!split&&q.group!=='server')rows=Object.keys(merged).map(function(k){return merged[k]});
  var ipCol=geoDim||['ip','ip_host','ip_inbound'].indexOf(q.group)>=0;
  return loadGeo(ipCol?rows.map(function(x){return ipOf(x.key,geoDim?'ip':q.group)}):[]).then(function(){
   var gi=function(x){return GEO[ipOf(x.key,geoDim?'ip':q.group)]};
   if(q.country)rows=rows.filter(function(x){return geoText(gi(x))===q.country});
   if(q.isp)rows=rows.filter(function(x){return geoIsp(gi(x))===q.isp});
   if(q.loc&&ipCol){var lw=q.loc.toLowerCase();rows=rows.filter(function(x){var g=gi(x);return (geoText(g)+' '+geoIsp(g)+(g&&g.mobile?' 移动':'')+(g&&g.hosting?' 机房':'')+(g&&g.proxy?' 代理':'')).toLowerCase().indexOf(lw)>=0})}
   if(q.group==='country'||q.group==='isp'){
    var agg={};rows.forEach(function(x){var g=gi(x),k=q.group==='country'?(geoText(g)||'未知'):(geoIsp(g)||'未知');var id=(split?x.srv.id+'|':'')+k;
     var o=agg[id]||(agg[id]={key:k,srv:split?x.srv:null,up:0,down:0,conns:0,ips:0,hosts:0,servers:[]});o.up+=x.up;o.down+=x.down;o.conns+=x.conns;o.ips++;o.hosts=Math.max(o.hosts,x.hosts);x.servers.forEach(function(n){if(o.servers.indexOf(n)<0)o.servers.push(n)})});
    rows=Object.keys(agg).map(function(k){return agg[k]});
   }
   if(q.minmb)rows=rows.filter(function(x){return x.up+x.down>=q.minmb*MB});
   if(q.country||q.isp||q.loc||q.minmb){mt={up:0,down:0,conns:0};rows.forEach(function(x){mt.up+=x.up;mt.down+=x.down;mt.conns+=x.conns})}
   var sk={up:function(x){return x.up},down:function(x){return x.down},conns:function(x){return x.conns}}[q.sort]||function(x){return x.up+x.down};
   if(['day','hour','month'].indexOf(q.group)>=0)rows.sort(function(a,b){return a.key<b.key?-1:a.key>b.key?1:(a.srv&&b.srv&&a.srv.name<b.srv.name?-1:1)});else rows.sort(function(a,b){return sk(b)-sk(a)});
   var total=rows.length;
   if(rows.length>q.limit)rows=rows.slice(0,q.limit);
   TS.rows=rows;TS.group=q.group;TS.split=split;
   drawTraffic(rows,q,list,{tot:tot,nic:nic,mt:mt,errs:errs,off:off,range:res.range,per:per,total:total,split:split,ipCol:ipCol&&!geoDim||q.group==='ip'});
  });
 }).catch(function(e){fail($('t-out'),e)});
}
function drawTraffic(arr,q,list,m){
 $('t-sum').innerHTML='<div class="card"><span class="stat">时间 <b class="small">'+fmtTime(m.range[0]*1000).slice(0,16)+' ~ '+fmtTime(m.range[1]*1000).slice(0,16)+'</b></span><span class="stat">范围 <b class="small">'+esc(list.length===1?list[0].name:list.length+' 台服务器')+'</b></span><br>'+
 '<span class="stat">代理总流量 <b>'+fmtBytes(m.tot.up+m.tot.down)+'</b> <span class="small muted">↑'+fmtBytes(m.tot.up)+' ↓'+fmtBytes(m.tot.down)+'</span></span>'+
 (m.nic.rx||m.nic.tx?'<span class="stat">网卡流量 <b>'+fmtBytes(m.nic.rx+m.nic.tx)+'</b> <span class="small muted">出'+fmtBytes(m.nic.tx)+' 入'+fmtBytes(m.nic.rx)+'</span></span>':'')+
 '<span class="stat">筛选结果 <b>'+fmtBytes(m.mt.up+m.mt.down)+'</b></span><span class="stat">连接 <b>'+m.mt.conns+'</b></span><span class="stat small muted">共 '+m.total+' 项'+(m.total>arr.length?'，显示前 '+arr.length+' 项':'')+'</span>'+
 (m.errs.length?'<div class="err small">'+esc(m.errs.join('；'))+'</div>':'')+(m.off.length?'<div class="small muted">未开启流量统计：'+esc(m.off.join('、'))+'</div>':'')+'</div>';
 if(list.length>1&&q.group!=='server'){
  $('t-srvsum').innerHTML='<div class="tablewrap" style="margin-bottom:10px;max-height:220px"><table><thead><tr><th>服务器</th><th>分组</th><th class="num">代理总流量</th><th class="num">网卡流量</th><th class="num">筛选结果</th><th class="num">连接</th><th></th></tr></thead><tbody>'+
  m.per.map(function(p){if(p.e)return '<tr><td>'+esc(p.s.name)+'</td><td>'+esc(p.s.group)+'</td><td colspan="5" class="err small">'+esc(p.e.message)+'</td></tr>';var d=p.d;
   return '<tr><td><a data-scope="'+esc(p.s.id)+'">'+esc(p.s.name)+'</a></td><td>'+esc(p.s.group)+'</td><td class="num">'+fmtBytes(d.total.up+d.total.down)+'</td><td class="num">'+(d.nic?fmtBytes(d.nic.rx+d.nic.tx):'-')+'</td><td class="num"><b>'+fmtBytes(d.matched.up+d.matched.down)+'</b></td><td class="num">'+d.matched.conns+'</td><td class="small muted">'+(d.enabled?'':'未开启统计')+'</td></tr>'}).join('')+'</tbody></table></div>';
  bind($('t-srvsum'),'a[data-scope]',function(a){var n=JSON.parse(JSON.stringify(q));n.scope='s:'+a.getAttribute('data-scope');TS.stack.push({label:srvById(a.getAttribute('data-scope')).name,q:n});runTraffic()});
 }
 if(['day','hour','month'].indexOf(q.group)>=0&&arr.length&&!m.split)$('t-chart').innerHTML=chart(arr);
 var max=arr.reduce(function(mx,x){return Math.max(mx,x.up+x.down)},0)||1;
 var label=DIMS.filter(function(g){return g[0]===q.group})[0][1],ipCol=['ip','ip_host','ip_inbound'].indexOf(q.group)>=0;
 $('t-out').innerHTML=arr.length?'<table><thead><tr>'+(m.split?'<th>服务器</th>':'')+'<th>'+esc(label)+'</th>'+(ipCol?'<th>归属地</th><th>运营商</th>':'')+'<th class="num">上行</th><th class="num">下行</th><th class="num">合计</th><th>占比</th><th class="num">连接</th><th class="num">IP数</th><th class="num">地址数</th>'+(!m.split&&list.length>1?'<th>服务器</th>':'')+'<th></th></tr></thead><tbody>'+
 arr.map(function(x,i){var t=x.up+x.down,ip=ipCol?ipOf(x.key,q.group):null,g=ip?GEO[ip]:null;
  return '<tr>'+(m.split?'<td>'+esc(x.srv?x.srv.name:x.servers.join('、'))+(x.srv&&x.srv.group?' <span class="small muted">'+esc(x.srv.group)+'</span>':'')+'</td>':'')+
  '<td class="wrap"><a data-drill="'+i+'">'+esc(x.key)+'</a> '+(ip?geoTags(g):'')+'</td>'+(ipCol?'<td>'+esc(geoText(g))+'</td><td class="wrap small">'+esc(geoIsp(g))+'</td>':'')+
  '<td class="num">'+fmtBytes(x.up)+'</td><td class="num">'+fmtBytes(x.down)+'</td><td class="num"><b>'+fmtBytes(t)+'</b></td><td><div class="meter"><i style="width:'+Math.max(1,Math.round(t/max*100))+'%"></i></div></td><td class="num">'+x.conns+'</td><td class="num">'+x.ips+'</td><td class="num">'+x.hosts+'</td>'+
  (!m.split&&list.length>1?'<td class="small">'+esc(x.servers.join('、'))+'</td>':'')+'<td>'+(ip?'<a data-dev="'+esc(ip)+'">设备详情</a>':'')+'</td></tr>'}).join('')+'</tbody></table>':'<p class="muted" style="padding:8px">没有数据</p>';
 bind($('t-out'),'a[data-drill]',function(a){drill(arr[Number(a.getAttribute('data-drill'))],q)});
 bind($('t-out'),'a[data-dev]',function(a){deviceDialog(a.getAttribute('data-dev'),q)});
}
// 日期/小时/月份键是服务器本地时间：用该服务器返回的 UTC 偏移换算为时间戳
function keyRange(key,group,tzoff){
 var p=key.split(/[- :]/).map(Number),off=Number(tzoff)||0;
 var y=p[0],mo=(p[1]||1)-1,d=p[2]||1,h=p[3]||0;
 var s=Date.UTC(y,mo,d,group==='hour'?h:0)/1000-off;
 if(group==='day')return[s,s+86400];if(group==='hour')return[s,s+3600];
 return[s,Date.UTC(y,mo+1,1)/1000-off];
}
function drill(x,q){
 var n=JSON.parse(JSON.stringify(q)),k=x.key,label,g=q.group;
 if(x.srv){n.scope='s:'+x.srv.id}
 if(g==='server'){n.scope='s:'+x.srv.id;n.group='ip';label=x.srv.name}
 else if(g==='ip'){n.ip_exact=k;n.group='host';label='IP '+k}
 else if(g==='host'){n.host_exact=k;n.group='ip';label=k}
 else if(g==='domain'){n.domain_exact=k;n.group='host';label=k}
 else if(g==='country'){n.country=k;n.group='ip';label=k}
 else if(g==='isp'){n.isp=k;n.group='ip';label=k}
 else if(g==='inbound'){n.inbound=k;n.group='ip';label=k}
 else if(g==='outbound'){n.outbound=k;n.group='ip';label='出站 '+k}
 else if(g==='ip_host'){var p=k.split(' -> ');n.ip_exact=p[0];n.host_exact=p[1];n.group='hour';label=k}
 else if(g==='ip_inbound'){var p2=k.split(' · ');n.ip_exact=p2[0];n.inbound=p2[1];n.group='host';label=k}
 else{var r=keyRange(k,g,x.tzoff);n.range='custom';n.cstart=r[0];n.cend=r[1];n.group=g==='month'?'day':g==='day'?'hour':'ip_host';label=k}
 if(x.srv&&g!=='server')label=x.srv.name+' · '+label;
 TS.stack.push({label:label,q:n});runTraffic();
}
function deviceDialog(ip,q){
 q=q||{scope:'',range:'7d'};
 var list=scopeServers(q.scope);
 modal('设备详情 · '+esc(ip),'<div id="dv-geo" class="card" style="margin-bottom:10px"></div><div id="dv-sum"></div><div id="dv-out"></div>');
 busy($('dv-out'));
 loadGeo([ip]).then(function(){var g=GEO[ip];
  $('dv-geo').innerHTML=g&&!g.local?'<div class="kv"><span>IP</span><span><b>'+esc(ip)+'</b> '+geoTags(g)+'</span><span>归属地</span><span>'+esc(geoText(g))+'</span><span>运营商</span><span>'+esc(g.isp||'-')+'</span><span>组织</span><span>'+esc(g.org||'-')+'</span><span>ASN</span><span>'+esc(g.as||'-')+'</span>'+
  '<span>判断</span><span>'+(g.hosting?'<b class="err">机房/服务器IP：通常不是个人设备，可能是节点被转用或泄露</b>':g.proxy?'<b class="err">代理/VPN 出口IP</b>':g.mobile?'移动网络（手机/流量卡）':'家庭/企业宽带')+'</span></div>':
  '<span class="muted">'+(g&&g.local?'内网/本机地址（Vmess 经 Argo/CDN 转发时显示为 127.0.0.1 或 CDN 节点）':'未查询到归属地（可在设置中更换数据源）')+'</span>';
 });
 rangeOf(q).then(function(range){
  var base={start:range[0],end:range[1],ip_exact:ip},span=range[1]-range[0];
  $('dv-sum').innerHTML='<p class="small muted">时间：'+fmtTime(range[0]*1000).slice(0,16)+' ~ '+fmtTime(range[1]*1000).slice(0,16)+'</p>';
  return Promise.all(list.map(function(s){
   return Promise.all([call(s.id,'traffic',Object.assign({group:'host',limit:50},base)),call(s.id,'traffic',Object.assign({group:'inbound',limit:20},base)),
    call(s.id,'traffic',Object.assign({group:span>3*86400?'day':'hour',limit:2000},base)),call(s.id,'peers').catch(function(){return{peers:[]}}),
    call(s.id,'logs',{ipx:ip,limit:30}).catch(function(){return{records:[]}})]).then(function(r){
     if(oldAgent(r[0],true))return{s:s,e:new Error(OLD_AGENT)};
     r[4].records=(r[4].records||[]).filter(function(l){return l.src===ip});return{s:s,r:r}},function(e){return{s:s,e:e}});
  }));
 }).then(function(rs){
  var seen=rs.filter(function(x){if(x.e)return true;return x.r[0].matched.conns||x.r[4].records.length||x.r[3].peers.some(function(p){return p.ip===ip})});
  if(!seen.length){$('dv-out').innerHTML='<p class="muted">所选时间段内该IP在'+(list.length>1?'这些服务器':'该服务器')+'上没有流量或连接记录</p>';return}
  $('dv-sum').innerHTML+='<div class="tablewrap" style="margin-bottom:10px"><table><thead><tr><th>经由服务器</th><th>分组 / 地址</th><th class="num">流量</th><th class="num">连接</th><th>协议</th><th>最近连接记录</th><th>状态</th></tr></thead><tbody>'+
  seen.map(function(x){if(x.e)return '<tr><td>'+esc(x.s.name)+'</td><td colspan="6" class="err small">'+esc(x.e.message)+'</td></tr>';
   var h=x.r[0].matched,peer=x.r[3].peers.filter(function(p){return p.ip===ip})[0],logs=x.r[4].records;
   return '<tr><td><b>'+esc(x.s.name)+'</b></td><td class="small">'+esc(x.s.group||'-')+' / '+esc(x.s.host)+'</td><td class="num">'+fmtBytes(h.up+h.down)+'</td><td class="num">'+h.conns+'</td><td class="small">'+esc(x.r[1].rows.map(function(p){return p.key}).join('、'))+'</td>'+
   '<td class="small">'+(logs.length?esc(logs[logs.length-1].time)+' ~ '+esc(logs[0].time):'-')+'</td><td>'+(peer?'<span class="okc">在线 '+peer.conns+'</span>':'离线')+'</td></tr>'}).join('')+'</tbody></table></div>';
  $('dv-out').innerHTML=seen.map(function(x){
   if(x.e)return '';
   var hosts=x.r[0],tl=x.r[2],logs=x.r[4].records||[];
   var hmax=hosts.rows.reduce(function(m,y){return Math.max(m,y.up+y.down)},0)||1;
   return '<div class="card section"><h3>通过「'+esc(x.s.name)+'」（'+esc(x.s.host)+'）访问的地址 <span class="small muted">'+hosts.rows.length+' 个，'+fmtBytes(hosts.matched.up+hosts.matched.down)+'</span></h3>'+
   (logs.length?'<p class="small muted">源端口：'+esc(logs.map(function(l){return l.sport}).filter(function(v,i,a){return v&&a.indexOf(v)===i}).slice(0,10).join(', '))+'</p>':'')+
   (tl.rows.length?chart(tl.rows):'')+
   '<div class="tablewrap" style="max-height:280px"><table><thead><tr><th>访问地址</th><th class="num">上行</th><th class="num">下行</th><th class="num">合计</th><th>占比</th><th class="num">连接</th><th>时间</th></tr></thead><tbody>'+hosts.rows.map(function(h){var t=h.up+h.down;
    return '<tr><td class="wrap">'+esc(h.key)+'</td><td class="num">'+fmtBytes(h.up)+'</td><td class="num">'+fmtBytes(h.down)+'</td><td class="num"><b>'+fmtBytes(t)+'</b></td><td><div class="meter"><i style="width:'+Math.max(1,Math.round(t/hmax*100))+'%"></i></div></td><td class="num">'+h.conns+'</td><td class="small">'+esc(h.first.slice(5,16))+' ~ '+esc(h.last.slice(5,16))+'</td></tr>'}).join('')+'</tbody></table></div>'+
   (logs.length?'<details style="margin-top:6px"><summary class="small">最近 '+logs.length+' 条连接日志</summary><div class="tablewrap" style="max-height:240px"><table><thead><tr><th>时间</th><th>协议</th><th>端口</th><th>目标</th><th>备注</th></tr></thead><tbody>'+logs.map(function(l){return '<tr><td>'+esc(l.time)+'</td><td>'+esc(l.proto||'')+'</td><td>'+esc(l.sport)+'</td><td class="wrap">'+esc(l.domain||l.dst)+'</td><td class="wrap'+(l.err?' err':'')+'">'+esc(l.err||l.out||'')+'</td></tr>'}).join('')+'</tbody></table></div></details>':'')+'</div>';
  }).join('');
 }).catch(function(e){fail($('dv-out'),e)});
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
 if(!TS.rows||!TS.rows.length)return toast('请先查询');
 var ipCol=['ip','ip_host','ip_inbound'].indexOf(TS.group)>=0,q=function(v){return '"'+String(v==null?'':v).replace(/"/g,'""')+'"'};
 var lines=['server,key,'+(ipCol?'location,isp,':'')+'upload,download,total,conns,ips,hosts'].concat(TS.rows.map(function(x){var ip=ipCol?ipOf(x.key,TS.group):null,g=ip?GEO[ip]:null;
  return [q(x.srv?x.srv.name:x.servers.join('/')),q(x.key)].concat(ipCol?[q(geoText(g)),q(geoIsp(g))]:[]).concat([x.up,x.down,x.up+x.down,x.conns,x.ips,x.hosts]).join(',')}));
 var a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['\\ufeff'+lines.join('\\n')],{type:'text/csv'}));a.download='traffic-'+TS.group+'.csv';a.click();
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
  if(a==='ips'){var st=s.stat||{ips:[]};modal('订阅访问IP · '+esc(s.name),'<p class="small muted">如出现陌生IP，说明订阅链接可能已泄露，请重置订阅链接，并对相关服务器重置参数。</p><div class="tablewrap"><table><thead><tr><th>IP</th><th>地区</th><th>次数</th><th>首次</th><th>最近</th></tr></thead><tbody>'+st.ips.map(function(x){return '<tr><td>'+esc(x.ip)+geoSpan(x.ip)+'</td><td>'+esc(x.cc)+'</td><td>'+(x.n||1)+'</td><td>'+fmtTime(x.first)+'</td><td>'+fmtTime(x.last)+'</td></tr>'}).join('')+'</tbody></table></div>'+(st.last?'<p class="small muted">最近客户端：'+esc(st.last.ua)+'</p>':''),true);geoFill($('modal'));return}
  if(a==='preview'){modal('节点预览 · '+esc(s.name),'<div id="pv"></div>',true);busy($('pv'));fetch(s.url+'?format=plain',{credentials:'omit'}).then(function(r){return r.text()}).then(function(t){var ls=t.split('\\n').filter(Boolean);$('pv').innerHTML='<p class="small">共 '+ls.length+' 个节点（预览也会计入访问统计）</p>'+ls.map(function(l){return '<div class="link">'+esc(l)+'</div>'}).join('')}).catch(function(e){fail($('pv'),e)})}
 });
}
var PROTO_LABEL={vless:'Vless',vmess:'Vmess','vmess-argo':'Vmess-Argo',hysteria2:'Hy2',tuic:'Tuic',anytls:'Anytls',other:'节点'};
function applyTpl(tpl,v){return String(tpl||'{server}-{proto}').replace(/\\{(\\w+)\\}/g,function(all,k){return v[k]!==undefined&&v[k]!==null?String(v[k]):all}).slice(0,64)}
function customName(link){if(link.indexOf('vmess://')===0){try{return JSON.parse(decodeURIComponent(escape(atob(link.slice(8).trim())))).ps||''}catch(e){return ''}}var i=link.indexOf('#');if(i<0)return '';try{return decodeURIComponent(link.slice(i+1))}catch(e){return link.slice(i+1)}}
function editSub(s){
 s=s||{servers:[],protos:[],custom:[],enabled:true,rename:true,tpl:'{server}-{proto}',names:{},exclude:[]};
 var names=Object.assign({},s.names||{}),exclude={};(s.exclude||[]).forEach(function(k){exclude[k]=1});
 var ex=s.expires?localInput(s.expires):'',groups=groupNames();
 modal(s.id?'编辑订阅':'新建订阅',
 '<div class="row"><div class="field"><span class="small muted">名称</span><input id="e-name" value="'+esc(s.name||'')+'"></div><div class="field"><span class="small muted">到期时间（可选）</span><input type="datetime-local" id="e-exp" value="'+ex+'"></div></div>'+
 '<div class="field"><span class="small muted">包含的服务器'+(groups.length>1?'　按分组全选：'+groups.map(function(g,i){return '<a data-eg="'+i+'">'+esc(g[0]||'未分组')+'</a>'}).join(' '):'')+'</span><div class="bar">'+S.servers.map(function(x){var c=(S.links||[]).filter(function(l){return l.id===x.id})[0];return '<label><input type="checkbox" data-es="'+esc(x.id)+'"'+(s.servers.indexOf(x.id)>=0?' checked':'')+'>'+esc(x.name)+(x.group?' <span class="small muted">'+esc(x.group)+'</span>':'')+(c&&c.t?'':' <span class="small err">(无缓存)</span>')+'</label>'}).join('')+'</div></div>'+
 '<div class="field"><span class="small muted">协议（不选表示全部）</span><div class="bar">'+PROTOS.map(function(p){return '<label><input type="checkbox" data-ep="'+p[0]+'"'+(s.protos.indexOf(p[0])>=0?' checked':'')+'>'+p[1]+'</label>'}).join('')+'</div></div>'+
 '<div class="field"><span class="small muted">自定义节点链接（每行一个，支持 vless/vmess/hysteria2/tuic/anytls/trojan/ss 等）</span><textarea id="e-custom" rows="4">'+esc(s.custom.join('\\n'))+'</textarea></div>'+
 '<div class="section card"><h3>节点命名</h3><div class="bar small"><label><input type="checkbox" id="e-ren"'+(s.rename?' checked':'')+'>未单独命名的节点使用模板</label>'+
 '模板 <input id="e-tpl" size="22" value="'+esc(s.tpl||'{server}-{proto}')+'"><button id="e-fill">按模板填充全部</button><button id="e-pre">加前缀</button><button id="e-suf">加后缀</button><button id="e-rep">查找替换</button><button id="e-clr">清空单独命名</button></div>'+
 '<p class="small muted">模板变量：{server} 服务器名、{group} 分组、{proto} 协议、{type} 链接类型、{host} 服务器地址、{n} 序号、{orig} 原名称。单独设置的名称优先；重名自动加序号；重置参数后名称保持不变。取消勾选可从订阅中排除该节点。</p>'+
 '<div class="tablewrap" style="max-height:340px"><table><thead><tr><th><input type="checkbox" id="e-all" checked title="全选"></th><th>服务器</th><th>协议</th><th>原名称</th><th>订阅中的名称</th></tr></thead><tbody id="e-nodes"><tr><td colspan="5" class="muted">加载中…</td></tr></tbody></table></div></div>'+
 '<div class="row"><div class="field"><label><input type="checkbox" id="e-en"'+(s.enabled?' checked':'')+'>启用</label></div><div class="field"><span class="small muted">备注</span><input id="e-note" value="'+esc(s.note||'')+'"></div></div>'+
 '<div class="bar"><button class="primary" id="e-save">保存</button><span class="err small" id="e-err"></span></div>');
 var nodes=[];
 function selServers(){return Array.prototype.map.call(document.querySelectorAll('[data-es]:checked'),function(c){return c.getAttribute('data-es')})}
 function selProtos(){return Array.prototype.map.call(document.querySelectorAll('[data-ep]:checked'),function(c){return c.getAttribute('data-ep')})}
 function collect(){document.querySelectorAll('[data-nk]').forEach(function(inp){var k=inp.getAttribute('data-nk');if(inp.value.trim())names[k]=inp.value.trim();else delete names[k]});
  document.querySelectorAll('[data-nx]').forEach(function(c){var k=c.getAttribute('data-nx');if(c.checked)delete exclude[k];else exclude[k]=1})}
 function draw(){
  var protos=selProtos(),order=selServers(),n=0,tpl=val('e-tpl'),ren=checked('e-ren');
  var rows=[];order.forEach(function(id){nodes.forEach(function(x){if(x.serverId===id&&(!protos.length||protos.indexOf(x.proto)>=0))rows.push(x)})});
  $('e-custom').value.split(/\\r?\\n/).map(function(l){return l.trim()}).filter(Boolean).forEach(function(l,i){rows.push({key:'c|'+i,server:'自定义',group:'',proto:'other',protoLabel:(l.split(':')[0]||'').toUpperCase(),label:'custom',orig:customName(l),host:''})});
  $('e-nodes').innerHTML=rows.length?rows.map(function(x){var inc=!exclude[x.key];if(inc)n++;
   var preview=ren&&x.label!=='custom'?applyTpl(tpl,{server:x.server,group:x.group,proto:x.protoLabel||PROTO_LABEL[x.proto]||x.proto,type:x.label,host:x.host,n:n,orig:x.orig}):x.orig;
   return '<tr><td><input type="checkbox" data-nx="'+esc(x.key)+'"'+(inc?' checked':'')+'></td><td>'+esc(x.server)+(x.group?' <span class="small muted">'+esc(x.group)+'</span>':'')+'</td><td>'+esc(x.protoLabel||PROTO_LABEL[x.proto]||x.proto)+'</td><td class="wrap small">'+esc(x.orig)+'</td>'+
   '<td><input data-nk="'+esc(x.key)+'" value="'+esc(names[x.key]||'')+'" placeholder="'+esc(preview)+'" size="26"'+(inc?'':' disabled')+'></td></tr>'}).join(''):'<tr><td colspan="5" class="muted">请选择服务器或添加自定义节点（服务器显示「无缓存」时，先在订阅页点击「刷新全部节点缓存」）</td></tr>';
  document.querySelectorAll('[data-nx]').forEach(function(c){c.addEventListener('change',function(){collect();draw()})});
  document.querySelectorAll('[data-nk]').forEach(function(i){i.addEventListener('change',collect)});
  TSUB=rows;
 }
 var TSUB=[];
 function load(){var ids=selServers();collect();
  (ids.length?api('/api/subs/nodes?ids='+encodeURIComponent(ids.join(','))):Promise.resolve({data:[]})).then(function(j){nodes=j.data.map(function(x){return Object.assign(x,{host:(srvById(x.serverId)||{}).host||''})});draw()}).catch(function(e){$('e-err').textContent=e.message});
 }
 document.querySelectorAll('[data-es]').forEach(function(c){c.addEventListener('change',load)});
 document.querySelectorAll('[data-ep]').forEach(function(c){c.addEventListener('change',function(){collect();draw()})});
 bind(null,'[data-eg]',function(a){var g=groups[Number(a.getAttribute('data-eg'))][0];document.querySelectorAll('[data-es]').forEach(function(c){var x=srvById(c.getAttribute('data-es'));if(x&&(x.group||'')===g)c.checked=true});load()});
 $('e-custom').addEventListener('change',function(){collect();draw()});
 $('e-tpl').addEventListener('input',function(){collect();draw()});
 $('e-ren').addEventListener('change',function(){collect();draw()});
 $('e-all').addEventListener('change',function(){var on=checked('e-all');TSUB.forEach(function(x){if(on)delete exclude[x.key];else exclude[x.key]=1});draw()});
 function eachInput(fn){collect();document.querySelectorAll('[data-nk]:not([disabled])').forEach(function(inp){var v=fn(inp.value||inp.placeholder,inp);if(v!=null)inp.value=v});collect();draw()}
 $('e-fill').addEventListener('click',function(){eachInput(function(v,inp){return inp.placeholder})});
 $('e-pre').addEventListener('click',function(){var p=prompt('前缀（如 🇯🇵 或 [家庭] ）');if(p)eachInput(function(v){return p+v})});
 $('e-suf').addEventListener('click',function(){var p=prompt('后缀');if(p)eachInput(function(v){return v+p})});
 $('e-rep').addEventListener('click',function(){var a=prompt('查找内容');if(!a)return;var b=prompt('替换为','');if(b==null)return;eachInput(function(v){return v.split(a).join(b)})});
 $('e-clr').addEventListener('click',function(){if(confirm('清空全部单独命名？（将按模板或原名称显示）')){names={};draw()}});
 $('e-save').addEventListener('click',function(){
  collect();
  var body={id:s.id,name:val('e-name'),expires:val('e-exp')?new Date(val('e-exp')).getTime():0,rename:checked('e-ren'),tpl:val('e-tpl'),enabled:checked('e-en'),custom:$('e-custom').value,note:val('e-note'),
   servers:selServers(),protos:selProtos(),names:names,exclude:Object.keys(exclude)};
  api('/api/subs',{body:body}).then(function(j){closeModal();drawSubs(j.data);toast('已保存')}).catch(function(e){$('e-err').textContent=e.message});
 });
 load();
}

// ================= 审计日志
var KINDS={login:'登录',op:'服务器操作',panel:'面板变更'};
function viewAudit(){
 var now=Date.now();
 $('view').innerHTML='<div class="card" style="margin-bottom:10px"><div class="bar"><select id="a-kind"><option value="">全部类型</option><option value="login">登录</option><option value="op">服务器操作</option><option value="panel">面板变更</option></select>'+
 '<input id="a-ip" placeholder="IP" size="14"><input id="a-q" placeholder="关键字（操作/服务器/详情）" size="20"><input type="datetime-local" id="a-from"> 至 <input type="datetime-local" id="a-to">'+
 '<button class="primary" id="a-go">查询</button></div><div class="bar small" style="margin-top:8px">清理：删除 <input type="datetime-local" id="a-pf" value="'+localInput(now-365*86400000)+'"> 至 <input type="datetime-local" id="a-pt" value="'+localInput(now-7*86400000)+'"> 的记录<button id="a-purge" class="danger">删除</button>'+
 '<span class="muted">（删除需二次验证；审计日志按「设置」中的保留天数自动过期）</span></div></div><div class="tablewrap" id="a-out"></div><div style="margin-top:8px"><button id="a-more" hidden>加载更多</button></div>';
 var cursor=null,items=[];
 function q(more){
  if(!more){items=[];cursor=null;busy($('a-out'))}
  var qs='kind='+encodeURIComponent(val('a-kind'))+'&ip='+encodeURIComponent(val('a-ip'))+'&q='+encodeURIComponent(val('a-q'))+'&limit=200'+
   (val('a-from')?'&from='+new Date(val('a-from')).getTime():'')+(val('a-to')?'&to='+new Date(val('a-to')).getTime():'')+(more&&cursor?'&cursor='+encodeURIComponent(cursor):'');
  api('/api/audit?'+qs).then(function(j){items=items.concat(j.data.items);cursor=j.data.cursor;$('a-more').hidden=!cursor;
   $('a-out').innerHTML=items.length?'<table><thead><tr><th>时间</th><th>类型</th><th>操作</th><th>服务器</th><th>IP</th><th>结果</th><th>详情</th></tr></thead><tbody>'+items.map(function(e){
    return '<tr><td>'+fmtTime(e.t)+'</td><td>'+esc(KINDS[e.k]||e.k)+'</td><td>'+esc(e.a)+'</td><td>'+esc(e.s)+'</td><td>'+(e.ip&&e.ip!=='unknown'?esc(e.ip)+geoSpan(e.ip):'<span class="muted">未知</span>')+(e.cc?' <span class="chip">'+esc(e.cc)+'</span>':'')+'</td><td class="'+(e.ok?'okc':'err')+'">'+(e.ok?'成功':'失败')+'</td><td class="wrap">'+esc(e.m)+(e.u?' <span class="muted">'+esc(e.u)+'</span>':'')+'</td></tr>'}).join('')+'</tbody></table>':'<p class="muted" style="padding:8px">没有记录</p>';
  geoFill($('a-out'));
  }).catch(function(e){fail($('a-out'),e)});
 }
 $('a-go').addEventListener('click',function(){q(false)});
 $('a-more').addEventListener('click',function(){q(true)});
 $('a-purge').addEventListener('click',function(){
  if(!S.me.settings.totp)return toast('删除审计日志需要二次验证，请先在「设置 → 安全」中开启二次验证');
  var from=new Date(val('a-pf')).getTime(),to=new Date(val('a-pt')).getTime();
  modal('删除审计日志','<p class="small">将删除 '+fmtTime(from)+' 至 '+fmtTime(to)+' 的审计日志，此操作不可恢复，并会记入新的审计日志。</p><div class="bar"><input id="ap-code" inputmode="numeric" autocomplete="one-time-code" placeholder="6位二次验证码"><button class="danger" id="ap-go">验证并删除</button></div><p class="err small" id="ap-err"></p>',true);
  $('ap-go').addEventListener('click',function(){api('/api/audit/purge',{body:{from:from,to:to,code:val('ap-code')}}).then(function(j){closeModal();toast('已删除 '+j.data.deleted+' 条');q(false)}).catch(function(e){$('ap-err').textContent=e.message})});
 });
 q(false);
}

// ================= 设置
function viewSettings(){
 api('/api/me').then(function(j){S.me=j;var st=j.settings,ev=j.events;
  $('view').innerHTML=
  '<div class="card section"><h3>基本</h3><div class="row"><div class="field"><span class="small muted">面板标题</span><input id="c-title" value="'+esc(st.title)+'"></div>'+
  '<div class="field"><span class="small muted">时区（UTC偏移小时，用于报告）</span><input id="c-tz" type="number" value="'+esc(st.tz)+'"></div>'+
  '<div class="field"><span class="small muted">登录有效期（小时）</span><input id="c-sess" type="number" value="'+esc(st.sessionHours)+'"></div>'+
  '<div class="field"><span class="small muted">审计日志保留天数（缩短需二次验证码）</span><input id="c-ad" type="number" value="'+esc(st.auditDays)+'"></div>'+
  '<div class="field"><span class="small muted">二次验证码（缩短保留天数时填写）</span><input id="c-adcode" inputmode="numeric" placeholder="6位验证码"></div>'+
  '<div class="field"><span class="small muted">IP归属地数据源</span><select id="c-geo"><option value="ipwhois">ipwho.is（HTTPS 加密传输，推荐）</option><option value="ipapi">ip-api.com（可标记移动网络/机房/代理，但免费版为明文HTTP，IP会以明文发送）</option><option value="off">关闭</option></select></div>'+
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
  $('c-geo').value=st.geo||'ipwhois';
  api('/api/health').then(function(h){var ids=Object.keys(h.data);$('c-health').textContent=ids.length?'检测状态：'+ids.map(function(id){var x=h.data[id],s=srvById(id);return (s?s.name:id)+(x.down?' 离线':' 正常')+(x.fails?'(失败'+x.fails+'次)':'')}).join('；'):'尚未运行检测（部署后Cron每5分钟执行）'}).catch(function(){});
  $('c-save').addEventListener('click',function(){
   var events={};document.querySelectorAll('[data-ev]').forEach(function(c){events[c.getAttribute('data-ev')]=c.checked});
   var body={title:val('c-title'),tz:Number(val('c-tz')),sessionHours:Number(val('c-sess')),auditDays:Number(val('c-ad')),totpCode:val('c-adcode'),geo:val('c-geo'),linkCacheHours:Number(val('c-lc')),loginAllow:$('c-allow').value,
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
