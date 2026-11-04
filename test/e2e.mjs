// 端到端测试：在 Node 中运行 Worker（node:net 模拟 cloudflare:sockets），连接真实的 sbagent.py
// 用法：node test/e2e.mjs <sbagent.py 路径> <测试用 SB_DIR>
//   SB_DIR 需包含 sb.json 等配置与 sing-box.log；Windows 下用 sing-box.bat 作为假的 sing-box
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { loadWorker, memoryKV, fakeCtx } from './harness.mjs';

const [agentPy, sbDir] = process.argv.slice(2);
let fails = 0;
const check = (cond, msg) => { console.log((cond ? 'PASS ' : 'FAIL ') + msg); if (!cond) fails++; };

const mod = await loadWorker();
const worker = mod.default;

// 启动 sbagent API（完整权限）
const token = 'e2e-' + crypto.randomUUID();
const port = 20000 + Math.floor(Math.random() * 20000);
fs.writeFileSync(path.join(sbDir, 'sbapi.json'), JSON.stringify({ port, token, path: '/e2epath', listen: '127.0.0.1', perms: ['read', 'links', 'manage'], reset_interval: 0 }));
for (const [n, l] of [['vl_reality.txt', 'vless://u@1.2.3.4:20001?security=reality#vl-reality-h'], ['hy2.txt', 'hysteria2://u@1.2.3.4:20003#hy2-h'],
  ['vm_ws.txt', 'vmess://' + Buffer.from(JSON.stringify({ add: '1.2.3.4', ps: 'vm-ws-h', id: 'u' })).toString('base64')]]) {
  fs.writeFileSync(path.join(sbDir, n), l + '\n');
}
const env0 = { ...process.env, SB_DIR: sbDir, SB_WEBDIR: path.join(sbDir, '..', 'web'), SB_CMD: path.join(sbDir, 'nope'),
  SB_BIN: path.join(sbDir, '..', 'sing-box.bat'), PYTHONIOENCODING: 'utf-8' };
const agent = spawn('python', ['-X', 'utf8', agentPy, 'serve'], { env: env0, stdio: ['ignore', 'inherit', 'inherit'] });
await new Promise((r) => setTimeout(r, 1500));

const env = { ADMIN_PASSWORD: 'pw-123456', SBYG_KV: memoryKV() };
const ctx = fakeCtx();
let cookie = '';
let fromIp = '198.51.100.1';
async function req(method, p, body, headers = {}) {
  const h = { 'cf-connecting-ip': fromIp, ...headers };
  if (cookie) h.cookie = cookie;
  if (body !== undefined) h['content-type'] = 'application/json';
  const r = await worker.fetch(new Request('https://panel.example' + p, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }), env, ctx);
  await ctx.flush();
  const sc = r.headers.get('set-cookie');
  if (sc) cookie = sc.split(';')[0].endsWith('=') ? '' : sc.split(';')[0];
  const ct = r.headers.get('content-type') || '';
  return { status: r.status, headers: r.headers, body: ct.includes('json') ? await r.json() : await r.text() };
}
const X = { 'x-sbyg': '1' };
const post = (p, body) => req('POST', p, body, X);

try {
  // ---------- 页面与安全头
  let r = await req('GET', '/');
  const csp = r.headers.get('content-security-policy');
  const nonce = (csp.match(/'nonce-([^']+)'/) || [])[1];
  check(r.status === 200 && nonce && r.body.includes('<script nonce="' + nonce + '">'), 'page served with per-response CSP nonce');
  check(!/script-src[^;]*unsafe-inline/.test(csp) && !/\son[a-z]+="/i.test(r.body), 'no unsafe-inline scripts, no inline event handlers');
  const script = r.body.match(/<script[^>]*>([\s\S]*)<\/script>/)[1];
  try { new Function(script); check(true, 'page script parses'); } catch (e) { check(false, 'page script parses: ' + e.message); }
  const r2 = await req('GET', '/');
  check(r2.headers.get('content-security-policy') !== csp, 'nonce differs per response');

  // ---------- 登录与会话
  check((await req('GET', '/api/servers')).status === 401, 'unauthenticated -> 401');
  check((await req('GET', '/api/pre')).body.title === 'Sing-box-yg 管理面板', 'pre-login info');
  check((await req('POST', '/api/login', { password: 'x' })).status === 403, 'POST without x-sbyg header -> 403');
  check((await req('POST', '/api/login', { password: 'x' }, { ...X, origin: 'https://evil.example' })).status === 403, 'cross-origin POST -> 403');
  r = await post('/api/login', { password: 'wrong' });
  check(r.status === 401 && !cookie, 'wrong password -> 401');
  r = await post('/api/login', { password: 'pw-123456' });
  check(r.status === 200 && cookie.startsWith('__Host-sbyg_s='), 'login sets __Host- session cookie');
  const goodCookie = cookie;
  cookie = goodCookie.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A'));
  check((await req('GET', '/api/me')).status === 401, 'tampered cookie rejected');
  cookie = '__Host-sbyg_s=9999999999.0.abcde';
  check((await req('GET', '/api/me')).status === 401, 'malformed cookie -> 401');
  cookie = goodCookie;
  r = await worker.fetch(new Request('https://panel.example/api/settings', { method: 'POST', headers: { ...X, cookie }, body: '{bad' }), env, ctx);
  check(r.status === 400, 'invalid JSON body -> 400');

  // ---------- 服务器与 agent 调用
  r = await post('/api/servers', { name: 'bad', host: 'a b', port: 1, token: 'x'.repeat(20) });
  check(r.status === 400, 'invalid host rejected');
  r = await post('/api/servers', { name: '测试VPS', host: '127.0.0.1', port, path: '/e2epath', token });
  check(r.status === 200 && r.body.data.length === 1 && !('token' in r.body.data[0]), 'server added, token not exposed');
  const id = r.body.data[0].id;
  const call = (action, params) => post(`/api/servers/${id}/call`, { action, params });
  r = await call('status');
  check(r.status === 200 && r.body.data.installed && r.body.data.api.perms.length === 3 && 'traffic' in r.body.data, 'status incl. api perms + traffic info');
  r = await call('logs', { limit: 100 });
  check(r.status === 200 && r.body.data.total > 0, 'logs via worker');
  r = await call('traffic', { hours: 24, group: 'ip' });
  check(r.status === 200 && Array.isArray(r.body.data.rows), 'traffic query via worker');
  r = await call('logpolicy', { max_mb: 5, keep: 3, compress: true, retain_days: 7 });
  check(r.status === 200 && r.body.data.keep === 3, 'log policy via worker');
  r = await call('logprune', { start: 0, end: 1 });
  check(r.status === 200 && r.body.data.removed_lines === 0, 'log prune via worker');
  r = await call('apilog', { lines: 50 });
  check(r.status === 200 && r.body.data.entries.some((e) => e.action === 'logpolicy'), 'server-side API audit log');
  check((await call('shell', {})).status === 400, 'unknown action blocked by worker');
  r = await call('links');
  check(r.status === 200 && r.body.data.links.length === 3, 'links via worker');
  check(JSON.parse(await env.SBYG_KV.get('links:' + id)).links.length === 3, 'links cached in KV');

  // ---------- 订阅
  r = await post('/api/subs', { name: '我的订阅', servers: [id], protos: ['vless', 'vmess'], rename: true, custom: 'trojan://p@5.6.7.8:443#custom' });
  check(r.status === 200 && r.body.data.length === 1, 'subscription created');
  let sub = r.body.data[0];
  check(/^https:\/\/panel\.example\/sub\/[a-f0-9]{32}$/.test(sub.url), 'subscription url');
  r = await post('/api/subs', { name: 'x', custom: 'not-a-link' });
  check(r.status === 400, 'invalid custom link rejected');
  cookie = '';
  r = await req('GET', '/sub/' + sub.url.split('/').pop() + '?format=plain');
  const lines = r.body.split('\n');
  check(r.status === 200 && lines.length === 3 && lines[0].endsWith('#' + encodeURIComponent('测试VPS-vless')) && lines[2] === 'trojan://p@5.6.7.8:443#custom', 'subscription content: filtered protos, renamed, custom (no auth needed)');
  const vm = JSON.parse(Buffer.from(lines[1].slice(8), 'base64').toString());
  check(vm.ps === '测试VPS-vmess', 'vmess link renamed inside base64 JSON');
  r = await req('GET', '/sub/' + sub.url.split('/').pop());
  check(Buffer.from(r.body, 'base64').toString().split('\n').length === 3, 'default format is base64');
  fromIp = '203.0.113.77';
  await req('GET', '/sub/' + sub.url.split('/').pop());
  fromIp = '198.51.100.1';
  cookie = goodCookie;
  r = await req('GET', '/api/subs');
  sub = r.body.data[0];
  check(sub.stat.hits === 3 && sub.stat.ips.length === 2, 'subscription access stats (hits + distinct IPs)');
  const oldTok = sub.url.split('/').pop();
  r = await post('/api/subs/' + sub.id + '/rotate', {});
  check(r.body.data[0].url.split('/').pop() !== oldTok, 'rotate subscription token');
  cookie = '';
  check((await req('GET', '/sub/' + oldTok)).status === 404, 'old subscription url -> 404');
  cookie = goodCookie;
  r = await post('/api/subs/rotate-all', {});
  check(r.status === 200, 'rotate all subscriptions');

  // ---------- 重置后订阅自动使用新参数
  const before = fs.readFileSync(path.join(sbDir, 'sb.json'), 'utf8');
  r = await call('reset', { items: 'uuid,path,reality' });
  check(r.status === 200 && r.body.data.changed.uuid && fs.readFileSync(path.join(sbDir, 'sb.json'), 'utf8') !== before, 'reset via worker');
  check(JSON.parse(await env.SBYG_KV.get('links:' + id)).t > 0, 'link cache refreshed by reset');

  // ---------- 审计日志
  r = await req('GET', '/api/audit?limit=100');
  const acts = r.body.data.items.map((e) => e.k + ':' + e.a);
  check(acts.includes('login:登录成功') && acts.includes('login:登录失败') && acts.includes('op:重置参数') && acts.includes('op:查看节点链接') && acts.includes('panel:新建订阅'),
    'audit records logins, ops, link views, panel changes');
  check(r.body.data.items[0].t >= r.body.data.items[r.body.data.items.length - 1].t, 'audit newest first');
  r = await req('GET', '/api/audit?kind=login&limit=100');
  check(r.body.data.items.every((e) => e.k === 'login'), 'audit filter by kind');
  r = await post('/api/audit/purge', { from: 0, to: Date.now() + 1000 });
  check(r.status === 200 && r.body.data.deleted > 5, 'audit purge by time range (' + r.body.data.deleted + ')');

  // ---------- 设置：校验、TG、登录白名单防自锁
  r = await post('/api/settings', { loginAllow: '10.0.0.0/8' });
  check(r.status === 400 && /不在白名单/.test(r.body.error), 'login allowlist refuses to lock out current IP');
  r = await post('/api/settings', { loginAllow: '198.51.100.0/24, 2001:db8::/32', title: '我的面板', tg: { token: 'bad' } });
  check(r.status === 400, 'invalid TG token rejected');
  r = await post('/api/settings', { loginAllow: '198.51.100.0/24, 2001:db8::/32', title: '我的面板', tg: { token: '123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ', chat: '-100123456', events: { daily: true } } });
  check(r.status === 200 && r.body.settings.title === '我的面板' && r.body.settings.tg.tokenSet && !('token' in r.body.settings.tg), 'settings saved, TG token never returned');
  r = await req('GET', '/api/me');
  check(JSON.stringify(r.body).indexOf('ABCDEFGHIJKLMNOP') < 0, 'TG token not exposed in /api/me');
  check(mod.ipInCidr('2001:db8::1', '2001:db8::/32') && !mod.ipInCidr('2001:db9::1', '2001:db8::/32') && mod.ipInCidr('::ffff:10.1.2.3', '10.0.0.0/8'), 'CIDR matching v4/v6/mapped');
  fromIp = '203.0.113.9';
  r = await post('/api/login', { password: 'pw-123456' });
  check(r.status === 403, 'login from IP outside allowlist -> 403');
  fromIp = '198.51.100.1';
  cookie = goodCookie;
  await post('/api/settings', { loginAllow: '' });

  // ---------- 二次验证
  r = await post('/api/totp/setup', {});
  const secret = r.body.secret;
  check(/^[A-Z2-7]{32}$/.test(secret) && r.body.uri.startsWith('otpauth://totp/'), 'TOTP secret generated');
  check((await post('/api/totp/enable', { code: '000000' })).status === 400, 'TOTP enable rejects wrong code');
  const code = await mod.totpCode(secret, Math.floor(Date.now() / 30000));
  r = await post('/api/totp/enable', { code });
  check(r.status === 200, 'TOTP enabled with valid code');
  check(await mod.totpCode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1) === '287082', 'TOTP matches RFC 6238 test vector');
  cookie = '';
  r = await post('/api/login', { password: 'pw-123456' });
  check(r.status === 401 && r.body.needTotp, 'login asks for TOTP code');
  r = await post('/api/login', { password: 'pw-123456', code: await mod.totpCode(secret, Math.floor(Date.now() / 30000)) });
  check(r.status === 200 && cookie, 'login with TOTP');
  const totpCookie = cookie;

  // ---------- 退出所有设备
  r = await post('/api/logout-all', {});
  cookie = totpCookie;
  check((await req('GET', '/api/me')).status === 401, 'logout-all invalidates existing sessions');
  r = await post('/api/login', { password: 'pw-123456', code: await mod.totpCode(secret, Math.floor(Date.now() / 30000)) });
  check(r.status === 200, 'can log in again after logout-all');

  // ---------- 导出需要密码
  r = await post('/api/export', { password: 'nope' });
  check(r.status === 403, 'export requires password');
  r = await post('/api/export', { password: 'pw-123456' });
  check(r.status === 200 && r.body.servers[0].token === token && Array.isArray(r.body.subs), 'export with password includes tokens + subs');

  // ---------- 定时任务：离线检测与恢复
  await post('/api/settings', { monitor: { enabled: true, failCount: 2 }, tg: { events: { offline: false, recover: false } } });
  await mod.cronTick(env);
  let h = JSON.parse(await env.SBYG_KV.get('health'));
  check(h[id] && h[id].fails === 0 && !h[id].down, 'cron health check: online');
  const servers = JSON.parse(await env.SBYG_KV.get('servers'));
  servers[0].port = port + 1;
  await env.SBYG_KV.put('servers', JSON.stringify(servers));
  await mod.cronTick(env);
  await mod.cronTick(env);
  h = JSON.parse(await env.SBYG_KV.get('health'));
  check(h[id].down && h[id].fails === 2, 'cron marks server offline after N failures');
  servers[0].port = port;
  await env.SBYG_KV.put('servers', JSON.stringify(servers));
  await mod.cronTick(env);
  h = JSON.parse(await env.SBYG_KV.get('health'));
  check(!h[id].down, 'cron marks server recovered');

  // ---------- 登录爆破限制
  cookie = '';
  for (let i = 0; i < 10; i++) await post('/api/login', { password: 'bad' + i });
  r = await post('/api/login', { password: 'pw-123456' });
  check(r.status === 429, 'login rate limited after 10 failures');
} finally {
  agent.kill();
}
console.log('FAILS:', fails);
process.exit(fails ? 1 : 0);
