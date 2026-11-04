// 端到端测试：在 Node 中运行 Worker（node:net 模拟 cloudflare:sockets），连接真实的 sbagent.py
// 用法：node test/e2e.mjs <sbagent.py 路径> <测试用 SB_DIR>
//   SB_DIR 需包含 sb.json 等配置与 sing-box.log；Windows 下用 sing-box.bat 作为假的 sing-box
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import http from 'node:http';
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
const fakeShare = path.join(sbDir, '..', 'fake_share.py');
fs.writeFileSync(fakeShare, [
  'import json, os, re',
  'd = os.environ["SB_DIR"]',
  'cfg = json.loads(re.sub(r"//.*", "", open(os.path.join(d, "sb.json"), encoding="utf-8").read()))',
  'u = cfg["inbounds"][0]["users"][0]["uuid"]',
  'open(os.path.join(d, "vl_reality.txt"), "w").write("vless://%s@1.2.3.4:20001?security=reality#vl-reality-h\\n" % u)',
].join('\n'));
const env0 = { ...process.env, SB_DIR: sbDir, SB_WEBDIR: path.join(sbDir, '..', 'web'), SB_CMD: path.join(sbDir, 'nope'),
  SB_BIN: path.join(sbDir, '..', 'sing-box.bat'), PYTHONIOENCODING: 'utf-8', SB_SHARE_CMD: 'python -X utf8 "' + fakeShare + '"' };
// 拦截公开IP库请求（不访问外网），记录调用次数以验证缓存
const realFetch = globalThis.fetch;
let geoCalls = 0, geoAsked = [];
globalThis.fetch = async (u, opt) => {
  if (String(u).startsWith('http://ip-api.com/batch')) {
    geoCalls++;
    const ips = JSON.parse(opt.body);
    geoAsked.push(...ips);
    return new Response(JSON.stringify(ips.map((ip) => ({ status: 'success', query: ip, country: '日本', countryCode: 'JP', regionName: '东京都', city: '东京', isp: 'NTT', org: 'NTT Docomo', as: 'AS4713 NTT', mobile: ip.endsWith('.5'), proxy: false, hosting: ip.endsWith('.9') }))));
  }
  if (String(u).startsWith('https://raw.githubusercontent.com/yixuexiaoao/sing-box-yg/main/')) {
    ghCalls++;
    const f = String(u).split('/').pop();
    return new Response(f === 'version' ? 'v99.1更新内容：\n1、新功能A\n2、修复B\n\nv26.1更新内容：\nold' : 'import os\nVERSION = "9.9.9"\n');
  }
  if (String(u).startsWith('https://data.jsdelivr.com/v1/package/gh/SagerNet/sing-box')) {
    return new Response(JSON.stringify({ versions: ['1.15.0-alpha.2', '1.14.4', '1.15.0-alpha.10', '1.14.3', 'bad;version', '1.13.0-rc.1'] }));
  }
  if (String(u).startsWith('https://ipwho.is/')) {
    whoisCalls++;
    const ip = decodeURIComponent(String(u).slice(17).split('?')[0]);
    return new Response(JSON.stringify({ success: true, country: '新加坡', country_code: 'SG', region: '新加坡', city: '新加坡', connection: { asn: 16509, org: 'Amazon', isp: 'Amazon.com' }, ip }));
  }
  return realFetch(u, opt);
};
let whoisCalls = 0, ghCalls = 0;
const agentCopy = path.join(sbDir, '..', 'sbagent_copy.py');
fs.copyFileSync(agentPy, agentCopy);
const upFiles = {};
const upSrv = http.createServer((q, res) => { const b = upFiles[q.url]; res.writeHead(b ? 200 : 404); res.end(b || ''); });
await new Promise((r) => upSrv.listen(0, '127.0.0.1', r));
env0.SB_UPDATE_BASE = 'http://127.0.0.1:' + upSrv.address().port;
env0.SB_SCRIPT = path.join(sbDir, '..', 'usr_bin_sb');
fs.writeFileSync(env0.SB_SCRIPT, '#!/bin/bash\n# old\n');
let agent = spawn('python', ['-X', 'utf8', agentCopy, 'serve'], { env: env0, stdio: ['ignore', 'inherit', 'inherit'] });
const restartAgent = async (perms) => {
  const conf = JSON.parse(fs.readFileSync(path.join(sbDir, 'sbapi.json'), 'utf8'));
  conf.perms = perms;
  fs.writeFileSync(path.join(sbDir, 'sbapi.json'), JSON.stringify(conf));
  agent.kill();
  await new Promise((r) => setTimeout(r, 800));
  agent = spawn('python', ['-X', 'utf8', agentCopy, 'serve'], { env: env0, stdio: ['ignore', 'inherit', 'inherit'] });
  await new Promise((r) => setTimeout(r, 1500));
};
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
  const flip = (c) => (c === 'A' ? 'B' : 'A');
  cookie = goodCookie.slice(0, -10) + flip(goodCookie.slice(-10, -9)) + goodCookie.slice(-9);
  check((await req('GET', '/api/me')).status === 401, 'tampered cookie rejected');
  // 末位字符只有4位有效，替换后可能解码为同一签名：必须因编码不规范被拒绝
  const last = goodCookie.slice(-1), alt = 'AEIMQUYcgkosw048'.includes(last) ? String.fromCharCode(last.charCodeAt(0) + 1) : last;
  if (alt !== last) {
    cookie = goodCookie.slice(0, -1) + alt;
    check((await req('GET', '/api/me')).status === 401, 'non-canonical signature encoding rejected');
  }
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
  check(r.status === 200 && lines.length === 3 && lines[0].endsWith('#' + encodeURIComponent('测试VPS-Vless')) && lines[2] === 'trojan://p@5.6.7.8:443#custom', 'subscription content: filtered protos, template names, custom keeps its name (no auth needed)');
  const vm = JSON.parse(Buffer.from(lines[1].slice(8), 'base64').toString());
  check(vm.ps === '测试VPS-Vmess', 'vmess link renamed inside base64 JSON');
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
  const newUuid = r.body.data.changed.uuid;
  const subTok = (await req('GET', '/api/subs')).body.data[0].url.split('/').pop();
  const subText = async () => { const c0 = cookie; cookie = ''; const x = await req('GET', '/sub/' + subTok + '?format=plain'); cookie = c0; return x.body; };
  check((await subText()).includes('vless://' + newUuid + '@'), 'reset from panel -> subscription immediately serves the new UUID');
  // 模拟在 VPS 上执行重置（菜单18/定时重置/泄露自动重置）：分享链接文件变化，面板事先并不知情
  fs.writeFileSync(path.join(sbDir, 'vl_reality.txt'), 'vless://vps-side-reset-uuid@1.2.3.4:20001?security=reality#vl-reality-h\n');
  check(!(await subText()).includes('vps-side-reset-uuid'), 'before cron: subscription still uses cached links');
  await mod.cronTick(env);
  check((await subText()).includes('vless://vps-side-reset-uuid@'), 'after cron tick: VPS-side reset synced into subscription');
  const cacheRev = JSON.parse(await env.SBYG_KV.get('links:' + id)).rev;
  await mod.cronTick(env);
  check(JSON.parse(await env.SBYG_KV.get('links:' + id)).rev === cacheRev, 'no refresh when params unchanged');

  // ---------- 订阅节点命名：单独命名、模板、排除、重名、自定义节点
  r = await req('GET', '/api/subs/nodes?ids=' + id);
  check(r.status === 200 && r.body.data.length === 3 && r.body.data.every((x) => x.key.startsWith(id + '|') && x.orig), 'subscription node list for editor');
  const subId = (await req('GET', '/api/subs')).body.data[0].id;
  r = await post('/api/subs', { id: subId, name: '我的订阅', servers: [id], protos: [], rename: true, tpl: '🇯🇵 {server} {proto} #{n}', custom: 'trojan://p@5.6.7.8:443#custom\ntrojan://q@5.6.7.9:443#second',
    names: { [id + '|hysteria2']: '东京-高速', 'c|1': '东京-高速' }, exclude: [id + '|vmess-ws'] });
  check(r.status === 200, 'subscription naming saved');
  const named = (await subText()).split('\n');
  const nm = named.map((l) => decodeURIComponent(l.split('#').pop()));
  check(named.length === 4 && nm[0] === '🇯🇵 测试VPS Vless #1' && nm[1] === '东京-高速' && nm[2] === 'custom' && nm[3] === '东京-高速-2',
    'per-node names override template, {n} numbering, excluded node removed, custom keeps name, duplicates de-duplicated: ' + JSON.stringify(nm));
  check(mod.applyTpl('{server}-{proto}-{missing}', { server: 'a', proto: 'b' }) === 'a-b-{missing}', 'template keeps unknown variables');

  // ---------- 服务器分组
  r = await post('/api/servers', { name: '第二台', host: '127.0.0.2', port: 1234, path: '/x', token: 'y'.repeat(20), group: '香港' });
  const id2 = r.body.data.find((x) => x.name === '第二台').id;
  check(r.body.data.find((x) => x.id === id2).group === '香港', 'server group saved');
  r = await post('/api/servers/group', { ids: [id, id2], group: '亚洲' });
  check(r.body.data.every((x) => x.group === '亚洲'), 'batch set group');
  r = await post('/api/groups/rename', { from: '亚洲', to: '亚太' });
  check(r.body.data.every((x) => x.group === '亚太'), 'rename group');
  await req('DELETE', '/api/servers/' + id2, undefined, X);

  // ---------- 流量周期
  const T = (s) => Date.parse(s + 'Z') - 8 * 3600000; // 面板时区 UTC+8 的本地时间
  let pr = mod.cyclePeriods({ mode: 'month', day: 31 }, T('2026-02-15T10:00:00'), 8);
  check(pr.cur[0] === T('2026-01-31T00:00:00') && pr.cur[1] === T('2026-02-28T00:00:00') && pr.prev[0] === T('2025-12-31T00:00:00'), 'monthly cycle on day 31 falls back to month end');
  pr = mod.cyclePeriods({ mode: 'month', day: 1 }, T('2026-11-04T00:00:00'), 8);
  check(pr.cur[0] === T('2026-11-01T00:00:00') && pr.cur[1] === T('2026-12-01T00:00:00') && pr.prev[0] === T('2026-10-01T00:00:00'), 'monthly cycle on day 1');
  pr = mod.cyclePeriods({ mode: 'days', len: 30, start: '2026-11-01' }, T('2026-12-01T00:00:01'), 8);
  check(pr.cur[0] === T('2026-12-01T00:00:00') && pr.prev[0] === T('2026-11-01T00:00:00') && pr.prev[1] === T('2026-12-01T00:00:00'), '30-day cycle: 11-01~11-30, then restarts 12-01');
  r = await post('/api/servers', { id, name: '测试VPS', host: '127.0.0.1', port, path: '/e2epath', cycle: { mode: 'days', len: 30, start: 'bad' } });
  check(r.status === 400, 'invalid cycle rejected');
  r = await post('/api/servers', { id, name: '测试VPS', host: '127.0.0.1', port, path: '/e2epath', cycle: { mode: 'month', day: 1, quotaGB: 1000, alertPct: 80, count: 'max', source: 'nic' } });
  check(r.status === 200 && r.body.data[0].cycle.count === 'max', 'cycle saved');
  r = await post('/api/servers/' + id + '/cycle', {});
  check(r.status === 200 && r.body.data.cur.quota === 1000 * 1073741824 && typeof r.body.data.prev.used === 'number' && r.body.data.cur.start < Date.now(), 'cycle usage computed via agent');

  // ---------- IP 归属地
  r = await post('/api/geo', { ips: ['192.0.2.77', 'not-an-ip', '<script>'] });
  check(r.status === 200 && whoisCalls === 1 && r.body.data['192.0.2.77'].as === 'AS16509' && !('not-an-ip' in r.body.data) && !('<script>' in r.body.data),
    'default provider ipwho.is over HTTPS; invalid inputs ignored');
  await post('/api/settings', { geo: 'ipapi' });
  r = await post('/api/geo', { ips: ['203.0.113.5', '203.0.113.9', '127.0.0.1', '10.1.2.3', '198.51.100.20'] });
  check(r.status === 200 && r.body.data['203.0.113.5'].country === '日本' && r.body.data['203.0.113.5'].mobile && r.body.data['203.0.113.9'].hosting, 'geo lookup with mobile/hosting flags');
  check(r.body.data['127.0.0.1'].local && r.body.data['10.1.2.3'].local && !geoAsked.includes('127.0.0.1') && !geoAsked.includes('10.1.2.3'), 'private IPs never sent to the public IP database');
  const calls = geoCalls;
  r = await post('/api/geo', { ips: ['203.0.113.5', '198.51.100.20'] });
  check(geoCalls === calls && r.body.data['198.51.100.20'].city === '东京', 'geo results cached in KV');
  await post('/api/settings', { geo: 'off' });
  r = await post('/api/geo', { ips: ['192.0.2.200'] });
  check(geoCalls === calls && !r.body.data['192.0.2.200'], 'geo lookup can be turned off');
  await post('/api/settings', { geo: 'ipapi' });

  // ---------- 审计日志
  r = await req('GET', '/api/audit?limit=100');
  const acts = r.body.data.items.map((e) => e.k + ':' + e.a);
  check(acts.includes('login:登录成功') && acts.includes('login:登录失败') && acts.includes('op:重置参数') && acts.includes('op:查看节点链接') && acts.includes('panel:新建订阅'),
    'audit records logins, ops, link views, panel changes');
  check(r.body.data.items[0].t >= r.body.data.items[r.body.data.items.length - 1].t, 'audit newest first');
  r = await req('GET', '/api/audit?kind=login&limit=100');
  check(r.body.data.items.every((e) => e.k === 'login'), 'audit filter by kind');
  r = await post('/api/audit/purge', { from: 0, to: Date.now() + 1000 });
  check(r.status === 403 && /开启二次验证/.test(r.body.error), 'audit purge refused while 2FA not enabled');
  r = await post('/api/settings', { auditDays: 7 });
  check(r.status === 403, 'shortening audit retention refused while 2FA not enabled');

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
  const freshCode = async () => { await env.SBYG_KV.delete('totp_used'); return mod.totpCode(secret, Math.floor(Date.now() / 30000)); };
  r = await post('/api/login', { password: 'pw-123456', code });
  check(r.status === 401 && /已使用/.test(r.body.error), 'TOTP code already used for enabling cannot be reused for login');
  const loginCode = await freshCode();
  r = await post('/api/login', { password: 'pw-123456', code: loginCode });
  check(r.status === 200 && cookie, 'login with TOTP');
  const totpCookie = cookie;
  cookie = '';
  r = await post('/api/login', { password: 'pw-123456', code: loginCode });
  check(r.status === 401, 'same TOTP code cannot log in twice (replay)');
  cookie = totpCookie;

  // ---------- 退出所有设备
  r = await post('/api/logout-all', {});
  cookie = totpCookie;
  check((await req('GET', '/api/me')).status === 401, 'logout-all invalidates existing sessions');
  r = await post('/api/login', { password: 'pw-123456', code: await freshCode() });
  check(r.status === 200, 'can log in again after logout-all');

  // ---------- 审计日志删除需二次验证
  const nowCode = freshCode;
  r = await post('/api/audit/purge', { from: 0, to: Date.now() + 1000, code: '000000' });
  check(r.status === 403 && /验证码错误/.test(r.body.error), 'audit purge with wrong 2FA code -> 403');
  r = await post('/api/audit/purge', { from: 0, to: Date.now() + 1000, code: await nowCode() });
  check(r.status === 200 && r.body.data.deleted > 5, 'audit purge with valid 2FA code (' + r.body.data.deleted + ')');
  r = await req('GET', '/api/audit?limit=10');
  check(r.body.data.items.some((e) => e.a === '清理审计日志'), 'the purge itself is recorded');
  r = await post('/api/settings', { auditDays: 7 });
  check(r.status === 403, 'shortening retention needs 2FA code');
  r = await post('/api/settings', { auditDays: 7, totpCode: await nowCode() });
  check(r.status === 200 && r.body.settings.auditDays === 7, 'shortening retention with 2FA code');
  r = await post('/api/settings', { auditDays: 60 });
  check(r.status === 200, 'extending retention needs no code');

  // ---------- 升级 sing-box-yg
  r = await req('GET', '/api/latest');
  check(r.status === 200 && r.body.data.script === 'v99.1' && r.body.data.agent === '9.9.9' && r.body.data.notes[0] === '1、新功能A' && r.body.data.notes.length === 2, 'latest versions parsed from GitHub');
  check(r.body.data.core === '1.14.4' && r.body.data.corePre === '1.15.0-alpha.10', 'latest sing-box core versions (semver sorted, invalid tags ignored)');
  const gh = ghCalls;
  await req('GET', '/api/latest');
  check(ghCalls === gh, 'latest versions cached');
  r = await call('status');
  check(r.status === 200 && 'script_version' in r.body.data, 'status reports script version');
  const agentSrc = fs.readFileSync(agentCopy, 'utf8');
  upFiles['/sb.sh'] = '#!/bin/bash\nexport sbrepo="x"\necho new\n';
  upFiles['/sbagent.py'] = agentSrc.replace(/^VERSION = "[^"]+"/m, 'VERSION = "9.9.9"');
  upFiles['/version'] = 'v99.1更新内容：\nx\n';
  r = await call('upgrade');
  check(r.status === 502 && /upgrade/.test(r.body.error) && fs.readFileSync(env0.SB_SCRIPT, 'utf8').includes('# old'),
    'remote upgrade refused by default even with manage permission (no code execution via a leaked token)');
  r = await call('coreupgrade', { version: '1.14.3' });
  check(r.status === 502 && /upgrade/.test(r.body.error), 'core upgrade refused by default (needs separate upgrade permission)');
  await restartAgent(['read', 'links', 'manage', 'upgrade']);
  r = await call('coreupgrade', { version: '1.2.3;id' });
  check(r.status === 502 && /版本格式错误/.test(r.body.error), 'core upgrade rejects malformed version even with permission');
  r = await call('upgrade');
  check(r.status === 200 && r.body.data.to.agent === '9.9.9' && r.body.data.to.script === 'v99.1' && fs.readFileSync(env0.SB_SCRIPT, 'utf8').includes('echo new'), 'upgrade via panel replaces files on the server');
  r = await req('GET', '/api/audit?kind=op&limit=50');
  check(r.body.data.items.some((e) => e.a === '升级 sing-box-yg' && e.ok), 'upgrade recorded in audit log');
  // 导入的订阅经过校验：非法令牌重新生成，无效链接整条丢弃
  r = await post('/api/import', { servers: [], subs: [{ id: 'imp1', name: '导入', token: 'not-hex', custom: ['trojan://a@1.1.1.1:443#x'], servers: [], evil: '<x>' }, { id: 'imp2', name: '坏', custom: ['javascript:alert(1)'] }] });
  check(r.status === 200 && r.body.data.subs === 1, 'import validates subscriptions');
  const imp = (await req('GET', '/api/subs')).body.data.find((x) => x.id === 'imp1');
  check(imp && /^https:\/\/panel\.example\/sub\/[a-f0-9]{32}$/.test(imp.url) && !('evil' in imp), 'imported subscription gets a valid token, unknown fields dropped');
  check((await req('GET', '/api/me')).body.weakPassword === true, 'weak panel password flagged (<12 chars)');

  // ---------- 导出需要密码
  r = await post('/api/export', { password: 'nope' });
  check(r.status === 403, 'export requires password');
  r = await post('/api/export', { password: 'pw-123456' });
  check(r.status === 200 && r.body.servers[0].token === token && Array.isArray(r.body.subs), 'export with password includes tokens + subs');

  // ---------- 敏感数据加密存储（DATA_KEY）
  const rawServers = () => JSON.parse(env.SBYG_KV._map.get('servers').value);
  check(rawServers()[0].token === token, 'without DATA_KEY tokens are stored as-is');
  await post('/api/settings', { tg: { token: '123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ', chat: '-100123456' } });
  env.DATA_KEY = 'test-data-key-' + crypto.randomUUID();
  await mod.cronTick(env);
  check(rawServers().every((x) => String(x.token).startsWith('enc:v1:')) && !JSON.stringify(rawServers()).includes(token), 'cron migrates server tokens to AES-GCM encrypted form');
  const rawSettings = JSON.parse(env.SBYG_KV._map.get('settings').value);
  check(rawSettings.tg.token.startsWith('enc:v1:') && !JSON.stringify(rawSettings).includes('ABCDEFGHIJ'), 'TG bot token encrypted at rest');
  check((await env.SBYG_KV.get('totp_secret')).startsWith('enc:v1:') && !(await env.SBYG_KV.get('totp_secret')).includes(secret), 'TOTP secret encrypted at rest');
  r = await call('ping');
  check(r.status === 200 && r.body.data.pong, 'servers still reachable with encrypted tokens');
  r = await post('/api/export', { password: 'pw-123456' });
  check(r.status === 200 && r.body.servers[0].token === token, 'export (password protected) still returns usable tokens');
  r = await post('/api/servers', { id, name: '测试VPS', host: '127.0.0.1', port, path: '/e2epath', token: 'new-token-' + 'x'.repeat(20) });
  check(rawServers()[0].token.startsWith('enc:v1:'), 'newly saved tokens are encrypted');
  await post('/api/servers', { id, name: '测试VPS', host: '127.0.0.1', port, path: '/e2epath', token });
  const goodKey = env.DATA_KEY;
  env.DATA_KEY = 'wrong-key';
  r = await call('ping');
  check(r.status === 500 && /DATA_KEY/.test(r.body.error), 'wrong DATA_KEY fails loudly instead of using garbage');
  env.DATA_KEY = goodKey;
  check((await req('GET', '/api/me')).body.dataEncrypted === true, 'panel reports data encryption on');
  r = await post('/api/login', { password: 'pw-123456', code: await freshCode() });
  check(r.status === 200, 'TOTP login works with encrypted secret');

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
  upSrv.close();
}
console.log('FAILS:', fails);
process.exit(fails ? 1 : 0);
