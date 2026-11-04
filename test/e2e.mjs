// 端到端测试：在 Node 中运行 Worker（用 node:net 模拟 cloudflare:sockets），连接真实的 sbagent.py
// 用法：node test/e2e.mjs <sbagent.py 路径> <测试用 SB_DIR>
//   SB_DIR 需包含 sb.json 等配置与 sing-box.log；Windows 下可用 sing-box.bat 作为假的 sing-box
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { Duplex } from 'node:stream';
import { pathToFileURL, fileURLToPath } from 'node:url';

const [agentPy, sbDir] = process.argv.slice(2);
const here = path.dirname(fileURLToPath(import.meta.url));
let fails = 0;
const check = (cond, msg) => { console.log((cond ? 'PASS ' : 'FAIL ') + msg); if (!cond) fails++; };

// 1. 载入 Worker，替换 cloudflare:sockets
globalThis.__connect = ({ hostname, port }) => {
  const s = net.connect({ host: hostname, port });
  s.on('error', () => {});
  const { readable, writable } = Duplex.toWeb(s);
  return { readable, writable, close: () => s.destroy() };
};
const src = fs.readFileSync(path.join(here, '..', 'src', 'worker.js'), 'utf8')
  .replace("import { connect } from 'cloudflare:sockets';", 'const connect = (...a) => globalThis.__connect(...a);');
const tmp = path.join(os.tmpdir(), 'sbyg-worker-' + process.pid + '.mjs');
fs.writeFileSync(tmp, src);
const worker = (await import(pathToFileURL(tmp).href)).default;

// 2. 启动 sbagent API
const token = 'e2e-' + crypto.randomUUID();
const port = 20000 + Math.floor(Math.random() * 20000);
fs.writeFileSync(path.join(sbDir, 'sbapi.json'), JSON.stringify({ port, token, path: '/e2epath', listen: '127.0.0.1' }));
const env0 = { ...process.env, SB_DIR: sbDir, SB_WEBDIR: path.join(sbDir, '..', 'web'), SB_CMD: path.join(sbDir, 'nope'),
  SB_BIN: path.join(sbDir, '..', 'sing-box.bat'), PYTHONIOENCODING: 'utf-8' };
const agent = spawn('python', ['-X', 'utf8', agentPy, 'serve'], { env: env0, stdio: ['ignore', 'inherit', 'inherit'] });
await new Promise((r) => setTimeout(r, 1500));

// 3. 模拟 Worker 环境
const store = new Map();
const env = {
  ADMIN_PASSWORD: 'pw-123456',
  SBYG_KV: { get: async (k) => store.get(k) ?? null, put: async (k, v) => { store.set(k, v); } },
};
let cookie = '';
async function req(method, p, body, headers = {}) {
  const h = { 'cf-connecting-ip': '198.51.100.1', ...headers };
  if (cookie) h.cookie = cookie;
  if (body !== undefined) { h['content-type'] = 'application/json'; }
  const r = await worker.fetch(new Request('https://panel.example' + p, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }), env);
  const sc = r.headers.get('set-cookie');
  if (sc && sc.startsWith('sbyg_s=') && !sc.startsWith('sbyg_s=;')) cookie = sc.split(';')[0];
  const ct = r.headers.get('content-type') || '';
  return { status: r.status, body: ct.includes('json') ? await r.json() : await r.text() };
}
const X = { 'x-sbyg': '1' };

try {
  let r = await req('GET', '/');
  check(r.status === 200 && r.body.includes('Sing-box-yg 管理面板'), 'page served');
  const script = r.body.match(/<script>([\s\S]*)<\/script>/)[1];
  try { new Function(script); check(true, 'page script parses'); } catch (e) { check(false, 'page script parses: ' + e.message); }
  check(!/\$\{|`/.test(script), 'page script has no template-literal leftovers');

  const pageRes = await worker.fetch(new Request('https://panel.example/'), env);
  const etag = pageRes.headers.get('etag');
  const notMod = await worker.fetch(new Request('https://panel.example/', { headers: { 'if-none-match': etag } }), env);
  check(etag && notMod.status === 304, 'page ETag -> 304 on revalidation');

  r = await req('GET', '/api/servers');
  check(r.status === 401, 'unauthenticated -> 401');
  cookie = 'sbyg_s=9999999999.abcde';
  check((await req('GET', '/api/me')).status === 401, 'malformed session cookie -> 401 (not 500)');
  cookie = '';
  r = await worker.fetch(new Request('https://panel.example/api/login', { method: 'POST', headers: X, body: '{bad' }), env);
  check(r.status === 400, 'invalid JSON body -> 400');
  r = await req('POST', '/api/login', { password: 'x' });
  check(r.status === 403, 'POST without x-sbyg header -> 403 (CSRF guard)');
  r = await req('POST', '/api/login', { password: 'wrong' }, X);
  check(r.status === 401 && !cookie, 'wrong password -> 401');
  r = await req('POST', '/api/login', { password: 'pw-123456' }, X);
  check(r.status === 200 && cookie.startsWith('sbyg_s='), 'login sets session cookie');
  const goodCookie = cookie;
  cookie = goodCookie.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A'));
  check((await req('GET', '/api/me')).status === 401, 'tampered cookie rejected');
  cookie = goodCookie;

  r = await req('POST', '/api/servers', { name: 'bad', host: 'a b', port: 1, token: 'x'.repeat(20) }, X);
  check(r.status === 400, 'invalid host rejected');
  r = await req('POST', '/api/servers', { name: '测试VPS', host: '127.0.0.1', port, path: '/e2epath', token }, X);
  check(r.status === 200 && r.body.data.length === 1 && !('token' in r.body.data[0]), 'server added, token not exposed');
  const id = r.body.data[0].id;

  const call = (action, params) => req('POST', `/api/servers/${id}/call`, { action, params }, X);
  r = await call('status');
  check(r.status === 200 && r.body.data.installed && r.body.data.inbounds.length === 5, 'status via worker -> agent');
  r = await call('logs', { limit: 100 });
  check(r.status === 200 && r.body.data.total > 0 && r.body.data.records[0].time, 'logs via worker (records=' + (r.body.data && r.body.data.total) + ')');
  r = await call('logs', { ip: '203.0.113.5' });
  check(r.status === 200 && r.body.data.records.every((x) => x.src === '203.0.113.5'), 'logs ip filter');
  r = await call('stats', { hours: 24 });
  check(r.status === 200 && r.body.data.ips.length > 0, 'stats via worker');
  r = await call('peers');
  check(r.status === 200 && Array.isArray(r.body.data.peers), 'peers via worker');
  r = await call('rawlog', { lines: 5 });
  check(r.status === 200 && r.body.data.lines.length > 0, 'rawlog via worker');
  r = await call('leakcheck');
  check(r.status === 200 && typeof r.body.data.unique_ips === 'number', 'leakcheck via worker');
  r = await call('shell', {});
  check(r.status === 400, 'unknown action blocked by worker');

  const before = fs.readFileSync(path.join(sbDir, 'sb.json'), 'utf8');
  r = await call('reset', { items: 'uuid,path,reality' });
  const after = fs.readFileSync(path.join(sbDir, 'sb.json'), 'utf8');
  check(r.status === 200 && r.body.data.changed.uuid && after.includes(r.body.data.changed.uuid) && before !== after,
    'reset via worker changes uuid on server');
  check(r.body.data.changed.reality && after.includes(r.body.data.changed.reality.short_id), 'reset via worker changes reality');

  // 错误路径
  r = await req('POST', '/api/servers', { id, name: '测试VPS', host: '127.0.0.1', port, path: '/e2epath', token: 'wrong-token-xxxxxxxxxxxx' }, X);
  r = await call('ping');
  check(r.status === 502 && /404/.test(r.body.error), 'wrong token -> clear error: ' + r.body.error);
  r = await req('POST', '/api/servers', { id, name: '测试VPS', host: '127.0.0.1', port: port + 1, path: '/e2epath', token }, X);
  r = await call('ping');
  check(r.status === 502, 'closed port -> error: ' + r.body.error);

  r = await req('GET', '/api/export');
  const exported = r.body;
  check(exported[0].token === token, 'export includes token');
  r = await req('POST', '/api/import', [{ name: 'x2', host: '127.0.0.1', port: port + 1, path: '/e2epath', token }], X);
  check(r.status === 200 && r.body.data.updated === 1 && r.body.data.added === 0, 'import merges by host+port');
  r = await req('DELETE', `/api/servers/${id}`, undefined, X);
  check((await req('GET', '/api/servers')).body.data.length === 0, 'delete server');

  // 登录爆破限制
  cookie = '';
  for (let i = 0; i < 10; i++) await req('POST', '/api/login', { password: 'bad' + i }, X);
  r = await req('POST', '/api/login', { password: 'pw-123456' }, X);
  check(r.status === 429, 'login rate limited after 10 failures');
} finally {
  agent.kill();
  fs.unlinkSync(tmp);
}
console.log('FAILS:', fails);
process.exit(fails ? 1 : 0);
