import assert from 'node:assert/strict';
import { fakeCtx, loadWorker, memoryKV, memoryAuthState } from './harness.mjs';

const mod = await loadWorker();
async function panel() {
  const env = { ADMIN_PASSWORD: crypto.randomUUID(), SBYG_KV: memoryKV() };
  env.AUTH_STATE = memoryAuthState(mod, env);
  let cookie = '';
  async function request(path, body) {
    const ctx = fakeCtx();
    const response = await mod.default.fetch(new Request('https://panel.example' + path, {
      method: body ? 'POST' : 'GET',
      headers: { cookie, 'x-sbyg': '1', 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    }), env, ctx);
    await ctx.flush();
    assert.equal(response.status, 200, path);
    const next = response.headers.get('set-cookie');
    if (next) cookie = next.split(';')[0];
    return response.json();
  }
  await request('/api/login', { password: env.ADMIN_PASSWORD });
  return { env, request };
}

const source = await panel();
const server = { name: 'fixture', host: '192.0.2.101', port: 7134, path: '/test', token: crypto.randomUUID(),
  cycle: { mode: 'month', day: 7, quotaGB: 128 } };
const [original] = (await source.request('/api/servers', server)).data;
await source.request('/api/subs', {
  name: 'example', servers: [original.id], names: { [original.id + '|VLESS']: 'renamed', 'c|0': 'custom' },
  exclude: [original.id + '|VMess'], custom: ['trojan://test@fixture.example:443#node'],
});
const backup = await source.request('/api/export', { password: source.env.ADMIN_PASSWORD });
for (const existing of [false, true]) {
  const target = await panel();
  if (existing) await target.request('/api/servers', server);
  await target.request('/api/import', backup);
  const [restored] = (await target.request('/api/servers')).data;
  const [sub] = (await target.request('/api/subs')).data;
  assert.deepEqual(restored.cycle, original.cycle);
  assert.deepEqual(sub.servers, [restored.id]);
  assert.deepEqual(sub.names, { [restored.id + '|VLESS']: 'renamed', 'c|0': 'custom' });
  assert.deepEqual(sub.exclude, [restored.id + '|VMess']);
}
console.log('PASS restore subscriptions, node names, exclusions and billing cycle on new and existing servers');

const audit = await panel();
const expected = [];
for (let i = 0; i < 203; i++) {
  const name = 'page-test-' + String(i).padStart(3, '0');
  expected.push(name);
  await audit.env.SBYG_KV.put('a:' + name, '', { metadata: { t: Date.now(), k: 'op', a: name, s: '', m: '' } });
}
let cursor = '';
const seen = [];
do {
  const page = (await audit.request('/api/audit?q=page-test&cursor=' + encodeURIComponent(cursor))).data;
  seen.push(...page.items.map((item) => item.a));
  cursor = page.cursor;
} while (cursor);
assert.deepEqual(seen, expected);
console.log('PASS paginated audit returns all 203 matching rows once');
