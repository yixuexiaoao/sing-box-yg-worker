import assert from 'node:assert/strict';
import vm from 'node:vm';
import { fakeCtx, loadWorker, memoryKV, memoryAuthState } from './harness.mjs';

const mod = await loadWorker();
const env = { ADMIN_PASSWORD: 'search-test-password', SBYG_KV: memoryKV() };
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
  if (response.headers.has('set-cookie')) cookie = response.headers.get('set-cookie').split(';')[0];
  assert.equal(response.status, 200, path);
  return response.json();
}
await request('/api/login', { password: env.ADMIN_PASSWORD });
for (const key of env.SBYG_KV._map.keys()) if (key.startsWith('a:')) await env.SBYG_KV.delete(key);
for (let i = 0; i < 2500; i++) {
  await env.SBYG_KV.put('a:' + String(i).padStart(5, '0'), '', {
    metadata: { t: 100000 - i, k: i === 1250 || i === 2250 ? 'rare' : 'op', a: 'row-' + i, s: '', m: '', ip: '198.51.100.1' },
  });
}
const list = env.SBYG_KV.list.bind(env.SBYG_KV);
let listCalls = 0;
env.SBYG_KV.list = async (options) => { listCalls++; return list(options); };
let result = (await request('/api/audit?kind=rare&limit=1')).data;
assert.equal(result.items[0].a, 'row-1250');
assert.equal(listCalls, 2);
const cursor = result.cursor;
result = (await request('/api/audit?kind=rare&limit=1&cursor=' + encodeURIComponent(cursor))).data;
assert.equal(result.items[0].a, 'row-2250');
assert.equal(listCalls, 4);
result = (await request('/api/audit?kind=rare&limit=1&cursor=' + encodeURIComponent(result.cursor))).data;
assert.equal(result.items.length, 0);
assert.equal(result.cursor, null);
const legacyCursor = (await list({ prefix: 'a:', limit: 1000 })).cursor;
assert.equal((await request('/api/audit?kind=rare&limit=1&cursor=' + encodeURIComponent(legacyCursor))).data.items[0].a, 'row-1250');
assert.equal((await request('/api/audit?kind=rare&from=99000&limit=1')).data.cursor, null);
console.log('PASS sparse audit limit=1 finds row 1250 in 2 KV lists, exact resume and legacy cursors');

const realFetch = globalThis.fetch;
let providerCalls = 0;
let activeProviders = 0;
let peakProviders = 0;
const get = env.SBYG_KV.get.bind(env.SBYG_KV);
const kvBatches = [];
env.SBYG_KV.get = async (key) => {
  if (Array.isArray(key)) kvBatches.push(key.length);
  else assert.ok(!key.startsWith('geo:'), 'geo caches use bulk KV reads');
  return get(key);
};
globalThis.fetch = async (_url, options) => {
  providerCalls++;
  activeProviders++;
  peakProviders = Math.max(peakProviders, activeProviders);
  assert.ok(options.signal instanceof AbortSignal);
  await new Promise((resolve) => setTimeout(resolve, 2));
  activeProviders--;
  return Response.json({ success: true, country: 'fixture', country_code: 'US', connection: {} });
};
try {
  const ips = Array.from({ length: 40 }, (_, index) => '198.51.100.' + (index + 1));
  const reply = await request('/api/geo', { ips });
  assert.equal(providerCalls, 40);
  assert.equal(Object.keys(reply.data).length, 40);
  assert.equal(peakProviders, 6);
  await request('/api/geo', { ips });
  assert.equal(providerCalls, 40);
  assert.deepEqual(kvBatches, [40, 40]);
  kvBatches.length = 0;
  const cachedIps = Array.from({ length: 205 }, (_, index) => '198.51.100.' + (index + 1));
  for (const ip of cachedIps) await env.SBYG_KV.put('geo:' + ip, JSON.stringify({ country: 'cached' }));
  await request('/api/geo', { ips: [...cachedIps, ...cachedIps] });
  assert.deepEqual(kvBatches, [100, 100, 5]);
  assert.equal(providerCalls, 40);
} finally {
  globalThis.fetch = realFetch;
}
console.log('PASS geo reads 205 cached IPs in 3 KV calls, reuses cache and limits providers to 6 with timeout');

const html = await (await mod.default.fetch(new Request('https://panel.example/'), env, fakeCtx())).text();
const app = html.match(/src="(\/app\.[a-f0-9]+\.js)"/)[1];
const script = await (await mod.default.fetch(new Request('https://panel.example' + app), env, fakeCtx())).text();
const sandbox = { document: { getElementById() { return {}; }, addEventListener() {} } };
vm.runInNewContext(script.replace(/boot\(\);\s*\}\)\(\);\s*$/, 'globalThis.geoTest={loadGeo,GEO};})();'), sandbox);
const { loadGeo, GEO } = sandbox.geoTest;
let browserCalls = 0;
const batches = [];
const missing = '198.51.100.75';
sandbox.fetch = async (_path, options) => {
  browserCalls++;
  const ips = JSON.parse(options.body).ips;
  batches.push(ips);
  await new Promise((resolve) => setTimeout(resolve, 2));
  return Response.json({ ok: true, data: Object.fromEntries(ips.filter((ip) => ip !== missing || browserCalls > 3).map((ip) => [ip, { country: 'fixture' }])) });
};
const ips = Array.from({ length: 100 }, (_, index) => '198.51.100.' + (index + 1));
await Promise.all([loadGeo([...ips, ...ips]), loadGeo(ips.slice(20))]);
assert.equal(browserCalls, 3);
assert.deepEqual(batches.map((batch) => batch.length), [40, 40, 20]);
assert.equal(Object.keys(GEO).length, 99);
await loadGeo([missing]);
assert.equal(browserCalls, 4);
assert.ok(GEO[missing]);
await loadGeo(ips);
assert.equal(browserCalls, 4);
console.log('PASS browser 100-IP lookup uses 40/40/20 batches, shares overlapping work and retries omissions');
