import assert from 'node:assert/strict';
import { loadWorker, memoryKV, memoryAuthState, fakeCtx } from './harness.mjs';

const mod = await loadWorker();
const password = 'auth-test-password';
const env = { ADMIN_PASSWORD: password, SBYG_KV: memoryKV(), DATA_KEY: 'auth-test-data-key' };
env.AUTH_STATE = memoryAuthState(mod, env);
const state = async (body) => {
  const response = await env.AUTH_STATE.get('admin').fetch('https://auth.internal/', { method: 'POST', body: JSON.stringify(body) });
  return response.json();
};
const key = 'fail:198.51.100.10';
assert.equal((await state({ op: 'login', key, password })).ok, true);
const countKey = 'fail:198.51.100.20';
await Promise.all(Array.from({ length: 10 }, () => state({ op: 'verify', key: countKey, passwordCheck: true, password: 'incorrect' })));
assert.equal((await env.AUTH_STATE._storage.get(countKey)).count, 10);
assert.equal((await state({ op: 'verify', key: countKey, passwordCheck: true, password })).status, 429);
await env.AUTH_STATE._storage.put(countKey, { count: 10, until: Date.now() - 1 });
assert.equal((await state({ op: 'verify', key: countKey, passwordCheck: true, password })).ok, true);
const setup = await state({ op: 'setup' });
const code = await mod.totpCode(setup.secret, Math.floor(Date.now() / 30000));
assert.equal((await state({ op: 'enable', key, password, code })).ok, true);
assert.equal((await state({ op: 'setup' })).status, 409);
assert.equal((await state({ op: 'enable', key, password, code })).status, 409);
await env.SBYG_KV.put('settings', JSON.stringify({ totp: false }));
assert.equal((await state({ op: 'status' })).totp, true);
assert.equal((await state({ op: 'login', key, password })).needTotp, true);
const auth = await env.AUTH_STATE._storage.get('auth');
auth.used = 0;
await env.AUTH_STATE._storage.put('auth', auth);
const verified = await Promise.all([state({ op: 'login', key, password, code }), state({ op: 'login', key, password, code })]);
assert.equal(verified.filter((result) => result.ok).length, 1);
const version = (await state({ op: 'status' })).version;
await Promise.all([state({ op: 'logout-all' }), state({ op: 'logout-all' })]);
assert.equal(BigInt((await state({ op: 'status' })).version), BigInt(version) + 2n);
assert.ok((await env.AUTH_STATE._storage.get('auth')).secret.startsWith('enc:v1:'));
const encrypted = (await env.AUTH_STATE._storage.get('auth')).secret;
env.DATA_KEY = 'incorrect';
assert.match((await state({ op: 'problem' })).error, /DATA_KEY/);
assert.equal((await env.AUTH_STATE._storage.get('auth')).secret, encrypted);
env.DATA_KEY = 'auth-test-data-key';
assert.equal((await state({ op: 'problem' })).error, '');

const legacyEnv = { ADMIN_PASSWORD: password, SBYG_KV: memoryKV() };
await legacyEnv.SBYG_KV.put('settings', JSON.stringify({ totp: true }));
await legacyEnv.SBYG_KV.put('totp_secret', setup.secret);
await legacyEnv.SBYG_KV.put('totp_used', String(Math.floor(Date.now() / 30000)));
await legacyEnv.SBYG_KV.put('sessver', '7');
await legacyEnv.SBYG_KV.put(key, '10');
legacyEnv.AUTH_STATE = memoryAuthState(mod, legacyEnv);
const legacy = (body) => legacyEnv.AUTH_STATE.get('admin').fetch('https://auth.internal/', { method: 'POST', body: JSON.stringify(body) }).then((r) => r.json());
assert.deepEqual(await legacy({ op: 'status' }), { totp: true, version: '7' });
assert.equal((await legacy({ op: 'login', key, password, code })).status, 429);
assert.equal((await legacy({ op: 'login', key: 'fail:198.51.100.11', password, code })).ok, false);
const migrated = await legacyEnv.AUTH_STATE._storage.get('auth');
migrated.legacyUntil = Date.now() - 1;
await legacyEnv.AUTH_STATE._storage.put('auth', migrated);
const getLegacy = legacyEnv.SBYG_KV.get.bind(legacyEnv.SBYG_KV);
legacyEnv.SBYG_KV.get = async (name) => {
  assert.ok(!name.startsWith('fail:'), 'legacy failure reads stop after the migration window');
  return getLegacy(name);
};
assert.equal((await legacy({ op: 'verify', key: 'fail:198.51.100.12', passwordCheck: true, password })).ok, true);
for (const [settings, secret, expected] of [
  ['{', setup.secret, 503],
  ['null', setup.secret, 503],
  [JSON.stringify({ totp: true }), '', 503],
  [JSON.stringify({ totp: false }), setup.secret, true],
]) {
  const initial = { ADMIN_PASSWORD: password, SBYG_KV: memoryKV() };
  await initial.SBYG_KV.put('settings', settings);
  if (secret) await initial.SBYG_KV.put('totp_secret', secret);
  initial.AUTH_STATE = memoryAuthState(mod, initial);
  const inspect = () => initial.AUTH_STATE.get('admin').fetch('https://auth.internal/', { method: 'POST', body: JSON.stringify({ op: 'status' }) }).then((r) => r.json());
  const result = await inspect();
  assert.equal(expected === true ? result.totp : result.status, expected);
  if (expected === 503) {
    assert.equal(await initial.AUTH_STATE._storage.get('auth'), undefined);
    await initial.SBYG_KV.put('settings', JSON.stringify({ totp: true }));
    await initial.SBYG_KV.put('totp_secret', setup.secret);
    assert.equal((await inspect()).totp, true);
  }
}
const missing = await mod.default.fetch(new Request('https://panel.example/api/pre'), { ADMIN_PASSWORD: password, SBYG_KV: memoryKV() }, fakeCtx());
assert.equal(missing.status, 503);
console.log('PASS AuthState migration, encrypted storage, authority, transactions and fail-closed binding');
