// 测试/本地预览共用：在 Node 中加载 Worker（用 node:net 模拟 cloudflare:sockets）与内存版 KV
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { Duplex } from 'node:stream';
import { pathToFileURL, fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

// 测试中的 sbagent 运行在 127.0.0.1：允许内网地址（线上 Worker 会拒绝，见 validServer）
globalThis.__SBYG_ALLOW_PRIVATE = true;
globalThis.__connect = ({ hostname, port }) => {
  const s = net.connect({ host: hostname, port });
  s.on('error', () => {});
  const { readable, writable } = Duplex.toWeb(s);
  return { readable, writable, close: () => s.destroy() };
};

export async function loadWorker() {
  const src = fs.readFileSync(path.join(here, '..', 'src', 'worker.js'), 'utf8')
    .replace("import { connect } from 'cloudflare:sockets';", 'const connect = (...a) => globalThis.__connect(...a);');
  const tmp = path.join(os.tmpdir(), 'sbyg-worker-' + process.pid + '-' + Date.now() + '.mjs');
  fs.writeFileSync(tmp, src);
  const mod = await import(pathToFileURL(tmp).href);
  fs.unlinkSync(tmp);
  return mod;
}

// 与 Workers KV 行为一致的子集：get/put(metadata, expirationTtl)/delete/list(prefix, cursor, limit，按键名排序)
export function memoryKV() {
  const m = new Map();
  const alive = (k) => {
    const e = m.get(k);
    if (e && e.exp && e.exp < Date.now()) { m.delete(k); return null; }
    return e;
  };
  return {
    _map: m,
    async get(k) {
      const read = (key) => { const e = alive(key); return e ? e.value : null; };
      return Array.isArray(k) ? new Map(k.map((key) => [key, read(key)])) : read(k);
    },
    async put(k, v, opt = {}) { m.set(k, { value: String(v), metadata: opt.metadata, exp: opt.expirationTtl ? Date.now() + opt.expirationTtl * 1000 : 0 }); },
    async delete(k) { m.delete(k); },
    async list({ prefix = '', cursor, limit = 1000 } = {}) {
      const keys = [...m.keys()].filter((k) => k.startsWith(prefix) && alive(k)).sort();
      const start = cursor ? Number(cursor) : 0;
      const page = keys.slice(start, start + limit);
      const done = start + limit >= keys.length;
      return { keys: page.map((name) => ({ name, metadata: m.get(name).metadata })), list_complete: done, cursor: done ? undefined : String(start + limit) };
    },
  };
}

export function fakeCtx() {
  const pending = [];
  return { waitUntil: (p) => pending.push(p), flush: () => Promise.all(pending.splice(0)) };
}

// 本地使用真实 AuthState 类，模拟事务回滚和单对象请求串行化。
export function memoryAuthState(mod, env) {
  const values = new Map();
  let queue = Promise.resolve();
  const clone = (value) => value === undefined ? undefined : structuredClone(value);
  const storage = {
    async get(key) { return clone(values.get(key)); },
    async put(key, value) { values.set(key, clone(value)); },
    async delete(keys) { for (const key of Array.isArray(keys) ? keys : [keys]) values.delete(key); },
    async list({ prefix = '', limit = Infinity } = {}) {
      return new Map([...values].filter(([key]) => key.startsWith(prefix)).sort(([a], [b]) => a.localeCompare(b)).slice(0, limit).map(([key, value]) => [key, clone(value)]));
    },
    async setAlarm(time) { storage.alarm = time; },
    async getAlarm() { return storage.alarm || null; },
    async transaction(fn) {
      const before = structuredClone(values);
      try { return await fn(storage); }
      catch (e) { values.clear(); for (const [key, value] of before) values.set(key, value); throw e; }
    },
  };
  const state = { storage, blockConcurrencyWhile(fn) {
    const work = queue.then(fn);
    queue = work.catch(() => {});
    return work;
  } };
  const object = new mod.AuthState(state, env);
  return {
    _storage: storage,
    idFromName(name) { return name; },
    get() { return { fetch: (url, options) => object.fetch(new Request(url, options)) }; },
  };
}
