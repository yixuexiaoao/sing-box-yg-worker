// 本地预览：node test/dev-server.mjs [端口]，用 node:net 模拟 cloudflare:sockets，KV 存于内存
// 环境变量 ADMIN_PASSWORD 设置登录密码（默认 admin123）
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { Duplex, Readable } from 'node:stream';
import { pathToFileURL, fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
globalThis.__connect = ({ hostname, port }) => {
  const s = net.connect({ host: hostname, port });
  s.on('error', () => {});
  const { readable, writable } = Duplex.toWeb(s);
  return { readable, writable, close: () => s.destroy() };
};
const src = fs.readFileSync(path.join(here, '..', 'src', 'worker.js'), 'utf8')
  .replace("import { connect } from 'cloudflare:sockets';", 'const connect = (...a) => globalThis.__connect(...a);');
const tmp = path.join(os.tmpdir(), 'sbyg-dev-' + process.pid + '.mjs');
fs.writeFileSync(tmp, src);
const worker = (await import(pathToFileURL(tmp).href)).default;
const store = new Map();
const env = {
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'admin123',
  SBYG_KV: { get: async (k) => store.get(k) ?? null, put: async (k, v) => { store.set(k, v); } },
};
const port = Number(process.argv[2] || 8787);
http.createServer(async (req, res) => {
  const body = ['GET', 'HEAD'].includes(req.method) ? undefined : Readable.toWeb(req);
  const r = await worker.fetch(new Request('http://localhost:' + port + req.url,
    { method: req.method, headers: req.headers, body, duplex: 'half' }), env);
  res.writeHead(r.status, Object.fromEntries(r.headers));
  res.end(Buffer.from(await r.arrayBuffer()));
}).listen(port, () => console.log('sing-box-yg-worker dev: http://localhost:' + port));
