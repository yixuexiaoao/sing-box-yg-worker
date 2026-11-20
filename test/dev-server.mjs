// 本地预览需要通过环境变量 ADMIN_PASSWORD 设置登录密码。
import http from 'node:http';
import { Readable } from 'node:stream';
import { loadWorker, memoryKV, memoryAuthState, fakeCtx } from './harness.mjs';

if (!process.env.ADMIN_PASSWORD) {
  console.error('启动本地预览前请设置 ADMIN_PASSWORD。');
  process.exit(1);
}
const mod = await loadWorker();
const worker = mod.default;
const env = { ADMIN_PASSWORD: process.env.ADMIN_PASSWORD, SBYG_KV: memoryKV() };
env.AUTH_STATE = memoryAuthState(mod, env);
const port = Number(process.argv[2] || 8787);
http.createServer(async (req, res) => {
  if (![`127.0.0.1:${port}`, `localhost:${port}`].includes(req.headers.host)) {
    res.writeHead(400).end();
    return;
  }
  const body = ['GET', 'HEAD'].includes(req.method) ? undefined : Readable.toWeb(req);
  const r = await worker.fetch(new Request('http://' + req.headers.host + req.url, { method: req.method, headers: req.headers, body, duplex: 'half' }), env, fakeCtx());
  const headers = Object.fromEntries(r.headers);
  res.writeHead(r.status, headers);
  res.end(Buffer.from(await r.arrayBuffer()));
}).listen(port, '127.0.0.1', () => console.log('sing-box-yg-worker dev: http://127.0.0.1:' + port));
