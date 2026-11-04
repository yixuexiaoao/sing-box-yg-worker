// 本地预览：node test/dev-server.mjs [端口]，KV 存于内存；环境变量 ADMIN_PASSWORD 设置登录密码（默认 admin123）
import http from 'node:http';
import { Readable } from 'node:stream';
import { loadWorker, memoryKV, fakeCtx } from './harness.mjs';

const worker = (await loadWorker()).default;
const env = { ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'admin123', SBYG_KV: memoryKV() };
const port = Number(process.argv[2] || 8787);
http.createServer(async (req, res) => {
  const body = ['GET', 'HEAD'].includes(req.method) ? undefined : Readable.toWeb(req);
  const r =await worker.fetch(new Request('http://localhost:' + port + req.url, { method: req.method, headers: req.headers, body, duplex: 'half' }), env, fakeCtx());
  const headers = Object.fromEntries(r.headers);
  res.writeHead(r.status, headers);
  res.end(Buffer.from(await r.arrayBuffer()));
}).listen(port, () => console.log('sing-box-yg-worker dev: http://localhost:' + port));
