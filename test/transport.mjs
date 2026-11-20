import assert from 'node:assert/strict';
import { loadWorker } from './harness.mjs';

const { callAgent, deriveKeys, seal, unseal } = await loadWorker();
const server = { host: '127.0.0.1', port: 12345, token: 'test-transport-token' };
const encoder = new TextEncoder();

async function expectFailure(chunks, expected, options = {}) {
  let closes = 0;
  const readable = new ReadableStream({ start(controller) {
    for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
    if (!options.wait) controller.close();
  } });
  const writable = new WritableStream({ write() {
    if (options.rejectWrite) throw new Error('write rejected');
  } });
  const open = () => ({ readable, writable, close() { closes++; } });
  await assert.rejects(callAgent(server, 'ping', {}, options.wait ? 20 : 1000, open), expected);
  assert.equal(readable.locked, false);
  assert.equal(writable.locked, false);
  assert.equal(closes, 1);
}

await expectFailure(['HTTP/1.0 200 OK\r\nContent-Len', 'gth: 2\r\n\r\n{'], { message: /响应不完整/, status: 502 });
await expectFailure(['HTTP/1.0 200 OK\r\nContent-Length: 99999999\r\n\r\n'], { message: /响应过大/, status: 502 });
await expectFailure(['HTTP/1.0 200 OK\r\nX-Test: ' + 'a'.repeat(16384)], { message: /响应头过大/, status: 502 });
await expectFailure(['HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n'], { message: /服务器拒绝请求/, status: 502 });
await expectFailure([], { message: /连接服务器超时/, status: 504 }, { wait: true });
await expectFailure([], { message: /write rejected/, status: 502 }, { rejectWrite: true });

const keys = await deriveKeys(server.token);
const large = await seal({ message: 'a'.repeat(16 * 1024 * 1024) }, keys);
await assert.rejects(unseal(large, keys), { message: /响应过大/, status: 502 });
console.log('PASS 套接字解锁与关闭、超时、分段响应头、不完整正文、大小限制与解压上限');
