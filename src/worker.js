// sing-box-yg-worker：Cloudflare Worker 多服务器管理面板
// 配合 sing-box-yg 脚本的 sbagent API（主菜单19）使用：查看连接日志/源IP/访问目标、一键重置参数、节点链接、重启等
// 绑定：KV 命名空间 SBYG_KV；机密变量 ADMIN_PASSWORD（面板登录密码）
// 与服务器通信：cloudflare:sockets 直连 IP:端口，报文 AES-256-CBC + HMAC-SHA256 加密签名，带时间戳与 nonce 防重放
import { connect } from 'cloudflare:sockets';

const VERSION = '1.0.0';
const SESSION_TTL = 12 * 3600;
const LOGIN_MAX_FAIL = 10;
const enc = new TextEncoder();
const dec = new TextDecoder();
const ACTIONS = new Set(['ping', 'status', 'logs', 'stats', 'peers', 'rawlog', 'links', 'reset', 'restart',
  'logon', 'logoff', 'clearlog', 'schedule', 'leakconf', 'leakcheck']);

export default {
  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (e) {
      return json({ ok: false, error: (e && e.message) || String(e) }, e && e.status ? e.status : 500);
    }
  },
};

// ------------------------------------------------------------------ 路由
async function route(request, env) {
  const url = new URL(request.url);
  const p = url.pathname;
  if (request.method === 'GET' && (p === '/' || p === '/index.html')) {
    return new Response(PAGE, { headers: { 'content-type': 'text/html; charset=utf-8', ...SEC_HEADERS } });
  }
  if (!p.startsWith('/api/')) return new Response('Not Found', { status: 404 });
  if (!env.ADMIN_PASSWORD) throw httpError(500, '未设置 ADMIN_PASSWORD 机密变量，请在 Worker 设置中添加');
  if (!env.SBYG_KV) throw httpError(500, '未绑定 KV 命名空间 SBYG_KV，请在 Worker 设置中绑定');
  if (request.method !== 'GET' && request.headers.get('x-sbyg') !== '1') throw httpError(403, 'forbidden');

  if (p === '/api/login' && request.method === 'POST') return login(request, env);
  if (p === '/api/logout' && request.method === 'POST') {
    return json({ ok: true }, 200, { 'set-cookie': 'sbyg_s=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' });
  }
  if (!(await checkSession(request, env))) throw httpError(401, '未登录或登录已过期');

  if (p === '/api/me') return json({ ok: true, version: VERSION });
  if (p === '/api/servers' && request.method === 'GET') {
    return json({ ok: true, data: (await getServers(env)).map(publicServer) });
  }
  if (p === '/api/servers' && request.method === 'POST') return json({ ok: true, data: await saveServer(env, await request.json()) });
  if (p === '/api/export' && request.method === 'GET') {
    return new Response(JSON.stringify(await getServers(env), null, 2), {
      headers: { 'content-type': 'application/json', 'content-disposition': 'attachment; filename="sbyg-servers.json"' },
    });
  }
  if (p === '/api/import' && request.method === 'POST') return json({ ok: true, data: await importServers(env, await request.json()) });
  let m = p.match(/^\/api\/servers\/([\w-]+)$/);
  if (m && request.method === 'DELETE') {
    const list = (await getServers(env)).filter((s) => s.id !== m[1]);
    await env.SBYG_KV.put('servers', JSON.stringify(list));
    return json({ ok: true });
  }
  m = p.match(/^\/api\/servers\/([\w-]+)\/call$/);
  if (m && request.method === 'POST') {
    const srv = (await getServers(env)).find((s) => s.id === m[1]);
    if (!srv) throw httpError(404, '服务器不存在');
    const body = await request.json();
    if (!ACTIONS.has(body.action)) throw httpError(400, '不支持的操作');
    const t0 = Date.now();
    const data = await callAgent(srv, body.action, body.params || {}, body.action === 'reset' ? 300000 : 60000);
    return json({ ok: true, data, ms: Date.now() - t0 });
  }
  throw httpError(404, 'not found');
}

const SEC_HEADERS = {
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
};

function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
  });
}

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

// ------------------------------------------------------------------ 登录与会话
async function sessionKey(env) {
  const raw = await crypto.subtle.digest('SHA-256', enc.encode('sbyg-session:' + env.ADMIN_PASSWORD));
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function login(request, env) {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const failKey = 'fail:' + ip;
  const fails = parseInt((await env.SBYG_KV.get(failKey)) || '0', 10);
  if (fails >= LOGIN_MAX_FAIL) throw httpError(429, '登录失败次数过多，请15分钟后再试');
  const { password } = await request.json();
  const key = await sessionKey(env);
  // 两边都做 HMAC 再比较，避免时序侧信道
  const a = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode('pw:' + String(password || ''))));
  const b = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode('pw:' + env.ADMIN_PASSWORD)));
  if (!timingSafeEqual(a, b)) {
    await env.SBYG_KV.put(failKey, String(fails + 1), { expirationTtl: 900 });
    throw httpError(401, '密码错误');
  }
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL;
  const sig = b64url(await crypto.subtle.sign('HMAC', key, enc.encode('sess:' + exp)));
  return json({ ok: true }, 200, {
    'set-cookie': `sbyg_s=${exp}.${sig}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL}`,
  });
}

async function checkSession(request, env) {
  const m = (request.headers.get('cookie') || '').match(/(?:^|;\s*)sbyg_s=(\d+)\.([\w-]+)/);
  if (!m || parseInt(m[1], 10) < Date.now() / 1000) return false;
  const key = await sessionKey(env);
  return crypto.subtle.verify('HMAC', key, b64urlDecode(m[2]), enc.encode('sess:' + m[1]));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}

// ------------------------------------------------------------------ 服务器列表（KV）
async function getServers(env) {
  return JSON.parse((await env.SBYG_KV.get('servers')) || '[]');
}

function publicServer(s) {
  return { id: s.id, name: s.name, host: s.host, port: s.port, path: s.path, group: s.group || '', note: s.note || '' };
}

function validServer(s) {
  const host = String(s.host || '').trim().replace(/^\[|\]$/g, '');
  const port = parseInt(s.port, 10);
  const path = String(s.path || '/api').trim();
  if (!/^[A-Za-z0-9.:-]{1,253}$/.test(host)) throw httpError(400, '服务器地址格式错误');
  if (!(port > 0 && port < 65536) || port === 25) throw httpError(400, '端口错误');
  if (!/^\/[A-Za-z0-9/_-]{0,64}$/.test(path)) throw httpError(400, 'API路径格式错误');
  return {
    name: String(s.name || host).slice(0, 64), host, port, path,
    group: String(s.group || '').slice(0, 32), note: String(s.note || '').slice(0, 200),
  };
}

async function saveServer(env, body) {
  const list = await getServers(env);
  const v = validServer(body);
  const token = String(body.token || '').trim();
  if (body.id) {
    const i = list.findIndex((s) => s.id === body.id);
    if (i < 0) throw httpError(404, '服务器不存在');
    list[i] = { ...list[i], ...v, token: token || list[i].token };
  } else {
    if (token.length < 16) throw httpError(400, 'Token 不能为空');
    list.push({ id: crypto.randomUUID().slice(0, 8), ...v, token, created: Date.now() });
  }
  await env.SBYG_KV.put('servers', JSON.stringify(list));
  return list.map(publicServer);
}

async function importServers(env, arr) {
  if (!Array.isArray(arr)) arr = [arr];
  const list = await getServers(env);
  let added = 0, updated = 0;
  for (const raw of arr) {
    const v = validServer(raw);
    const token = String(raw.token || '').trim();
    if (token.length < 16) continue;
    const i = list.findIndex((s) => s.host === v.host && s.port === v.port);
    if (i >= 0) { list[i] = { ...list[i], ...v, token }; updated++; }
    else { list.push({ id: crypto.randomUUID().slice(0, 8), ...v, token, created: Date.now() }); added++; }
  }
  await env.SBYG_KV.put('servers', JSON.stringify(list));
  return { added, updated };
}

// ------------------------------------------------------------------ 与服务器 sbagent 通信
// 报文格式与 sbagent.py 一致：
//   {"v":1,"iv":b64,"ct":b64,"z":0|1,"mac":b64}
//   mac = HMAC-SHA256(SHA256("sbyg-mac:"+token), "v1|" + ("z"|"-") + iv + ct)
//   ct  = AES-256-CBC(SHA256("sbyg-enc:"+token), iv, z ? zlib(明文) : 明文)
export async function deriveKeys(token) {
  const e = await crypto.subtle.digest('SHA-256', enc.encode('sbyg-enc:' + token));
  const m = await crypto.subtle.digest('SHA-256', enc.encode('sbyg-mac:' + token));
  return {
    enc: await crypto.subtle.importKey('raw', e, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']),
    mac: await crypto.subtle.importKey('raw', m, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']),
  };
}

function macInput(iv, ct, z) {
  const head = enc.encode(z ? 'v1|z' : 'v1|-');
  const out = new Uint8Array(head.length + iv.length + ct.length);
  out.set(head, 0);
  out.set(iv, head.length);
  out.set(ct, head.length + iv.length);
  return out;
}

async function streamBytes(data, stream) {
  const res = new Response(new Blob([data]).stream().pipeThrough(stream));
  return new Uint8Array(await res.arrayBuffer());
}

export async function seal(obj, keys) {
  let pt = enc.encode(JSON.stringify(obj));
  const z = pt.length > 512;
  if (z) pt = await streamBytes(pt, new CompressionStream('deflate'));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, keys.enc, pt));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', keys.mac, macInput(iv, ct, z)));
  return { v: 1, iv: b64(iv), ct: b64(ct), z: z ? 1 : 0, mac: b64(mac) };
}

export async function unseal(env, keys) {
  const iv = b64decode(env.iv), ct = b64decode(env.ct), mac = b64decode(env.mac);
  const z = !!env.z;
  if (env.v !== 1 || iv.length !== 16 || !(await crypto.subtle.verify('HMAC', keys.mac, mac, macInput(iv, ct, z)))) {
    throw new Error('响应签名校验失败');
  }
  let pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, keys.enc, ct));
  if (z) pt = await streamBytes(pt, new DecompressionStream('deflate'));
  return JSON.parse(dec.decode(pt));
}

export async function callAgent(srv, action, params, timeoutMs = 60000, openSocket = connect) {
  const keys = await deriveKeys(srv.token);
  const nonce = hex(crypto.getRandomValues(new Uint8Array(16)));
  const req = { ts: Math.floor(Date.now() / 1000), nonce, action, params };
  const body = enc.encode(JSON.stringify(await seal(req, keys)));
  const resp = await httpPost(srv.host, srv.port, srv.path || '/api', body, timeoutMs, openSocket);
  if (resp.status === 404) throw httpError(502, '服务器拒绝请求(404)：请检查Token、API路径，以及VPS系统时间是否准确');
  if (resp.status !== 200) throw httpError(502, '服务器返回 HTTP ' + resp.status);
  const out = await unseal(JSON.parse(dec.decode(resp.body)), keys);
  if (out.rn !== nonce) throw httpError(502, '响应与请求不匹配');
  if (!out.ok) throw httpError(502, out.error || '服务器执行失败');
  return out.data;
}

async function httpPost(host, port, path, body, timeoutMs, openSocket) {
  const hostname = String(host).replace(/^\[|\]$/g, '');
  let timer;
  const socket = openSocket({ hostname, port: Number(port) });
  const work = (async () => {
    const w = socket.writable.getWriter();
    const hostHdr = (hostname.includes(':') ? '[' + hostname + ']' : hostname) + ':' + port;
    await w.write(enc.encode(`POST ${path} HTTP/1.1\r\nHost: ${hostHdr}\r\nUser-Agent: sbyg-worker/${VERSION}\r\n` +
      `Content-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`));
    await w.write(body);
    w.releaseLock();
    const r = socket.readable.getReader();
    const chunks = [];
    let total = 0, need = -1, headLen = -1;
    for (;;) {
      const { value, done } = await r.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
      if (total > 64 * 1024 * 1024) throw new Error('响应过大');
      if (headLen < 0) {
        const buf = concat(chunks, total);
        const i = indexOfCRLF2(buf);
        if (i >= 0) {
          headLen = i + 4;
          const cl = dec.decode(buf.subarray(0, i)).match(/\r\ncontent-length:\s*(\d+)/i);
          if (cl) need = headLen + parseInt(cl[1], 10);
        }
      }
      if (need >= 0 && total >= need) break;
    }
    const buf = concat(chunks, total);
    const i = indexOfCRLF2(buf);
    if (i < 0) throw new Error('服务器无响应或响应不完整');
    const status = parseInt(dec.decode(buf.subarray(0, i)).split(' ')[1], 10);
    return { status, body: buf.subarray(i + 4, need >= 0 ? need : buf.length) };
  })();
  const timeout = new Promise((_, rej) => {
    timer = setTimeout(() => rej(httpError(504, '连接服务器超时：请检查IP/端口与VPS防火墙')), timeoutMs);
  });
  try {
    return await Promise.race([work, timeout]);
  } catch (e) {
    if (e.status) throw e;
    throw httpError(502, '连接服务器失败：' + (e.message || e));
  } finally {
    clearTimeout(timer);
    try { socket.close(); } catch (_) { /* 已关闭 */ }
  }
}

function concat(chunks, total) {
  if (chunks.length === 1) return chunks[0];
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  chunks.length = 0;
  chunks.push(out);
  return out;
}

function indexOfCRLF2(b) {
  for (let i = 0; i + 3 < b.length; i++) {
    if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) return i;
  }
  return -1;
}

// ------------------------------------------------------------------ 编码工具
function b64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
function b64decode(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64url(buf) {
  return b64(new Uint8Array(buf)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  return b64decode(s + '='.repeat((4 - (s.length % 4)) % 4));
}
function hex(u8) {
  return Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
}

// ------------------------------------------------------------------ 前端页面
// 注意：页面脚本中不使用反引号与 ${}，以便整体放在模板字符串里
const PAGE = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sing-box-yg 管理面板</title>
<style>
:root{--bg:#f5f6f8;--card:#fff;--fg:#1d2330;--muted:#6b7280;--line:#e3e6ea;--accent:#2563eb;--accent-fg:#fff;--ok:#16a34a;--bad:#dc2626;--warn:#d97706;--chip:#eef2f7;--code:#f1f3f6}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b23;--fg:#e6e8ec;--muted:#9aa3af;--line:#2a303b;--accent:#3b82f6;--accent-fg:#fff;--ok:#22c55e;--bad:#f87171;--warn:#fbbf24;--chip:#232a35;--code:#11151c}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
header{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between;padding:12px 16px;background:var(--card);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
header h1{font-size:16px;margin:0}
main{padding:16px;max-width:1400px;margin:0 auto}
button,select,input,textarea{font:inherit;color:inherit}
button{background:var(--chip);border:1px solid var(--line);border-radius:6px;padding:5px 10px;cursor:pointer}
button:hover{border-color:var(--accent)}
button.primary{background:var(--accent);color:var(--accent-fg);border-color:var(--accent)}
button.danger{color:var(--bad)}
button:disabled{opacity:.5;cursor:default}
input,select,textarea{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:5px 8px;min-width:0}
textarea{width:100%;font-family:ui-monospace,Consolas,monospace;font-size:12px}
.bar{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.card h3{margin:0;font-size:15px;display:flex;gap:6px;align-items:center}
.muted{color:var(--muted)}
.small{font-size:12px}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;background:var(--muted)}
.dot.ok{background:var(--ok)}.dot.bad{background:var(--bad)}.dot.warn{background:var(--warn)}
.chips{display:flex;flex-wrap:wrap;gap:4px;margin:6px 0}
.chip{background:var(--chip);border-radius:4px;padding:1px 6px;font-size:12px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:2px 10px;font-size:12px;margin:6px 0}
.kv span:nth-child(odd){color:var(--muted)}
.actions{display:flex;flex-wrap:wrap;gap:4px;margin-top:8px}
.actions button{font-size:12px;padding:3px 8px}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:flex-start;justify-content:center;padding:24px 8px;z-index:10;overflow:auto}
.dialog{background:var(--card);border-radius:10px;width:min(1200px,100%);padding:14px;border:1px solid var(--line)}
.dialog.narrow{width:min(560px,100%)}
.dialog h2{margin:0 0 10px;font-size:16px;display:flex;justify-content:space-between;align-items:center;gap:8px}
.tablewrap{overflow:auto;max-height:65vh;border:1px solid var(--line);border-radius:6px}
table{border-collapse:collapse;width:100%;font-size:12px}
th,td{padding:4px 8px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap;vertical-align:top}
th{position:sticky;top:0;background:var(--card)}
td.wrap{white-space:normal;word-break:break-all;min-width:200px}
.err{color:var(--bad)}
a{color:var(--accent);cursor:pointer;text-decoration:none}
.link{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all;background:var(--code);padding:6px;border-radius:6px;margin:4px 0}
.login{max-width:340px;margin:12vh auto}
.toast{position:fixed;right:16px;bottom:16px;background:var(--fg);color:var(--bg);padding:8px 12px;border-radius:6px;z-index:20;max-width:80vw}
label{display:inline-flex;gap:4px;align-items:center}
.field{display:flex;flex-direction:column;gap:3px;margin-bottom:8px}
.stat{display:inline-block;margin-right:14px}
.stat b{font-size:18px}
.tabs button.on{background:var(--accent);color:var(--accent-fg)}
@media (max-width:600px){.grid{grid-template-columns:1fr}main{padding:10px}}
</style>
</head>
<body>
<div id="app"></div>
<script>
(function(){
var $app=document.getElementById('app');
var servers=[],statusMap={},selected={};
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function api(path,opt){opt=opt||{};var h={'x-sbyg':'1'};if(opt.body!==undefined){h['content-type']='application/json'}
 return fetch(path,{method:opt.method||(opt.body!==undefined?'POST':'GET'),headers:h,body:opt.body!==undefined?JSON.stringify(opt.body):undefined,credentials:'same-origin'})
 .then(function(r){return r.json().catch(function(){return{ok:false,error:'HTTP '+r.status}}).then(function(j){if(r.status===401&&path!=='/api/login'){showLogin();throw new Error(j.error||'未登录')}if(!j.ok)throw new Error(j.error||('HTTP '+r.status));return j})})}
function call(id,action,params){return api('/api/servers/'+id+'/call',{body:{action:action,params:params||{}}}).then(function(j){return j.data})}
function toast(msg){var t=document.createElement('div');t.className='toast';t.textContent=msg;document.body.appendChild(t);setTimeout(function(){t.remove()},3500)}
function fmtBytes(n){n=n||0;if(n<1024)return n+' B';if(n<1048576)return (n/1024).toFixed(1)+' KB';if(n<1073741824)return (n/1048576).toFixed(1)+' MB';return (n/1073741824).toFixed(2)+' GB'}
function fmtUp(s){s=s||0;var d=Math.floor(s/86400),h=Math.floor(s%86400/3600);return d?d+'天'+h+'时':h+'时'+Math.floor(s%3600/60)+'分'}
function copy(text){(navigator.clipboard?navigator.clipboard.writeText(text):Promise.reject()).then(function(){toast('已复制')},function(){var t=document.createElement('textarea');t.value=text;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove();toast('已复制')})}
function srvById(id){for(var i=0;i<servers.length;i++)if(servers[i].id===id)return servers[i]}
function modal(html,narrow){closeModal();var m=document.createElement('div');m.className='modal';m.id='modal';m.innerHTML='<div class="dialog'+(narrow?' narrow':'')+'">'+html+'</div>';m.addEventListener('click',function(e){if(e.target===m)closeModal()});document.body.appendChild(m);return m}
function closeModal(){var m=document.getElementById('modal');if(m)m.remove()}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeModal()});

function showLogin(){
 $app.innerHTML='<div class="login card"><h3>Sing-box-yg 多服务器管理面板</h3><p class="muted small">请输入管理密码 (ADMIN_PASSWORD)</p><form id="lf"><div class="field"><input type="password" id="pw" autocomplete="current-password" autofocus></div><button class="primary" style="width:100%">登录</button></form><p class="err small" id="lerr"></p></div>';
 document.getElementById('lf').onsubmit=function(e){e.preventDefault();api('/api/login',{body:{password:document.getElementById('pw').value}}).then(function(){boot()}).catch(function(err){document.getElementById('lerr').textContent=err.message})};
}

function boot(){api('/api/me').then(function(j){renderShell(j.version);loadServers()}).catch(function(){})}

function renderShell(ver){
 $app.innerHTML='<header><h1>Sing-box-yg 管理面板 <span class="muted small">v'+esc(ver)+'</span></h1><div class="bar">'+
 '<button class="primary" id="b-add">添加服务器</button><button id="b-refresh">全部刷新</button>'+
 '<button id="b-batch">批量操作</button><button id="b-io">导入/导出</button><button id="b-logout">退出</button></div></header>'+
 '<main><div id="summary" class="muted small" style="margin-bottom:10px"></div><div class="grid" id="grid"></div></main>';
 document.getElementById('b-add').onclick=function(){editServer()};
 document.getElementById('b-refresh').onclick=refreshAll;
 document.getElementById('b-batch').onclick=batchDialog;
 document.getElementById('b-io').onclick=ioDialog;
 document.getElementById('b-logout').onclick=function(){api('/api/logout',{body:{}}).then(showLogin)};
}

function loadServers(){return api('/api/servers').then(function(j){servers=j.data;renderGrid();refreshAll()})}

function renderGrid(){
 var g=document.getElementById('grid');if(!g)return;
 if(!servers.length){g.innerHTML='<div class="card muted">还没有服务器。在VPS上运行 <b>sb</b> 选择 <b>19 → 1</b> 安装API服务，再选择 <b>19 → 2</b> 复制对接信息，然后点击「添加服务器」粘贴。</div>';updateSummary();return}
 g.innerHTML=servers.map(cardHtml).join('');
 g.querySelectorAll('[data-act]').forEach(function(b){b.onclick=function(){onAction(b.getAttribute('data-act'),b.getAttribute('data-id'))}});
 g.querySelectorAll('input[data-sel]').forEach(function(c){c.onchange=function(){selected[c.getAttribute('data-sel')]=c.checked}});
 updateSummary();
}

function updateSummary(){
 var el=document.getElementById('summary');if(!el)return;
 var on=0,act=0;servers.forEach(function(s){var st=statusMap[s.id];if(st&&st.data){on++;if(st.data.active)act++}});
 el.textContent='服务器 '+servers.length+' 台，在线 '+on+' 台，Sing-box运行中 '+act+' 台';
}

function cardHtml(s){
 var st=statusMap[s.id],d=st&&st.data,dot='',body='';
 if(!st){dot='';body='<div class="muted small">加载中…</div>'}
 else if(st.error){dot='bad';body='<div class="err small">'+esc(st.error)+'</div>'}
 else{
  dot=d.active?'ok':'warn';
  body='<div class="chips">'+(d.inbounds||[]).map(function(i){return '<span class="chip">'+esc(i.name)+' :'+esc(i.port)+'</span>'}).join('')+'</div>'+
  '<div class="kv"><span>系统</span><span>'+esc(d.os||'-')+' / '+esc(d.hostname)+'</span>'+
  '<span>内核</span><span>sing-box '+esc(d.version||'-')+(d.active?'':' <b class="err">未运行</b>')+'</span>'+
  '<span>IP</span><span>'+esc(d.server_ip||'-')+'</span>'+
  '<span>运行</span><span>'+fmtUp(d.uptime)+'，负载 '+esc((d.load||[]).join(' '))+(d.mem&&d.mem.MemTotal?'，内存 '+fmtBytes(d.mem.MemTotal-d.mem.MemAvailable)+'/'+fmtBytes(d.mem.MemTotal):'')+'</span>'+
  '<span>日志</span><span>'+(d.log&&d.log.enabled?'已开启 '+fmtBytes(d.log.size):'<span class="err">未开启</span>')+'</span>'+
  '<span>重置</span><span>'+(d.last_reset?esc(d.last_reset.time)+' ('+esc((d.last_reset.items||[]).join(','))+')':'从未')+(d.schedule?' · 已设定时':'')+(d.leak&&d.leak.enabled?' · 泄露检测':'')+'</span>'+
  (d.argo&&(d.argo.temp||d.argo.fixed)?'<span>Argo</span><span>'+esc(d.argo.fixed||d.argo.temp)+'</span>':'')+
  '</div>';
 }
 var b=function(act,label,cls){return '<button data-act="'+act+'" data-id="'+esc(s.id)+'"'+(cls?' class="'+cls+'"':'')+'>'+label+'</button>'};
 return '<div class="card"><h3><input type="checkbox" data-sel="'+esc(s.id)+'"'+(selected[s.id]?' checked':'')+'><span class="dot '+dot+'"></span>'+esc(s.name)+
 '<span class="muted small" style="margin-left:auto">'+esc(s.host)+':'+esc(s.port)+(st&&st.ms?' · '+st.ms+'ms':'')+'</span></h3>'+body+
 '<div class="actions">'+b('logs','访问日志')+b('stats','IP统计')+b('peers','在线IP')+b('links','节点链接')+b('reset','重置参数','danger')+
 b('settings','日志/定时/检测')+b('refresh','刷新')+b('restart','重启')+b('edit','编辑')+b('del','删除','danger')+'</div></div>';
}

function refreshOne(id){
 var t0=Date.now();
 return call(id,'status').then(function(d){statusMap[id]={data:d,ms:Date.now()-t0}},function(e){statusMap[id]={error:e.message}}).then(renderGrid);
}
function refreshAll(){statusMap={};renderGrid();return Promise.all(servers.map(function(s){return refreshOne(s.id)}))}

function onAction(act,id){
 var s=srvById(id);
 if(act==='refresh')return refreshOne(id);
 if(act==='edit')return editServer(s);
 if(act==='del'){if(confirm('删除服务器「'+s.name+'」？(仅从面板移除，不影响VPS)'))api('/api/servers/'+id,{method:'DELETE'}).then(loadServers).catch(function(e){toast(e.message)});return}
 if(act==='restart'){if(confirm('重启「'+s.name+'」的 Sing-box？'))call(id,'restart').then(function(d){toast(d.active?'重启成功':'重启后未运行，请检查');refreshOne(id)}).catch(function(e){toast(e.message)});return}
 if(act==='logs')return logsDialog(s);
 if(act==='stats')return statsDialog(s);
 if(act==='peers')return peersDialog(s);
 if(act==='links')return linksDialog(s);
 if(act==='reset')return resetDialog([s]);
 if(act==='settings')return settingsDialog(s);
}

// ---------- 添加/编辑服务器
function editServer(s){
 s=s||{};
 modal('<h2>'+(s.id?'编辑服务器':'添加服务器')+'<button onclick="this.closest(\\'.modal\\').remove()">关闭</button></h2>'+
 (s.id?'':'<div class="field"><span class="small muted">粘贴VPS上 sb → 19 → 2 输出的对接JSON，自动填写</span><textarea id="f-json" rows="3" placeholder="{&quot;name&quot;:&quot;...&quot;,&quot;host&quot;:&quot;...&quot;,&quot;port&quot;:...,&quot;path&quot;:&quot;...&quot;,&quot;token&quot;:&quot;...&quot;}"></textarea></div>')+
 '<div class="field"><span class="small muted">名称</span><input id="f-name" value="'+esc(s.name||'')+'"></div>'+
 '<div class="field"><span class="small muted">服务器IP或域名</span><input id="f-host" value="'+esc(s.host||'')+'"></div>'+
 '<div class="field"><span class="small muted">API端口</span><input id="f-port" type="number" value="'+esc(s.port||'')+'"></div>'+
 '<div class="field"><span class="small muted">API路径</span><input id="f-path" value="'+esc(s.path||'/api')+'"></div>'+
 '<div class="field"><span class="small muted">Token'+(s.id?' (留空表示不修改)':'')+'</span><input id="f-token" type="password" autocomplete="off"></div>'+
 '<div class="field"><span class="small muted">备注</span><input id="f-note" value="'+esc(s.note||'')+'"></div>'+
 '<div class="bar"><button class="primary" id="f-save">保存并测试</button><span class="err small" id="f-err"></span></div>',true);
 var js=document.getElementById('f-json');
 if(js)js.oninput=function(){try{var o=JSON.parse(js.value);['name','host','port','path','token'].forEach(function(k){if(o[k]!=null)document.getElementById('f-'+k).value=o[k]})}catch(e){}};
 document.getElementById('f-save').onclick=function(){
  var body={id:s.id,name:val('f-name'),host:val('f-host'),port:val('f-port'),path:val('f-path'),token:val('f-token'),note:val('f-note')};
  api('/api/servers',{body:body}).then(function(j){servers=j.data;var ns=s.id?srvById(s.id):servers[servers.length-1];closeModal();renderGrid();return refreshOne(ns.id).then(function(){var st=statusMap[ns.id];toast(st.error?'已保存，但连接失败：'+st.error:'已保存，连接成功')})})
  .catch(function(e){document.getElementById('f-err').textContent=e.message});
 };
}
function val(id){var e=document.getElementById(id);return e?e.value.trim():''}

// ---------- 访问日志
function logsDialog(s,preset){
 preset=preset||{};
 var m=modal('<h2>访问日志 · '+esc(s.name)+'<button onclick="this.closest(\\'.modal\\').remove()">关闭</button></h2>'+
 '<div class="bar" style="margin-bottom:8px"><input id="l-ip" placeholder="源IP" size="16" value="'+esc(preset.ip||'')+'"><input id="l-q" placeholder="访问目标/关键字" size="18" value="'+esc(preset.q||'')+'">'+
 '<select id="l-proto"><option value="">全部协议</option><option value="vless">Vless</option><option value="vmess">Vmess</option><option value="hysteria2">Hysteria2</option><option value="tuic">Tuic5</option><option value="anytls">Anytls</option></select>'+
 '<select id="l-hours"><option value="1">1小时</option><option value="6">6小时</option><option value="24" selected>24小时</option><option value="72">3天</option><option value="">全部</option></select>'+
 '<select id="l-limit"><option>100</option><option selected>300</option><option>1000</option><option>3000</option></select>'+
 '<label><input type="checkbox" id="l-err">只看失败/探测</label><label><input type="checkbox" id="l-local">隐藏Argo/本地</label>'+
 '<button class="primary" id="l-go">查询</button><button id="l-raw">原始日志</button></div><div id="l-info" class="small muted"></div><div class="tablewrap" id="l-out"></div>');
 function q(){
  var out=document.getElementById('l-out');out.innerHTML='<p class="muted" style="padding:8px">加载中…</p>';
  call(s.id,'logs',{ip:val('l-ip'),q:val('l-q'),proto:val('l-proto'),hours:val('l-hours')?Number(val('l-hours')):null,limit:Number(val('l-limit')),err:document.getElementById('l-err').checked,hidelocal:document.getElementById('l-local').checked})
  .then(function(d){
   document.getElementById('l-info').textContent=(d.enabled?'':'⚠ 连接日志未开启（在「日志/定时/检测」中开启）。 ')+'日志 '+fmtBytes(d.size)+'，记录范围 '+(d.first||'-')+' ~ '+(d.last||'-')+'，显示 '+d.matched+' 条 / 共 '+d.total+' 条';
   if(!d.records.length){out.innerHTML='<p class="muted" style="padding:8px">没有匹配的记录</p>';return}
   out.innerHTML='<table><thead><tr><th>时间</th><th>协议</th><th>源IP</th><th>端口</th><th>访问目标</th><th>网络</th><th>出站</th><th>备注</th></tr></thead><tbody>'+
   d.records.map(function(r){var tgt=r.domain||r.dst||'';var note=(r.domain&&r.dst&&r.domain!==r.dst?'原始目标 '+r.dst+' ':'')+(r.odst?'出站目标 '+r.odst+' ':'')+(r.user?'用户 '+r.user+' ':'');
    return '<tr><td>'+esc(r.time)+'</td><td>'+esc(r.proto||'')+'</td><td><a data-ip="'+esc(r.src)+'">'+esc(r.src)+'</a>'+(isLocal(r.src)?' <span class="chip">Argo/CDN</span>':'')+'</td><td>'+esc(r.sport)+'</td>'+
    '<td class="wrap">'+(tgt?'<a data-q="'+esc(tgt.replace(/:\\d+$/,''))+'">'+esc(tgt)+'</a>':'')+'</td><td>'+esc(r.net)+'</td><td>'+esc(r.out||'')+'</td><td class="wrap'+(r.err?' err':'')+'">'+esc(r.err||note)+'</td></tr>'}).join('')+'</tbody></table>';
   out.querySelectorAll('a[data-ip]').forEach(function(a){a.onclick=function(){document.getElementById('l-ip').value=a.getAttribute('data-ip');q()}});
   out.querySelectorAll('a[data-q]').forEach(function(a){a.onclick=function(){document.getElementById('l-q').value=a.getAttribute('data-q');q()}});
  }).catch(function(e){out.innerHTML='<p class="err" style="padding:8px">'+esc(e.message)+'</p>'});
 }
 document.getElementById('l-go').onclick=q;
 m.querySelectorAll('input').forEach(function(i){i.addEventListener('keydown',function(e){if(e.key==='Enter')q()})});
 document.getElementById('l-raw').onclick=function(){
  var out=document.getElementById('l-out');out.innerHTML='<p class="muted" style="padding:8px">加载中…</p>';
  call(s.id,'rawlog',{lines:500}).then(function(d){out.innerHTML='<pre class="link" style="margin:0;white-space:pre-wrap">'+esc(d.lines.join('\\n'))+'</pre>'}).catch(function(e){out.innerHTML='<p class="err">'+esc(e.message)+'</p>'});
 };
 q();
}
function isLocal(ip){return ip==='::1'||/^127\\./.test(ip||'')}

// ---------- 统计
function statsDialog(s){
 modal('<h2>源IP与访问目标统计 · '+esc(s.name)+'<button onclick="this.closest(\\'.modal\\').remove()">关闭</button></h2>'+
 '<div class="bar" style="margin-bottom:8px"><select id="s-hours"><option value="1">1小时</option><option value="6">6小时</option><option value="24" selected>24小时</option><option value="72">3天</option><option value="168">7天</option></select>'+
 '<span class="tabs bar"><button class="on" data-tab="ip">按源IP</button><button data-tab="dest">按访问目标</button></span></div><div id="s-sum" style="margin-bottom:8px"></div><div class="tablewrap" id="s-out"></div>');
 var data=null,tab='ip';
 function draw(){
  var out=document.getElementById('s-out');if(!data)return;
  if(tab==='ip'){out.innerHTML='<table><thead><tr><th>源IP</th><th>连接数</th><th>失败</th><th>首次</th><th>最近</th><th>协议</th><th>常访问目标</th><th></th></tr></thead><tbody>'+
   data.ips.map(function(x){return '<tr><td>'+esc(x.ip)+(x.local?' <span class="chip">Argo/CDN</span>':'')+'</td><td>'+x.count+'</td><td'+(x.err?' class="err"':'')+'>'+x.err+'</td><td>'+esc(x.first)+'</td><td>'+esc(x.last)+'</td><td>'+esc(x.protos.join(','))+'</td>'+
   '<td class="wrap">'+x.top.map(function(t){return esc(t[0])+' ('+t[1]+')'}).join('，')+'</td><td><a data-ip="'+esc(x.ip)+'">明细</a></td></tr>'}).join('')+'</tbody></table>';
   out.querySelectorAll('a[data-ip]').forEach(function(a){a.onclick=function(){logsDialog(s,{ip:a.getAttribute('data-ip')})}});
  }else{out.innerHTML='<table><thead><tr><th>访问目标</th><th>次数</th><th>来源IP数</th><th>最近访问</th><th></th></tr></thead><tbody>'+
   data.dests.map(function(x){return '<tr><td class="wrap">'+esc(x.host)+'</td><td>'+x.count+'</td><td>'+x.ips+'</td><td>'+esc(x.last)+'</td><td><a data-q="'+esc(x.host)+'">明细</a></td></tr>'}).join('')+'</tbody></table>';
   out.querySelectorAll('a[data-q]').forEach(function(a){a.onclick=function(){logsDialog(s,{q:a.getAttribute('data-q')})}});
  }
 }
 function load(){
  document.getElementById('s-out').innerHTML='<p class="muted" style="padding:8px">加载中…</p>';
  call(s.id,'stats',{hours:Number(val('s-hours')),top:300}).then(function(d){data=d;
   document.getElementById('s-sum').innerHTML='<span class="stat"><b>'+d.conns+'</b> 连接</span><span class="stat"><b>'+d.unique_ips+'</b> 个源IP</span><span class="stat"><b>'+d.unique_dests+'</b> 个访问目标</span><span class="stat"><b class="'+(d.errors?'err':'')+'">'+d.errors+'</b> 失败/探测</span>';draw()})
  .catch(function(e){document.getElementById('s-out').innerHTML='<p class="err" style="padding:8px">'+esc(e.message)+'</p>'});
 }
 document.getElementById('s-hours').onchange=load;
 document.querySelectorAll('[data-tab]').forEach(function(b){b.onclick=function(){tab=b.getAttribute('data-tab');document.querySelectorAll('[data-tab]').forEach(function(x){x.classList.toggle('on',x===b)});draw()}});
 load();
}

// ---------- 在线IP
function peersDialog(s){
 modal('<h2>当前在线客户端 · '+esc(s.name)+'<button onclick="this.closest(\\'.modal\\').remove()">关闭</button></h2><p class="small muted">TCP连接取自 ss，Hysteria2/Tuic(UDP) 取自 conntrack（需系统已加载 nf_conntrack）</p><div class="tablewrap" id="p-out"><p class="muted" style="padding:8px">加载中…</p></div>');
 call(s.id,'peers').then(function(d){
  document.getElementById('p-out').innerHTML=d.peers.length?'<table><thead><tr><th>源IP</th><th>协议</th><th>连接数</th><th></th></tr></thead><tbody>'+d.peers.map(function(p){return '<tr><td>'+esc(p.ip)+(p.local?' <span class="chip">Argo/CDN</span>':'')+'</td><td>'+esc(p.proto)+'</td><td>'+p.conns+'</td><td><a data-ip="'+esc(p.ip)+'">访问记录</a></td></tr>'}).join('')+'</tbody></table>':'<p class="muted" style="padding:8px">当前没有在线客户端</p>';
  document.querySelectorAll('#p-out a[data-ip]').forEach(function(a){a.onclick=function(){logsDialog(s,{ip:a.getAttribute('data-ip')})}});
 }).catch(function(e){document.getElementById('p-out').innerHTML='<p class="err" style="padding:8px">'+esc(e.message)+'</p>'});
}

// ---------- 节点链接
function linksHtml(d){
 return (d.links||[]).concat(d.subs||[]).map(function(x){return '<div><b class="small">'+esc(x.name)+'</b> <a data-copy="'+esc(x.link)+'">复制</a><div class="link">'+esc(x.link)+'</div></div>'}).join('')||'<p class="muted">暂无节点链接</p>';
}
function bindCopy(root){root.querySelectorAll('a[data-copy]').forEach(function(a){a.onclick=function(){copy(a.getAttribute('data-copy'))}})}
function linksDialog(s){
 var m=modal('<h2>节点与订阅链接 · '+esc(s.name)+'<button onclick="this.closest(\\'.modal\\').remove()">关闭</button></h2><p class="small err">链接即节点访问权限，请勿在不可信环境展示或分享</p><div id="k-out"><p class="muted">加载中…</p></div>');
 call(s.id,'links').then(function(d){var o=document.getElementById('k-out');o.innerHTML=linksHtml(d)+'<button id="k-all">复制全部节点链接</button>';bindCopy(o);
  document.getElementById('k-all').onclick=function(){copy((d.links||[]).map(function(x){return x.link}).join('\\n'))}})
 .catch(function(e){document.getElementById('k-out').innerHTML='<p class="err">'+esc(e.message)+'</p>'});
}

// ---------- 重置参数（单台或批量）
function resetDialog(list){
 modal('<h2>防泄露参数重置 · '+esc(list.map(function(s){return s.name}).join('、'))+'<button onclick="this.closest(\\'.modal\\').remove()">关闭</button></h2>'+
 '<p class="small">重置后旧的节点链接与订阅链接<b class="err">立即失效</b>，客户端需重新导入。服务器会自动重新生成本地订阅、同步Gitlab订阅并推送TG（如已设置）。</p>'+
 '<div class="field"><label><input type="checkbox" id="r-uuid" checked>UUID(密码) + Vmess路径</label><label><input type="checkbox" id="r-reality" checked>Reality 密钥对与 short_id</label>'+
 '<label><input type="checkbox" id="r-subtoken" checked>本地订阅链接路径</label><label><input type="checkbox" id="r-ports">Vless/Hy2/Tuic/Anytls 端口（需VPS防火墙放行全部端口；Vmess端口不变）</label></div>'+
 '<div class="bar"><button class="primary danger" id="r-go">确认重置</button><span class="small muted" id="r-st"></span></div><div id="r-out" style="margin-top:10px"></div>',list.length===1?false:true);
 document.getElementById('r-go').onclick=function(){
  var items=[];['uuid','reality','subtoken','ports'].forEach(function(k){if(document.getElementById('r-'+k).checked)items.push(k==='uuid'?'uuid,path':k)});
  if(!items.length)return toast('请至少选择一项');
  if(!confirm('确认重置 '+list.length+' 台服务器的参数？'))return;
  var btn=document.getElementById('r-go');btn.disabled=true;document.getElementById('r-st').textContent='重置中，每台约需10~60秒…';
  var out=document.getElementById('r-out');out.innerHTML='';
  Promise.all(list.map(function(s){
   var box=document.createElement('div');box.className='card';box.style.marginBottom='8px';box.innerHTML='<b>'+esc(s.name)+'</b> <span class="muted small">进行中…</span>';out.appendChild(box);
   return call(s.id,'reset',{items:items.join(',')}).then(function(d){
    var ch=d.changed||{};
    box.innerHTML='<b>'+esc(s.name)+'</b> <span class="small" style="color:var(--ok)">✔ 已重置 '+esc(Object.keys(ch).join(','))+(d.active?'':'，<b class="err">但Sing-box未运行</b>')+'</span>'+
    (ch.ports?'<div class="small">新端口：'+esc(JSON.stringify(ch.ports))+'</div>':'')+(list.length===1?linksHtml(d):'');bindCopy(box);refreshOne(s.id);
   },function(e){box.innerHTML='<b>'+esc(s.name)+'</b> <span class="err small">✘ '+esc(e.message)+'</span>'});
  })).then(function(){document.getElementById('r-st').textContent='完成';btn.disabled=false});
 };
}

// ---------- 日志开关 / 定时重置 / 泄露检测
function settingsDialog(s){
 modal('<h2>日志 / 定时重置 / 泄露检测 · '+esc(s.name)+'<button onclick="this.closest(\\'.modal\\').remove()">关闭</button></h2><div id="g-out"><p class="muted">加载中…</p></div>',true);
 call(s.id,'status').then(function(d){
  var lk=d.leak||{};
  document.getElementById('g-out').innerHTML=
  '<h3 class="small">连接访问日志</h3><p class="small">状态：'+(d.log.enabled?'已开启，'+fmtBytes(d.log.size):'<span class="err">未开启</span>')+'</p><div class="bar"><button id="g-logon">开启</button><button id="g-logoff">关闭</button><button id="g-clear" class="danger">清空日志</button></div>'+
  '<h3 class="small" style="margin-top:14px">定时自动重置（UUID+Reality+订阅路径）</h3><p class="small muted">'+esc(d.schedule||'未设置')+'</p><div class="bar"><button data-sch="daily">每天04:00</button><button data-sch="weekly">每周一04:00</button><button data-sch="off">关闭</button></div>'+
  '<h3 class="small" style="margin-top:14px">泄露检测（每小时检测一次）</h3>'+
  '<div class="bar small"><label><input type="checkbox" id="g-len"'+(lk.enabled?' checked':'')+'>开启</label> 最近 <input id="g-lh" type="number" style="width:70px" value="'+esc(lk.hours||24)+'"> 小时内，不同源IP超过 <input id="g-lt" type="number" style="width:70px" value="'+esc(lk.threshold||10)+'"> 个时'+
  '<select id="g-la"><option value="notify"'+(lk.action!=='reset'?' selected':'')+'>仅TG通知</option><option value="reset"'+(lk.action==='reset'?' selected':'')+'>自动重置并TG推送</option></select><button id="g-lsave" class="primary">保存</button><button id="g-lcheck">立即检测</button></div><div id="g-lres" class="small" style="margin-top:6px"></div>';
  function act(a,p,msg){return call(s.id,a,p).then(function(r){toast(msg);refreshOne(s.id);return r}).catch(function(e){toast(e.message)})}
  document.getElementById('g-logon').onclick=function(){act('logon',{},'连接日志已开启').then(function(){settingsDialog(s)})};
  document.getElementById('g-logoff').onclick=function(){act('logoff',{},'连接日志已关闭').then(function(){settingsDialog(s)})};
  document.getElementById('g-clear').onclick=function(){if(confirm('清空日志？'))act('clearlog',{},'日志已清空')};
  document.querySelectorAll('[data-sch]').forEach(function(b){b.onclick=function(){act('schedule',{mode:b.getAttribute('data-sch'),items:'all'},'已保存').then(function(){settingsDialog(s)})}});
  document.getElementById('g-lsave').onclick=function(){act('leakconf',{enabled:document.getElementById('g-len').checked,hours:Number(val('g-lh')),threshold:Number(val('g-lt')),action:val('g-la'),items:'all'},'已保存')};
  document.getElementById('g-lcheck').onclick=function(){call(s.id,'leakcheck').then(function(r){document.getElementById('g-lres').innerHTML='最近 '+esc(r.hours)+' 小时：'+r.unique_ips+' 个源IP（阈值 '+r.threshold+'）'+(r.exceeded?' <b class="err">已超过阈值</b>':' 正常')+'<br>'+r.ips.slice(0,20).map(function(x){return esc(x[0])+'('+x[1]+')'}).join('，')}).catch(function(e){toast(e.message)})};
 }).catch(function(e){document.getElementById('g-out').innerHTML='<p class="err">'+esc(e.message)+'</p>'});
}

// ---------- 批量操作
function batchDialog(){
 var ids=Object.keys(selected).filter(function(k){return selected[k]&&srvById(k)});
 var list=ids.length?ids.map(srvById):servers.slice();
 modal('<h2>批量操作<button onclick="this.closest(\\'.modal\\').remove()">关闭</button></h2><p class="small">对象：'+(ids.length?'已勾选的 ':'全部 ')+list.length+' 台 —— '+esc(list.map(function(s){return s.name}).join('、'))+'</p>'+
 '<div class="bar"><button id="x-reset" class="danger">批量重置参数</button><button id="x-restart">批量重启</button><button id="x-logon">批量开启日志</button><button id="x-stats">汇总24小时源IP</button></div><div id="x-out" style="margin-top:10px"></div>',true);
 document.getElementById('x-reset').onclick=function(){resetDialog(list)};
 function each(action,params,label){
  var out=document.getElementById('x-out');out.innerHTML='';
  list.forEach(function(s){var d=document.createElement('div');d.className='small';d.textContent=s.name+'：'+label+'中…';out.appendChild(d);
   call(s.id,action,params).then(function(){d.textContent=s.name+'：✔ 完成';refreshOne(s.id)},function(e){d.textContent=s.name+'：✘ '+e.message;d.className='small err'})});
 }
 document.getElementById('x-restart').onclick=function(){if(confirm('重启 '+list.length+' 台服务器的 Sing-box？'))each('restart',{},'重启')};
 document.getElementById('x-logon').onclick=function(){each('logon',{},'开启日志')};
 document.getElementById('x-stats').onclick=function(){
  var out=document.getElementById('x-out');out.innerHTML='<p class="muted">汇总中…</p>';
  Promise.all(list.map(function(s){return call(s.id,'stats',{hours:24,top:1000}).then(function(d){return{s:s,d:d}},function(e){return{s:s,e:e}})})).then(function(rs){
   var ipm={};rs.forEach(function(r){if(!r.d)return;r.d.ips.forEach(function(x){var o=ipm[x.ip]||(ipm[x.ip]={ip:x.ip,count:0,servers:[]});o.count+=x.count;o.servers.push(r.s.name)})});
   var arr=Object.keys(ipm).map(function(k){return ipm[k]}).sort(function(a,b){return b.count-a.count});
   out.innerHTML=rs.filter(function(r){return r.e}).map(function(r){return '<div class="err small">'+esc(r.s.name)+'：'+esc(r.e.message)+'</div>'}).join('')+
   '<div class="tablewrap"><table><thead><tr><th>源IP</th><th>连接数</th><th>访问的服务器</th></tr></thead><tbody>'+arr.map(function(x){return '<tr><td>'+esc(x.ip)+'</td><td>'+x.count+'</td><td class="wrap">'+esc(x.servers.join('、'))+'</td></tr>'}).join('')+'</tbody></table></div>';
  });
 };
}

// ---------- 导入导出
function ioDialog(){
 modal('<h2>导入 / 导出服务器<button onclick="this.closest(\\'.modal\\').remove()">关闭</button></h2>'+
 '<p class="small">导出文件包含所有服务器的 Token，请妥善保管。</p><div class="bar" style="margin-bottom:10px"><a href="/api/export" download><button>导出为JSON</button></a></div>'+
 '<div class="field"><span class="small muted">导入：粘贴导出的JSON数组，或一台/多台服务器的对接JSON（同IP+端口会被覆盖）</span><textarea id="i-json" rows="8"></textarea></div><button class="primary" id="i-go">导入</button> <span id="i-res" class="small"></span>',true);
 document.getElementById('i-go').onclick=function(){
  var v;try{v=JSON.parse(val('i-json'))}catch(e){return toast('JSON格式错误')}
  api('/api/import',{body:v}).then(function(j){document.getElementById('i-res').textContent='新增 '+j.data.added+' 台，更新 '+j.data.updated+' 台';loadServers()}).catch(function(e){toast(e.message)});
 };
}

boot();
})();
</script>
</body>
</html>`;
