// 从 Worker 实际提供的应用脚本验证图表渲染，防止内嵌模板转义与异常数据回归。
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { loadWorker, memoryKV, fakeCtx } from './harness.mjs';

const worker = (await loadWorker()).default;
const env = { ADMIN_PASSWORD: 'chart-test-password', SBYG_KV: memoryKV() };
const page = await worker.fetch(new Request('https://panel.example/'), env, fakeCtx());
const html = await page.text();
const src = html.match(/src="(\/app\.[a-f0-9]+\.js)"/)[1];
const response = await worker.fetch(new Request('https://panel.example' + src), env, fakeCtx());
const script = await response.text();
new vm.Script(script);
const elements = { summary: { innerHTML: '' } };
const sandbox = {
  document: { getElementById: (id) => elements[id] || {}, addEventListener() {} },
  requestAnimationFrame() {},
  setTimeout() {},
};
vm.runInNewContext(script.replace(/boot\(\);\s*\}\)\(\);\s*$/, 'globalThis.renderers={chart,serverMetrics,cycleVisual,cycleDate,cardHtml,updateSummary,csvCell,permissionText,refreshOne,rangeOf,loadLatest,releaseNotesHtml,scriptUpgradeComplete,exportCsv,TS,S};})();'), sandbox);
const { chart, serverMetrics, cycleVisual, cycleDate, cardHtml, updateSummary, csvCell, permissionText, refreshOne, rangeOf, loadLatest, releaseNotesHtml, scriptUpgradeComplete, exportCsv, TS, S } = sandbox.renderers;

assert.equal(scriptUpgradeComplete({ agent: '1.4.6', script_version: 'v26.11.19' }, { agent: '1.4.6', script: 'v26.11.20' }), false);
assert.equal(scriptUpgradeComplete({ agent: '1.4.6', script_version: 'v26.11.20' }, { agent: '1.4.6', script: 'v26.11.20' }), true);
assert.equal(scriptUpgradeComplete({ agent: '1.4.6' }, { agent: '1.4.6' }), true);

S.servers = [{ id: 'old' }, { id: 'current' }, { id: 'unknown' }];
S.status = { old: { data: { script_version: 'v26.11.4.3', agent: '1.4.6' } }, current: { data: { script_version: 'v26.11.19' } } };
S.latest = { releases: [
  { version: 'v26.11.19', notes: ['newest <release>'] },
  { version: 'v26.11.4.4', notes: ['patch release'] },
  { version: 'v26.11.4.3', notes: ['installed release'] },
  { version: 'v26.11.4.2', notes: ['older release'] },
] };
const recentNotes = releaseNotesHtml(['old']);
assert.ok(recentNotes.includes('newest &lt;release&gt;') && recentNotes.includes('patch release'));
assert.ok(!recentNotes.includes('installed release') && !recentNotes.includes('older release'));
assert.ok(!recentNotes.includes('最低版本'));
assert.ok(releaseNotesHtml().includes('按当前范围最低版本'));
assert.equal(releaseNotesHtml(['current']), '');
assert.equal(releaseNotesHtml(['unknown']), '');
S.latest = { notes: ['legacy notes'] };
assert.equal(releaseNotesHtml(['old']), '');
S.servers = [];
S.status = {};

const upgradeServer = { id: 'upgrade', name: '待更新', host: '192.0.2.1', port: 1234, cycle: { mode: 'off' } };
S.latest = { script: 'v26.11.19', agent: '1.4.6' };
S.status.upgrade = { data: { active: true, script_version: 'v26.11.18', agent: '1.4.5' } };
const upgradeCard = cardHtml(upgradeServer);
assert.ok(upgradeCard.includes('VPS 脚本 / agent 可升级'));
assert.ok(upgradeCard.indexOf('升级服务器') < upgradeCard.indexOf('<details'));
assert.equal((upgradeCard.match(/data-act="upgrade"/g) || []).length, 1);
S.status.upgrade.data.agent = '1.4.6';
assert.ok(cardHtml(upgradeServer).includes('升级服务器'));
S.status.upgrade.data.script_version = 'v26.11.19';
assert.ok(!cardHtml(upgradeServer).includes('升级服务器'));
S.latest = null;
assert.ok(!cardHtml(upgradeServer).includes('升级服务器'));
elements['latest-status'] = { textContent: '' };
sandbox.fetch = async () => Response.json({ ok: true, data: { script: 'v26.11.19', agent: '1.4.6', stale: true } });
await loadLatest();
assert.ok(elements['latest-status'].textContent.includes('缓存结果'));
sandbox.fetch = async () => Response.json({ ok: false, error: '测试请求失败' }, { status: 502 });
await assert.rejects(loadLatest(true), /测试请求失败/);
assert.ok(elements['latest-status'].textContent.includes('版本检查失败'));
sandbox.fetch = async () => Response.json({ ok: true, data: { script: 'v26.11.19', agent: '1.4.6' } });
await loadLatest(true);
assert.equal(elements['latest-status'].textContent, '');
S.latest = null;

assert.equal(csvCell(' @示例'), '"’ @示例"');
assert.equal(csvCell('＝示例'), '"’＝示例"');
assert.equal(csvCell('节点, "名称"'), '"节点, ""名称"""');
assert.equal(csvCell(25), '25');
assert.equal(permissionText(['read', '<未知权限>']), '只读、&lt;未知权限&gt;');

assert.equal(chart([]), '');
const zero = chart([{ key: '2026-11-18', up: 0, down: 0 }]);
assert.ok(zero.includes('合计 0 B'));
assert.ok(!/NaN|Infinity/.test(zero));
assert.equal((zero.match(/tabindex="0"/g) || []).length, 1);
const numeric = chart([{ key: '2026-11-18', up: '1024', down: '3072' }]);
assert.ok(numeric.includes('合计 4.00 KB'));
assert.ok(numeric.includes('height:25%'));
assert.ok(numeric.includes('height:75%'));
const invalid = chart([{ key: '"><img src=x onerror=alert(1)>', up: -5, down: Infinity }]);
assert.ok(!invalid.includes('<img'));
assert.ok(invalid.includes('&lt;img'));
assert.ok(!/NaN|Infinity|height:-/.test(invalid));
const many = chart(Array.from({ length: 2000 }, (_, i) => ({ key: String(i), up: i, down: i * 2 })));
assert.equal((many.match(/data-chart-detail=/g) || []).length, 2000);
assert.equal((many.match(/tabindex="0"/g) || []).length, 1);

assert.ok(serverMetrics({ mem: { MemTotal: 1024, MemAvailable: 256 } }).includes('--usage:75%'));
assert.ok(serverMetrics({ mem: { MemTotal: 1024 } }).includes('内存数据不可用'));
assert.ok(serverMetrics({ mem: { MemTotal: 1024, MemAvailable: -2 } }).includes('--usage:100%'));
assert.ok(!serverMetrics({ load: ['<img>'] }).includes('<img>'));
S.cycles.test = { cur: { start: 1, end: 2, used: 120, quota: 100, pct: 120 }, prev: {} };
const cycle = cycleVisual({ id: 'test', cycle: { mode: 'month', alertPct: 80 } });
assert.ok(cycle.includes('width:100%'));
assert.ok(cycle.includes('120%'));
assert.ok(cycle.includes('var(--bad)'));
assert.ok(cycle.includes('本月流量'));
assert.ok(cycle.includes('超额 20 B'));
S.cycles.test = { tz: 8, cur: { start: Date.UTC(2026, 10, 9, 16), end: Date.UTC(2026, 11, 9, 16), used: 20, quota: 100, pct: 20, source: 'nic' }, prev: {} };
assert.ok(cycleVisual({ id: 'test', cycle: { mode: 'month', count: 'max', alertPct: 80, source: 'nic' } }).includes('2026-12-10 重置'));
assert.ok(cycleVisual({ id: 'test', cycle: { mode: 'days', count: 'max', alertPct: 80, source: 'nic' } }).includes('本周期流量'));
assert.ok(cycleVisual({ id: 'test', cycle: { mode: 'month', count: 'max', alertPct: 80, source: 'nic' } }).includes('剩余 80 B'));
Object.assign(S.cycles.test.cur, { partial: true, since: '2026-11-11 08:00:00' });
assert.ok(cycleVisual({ id: 'test', cycle: { mode: 'month', source: 'nic' } }).includes('网卡从 2026-11-11 开始记录'));
S.cycles.test.cur.partial = false;
assert.ok(cycleVisual({ id: 'none', cycle: { mode: 'off' } }).includes('设置流量周期'));
S.cycles.test.cur.available = false;
assert.ok(cycleVisual({ id: 'test', cycle: { mode: 'month' } }).includes('暂无可用数据'));
assert.ok(!cycleVisual({ id: 'test', cycle: { mode: 'month' } }).includes('请开启流量统计'));
assert.ok(cycleVisual({ id: 'test', cycle: { mode: 'month' } }, { traffic: { enabled: false } }).includes('请开启流量统计'));
S.status.offline = { error: '连接超时' };
assert.ok(cardHtml({ id: 'offline', name: '离线', host: '192.0.2.1', port: 1234, cycle: { mode: 'off' } }).includes('设置流量周期'));
S.cycles.test.cur = { ...S.cycles.test.cur, available: true, used: 0, quota: 0, pct: null, source: 'proxy' };
const noQuota = cycleVisual({ id: 'test', cycle: { mode: 'month', source: 'nic' } });
assert.ok(noQuota.includes('未设配额') && noQuota.includes('网卡数据不可用，当前使用代理流量'));
assert.ok(!noQuota.includes('剩余') && !noQuota.includes('超额'));
assert.equal(cycleDate(Date.UTC(2026, 10, 30, 16), 8), '2026-12-01');
assert.equal(cycleDate(Date.UTC(2026, 10, 1, 0), -8), '2026-10-31');
S.servers = [{ id: 'a', group: 'one' }, { id: 'b', group: 'two' }, { id: 'c' }, { id: 'd' }];
S.status = { a: { data: { active: true } }, b: { data: { active: false } }, c: { error: 'offline' } };
updateSummary();
assert.ok(elements.summary.innerHTML.includes('运行中 1 台，服务停止 1 台，离线 1 台，待检测 1 台'));
S.groupFilter = 'one';
updateSummary();
assert.ok(elements.summary.innerHTML.includes('运行中 1 台，服务停止 0 台，离线 0 台，待检测 0 台'));
const pending = [];
sandbox.fetch = (url) => new Promise((resolve) => pending.push({ url, resolve }));
S.servers = [{ id: 'refresh', cycle: { mode: 'month' } }];
const oldRefresh = refreshOne('refresh');
const newRefresh = refreshOne('refresh');
S.servers = S.servers.map((server) => ({ ...server, group: 'new-group' }));
pending[1].resolve(Response.json({ ok: true, data: { active: true, hostname: 'new-status' } }));
await new Promise(setImmediate);
assert.equal(pending[2].url, '/api/servers/refresh/cycle');
pending[2].resolve(Response.json({ ok: true, data: { cur: { used: 42 } } }));
await newRefresh;
pending[0].resolve(Response.json({ ok: true, data: { active: false, hostname: 'stale-status' } }));
await oldRefresh;
assert.equal(S.status.refresh.data.hostname, 'new-status');
assert.equal(S.cycles.refresh.cur.used, 42);
assert.equal(pending.length, 3);
const ranges = rangeOf({ scope: 's:refresh', range: 'pcycle' });
pending[3].resolve(Response.json({ ok: true, data: { prev: { start: 1000, end: 9000, queryEnd: 8000 } } }));
assert.deepEqual(Array.from(await ranges), [1, 8]);
let csvUrlReleased, finishDownload, clicked = false;
const link = { click() { clicked = true; } };
sandbox.document.createElement = () => link;
sandbox.Blob = Blob;
sandbox.URL = { createObjectURL: () => 'blob:traffic', revokeObjectURL: (url) => { csvUrlReleased = url; } };
sandbox.setTimeout = (fn) => { finishDownload = fn; };
TS.group = 'day';
TS.rows = [{ servers: ['test'], key: '2026-11-20', up: 1, down: 2, conns: 1, ips: 1, hosts: 1 }];
exportCsv();
assert.ok(clicked && link.download === 'traffic-day.csv');
assert.equal(csvUrlReleased, undefined);
finishDownload();
assert.equal(csvUrlReleased, 'blob:traffic');
console.log('PASS 页面脚本语法、图表、CSV 与转义、内存、周期配额/时区/缺失数据和分组汇总');
