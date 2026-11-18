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
};
vm.runInNewContext(script.replace(/boot\(\);\s*\}\)\(\);\s*$/, 'globalThis.renderers={chart,serverMetrics,cycleVisual,updateSummary,csvCell,permissionText,S};})();'), sandbox);
const { chart, serverMetrics, cycleVisual, updateSummary, csvCell, permissionText, S } = sandbox.renderers;

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
S.servers = [{ id: 'a', group: 'one' }, { id: 'b', group: 'two' }, { id: 'c' }, { id: 'd' }];
S.status = { a: { data: { active: true } }, b: { data: { active: false } }, c: { error: 'offline' } };
updateSummary();
assert.ok(elements.summary.innerHTML.includes('运行中 1 台，服务停止 1 台，离线 1 台，待检测 1 台'));
S.groupFilter = 'one';
updateSummary();
assert.ok(elements.summary.innerHTML.includes('运行中 1 台，服务停止 0 台，离线 0 台，待检测 0 台'));
console.log('PASS 页面脚本语法、堆叠比例、零值/单点/2000 点、异常值/转义、内存缺失、超额配额和分组汇总');
