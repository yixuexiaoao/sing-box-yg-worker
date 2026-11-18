# sing-box-yg-worker 维护手册

本仓库在 Cloudflare Workers 上运行多台 VPS 的网页管理面板。正式代码源为 `yixuexiaoao/sing-box-yg-worker` 的 `main`。面板通过每台 VPS 的 sbagent 查询状态、日志、流量与订阅，也可在服务器允许时发起升级。[VPS 维护手册](https://github.com/yixuexiaoao/sing-box-yg/blob/main/MAINTENANCE.md)

## 功能与文件

| 文件 | 作用 |
|---|---|
| `src/worker.js` | Worker 路由、认证、TOTP、会话、服务器和订阅管理、审计、周期告警与定时任务。与 sbagent 通信的 `callAgent`、`seal`、`unseal` 也在这里。文件尾部 `PAGE` 为前端模板及页面脚本。 |
| `package.json` | 项目版本及本地开发、测试、部署命令。面板版本须与 `src/worker.js` 的 `VERSION` 一致。 |
| `wrangler.toml` | Worker 入口、兼容日期、`SBYG_KV` 绑定和 Cron 参数。发布前核对实际使用的 Cloudflare 环境和绑定。 |
| `test/charts.mjs` | 从 Worker 实际生成的页面脚本验证图表、更新提示和版本说明等前端行为。 |
| `test/e2e.mjs` | Worker 端到端测试。使用内存 KV，启动真实 sbagent 的临时副本验证协议、版本查询、权限、统计和升级。 |
| `test/harness.mjs`、`test/dev-server.mjs` | Node 中模拟 Cloudflare 套接字和 KV，以及本地预览服务。 |
| `README.md`、`CHANGELOG.md`、`SECURITY.md` | 分别说明用户功能及部署、发版变更及验证、安全边界。 |
| `LICENSE`、`.gitignore` | 授权条款和 Git 忽略规则。 |

面板数据存于 `SBYG_KV`。其中 `servers` 表示服务器配置，`settings` 表示面板设置，`subs` 表示订阅，`latest` 缓存版本信息。`ADMIN_PASSWORD` 和 `DATA_KEY` 使用 Cloudflare Secret。审计用于记录通过面板发起的操作，查询最新版本走 `/api/latest`。

## 怎么查更新

| 需要核对的版本 | 来源和验证入口 |
|---|---|
| Worker 面板自身 | GitHub `package.json`、`src/worker.js` 的 `VERSION`，以及生产面板页眉和 `/api/me`。GitHub 最新提交须与 Cloudflare 当前 Active Deployment 对照。 |
| VPS 脚本、agent | `UPSTREAM` 指向 VPS 正式仓库。`fetchLatest` 读取 `version` 和 `sbagent.py` 的开头，服务器 `status` 提供已装 `script_version` 与 `agent`。 |
| sing-box 内核 | 面板从 SagerNet 发布数据读取目标版本，已装版本由 VPS 状态接口提供。内核版本不参与脚本更新记录筛选。 |

1. 如果截图里的「GitHub 最新」比仓库版本旧，先看生产面板页眉，再点「检查更新 → 重新检查」。普通查询的版本缓存有效期是 30 分钟，手动重新检查绕开 KV 和子请求缓存。若仍有问题，对照已登录面板的 `/api/latest?refresh=1` 和 GitHub `main`。
2. 从某一张服务器卡片打开升级时，更新记录只展示高于该服务器已装脚本版本的段落。全局弹窗以表中可读取的最低脚本版本为起点，覆盖多个不同版本的服务器。已是最新或当前脚本版本未知时，页面隐藏不适用的历史。
3. 「检查更新」只查询版本。实际调用 VPS 的脚本或内核升级接口后，面板审计才会记录操作结果。实际部署面板代码的记录在 Cloudflare 的 Deployments。若使用自动构建，同时确认连接的 Git 仓库、生产分支和构建结果。[Cloudflare Workers Builds](https://developers.cloudflare.com/workers/ci-cd/builds/)

## 联动和发版

- 查询链路在 `latestVersions` 和 `fetchLatest`，界面在 `upgradeDialog`。更新记录依赖 VPS `version` 的段落标题。修改段落格式时同时验证 VPS 菜单和 Worker 对旧数据、混合服务器版本及缓存迁移的处理。
- 协议和权限与 VPS 的 `sbagent.py` 配套。改动作时检查两端的 `ACTIONS`、Worker 的 `READ_ACTIONS`、审计名及服务器端权限表。
- 改动后运行 `node --check src/worker.js`、`node test/charts.mjs` 和 `node test/e2e.mjs <sbagent.py 路径> <测试 SB_DIR>`。端到端测试会修改测试文件，使用临时配置目录。界面改动使用本地预览或模拟数据走一遍用户操作流程。
- 发布时同步更新 `package.json` 和 `src/worker.js` 的版本及 `CHANGELOG.md`。核对远端提交之后，单独验证 Cloudflare 生产面板的页眉和升级检查结果。
