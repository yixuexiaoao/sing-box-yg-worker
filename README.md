# sing-box-yg-worker

部署在 Cloudflare Workers 上的 **多服务器 Web 管理面板**，配合 [sing-box-yg](https://github.com/yixuexiaoao/sing-box-yg) 脚本的 API（一键安装第六步或 `sb` 主菜单 19 开启）使用。

## 功能

**服务器**
- 总览：在线状态、Sing-box 运行状态与版本、各协议端口、系统负载/内存、日志/流量统计状态、API 权限、上次重置
- 访问日志：每个连接的 **源IP:端口、协议、访问目标（含嗅探域名）、网络类型、出站通道**，按源IP/关键字/协议/时间筛选；认证失败与主动探测记录；原始日志
- 连接统计：按源IP / 访问目标统计；在线客户端IP
- 防泄露参数重置：UUID+Vmess路径、Reality 密钥、本地订阅路径、端口（可选）；单台、批量或 **一键全部重置**，可同时重置面板中全部订阅链接
- 日志/流量/定时：开关连接日志、**日志策略（单文件上限、归档份数、gzip 压缩、保留天数）**、**按时间段删除日志**、开关流量统计、流量保留天数与按时间段清理、定时重置、泄露检测
- 服务器端 API 审计日志（来源IP、操作、结果、封禁记录）

**流量统计**
- 数据来自各服务器 sing-box 的连接计数（Clash API，仅监听本机），按小时聚合并与服务器总流量对账
- 可选服务器（或全部）、时间段（今天/昨天/24小时/7天/30天/自定义），**按源IP、访问地址、日期、小时、协议、出站、源IP+访问地址** 分组，按 IP/访问地址/协议筛选，点击下钻，按日/小时显示柱状图，导出 CSV

**订阅管理**
- 把多台服务器的节点（可按协议筛选）与自定义节点链接合并为一个订阅链接（Base64，或 `?format=plain` 明文），可统一改名为「服务器名-协议」
- 服务器重置参数后订阅内容自动使用新参数；节点缓存按设置定期刷新
- 订阅可设到期时间、启用/停用、**一键重置链接**（单个或全部）；记录访问次数与访问IP，**被新IP访问时可 TG 通知**，便于发现订阅泄露

**审计日志与通知**
- 记录登录（成功/失败/被拒绝，含IP、国家、浏览器）、服务器操作、查看节点链接、面板设置/服务器/订阅变更、导出等；按类型/IP/关键字/时间段查询，按时间段删除，按保留天数自动过期
- Telegram 通知可单独开关：登录成功、登录失败、服务器操作、面板变更、服务器离线、服务器恢复、每日流量报告、流量超额告警、订阅被新IP访问；支持发送测试消息

**设置**
- 面板标题、时区、登录有效期、审计日志保留天数、节点缓存刷新间隔
- 安全：登录 IP 白名单（保存时会检查不会把自己锁在外面）、**TOTP 二次验证**、退出所有设备
- 监控：离线检测（连续失败次数）、每日报告时间、单台服务器日流量告警阈值

## 安全设计

- Worker 通过 `cloudflare:sockets` 直连 `服务器IP:端口`；每个请求 **AES-256-CBC 加密 + HMAC-SHA256 签名**（密钥由服务器 Token 派生），带时间戳（±300 秒）与一次性 nonce，响应同样加密并与请求 nonce 绑定
- 服务器端（sbagent）：
  - **权限分级**：只读 / 查看节点链接 / 管理，安装时选择；**权限、IP白名单、Token 只能在 VPS 上修改，API 中没有任何修改它们或执行命令的接口**——Token 万一泄露，对方也无法控制 VPS 或提升权限
  - 可选 IP 白名单；同一 IP 认证失败 10 次封禁 1 小时；两次重置的最小间隔；未通过校验的请求一律返回 404；审计日志
- 面板：
  - `ADMIN_PASSWORD` 机密变量；可选 TOTP 二次验证与登录 IP 白名单；同一 IP 连续失败 10 次锁定 15 分钟
  - `__Host-` 前缀 HttpOnly + Secure + SameSite=Strict 会话 Cookie，带会话版本号，可一键退出所有设备；修改密码后全部会话失效
  - 写操作要求自定义请求头并校验 Origin（防 CSRF）；页面 CSP 使用每次请求随机的 nonce，禁止内联事件与外部脚本；所有输出均转义
  - Token、TG Bot Token、TOTP 密钥只保存在 KV 中，接口不返回；导出备份需再次输入密码，并记入审计日志

> 服务器会校验请求时间，请确保 VPS 系统时间准确（误差在 5 分钟内）。

## 部署

### 方式一：Cloudflare 网页后台（无需本地环境）

1. Cloudflare 后台 → **存储和数据库 → KV** → 创建命名空间，例如 `sbyg`
2. **Workers 和 Pages → 创建 → Worker**，名称随意，部署后点击 **编辑代码**，把 [`src/worker.js`](src/worker.js) 全部内容粘贴进去并部署
3. Worker → **设置 → 绑定** → 添加 **KV 命名空间**，变量名填 `SBYG_KV`，选择第 1 步的命名空间
4. Worker → **设置 → 变量和机密** → 添加 **机密(Secret)**，名称 `ADMIN_PASSWORD`，值为面板登录密码（建议 16 位以上）
5. Worker → **设置 → 触发事件** → 添加 **Cron 触发器** `*/5 * * * *`（离线检测、每日报告、刷新节点缓存需要）
6. 打开 Worker 地址（可绑定自定义域名），输入密码登录

### 方式二：Wrangler 命令行

```bash
git clone https://github.com/yixuexiaoao/sing-box-yg-worker.git
cd sing-box-yg-worker
npx wrangler login
npx wrangler kv namespace create SBYG_KV   # 把输出的 id 填入 wrangler.toml
npx wrangler secret put ADMIN_PASSWORD
npx wrangler deploy                        # wrangler.toml 已包含每5分钟的 Cron 触发器
```

### 方式三：连接 Git 仓库自动构建（Workers Builds）

1. 先按方式一的第 1、4 步创建 KV 命名空间、设置 `ADMIN_PASSWORD` 机密
2. 把 [`wrangler.toml`](wrangler.toml) 中 `kv_namespaces` 的 `id` 改成**你自己的** KV 命名空间 ID（后台 KV 列表中可复制）
3. Workers 和 Pages → 创建 → 导入 Git 仓库，部署命令保持 `npx wrangler deploy`

> 注意：自动构建时以 `wrangler.toml` 为准，会覆盖后台手动设置的 KV 绑定、`workers_dev`、Cron 等配置；
> ID 填错会报 `KV namespace '...' is not valid [code: 10042]`。机密变量不会被覆盖。

## 添加服务器

1. 在 VPS 上一键安装 sing-box-yg 时，第六步选择开启 API（或之后运行 `sb` → **19 → 1**），按提示设置端口、权限、是否开启流量统计
2. 安装完成会显示对接 JSON（或 `sb` → **19 → 2** 查看），例如：
   ```json
   {"name": "vps1", "host": "1.2.3.4", "port": 23456, "path": "/3f9a1c2b7d4e", "token": "..."}
   ```
3. 在 VPS 后台防火墙放行该 TCP 端口
4. 面板点击 **添加服务器**，把 JSON 粘贴到第一个输入框（自动填写），保存后会立即测试连接

## 本地开发与测试

需要 Node.js 18+ 与 Python 3（测试会启动真实的 `sbagent.py`）：

```bash
# 端到端测试：Worker（用 node:net 模拟 cloudflare:sockets，内存版 KV）<-> sbagent.py
node test/e2e.mjs /path/to/sing-box-yg/sbagent.py /path/to/test/sbox
# 本地预览面板（KV 在内存中，默认密码 admin123）
node test/dev-server.mjs 8787
```

## 常见问题

- **连接服务器超时**：检查 IP/端口、VPS 防火墙与云厂商安全组；Cloudflare 不允许 Worker 连接 Cloudflare 自身 IP 段与 25 端口
- **服务器拒绝请求(404)**：Token 或 API 路径不一致（VPS 上更换过 Token 需在面板编辑同步）、来源IP不在服务器 API 白名单内或已被封禁、VPS 时间误差超过 5 分钟
- **权限不足**：服务器 API 权限只能在 VPS 上通过 `sb` → 19 → 6 修改
- **流量统计没有数据**：需在服务器「日志/流量/定时」中开启流量统计，且服务器 API 服务在运行（采集由 sbagent 完成）
- **被登录白名单锁在外面**：在 Cloudflare 后台 KV 中删除 `settings` 键即可恢复默认设置
- **Vmess 源IP 显示 127.0.0.1**：Vmess 经 Argo 隧道转发时 sing-box 只能看到本地连接；经 CDN 时看到的是 CDN 节点 IP
