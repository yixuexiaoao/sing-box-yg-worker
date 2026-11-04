# sing-box-yg-worker

部署在 Cloudflare Workers 上的 **多服务器 Web 管理面板**，配合 [sing-box-yg](https://github.com/yixuexiaoao/sing-box-yg) 脚本的 API（`sb` 主菜单 19）使用。

## 功能

- **服务器总览**：每台服务器的在线状态、Sing-box 运行状态与版本、各协议端口、系统负载/内存、日志与重置状态
- **访问日志**：按时间查看每个连接的 **源IP:端口、协议、访问目标（含嗅探到的域名）、网络类型、出站通道**；可按源IP、关键字、协议、时间段筛选；单独查看认证失败/主动探测记录；查看原始日志
- **统计**：按源IP（连接数、失败次数、首次/最近访问、常访问目标）、按访问目标（次数、来源IP数）统计，可点击进入明细
- **在线IP**：当前在线的客户端（TCP 取自 ss，Hysteria2/Tuic 取自 conntrack）
- **防泄露参数重置**：一键重置 UUID(密码)+Vmess路径、Reality 密钥与 short_id、本地订阅路径、端口（可选）；支持单台或批量；重置后返回新的节点与订阅链接，服务器自动同步 Gitlab 订阅和 TG 推送
- **定时重置 / 泄露检测**：设置每天/每周自动重置；设置“N 小时内不同源IP超过阈值”时 TG 通知或自动重置
- **其它**：重启 Sing-box、开关连接日志、清空日志、批量操作、跨服务器源IP汇总、服务器列表导入/导出

## 安全设计

- Worker 通过 `cloudflare:sockets` 直连 `服务器IP:端口`，不依赖域名与证书
- 每个请求用 **AES-256-CBC 加密 + HMAC-SHA256 签名**（密钥由服务器 Token 派生），带时间戳（±300 秒）与一次性 nonce，防窃听、防篡改、防重放；响应同样加密并与请求 nonce 绑定
- 服务器端对任何未通过校验的请求一律返回 `404`，不暴露 API 特征；API 路径随机生成
- 面板登录：`ADMIN_PASSWORD` 机密变量，HttpOnly + Secure + SameSite=Strict 会话 Cookie（12 小时），同一 IP 连续失败 10 次锁定 15 分钟；写操作要求自定义请求头防 CSRF
- Token 只保存在 KV 中，列表接口不返回 Token

> 由于服务器需要校验请求时间，请确保 VPS 系统时间准确（误差在 5 分钟内）。

## 部署

### 方式一：Cloudflare 网页后台（无需本地环境）

1. Cloudflare 后台 → **存储和数据库 → KV** → 创建命名空间，例如 `sbyg`
2. **Workers 和 Pages → 创建 → Worker**，名称随意，部署后点击 **编辑代码**，把 [`src/worker.js`](src/worker.js) 全部内容粘贴进去并部署
3. Worker → **设置 → 绑定** → 添加 **KV 命名空间**，变量名填 `SBYG_KV`，选择第 1 步的命名空间
4. Worker → **设置 → 变量和机密** → 添加 **机密(Secret)**，名称 `ADMIN_PASSWORD`，值为面板登录密码（建议 16 位以上）
5. 打开 Worker 地址（可绑定自定义域名），输入密码登录

### 方式二：Wrangler 命令行

```bash
git clone https://github.com/yixuexiaoao/sing-box-yg-worker.git
cd sing-box-yg-worker
npx wrangler login
npx wrangler kv namespace create SBYG_KV   # 把输出的 id 填入 wrangler.toml
npx wrangler secret put ADMIN_PASSWORD
npx wrangler deploy
```

## 添加服务器

1. 在 VPS 上运行 `sb`，选择 **19：API管理 → 1：安装/重启API服务**
2. 选择 **19 → 2：查看对接信息**，复制输出的整段 JSON，例如：
   ```json
   {"name": "vps1", "host": "1.2.3.4", "port": 23456, "path": "/3f9a1c2b7d4e", "token": "..."}
   ```
3. 在 VPS 后台防火墙放行该 TCP 端口
4. 面板点击 **添加服务器**，把 JSON 粘贴到第一个输入框（自动填写），保存后会立即测试连接

## 本地开发与测试

需要 Node.js 18+ 与 Python 3（测试会启动真实的 `sbagent.py`）：

```bash
# 端到端测试：Worker（用 node:net 模拟 cloudflare:sockets）<-> sbagent.py
node test/e2e.mjs /path/to/sing-box-yg/sbagent.py /path/to/test/sbox
# 本地预览面板（KV 在内存中，默认密码 admin123）
node test/dev-server.mjs 8787
```

## 常见问题

- **连接服务器超时**：检查 IP/端口、VPS 防火墙与云厂商安全组；Cloudflare 不允许 Worker 连接 Cloudflare 自身 IP 段与 25 端口
- **服务器拒绝请求(404)**：Token 或 API 路径不一致（VPS 上更换过 Token 需在面板编辑同步），或 VPS 时间误差超过 5 分钟
- **Vmess 源IP 显示 127.0.0.1**：Vmess 经 Argo 隧道转发时 sing-box 只能看到本地连接；经 CDN 时看到的是 CDN 节点 IP
