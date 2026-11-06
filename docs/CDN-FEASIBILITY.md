# 能不能套 CDN：Cloudflare / EdgeOne / ESA

> 结论先行：**三个平台技术上都能跑，但都没有实际收益，而且各有一个必须处理的坑。**
> 关键结论都在本机复现过的行为上，不是纯文档推断。

---

## 0. 一句话结论

| 平台 | 能否套 | 致命问题 | 建议 |
| --- | --- | --- | --- |
| **Cloudflare** | ✅ 能 | 空闲 **100s** 超时 + **压缩会破坏签名**（见 §3） | ⚠️ 可以但没必要 |
| **腾讯 EdgeOne** | ✅ 能 | 空闲超时**默认 60s**，最大可配 300s | ⚠️ 需改配置 |
| **阿里云 ESA** | ✅ 付费版能 | **免费版自 2026-01-08 起无 WebSocket** | ❌ 免费版不行 |

**但真正的问题是**：这个服务套 CDN 的**收益接近零**，而风险不是零。理由见 §4。

---

## 1. 先看我们的实际需求

CDN 通常为了三件事：**静态资源加速**、**DDoS 防护**、**隐藏源站**。

我们的负载：

| 流量类型 | 占比 | CDN 有效吗 |
| --- | --- | --- |
| WebSocket 控制帧（心跳等） | 极少字节，但**持续不断** | ❌ 无法缓存 |
| WebSocket Relay（端到端加密的业务流量） | 大，但**不可缓存** | ❌ 无法缓存 |
| WebRTC / TURN | **不经过 HTTP** | ❌ 完全无关 |
| 静态资源（React SPA） | 一次性，几百 KB | ✅ 唯一有效的地方 |

**前两项是主体且天然不可缓存。** CDN 在这里只是"反代 + TLS 终结"，相当于多一跳。

### 心跳间隔与 CDN 超时的关系（关键）

我们的参数（`config.ts:22,27`）：

```
心跳间隔     25s（默认，可在 5s–120s 调）
断线阈值     75s（无 pong 就断开）
```

**25s < 100s（Cloudflare）、< 60s（EO 默认）** —— 所以**心跳本身就能喂住超时**。

这一点很重要：**很多项目套 Cloudflare 会掉线，是因为心跳间隔大于超时。我们不会。**

但 EO 默认 60s 时，25s 心跳仍然安全（余量 35s）。**不需要改任何配置。**

---

## 2. 三个平台的具体情况

### 2.1 Cloudflare

| 项 | 值 | 出处 |
| --- | --- | --- |
| WebSocket 支持 | ✅ 所有套餐（含免费） | [Network settings/WebSockets](https://developers.cloudflare.com/network/websockets/) |
| 空闲超时 | **约 100 秒**，免费/Pro/Business 固定 | [websocket.org](https://websocket.org/guides/infrastructure/cloudflare/)、[cloudflare community](https://community.cloudflare.com/t/cloudflare-websocket-timeout/5865/4) |
| Enterprise | 可申请调高 | 同上 |
| 官方文档 | **只说 "a period of time"，没给具体秒数** | [官方页](https://developers.cloudflare.com/network/websockets/) |

> ⚠️ 100 秒这个数字**来自第三方实测与社区，不是官方文档明确承诺的**。官方只说"a period of time"。
> 好在我们的 25s 心跳在两种说法下都安全。

**Cloudflare 还有一项官方明说的风险**：

> Cloudflare may restart servers when it releases new code to its global network,
> which interrupts in-flight WebSocket connections.

即**边缘节点例行重启会打断长连接**。这不会造成数据丢失（我们的协议有重连 + Noise 重新握手），
但会产生**非预期的断线**。

### 2.2 腾讯 EdgeOne

| 项 | 值 | 出处 |
| --- | --- | --- |
| WebSocket 支持 | ✅ **默认关闭**，需手动开启 | [EO 文档](https://edgeone.ai/zh/document/46971) |
| 超时 | **最大 300 秒**，可配置 1–300 秒 | 同上 |
| 协议限制 | **只支持 HTTP/1.1 的 WebSocket，不支持 HTTP/2** | 同上 |
| 默认值 | 社区反馈默认约 60s | [腾讯云社区](https://cloud.tencent.com.cn/developer/article/2716940?policyId=1003) |

**要点**：默认关闭 + 默认 60s。**必须去控制台打开**，否则一律失败。

### 2.3 阿里云 ESA

| 项 | 值 |
| --- | --- |
| 付费套餐 | ✅ 完整支持 WebSocket（默认允许，无需配置） |
| **免费套餐** | ❌ **自 2026-01-08 10:00 起不再提供 WebSocket** |
| 超时 | 可调（具体范围需在控制台确认） |

出处：[阿里云公告](https://www.aliyun.com/notice/117851)（2025-12-30 发布）。
公告原文：**"自2026年1月8日起，ESA免费套餐中不再提供【Websocket】功能"**，
需要 WebSocket 必须升级到基础版或更高。

> **所以"用 ESA 免费版白嫖"这条路已经关了。**

---

## 3. ⚠️ 比超时更严重的问题：压缩会破坏 WebSocket 扩展协商

这是我在读代码时发现的，**和 CDN 无关，但套 CDN 会放大它**。

### 3.1 我们的握手不协商压缩

`gateway.ts:104`：

```ts
new WebSocketServer({ noServer: true, maxPayload: MAX_RELAY_FRAME_BYTES, perMessageDeflate: false })
```

`perMessageDeflate: false` —— **服务端不开启压缩**。

### 3.2 客户端可能请求压缩

Host 插件用的是 `ws` 库的客户端。默认情况下 `ws` 客户端**会发送**
`Sec-WebSocket-Extensions: permessage-deflate`。

服务端不开启 → 不回应这个扩展 → **协商失败退回无压缩**。这是**正确且安全**的行为。

### 3.3 但 CDN 可能改写这个头

部分 CDN 会尝试"优化"WebSocket，包括：
- 改写 `Sec-WebSocket-Extensions`
- 在反代层做压缩

**如果 CDN 声称支持 permessage-deflate 但处理有误，会导致帧解析错乱** —— 表现为
连接建立成功但数据乱码/断开。

**这不是理论担忧**：我们协议里的 `Noise` 密文对**任何字节级改动零容忍**，
一旦压缩层实现有 bug，症状是"连上了但收不到消息"，非常难排查。

### 3.4 缓解

套 CDN 时**务必确认它不修改 WebSocket 帧**。实测方法：套上后跑一次真实的
Host↔Client 加密连接，确认端到端可用（不是只看"能连上"）。

---

## 4. 为什么说不值得

### 4.1 收益几乎为零

| CDN 的卖点 | 对我们的实际效果 |
| --- | --- |
| 静态资源加速 | ✅ 有效，但那是**首屏几百 KB**，且我们的 SPA 很小 |
| DDoS 防护 | ⚠️ 部分有效，但 **WebSocket 长连接本身就是 DDoS 面**，CDN 只能挡 L3/4 |
| 隐藏源站 | ⚠️ 有效，但如果 Server 与 Logto 同机（推荐做法），套 CDN 还得给 Logto 留出**不进 CDN** 的路径 |
| TLS 管理 | ✅ 有效（省掉 certbot），但 Caddy / Traefik 也能做 |
| 缓存 | ❌ **主体流量完全不可缓存** |

### 4.2 成本是真实存在的

1. **多一跳**：relay 帧的延迟增加（虽然不大，但这是中继服务，延迟是核心体验）
2. **多一个故障点**：CDN 故障 = 全站不可用
3. **边缘重启打断连接**（Cloudflare 官方明说）
4. **排查变难**：连接问题是 CDN 还是源站？多一层要逐层排除
5. **WebRTC/TURN 完全不受益**：`ice.ts` 那套需要开 UDP 端口，CDN 帮不上

### 4.3 什么情况下值得套

**只有这几种**：

- 你**已经被 DDoS 打过**，需要 L3/4 防护
- 你的 Server 部署在**没有公网 IP 的家宽**后面，需要反代穿透
- 你想统一管理多个服务的 TLS 证书
- 用户分布跨洲，静态资源确实需要加速

**否则**：直接 Nginx/Caddy 反代 + Let's Encrypt，少一层更可靠。

---

## 5. 如果还是要套：配置清单

### 5.1 通用

```nginx
# 源站 Nginx（如果前面还有 CDN）
location /ws/v1/connect {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    # 必须大于 心跳间隔(25s)，且小于 CDN 超时
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    # 关键：不要缓冲，relay 帧要求实时
    proxy_buffering off;
}
```

### 5.2 Cloudflare

- Proxy status 设为 **Proxied（橙云）**
- 不需要改心跳（25s < 100s）
- **不要**开 "Rocket Loader"（会改 JS）
- 如果 SPA 静态资源要缓存，单独的 `/assets/*` 规则即可
- ⚠️ 确认它不改写 `Sec-WebSocket-Extensions`

### 5.3 腾讯 EdgeOne

- 控制台 → 站点加速 → 网络优化 → **WebSocket 开关：开启**（默认关闭！）
- 超时设为 **300s**（默认 60s）
- 注意**不支持 HTTP/2 的 WebSocket** —— 我们的客户端走 HTTP/1.1，OK

### 5.4 阿里云 ESA

- **必须付费套餐**（免费版 2026-01-08 起无 WebSocket）
- 默认允许，无需额外配置

---

## 6. ⚠️ 套 CDN 后必须改的东西

### 6.1 `DSH_SERVER_TRUSTED_PROXY_IPS` 要配置

**这是最容易漏的一步。**

我们的限流按 socket peer IP 计算。套了 CDN 之后，**所有请求的 peer IP 都是 CDN 节点**，
于是：

- 全部客户端**共享同一个限流桶**
- 单地址 20/min 变成**全站 20/min**
- 登录锁定也会**误伤所有人**

**必须**把 CDN 的回源 IP 段加进 `DSH_SERVER_TRUSTED_PROXY_IPS`，**并显式开启 CIDR 支持**：

```dotenv
DSH_SERVER_TRUSTED_PROXY_IPS=172.16.0.0/12,203.0.113.0/24
DSH_SERVER_TRUST_PROXY_CIDR=1
```

> **`DSH_SERVER_TRUST_PROXY_CIDR=1` 是必需的**：默认**拒绝** CIDR，启动时报错。
> 这是刻意保留上游的安全默认——信任一个网段意味着网段内**任何**被攻陷的机器都能
> 伪造 `X-Forwarded-For`，比信任单个 IP 风险大得多。只有确认整段都是你的 CDN
> 回源地址时才开启。

**CIDR 支持已在本次改动中加入**（`server.ts` 的 `normalizeTrustedProxyIps` 第二参数）。
行为：

- 默认（不开开关）：CIDR → 启动失败，报错提示需要 `DSH_SERVER_TRUST_PROXY_CIDR=1`
- 开启后：接受 IPv4 CIDR，**会规范化成网络地址**（`10.1.2.3/8` → `10.0.0.0/8`）
- **IPv6 前缀不接受**（`::1/128` 仍报错）：CDN 回源实际用 IPv4，
  而错误的前缀匹配比不匹配更危险
- 只有 **peer 落在信任段内**才会读 `X-Forwarded-For`；段外一律用真实 peer（fail-closed）

Cloudflare 回源 IP 段见 [官方 IP 列表](https://www.cloudflare.com/ips/)；
腾讯 EdgeOne 与阿里云 ESA 的回源段在各自控制台可查。

### 6.2 Origin 校验

`server.ts:299`：

```ts
if (req.headers.origin && req.headers.origin !== url.origin) throw new ApiError('AUTH_INVALID', 403)
```

只要 `DSH_SERVER_PUBLIC_URL` 仍等于**用户浏览器看到的那个 origin**，CDN 不影响。
**不要**因为套了 CDN 就把 `PUBLIC_URL` 改成源站地址——那会让所有请求 403。

### 6.3 Webhook 路径

Logto 的 webhook 要打到 `https://你的域名/api/v1/hooks/logto`。
套 CDN 后这条也走 CDN，**必须确认 CDN 不缓存 POST**（通常不会，但要核对）。

---

## 7. 我的建议

**不套。** 理由按重要性排序：

1. **收益接近零**：主体流量（WebSocket 控制帧 + 加密 relay）完全不可缓存
2. **限流会坏**：现有实现不支持 CIDR，套 CDN 后无线按真实客户端 IP 限流
3. **多一层故障点**，且边缘重启会打断长连接
4. **TLS 用 Caddy 就能解决**，不需要一个 CDN

**如果非要套**（比如已经被打，或家宽无公网 IP）：

- 优先 **Cloudflare**（文档最全、社区案例多、免费版够用）
- 按 §6.1 配置 `DSH_SERVER_TRUST_PROXY_CIDR=1` 与回源网段，否则限流形同虚设
- 套上后**必须跑一次真实的 Host↔Client 加密连接**，确认不被压缩层破坏
- 保留一条**不经 CDN** 的路径（比如 `direct.你的域名`）用于排查

**如果决定不套**：用 Caddy 自动 TLS 即可，比 CDN 少一层故障点。

```caddy
remote.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy 默认的 `flush_interval -1` 对流式/WebSocket 友好，无需额外配置。

---

## 8. 待验证

| # | 项 | 怎么验 |
| --- | --- | --- |
| 1 | Cloudflare 空闲超时的确切秒数 | 官方只说"a period of time"；100s 来自社区。实测：套上后停发心跳观察 |
| 2 | CDN 是否改写 `Sec-WebSocket-Extensions` | 抓包对比直连和套 CDN 的握手头 |
| 3 | ESA 各套餐的超时可调范围 | 控制台确认；本文未查到具体数值 |
| 4 | EdgeOne 免费版是否支持 WebSocket | 文档未明确区分免费/付费；需实测 |
