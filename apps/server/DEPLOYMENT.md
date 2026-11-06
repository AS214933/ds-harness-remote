# 部署与运维指南：多用户 + Logto

> 面向 fork 后自行部署 `apps/server` 的运维者。
> 设计依据见 [design-final-logto-multiuser.md](design-final-logto-multiuser.md)，
> MFA/激活状态的源码分析见 [research-logto-mfa-status.md](research-logto-mfa-status.md)。
>
> 本文中标注 **【实测】** 的结论，是在本地 Logto 1.46.0 + PostgreSQL 16 上真跑过的，
> 不是文档推断。

---

## 0. 先读这一节：M2M 密钥的风险

**这是整套方案最脆弱的地方，部署前必须理解。**

### 0.1 Logto 无法按 role 细分 Management API 权限

**【实测】** 自建 Logto 的 default 租户里，`management-api` 这个 API resource 只有一个 scope：

```sql
select count(*) from scopes
 where tenant_id='default' and resource_id='management-api';
-- 1
```

它只有 `all`。官方文档也写明（[M2M 快速开始](https://docs.logto.io/quick-starts/m2m)）：

> Logto provides a built-in "Logto Management API" resource, it's a **readonly resource
> with the `all` permission to access Logto Management API**

**而且这不是“尚未实现”，是 Logto 主动禁止修改：**

```json
POST /api/resources/management-api/scopes
→ 400 {"code":"resource.cannot_modify_management_api",
       "message":"Cannot modify Logto Management API."}

PATCH /api/resources/management-api
→ 400 {"code":"resource.cannot_modify_management_api"}
```

所以 Console → Applications → 你的 M2M 应用 → Roles 里，**能选的只有“分配/不分配那个含 all 的 role”，没有更细的粒度**。

### 0.1.1 ⚠️ 一个容易误判的行为

**【实测】** 向 token 端点请求一个不存在的 scope，**不会报错**：

| 请求的 scope | HTTP | 实际授予 |
| --- | --- | --- |
| `users:read` | 200 | **`None`**（空权限） |
| `password:verify` | 200 | `None` |
| `all` | 200 | `all` |
| （空） | 200 | `None` |

**陷阱**：传 `users:read` 会拿到一个 200 和一枚 token，看起来“细粒度授权成功了”，
但那枚 token **什么权限都没有**。真正的全权限只有 `all` 一个来源。

这也是 `auth/logto.ts` 里把 `scope` 硬编码为 `'all'` 的原因——
不是偷懒，是不存在别的值。

### 0.1.2 这是可预期的未来能力

Logto 官方博客（[Exploring the Management API](https://blog.logto.io/explore-management-api)）：

> It includes `all` permissions by default. **As Logto grows, we will continue to make
> permissions more granular.**

所以不要把 §0.1 当成永久约束：将来若出现细粒度 scope，
`auth/logto.ts` 里只需改 `scope` 一个字段就能收窄。**值得在升级 Logto 时复查一次**。

**这带来一个必须接受的事实：我们的 Server 只需要 3 个只读能力，却必须持有能删用户的凭据。**

| 我们实际使用的 | 泄露后额外获得 |
| --- | --- |
| 按 email 查用户 | 列出全部用户与应用、读审计日志、读 webhook 配置 |
| 校验密码 | **重置任意用户密码** |
| 读用户角色 | **停用 / 删除任意用户**、**新建应用**、**新建 webhook** |

### 0.2 泄露后的实际影响 —— 【实测】清单

用一个正常签发的 M2M token 逐项验证：

```
200  list users / applications / connectors / roles / organizations
200  read audit logs / jwt customizer / hooks
200  ** overwrite a user's password **
200  ** suspend a user **
204  ** delete a user **
201  ** create a new application **   ← 持久化
201  ** create a webhook **           ← 持久化，持续窃取
401  admin tenant (不同 audience，被挡住)
```

**结论：M2M 密钥泄露 = 整个 Logto 租户被接管。**

而且**新建应用和 webhook 是持久的**：你轮换了 secret 之后，攻击者留下的应用和 webhook 仍然存在。

### 0.3 因此必须做的四件事

1. **不要让 M2M 凭据进入任何客户端**。它只在 Server 进程内，永不写入日志、永不返回给前端。
   （`auth/logto.ts` 里已保证：凭据只用于构造 `Basic` 头，错误信息只带状态码。）
2. **Server 与 Logto 之间走内网**。能放同一台机器或同一 Docker network 就不要走公网。
3. **定期轮换**：Console → 应用 → 重新生成 secret。轮换后记得查有没有多余的应用和 webhook。
4. **开启 Logto 的审计日志并定期看**：`GET /api/logs`（我们自己的凭据就能读，说明攻击者也能）。

### 0.4 泄露后的应急步骤

```bash
# 1. 立即轮换 M2M secret（Console → 应用 → Regenerate）
# 2. 用新 secret 重启 Server
docker compose up -d --force-recreate server

# 3. 清查持久化后门（这两项攻击者可以留）
#    - 应用列表里有没有你不认识的 Machine-to-machine 应用
#    - Webhook 列表里有没有指向陌生 URL 的条目
```

官方 Console 路径：Applications / Webhooks 两个页面逐个核对。

---

## 1. 前置要求

| 项 | 要求 | 说明 |
| --- | --- | --- |
| Node.js | 22+ | 与 `apps/server` 的 Dockerfile 一致 |
| Logto | 1.46+ | 更早版本未验证；MFA 行为在 1.46 实测 |
| PostgreSQL | 14+ | Logto 自己需要 |
| **Logto 租户** | **必须是 default 租户** | 见 §2.1，这是最容易踩的坑 |

---

## 2. Logto 侧配置（一次性）

### 2.1 【实测】自建 Logto 有两个租户，别搞混

自建 Logto 同时监听两个端口，它们是**两个独立的租户**：

| 端口 | 租户 | API indicator | 存的是什么 |
| --- | --- | --- | --- |
| **3001**（默认） | `default` | `https://default.logto.app/api` | **你的终端用户** |
| 3002 | `admin` | `https://admin.logto.app/api` | 只有 Console 管理员 |

**实测后果**：

- 在 default 租户建的 M2M 应用 → **只有 :3001 能签发 token**，打 :3002 报 `invalid_client`
- 拿 default 的 token 打 :3002 的 API → `401 JWTClaimValidationFailed`（`aud` 不符）
- 种子数据自带的 `m-default` / `m-admin` / `Cloud Service` **都挂在 admin 租户下**，不能操作 default 租户的用户

> **Cloud 版没有这个问题**（单租户单端点），所以官方文档里完全看不出这个坑——**自建特有**。

### 2.2 建 M2M 应用

```
Console（default 租户）→ Applications → Create application → Machine-to-machine
```

⚠️ **M2M role 与 User role 不能混用，且创建后不能改类型。**

### 2.3 绑定 role

应用详情页 → Roles → 分配 **`Logto Management API access`**（新租户自带，已含 `all`）。

这是唯一可用的授权方式（§0.1）——没有更细的粒度。

### 2.4 记录四个值

```
LOGTO_ENDPOINT          = http(s)://<default 租户地址>      # 不是 admin 端口
LOGTO_M2M_CLIENT_ID     = <App ID>
LOGTO_M2M_CLIENT_SECRET = <App Secret>
LOGTO_API_RESOURCE      = https://default.logto.app/api     # 固定值
```

### 2.5 【实测】冒烟验证，别跳过

```bash
# 换成你自己的四个值
python3 docs/verify_logto.py
```

期望输出：

```
STEP 1 M2M token            → 200
STEP 4 verify 正确密码      → 204
STEP 5 verify 错误密码      → 422
STEP 6 停用用户 + 正确密码  → 204   ← 关键：确认停用不挡
```

**若 STEP 1 报 `invalid_client`** → 你建在了 admin 租户，或端点端口用错了。
**若 STEP 1 返回 400 但另一个端口是 200** → 就是租户/端口错配。

### 2.6 配置 Webhook（可选，但推荐）

不加 webhook 也能用，但**被停用的用户最长要等 8 小时** token 过期才被挡住。
加了之后是秒级。

**Console → Webhooks → Create webhook：**

| 字段 | 值 |
| --- | --- |
| Name | 任意，例如 `dsh-remote-revoke` |
| **Endpoint URL** | `https://你的域名/api/v1/hooks/logto`（**必须公网 HTTPS**） |
| **Events** | 只选两个：**`User.Deleted`** 与 **`User.SuspensionStatus.Updated`** |

创建后在 webhook 详情页：

1. 找到 **Signing key**，复制
2. 填进 Server 的 `LOGTO_WEBHOOK_SIGNING_KEY`

**然后配置 Server 的环境变量：**

```dotenv
LOGTO_WEBHOOK_SIGNING_KEY=<从 Console 复制的签名密钥>
```

**验证：** Console 里的 **"Send test payload"** 按钮会发一个测试事件。
Server 返回 200 即通。

> ⚠️ **Logto 要求 Endpoint URL 是公网可达的 HTTPS。** 本地 `http://127.0.0.1`
> 或内网 IP 会被拒绝投递（实测：hook 触发但投递失败）。
> 所以 webhook 这条链路**必须暴露公网**，这和我们把 Logto 放内网的建议（§0.3）
> 是不同方向的——**Server 要能被 Logto 回调，Logto 不需要被 Server 之外访问**。

**不配 webhook 的替代方案：** 缩短 `expiresAt`。当前 Web 会话 8 小时；
若可接受更短，改 `server.ts` 里的 `8 * 3600_000`。设备 access token 是 1 小时。

### 2.7 Webhook 的可靠性边界

| 事实 | 影响 |
| --- | --- |
| 只对 **≥500** 的响应重试，最多 3 次 | 返回 401/403/404 **不会**重试，那是永久失败 |
| 重试共享同一个 `deliveryId` | 幂等处理需要时可据此去重 |
| **不能阻断登录** | 异步投递，所以登录路径仍必须自查 `isSuspended` |
| 投递失败无人提醒 | 要定期看 Console 的 health status 与 recent requests |

**所以 webhook 只是缩短窗口，不是唯一控制。** 登录时的 `isSuspended` 检查是兜底。

---

## 3. Server 配置

### 3.1 环境变量

```dotenv
# --- Logto（全部配置后才会启用 Logto 登录） ---
LOGTO_ENDPOINT=https://logto.example.com
LOGTO_M2M_CLIENT_ID=<app id>
LOGTO_M2M_CLIENT_SECRET=<app secret>
LOGTO_API_RESOURCE=https://default.logto.app/api
LOGTO_ADMIN_ROLE=admin

# --- Webhook（可选；配置后停用/删除用户秒级生效） ---
LOGTO_WEBHOOK_SIGNING_KEY=<Console → Webhooks → Signing key>

# --- 以下仍然必填，即使已启用 Logto ---
DSH_SERVER_ACCOUNT=owner@example.com
DSH_SERVER_PASSWORD=<至少 12 字符>
DSH_SERVER_PUBLIC_URL=https://remote.example.com
DSH_SERVER_DATA_FILE=/data/state.json
```

### 3.2 为什么 `DSH_SERVER_ACCOUNT` / `PASSWORD` 还得留

它们有两个作用：

1. **回退路径**：`LOGTO_ENDPOINT` 没配时，用它们做原来的单账号比对
2. **首次登录的“收养”依据**：第一个通过 Logto 登录的人会**接管**环境账户名下的设备，
   这样升级时已配对的设备不会失联

> 配了 Logto 之后，`DSH_SERVER_PASSWORD` 不再是登录凭据（登录由 Logto 决定），
> 但仍要求存在且长度 ≥12，用于兼容与状态文件校验。

### 3.3 Logto 未配置时的行为

**完全走原来的环境变量单账号比对，行为一字不变。** 升级不会影响现有部署。

### 3.4 关于 `.env.example`

`apps/server/.env.example` 是**凭据类文件**，本仓库的工具链拒绝自动改写它。
请**手工**把 §3.1 的五个 `LOGTO_*` 变量追加进去，或直接写进你的 `.env`：

```dotenv
# --- Logto（可选；全部配置后启用） ---
LOGTO_ENDPOINT=https://logto.example.com
LOGTO_M2M_CLIENT_ID=<app id>
LOGTO_M2M_CLIENT_SECRET=<app secret>
LOGTO_API_RESOURCE=https://default.logto.app/api
LOGTO_ADMIN_ROLE=admin
```

> 只要 `LOGTO_ENDPOINT` 为空，Server 就退回环境单账号模式。

---

## 4. 升级与迁移

### 4.1 启用 Logto 的那一刻会发生什么

**【实测】** 第一个通过 Logto 登录的用户会**收养**环境账户：

```
之前：账户 owner@example.com 拥有 3 台设备
之后：同一个账户（外部 id = 第一次登录的 Logto user.id）仍拥有这 3 台设备
```

**不需要重新配对任何设备。** 这条路径有测试守着（`tests/store.test.ts`）。

### 4.2 第二个用户登录时

会得到**自己的新账户**，看不到第一个人的设备。收养只发生一次。

### 4.3 设备凭据的兼容性

`state.json` 里的 token 只绑 `deviceId`、不绑账户，所以原样搬迁后**老设备继续用旧 token 工作**。

### 4.4 部署步骤

```bash
# 1. 备份（迁移会原地改写 state.json）
cp /data/state.json /data/state.json.bak

# 2. 写好 .env（§3.1），然后重建
docker compose up -d --force-recreate server

# 3. 用一台真实设备验证还能连上  ← 最关键的一步
```

> `docker compose restart` **不会**重新加载环境变量，必须 `--force-recreate`。

### 4.5 回滚

```bash
# 改回不含 LOGTO_* 的 .env，然后
docker compose up -d --force-recreate server
# 若 state.json 已被改写且你需要旧格式，用备份恢复
cp /data/state.json.bak /data/state.json
```

> 注意：迁移是单向的（v1 → v2）。回滚到旧版本二进制前要先恢复 `state.json` 备份，
> 否则旧版本无法解析 v2 格式。

---

## 5. 需要知道的产品行为

### 5.1 2FA / passkey 在本服务不生效

**这是刻意的设计**，不是缺陷。

客户端（Host 插件、Android、浏览器扩展、VS Code）不支持两步验证，只发 email+password。
Server 用 Logto 的 `password/verify` 校验，该接口是**纯哈希比对**，不触发 MFA。

**【实测】** TOTP 用户和 passkey 用户都能用密码正常登录。

**安全含义**：用户即使在 Logto 开了 2FA，通过本服务登录时**只用了密码这一步**。
密码仍然必须正确，所以不是漏洞，但**降低了预期的保护强度**。

**建议写进你的部署说明**，让用户知情。

### 5.2 停用用户会被拒绝

**【实测】** `password/verify` 对停用用户仍返回 204，所以 Server 自己查 `isSuspended`。
停用用户在登录时拿到 `403 ACCOUNT_SUSPENDED`。

### 5.3 错误码语义

| 情况 | HTTP | code |
| --- | --- | --- |
| 密码错 / 邮箱不存在 / 匹配到多个 | 401 | `AUTH_INVALID` |
| 账号被停用 | 403 | `ACCOUNT_SUSPENDED` |
| 连续失败超过阈值 | 429 | `ACCOUNT_LOCKED`（带 `Retry-After`） |
| 限流 | 429 | `RATE_LIMITED` |
| Logto 不可达 | 503 | `AUTH_SERVICE_UNAVAILABLE` |

**503 与 401 的区分很重要**：Logto 故障返回 401 会让客户端提示用户重新输入一个
其实正确的密码。

**`ACCOUNT_LOCKED` 是新错误码**。老客户端不认识它，会落到通用的「登录失败」分支——
行为是可接受的（用户确实登不进去），但比不上专门的提示。如果你在意，
可以改成复用 `RATE_LIMITED`（客户端可能已有针对 429 的重试提示）。当前选择
`ACCOUNT_LOCKED` 是为了让日志和排错能区分「限流」与「锁定」。

### 5.4 Webhook 触发后发生什么

用户被删除或被停用时：

1. 该账户的**所有设备**标记为 `revoked` —— 注意是**撤销**，不只是断开连接
2. 该账户的**所有 token** 被删除（设备用旧 token 立即失效）
3. 账户 `status` 置为 `suspended`

**为什么用撤销而不是断开**：一个被停用的用户如果只是被断开，他带着仍然有效的
token 重连会**直接走回来**——因为 `password/verify` 看不见停用状态。

**恢复时需要运维手工介入**：把账户 `status` 改回 `active`，
然后让用户**重新配对设备**。设备不会自动解封，这是刻意的——
被撤销的设备可能对应一枚已泄露的 token。

---

## 6. 安全行为与限制

### 6.1 已有的防护

| 防护 | 做法 |
| --- | --- |
| 用户枚举（错误码） | 密码错与邮箱不存在返回同一个 401 |
| 用户枚举（时序） | 所有失败路径统一补到 700ms 预算【实测：修复前差 17 倍】 |
| 暴力破解（单来源） | 单地址 20/min |
| 暴力破解（换地址） | 每账户 60/min |
| **持续慢速猜测** | **连续失败 25 次 → 锁定 5 分钟** |
| 跨账户越权 | `connect.request` 校验账户归属，回 `HOST_OFFLINE` 而非新增错误码 |
| 存在性探测 | 外部设备返回 404，与不存在完全一致 |
| 密码变更后设备失效 | 环境密码变化时清空 tokens |
| 停用/删除后立即失效 | 配 Webhook 时秒级；否则等 token 过期 |

#### 关于锁定阈值的层级关系

三层限制的数值是**刻意分层**的，不要随意调低某一层：

```
单地址   20/min  ← 挡住单一来源
每账户   60/min  ← 挡住轮换地址
连击锁   25 次   ← 挡住持续慢速猜测
```

**每账户必须 > 单地址**：否则单地址 20 次的预算永远用不到，行为被悄悄改掉。
**锁定阈值必须 > 单地址**：同理，否则它先触发，锁定就变成了"改了限流语义"。

我开发时两次踩到这个坑（先设每账户 10、后设锁定 8），都是既有测试抓出来的。
如果你要调整，**先跑 §7 的回归**。

#### 锁定不是永久的

锁定 **5 分钟后自动解除**，并且**成功登录会清空连击数**。
理由：永久锁定会让任何人都能对任意邮箱做拒绝服务。

**副作用**：锁定状态在内存里，**重启会清空**。这是刻意的取舍——窗口很短，
持久化会让每次失败登录都写一次盘。

### 6.2 时序对齐是个需要跟着环境走的常数

`auth/logto.ts` 里 `FAILURE_BUDGET_MS = 700` 是按 **Logto 1.46 + 本机 argon2 成本**实测定的。

**如果你换了 Identity Provider，或改了 Logto 的密码哈希成本，要重新实测。**
`tests/logto.integration.test.ts` 里有断言（三条失败路径相互差 < 2.5 倍），跑一遍就知道要不要调。

### 6.3 没有做的

- **密码过期检查**：本部署未启用该策略，代码里主动跳过（省一次网络调用、少一个失败面）。
- **Webhook 的去重**：`deliveryId` 收到了但没用来做幂等。吊销是幂等操作
  （重复吊销同一账户无副作用），所以不值得为此加状态。
- **账号级「永久封禁」**：只做到「撤销所有设备 + 账号置 suspended」。
  恢复需要运维手工把 `accounts.status` 改回 `active`，
  **被撤销的设备不会自动恢复**（这是刻意的，见 §5.4）。
- **锁定状态的持久化**：见 §6.1 最后一段。

---

## 7. 冒烟与回归

### 7.1 部署后必做

```bash
# 1. 健康检查
curl -fsS https://remote.example.com/healthz

# 2. 真实登录（用 Logto 里的一个账号）
curl -s -X POST https://remote.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"..."}' | head -c 300
# 期望：含 token / account / expiresAt / isAdmin

# 3. 用一台真实设备（Host 插件）连接验证
```

### 7.2 升级 Logto 后必跑

```bash
# 重新播种测试用户（幂等，可反复跑；探测脚本可能删过账号）
cd apps/server/tools
python3 seed_for_ts_test.py

python3 ../../../docs/verify_logto.py    # 核心链路（或按你的路径调整）
python3 ../../../docs/verify_mfa.py      # MFA / 停用 / 删除
```

> 集成测试依赖固定的测试账号（`t_happy@example.com` 等）。
> 如果之前跑过 §0.2 那种影响范围探测脚本，账号可能已被删除，
> 先用 `seed_for_ts_test.py` 重建。

**这三条断言任何一条变化，整套认证就失效：**

1. `password/verify` 仍**不**检查 `isSuspended`
2. `password/verify` 仍**不**检查 MFA
3. `mode.primaryEmail=exact` 仍**是**精确匹配

> 它们目前是“对我们有利的未检查”。Logto 哪天收紧了，我们的方案会**静默失效**——脚本就是防线。

### 7.3 升级 Logto 后额外复查：细粒度权限是否已出现

```bash
cd apps/server/tools
python3 probe_scope_narrowing.py
```

关注第 1 节输出：如果 `management-api` 的 scope 不再是单个 `management-api-all`，
说明 Logto 开始提供细粒度权限（§0.1.2）。**那时应该把 `auth/logto.ts` 的 `scope`
从 `all` 收窄到只需要的那几个**，这是降低泄露影响范围最直接的一次机会。

### 7.4 评估泄露影响范围

```bash
cd apps/server/tools
python3 probe_blast_radius.py <client_id> <client_secret>
```

用一份 M2M 凭据逐项验证它实际能做什么（只读、写、持久化后门）。

> ⚠️ 这个脚本**会真的删除用户**（为了验证 `DELETE` 可达）。**只对测试租户运行**，
> 或用后重新播种测试账号（§7.2）。

---

## 8. 排错

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 登录返回 503 | Logto 不可达或 M2M 凭据错 | 查 `LOGTO_ENDPOINT` 与 secret；跑 `verify_logto.py` |
| 登录返回 401，但密码确实对 | 可能匹配到多个用户（`AUTH_AMBIGUOUS` 并入 401） | 查 Logto 里该 email 是否有重复账号 |
| `invalid_client` | 建在了 admin 租户，或端口用错 | 见 §2.1 |
| `JWTClaimValidationFailed: aud` | token 与端点的 `resource` 不匹配 | `LOGTO_API_RESOURCE` 用 `https://default.logto.app/api` |
| 升级后设备全部离线 | 迁移未生效或账户名变了 | 检查 `state.json` 的 `version` 是否为 2；确认没改 `DSH_SERVER_ACCOUNT` |
| 登录后看不到设备 | 登录的是第二个账户 | 正常行为（§4.2）；用原账户登录 |
| `server could not listen` | 端口被占 | 查 `DSH_SERVER_PORT` |
| 登录返回 429 `ACCOUNT_LOCKED` | 该账户连续失败达阈值 | 等 5 分钟；或重启 Server 清空（状态在内存） |
| Webhook 在 Console 显示失败 | Endpoint URL 不是公网 HTTPS，或签名密钥不匹配 | 查 §2.6；本地地址会被拒绝投递 |
| Webhook 一直不触发 | 事件没选对 | 必须选 `User.Deleted` + `User.SuspensionStatus.Updated` |
| 停用用户仍能连 | 没配 webhook 且 token 未过期 | 等过期，或配 webhook（§2.6） |

---

## 9. 与上游的关系

你 fork 后维护的 `apps/server` 已偏离上游：

- 上游 `AGENTS.md` 明确**禁止**在本仓库实现完整多账号 Server 与数据库/migration
- 我们是 fork 的运营者，按自身需求实现
- **后果**：`apps/server` 后续基本无法直接 merge 上游改动，需手工取舍

**不要对外宣称这个 fork 与上游自部署版本行为一致。**

---

## 10. 上线检查表

- [ ] Logto 里确认是 **default 租户**（§2.1）
- [ ] M2M 应用已绑定含 `management-api-all` 的 role
- [ ] `LOGTO_API_RESOURCE` = `https://default.logto.app/api`
- [ ] `verify_logto.py` 与 `verify_mfa.py` 全绿
- [ ] Server 与 Logto 之间是内网（§0.3）
- [ ] M2M 凭据不在任何客户端、日志、仓库里
- [ ] `state.json` 已备份
- [ ] 迁移后**抽查一台真实设备**仍能连上
- [ ] 部署文档写明了「2FA 在本服务不生效」
- [ ] （可选）Webhook 已配置：`/api/v1/hooks/logto` 可从公网访问、签名密钥已填、
      Console 的 test payload 返回 200
- [ ] 知道泄露后的应急步骤（§0.4）：轮换 secret + 清查应用与 webhook
