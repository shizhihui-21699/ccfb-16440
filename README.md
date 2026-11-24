# VideoConf Admission — Elixir 入会身份校验与防闯入核心

一个不依赖外部服务即可运行的 Elixir/OTP 核心服务，覆盖：

- 九位会议号的安全生成与枚举猜测防护
- 入会口令、电话/PSTN 数字 PIN
- OIDC/SSO 组织身份校验与按组织限制
- 外部嘉宾的短期签名邀请令牌
- 等候室、单个审批、拒绝、一键全部放行
- 会中一键锁定；主持人和有效断线重连票据可进入
- 短期媒体票据与原子容量统计
- 面向万人发布会的 ETS 并发读、无单会议串行进程、批量放行游标

> 九位会议号只有约 9 亿种组合，因此它只能作为“便于输入/拨号的标识符”，不能作为安全边界。真正的边界是：组织身份、口令/PIN、嘉宾令牌、速率限制、风险验证和主持人审批。

## 运行与测试

```bash
mix deps.get          # 本项目当前无外部依赖
mix test
```

测试包含一个 10,000 并发入会用例和一个 10,000 人等候室批量放行用例。最近一次本机结果：

```text
10k join decisions: ~90-100 ms total, ~100k joins/s（测试环境，HMAC 快路径）
24 tests passed
```

该数字是进程内核心策略吞吐，不包含 HTTP/TLS、数据库、WebRTC 信令和媒体链路；生产容量仍需水平扩展这些层。

## 30 秒体验

```bash
iex -S mix
```

```elixir
# 主持人的 SSO 断言；生产环境应替换为 OIDC/JWT 验签
host = VideoConf.host_assertion("host-1", "acme")

{:ok, meeting} =
  VideoConf.create_meeting(%{
    org_id: "acme",
    host_id: "host-1",
    passcode: "secret-code",
    dial_in_pin: "246810",
    waiting_room?: true
  })

# 组织成员：SSO 断言证明组织身份，默认自动放行
alice_assertion = VideoConf.Identity.issue_assertion(%{
  principal_id: "alice",
  org_id: "acme"
})

VideoConf.join(%{
  meeting_id: meeting.id,
  assertion: alice_assertion,
  source_ip: "203.0.113.10"
})

# 外部访客：进入等候室
waiting =
  VideoConf.join(%{
    meeting_id: meeting.id,
    source_ip: "198.51.100.7",
    identity: VideoConf.Identity.new(principal_id: "guest-1", display_name: "Li")
  })

VideoConf.approve(meeting.id, waiting.waiting_id, host)
VideoConf.poll_waiting(waiting.waiting_token)

# 一键锁定
VideoConf.lock(meeting.id, host)

# 电话拨入：会议号 + 数字 PIN
VideoConf.dial_in(%{
  meeting_id: meeting.id,
  pin: "246810",
  call_id: "pstn-call-123",
  caller_number: "+15550101234"
})
```

## 核心设计

### 1. 会议号生成与枚举防护

`VideoConf.Credentials.generate_meeting_id/0` 使用 `:crypto.strong_rand_range/1` 生成 `100000000..999999999` 的九位编号，冲突时由 Store 重试。

枚举防护是多层的：

1. 每个来源 IP/设备和主体有尝试频率限制。
2. 同一来源对同一会议连续输错 5 次、同一来源累计输错 10 次，会要求完成轻量 Hashcash/PoW 或 CAPTCHA；PoW 答案通过一次性 `{challenge_jti, nonce}` 记录防止重放。
3. 全会议出现大量错误口令时，会提高风险等级，防止僵尸网络分散 IP 猜测。
4. 会议不存在和口令错误返回相同公开文案，并执行近似的口令校验时间，减少会议号探测侧信道。
5. 硬上限后直接返回 `:rate_limited`，但不永久锁定账号或会议，避免攻击者利用锁定接口做拒绝服务。

生产边缘应把 `VideoConf.RateLimiter` 的 ETS 固定窗口替换为 Redis/Edge KV 的全局滑动窗口或令牌桶，并接入 CAPTCHA、设备指纹、IP 信誉和 WAF。Phoenix controller 必须从 `conn.remote_ip` / 可信代理头填充 `source_ip`，不要把客户端表单里的 `source_ip` 当作限流键；PSTN/SIP 网关则应始终写入网关侧 `call_id`，可信运营商场景可附加已认证的主叫号码。

### 2. 口令与电话 PIN

- 普通口令使用 PBKDF2-SHA256 加盐慢哈希保存。
- 热路径同时保存由服务端 pepper 计算的 HMAC 快验证值；即使存储泄漏，没有 pepper 也不能高速爆破。
- PSTN 用户只能输入数字，因此可设置独立的 4–12 位 `dial_in_pin`；若没有独立 PIN，则仅当普通口令本身是数字时允许作为 DTMF PIN。
- 主叫号码只作为风险信号，不作为组织身份证明，因为 Caller ID 可伪造。

### 3. 组织身份

`VideoConf.Identity` 中的 `verified_org?: true` 只能来自验签后的 SSO/OIDC 断言或显式的可信网关入口。直接传入的原始 identity 会被降级，复制来的 `proof` 也会被清空；主机操作还会重新校验 identity 内携带的 HMAC/SSO proof：

```elixir
# 客户端不能通过提交 verified_org?: true 或 trusted_edge?: true 冒充组织成员
VideoConf.join(%{
  meeting_id: id,
  trusted_edge?: true, # 公共 join/1 路径会忽略这个提权键
  identity: %VideoConf.Identity{
    principal_id: "mallory",
    org_id: "acme",
    verified_org?: true
  }
})
# => 仍按未验证外部用户处理
```

只有已经完成会话/OIDC 鉴权的内部网关代码可以调用 `VideoConf.join_from_trusted_gateway/1`；该函数名应出现在代码审计和边界检查中。主机审批/锁定 API 的安全默认值则要求 `Identity.issue_assertion/1` 生成并验签过的短期断言。

支持的策略包括：

- `access_policy: :org_only`：仅允许指定组织成员；关闭等候室时直接拒绝外部用户。
- `access_policy: :org_and_invites`：组织成员和持嘉宾令牌者可走快速路径，其他人可进入等候室。
- `access_policy: :anyone_with_passcode`：持正确口令者可进入，适合公开发布会。

### 4. 外部嘉宾临时邀请

主持人可以签发带过期时间和 `jti` 的 HMAC 邀请令牌：

```elixir
{:ok, token} = VideoConf.issue_guest_invite(meeting.id, host_assertion, "partner-42", ttl: 3600)

VideoConf.join(%{meeting_id: meeting.id, guest_token: token})
```

令牌可放到邀请链接的 fragment 中；服务端可通过 `VideoConf.Store.revoke_jti/2` 或 `VideoConf.GuestInvite.revoke!/1` 吊销。生产环境也可把 `jti` 接入黑名单/版本号。

### 5. 等候室与一键全部放行

单个审批使用原子 `:ets.insert_new/2` 记录首个决定，重复点击或两个标签页同时审批不会产生冲突状态。

“全部放行”不为一万人逐个重写审批记录，而是在会议策略上写一个 `bulk_admit_before_ms` 游标：

- 发起前已排队的人符合 `requested_at_ms <= bulk_admit_before_ms`，轮询时换取入场票据。
- 游标之后新来的人仍继续等候。
- 主持人也可以 `approve/4` 或 `reject/4` 单个人。

生产环境可用 Phoenix PubSub/WebSocket/LiveView 在审批后立即推送，轮询只是兜底。

### 6. 一键锁定

```elixir
VideoConf.lock(meeting_id, host_assertion)
```

锁定后：

- 新的非主持人加入请求立即得到 `:meeting_locked`。
- 主持人凭有效 SSO 断言仍可进入并解锁。
- 持有有效短期 `join_ticket` 的断线重连参与者可恢复，避免网络抖动把正常参会者永久挡在外面。
- 主持人显式 `approve` 某个晚到嘉宾属于人工例外，会写审批记录。
- 闯入者已在会中时，仅锁定不够；主持人应使用移除/封禁能力。Meeting 已支持 `banned_principal_ids` 和 `banned_source_keys`，可继续接“移出会议”接口。

### 7. 万人发布会的低等待路径

万人场景不应让主持人逐个审批。建议配置：

```elixir
VideoConf.create_meeting(%{
  org_id: "launch-org",
  host_id: "host-1",
  access_policy: :anyone_with_passcode,
  passcode: "public-event-code",
  large_event?: true,          # 已授权身份跳过等候室
  waiting_room?: true,          # 可疑/无凭证来源仍可被拦住
  require_credential_to_wait?: true,
  capacity: 100_000
})
```

扩展点：

- 会议策略从 ETS 本地读；多节点用 Postgres/CockroachDB 持久化并通过缓存/失效广播同步。
- 入场票据是 HMAC 签名的 60 秒短期票据，媒体边缘节点可本地验票，不需要每次回源会议进程。
- `VideoConf.Presence` 用原子 ETS 计数器做幂等座位激活；多节点可换成 Redis/Lua 或分片计数。
- 大型发布会应使用 webinar 模式：少数 panelist 可推流，大量 attendee 只拉流/聊天受控，避免万人都有上行媒体链。
- 等候室连接可分片到多个 Phoenix node；审批事件通过 PubSub 广播。

## 主要模块

| 模块 | 职责 |
| --- | --- |
| `VideoConf.Admission` | 加入策略编排、审批、锁定、批量放行、轮询 |
| `VideoConf.Meeting` | 会议策略和口令/PIN 校验 |
| `VideoConf.Credentials` | 九位 ID、数字 PIN、PBKDF2、peppered HMAC |
| `VideoConf.Identity` | SSO 断言和组织成员身份 |
| `VideoConf.Token` | HMAC 签名、过期、常量时间比较 |
| `VideoConf.GuestInvite` | 外部嘉宾临时邀请 |
| `VideoConf.JoinTicket` | 给媒体边缘验证的短期入场票据 |
| `VideoConf.WaitingRoom` | ETS 等候室和原子审批决定 |
| `VideoConf.RateLimiter` | ETS 固定窗口计数 |
| `VideoConf.ProofOfWork` | 可疑枚举后的轻量验证 |
| `VideoConf.Presence` | 幂等媒体会话和容量计数 |
| `VideoConf.Store` | ETS 会议策略和 `jti` 吊销 |

## 生产化待替换项

1. ETS Store 换成持久化数据库，ETS/Nebulex 作为策略缓存。
2. 本地限流器换成边缘 + 全局共享限流，避免多节点预算相乘。
3. HMAC SSO 断言换成 OIDC ID Token/JWKS 验签或可信内部会话服务。
4. `VIDEO_CONF_SIGNING_SECRET` 放入 KMS/Secret Manager，并支持密钥轮换。
5. Phoenix Channel/LiveView + PubSub 替代等候室轮询。
6. 媒体服务器校验 `join_ticket` 后调用 `Presence.activate/2` 或其分布式等价物。
7. 增加审计日志：会议创建、策略变更、锁定、审批、拒绝、令牌签发、限流触发。
8. 增加分布式追踪和指标：`vc.join.duration`、`vc.join.result`、`vc.waiting.depth`、限流/PoW 触发率。
