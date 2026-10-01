# 数据权属凭证登记处

登记处把**数据集版本 → 字段派生关系 → 授权主体 → 用途/地域/期限**连成一条可验证凭证链：

- 每个数据集版本带清单摘要；字段分为 `source`（原始）与 `derived`（派生），派生关系构成无环 DAG。
- 原始授权、补充协议、局部撤回与争议裁定都是带 **Ed25519 签名**的法律事件，登记处只保存**签名文件摘要**（`document_hash`），从不保存合同正文。
- 派生字段只有在其**全部上游闭包内许可都覆盖本次用途/地域/期限且未被撤回**时，才能经双人批准签发凭证。
- 授权撤回/缩限/裁定时，影响沿派生闭包**级联传播**，已签发凭证与其验证凭据立即失效。
- 外部核验者凭不透明令牌只能知道“**该用途此刻是否有效**”，看不到许可方、合同、其他声明或字段。
- 全部签发、验证（成功与失败）、认证失败访问进入**哈希链审计日志**；凭证本身也构成一条哈希链。

唯一持久化介质是 SQLite（`DATA_CREDENTIAL_DB_PATH`，默认 `data/credential.sqlite3`），无需其他服务。

## 运行

```bash
npm install
npm run migrate          # 建库；输出登记处签名公钥
npm test                 # 21 项端到端测试
npm run start            # 监听 0.0.0.0:3000（PORT/HOST 可覆盖）
docker build -t data-credential . && docker run -p 3000:3000 data-credential
```

首个管理员通过环境变量在迁移时引导：`REGISTRY_ADMIN_ID` + `REGISTRY_ADMIN_PUBLIC_KEY`
（可选 `REGISTRY_ADMIN_NAME`）。之后由该管理员登记其他主体与公钥。

## 角色

| 角色 | 能力 |
|---|---|
| `admin` | 主体登记/停用、全部记录读取、管理端凭证撤销、审计与链校验 |
| `submitter` | 注册数据集版本、提交用途声明、为自己的凭证签发/撤销验证凭据 |
| `approver` | 查看待批声明并作出批准/拒绝（双人） |
| `arbitrator` | 对许可作出争议裁定（维持/变更/暂停/恢复/无效） |
| `authority` | 许可方：登记原始授权、补充协议、局部/全部撤回 |

## 请求签名协议（除公开端点外全部强制）

对规范化 JSON 封套做 Ed25519 签名（HTTP 头传输）：

```
X-Principal-Id, X-Timestamp (ISO, ±5 分钟), X-Nonce (一次性), X-Signature (base64)
signed = canonical({method, path, timestamp, nonce, body_sha256})
```

- nonce 落库唯一 → 重放被拒；时间窗外请求失效。
- 法律事件另需许可方/仲裁员对事件封套签名：
  `canonical({type, family_id, seq, document_hash, signer_id, payload, effective_at})`。
  事件 `seq` 必须是该许可当前最大序号 + 1（参与签名，服务器校验连续性）。
- `src/client.js` 提供与服务器逐字节一致的规范化与签名实现（测试即使用它）。

## 主要 API

| 方法/路径 | 角色 | 说明 |
|---|---|---|
| `GET /health` | 公开 | 健康检查 |
| `GET /v1/registry/public-key` | 公开 | 登记处 Ed25519 验签公钥 |
| `POST /v1/verify` | 公开 | 最小披露核验：`{token, purpose?, region?}` → `{valid, purpose, region, expires_at}` 或 `{valid:false, reason}` |
| `POST /v1/admin/principals` | admin | 登记主体（id/name/role/public_key） |
| `POST /v1/datasets/versions` | submitter | 注册版本：`manifest_hash` + 字段（kind/derived_from/licenses）；成环/未知上游拒绝 |
| `POST /v1/licenses` | authority | 原始授权（条款 + document_hash + 事件签名） |
| `POST /v1/licenses/:id/amendments` | 许可方 | 补充协议（携带新条款） |
| `POST /v1/licenses/:id/withdrawals` | 许可方 | 局部撤回（scope：field_id/dataset_id/purposes/regions 任意组合） |
| `POST /v1/licenses/:id/revocations` | 许可方 | 整条撤回，全部下游凭证级联失效 |
| `POST /v1/licenses/:id/rulings` | arbitrator | 裁定 uphold/modify/suspend/reinstate/void |
| `POST /v1/claims` | submitter | 提交用途声明（dataset/version/field?/purpose/region/requested_until?） |
| `POST /v1/claims/:id/decisions` | approver | 批准/拒绝；两个**不同**批准人后触发签发 |
| `GET /v1/credentials/:id` | 持有人/admin | 返回被签名文档、证据快照、父凭证、登记处签名 |
| `POST /v1/credentials/:id/tokens` | 持有人 | 签发不透明可撤销 bearer 令牌（仅存 SHA-256） |
| `POST /v1/tokens/revoke` | 持有人/admin | 撤销令牌 |
| `POST /v1/credentials/:id/revoke` | admin | 行政撤销凭证（连带令牌） |
| `GET /v1/admin/audit?result=&limit=` | admin | 审计查询 |
| `GET /v1/admin/audit/verify` | admin | 审计哈希链完整性校验 |
| `GET /v1/admin/credentials/verify` | admin | 凭证哈希链完整性校验 |

条款对象：`{purposes: ["research"|"marketing"|...|"*"], regions: ["CN"|...|"*"], valid_from, valid_until}`，
`null`/缺省列表表示该项不受限。

## 关键控制

- **职责分离（SoD）**：提交人不能批准自己的声明；`UNIQUE(claim_id, approver_id)` 阻止同一批准人重复表态。
- **双人批准并发一次生效**：裁决在 `BEGIN IMMEDIATE` 事务内做条件式状态迁移（仅 `pending` 可推进），两个第二批准并发到达时只有一个能读到“未决”状态并签发，另一个得到 `409 claim_decided`；凭证表对 `claim_id` 唯一，杜绝重复凭证。
- **签发时全量重验**：第二批准到达时重新计算上游闭包所有“字段→许可”边，逐边校验条款窗口、撤回集合与许可状态；闭包内存在无许可的 source 字段同样阻断。
- **撤回传播**：事件生效后找出引用该许可的全部有效凭证，用其完整证据边重验，失效者连同其令牌级联作废，记录原因与来源事件；旧凭证不会因恢复而自动复活，需要重新申请。
- **最小披露**：核验响应只含布尔结论与所申请用途/地域；失败原因仅粗粒度（unknown_token / scope_mismatch / revoked / expired / not_authorized）；审计只记令牌哈希前缀，不记明文。
- **敏感材料最小化**：合同正文从不入库（只存 document_hash 与签名）；许可记录仅当事方可见；批准人只能看到待批声明的最小必要字段。
- **审计**：成功/拒绝/错误三态，含 request_id 与哈希链，篡改任一条即导致 `/v1/admin/audit/verify` 断裂。

## 模块

```
src/db.js         SQLite 模式与版本迁移（user_version）、登记处签名密钥引导
src/crypto.js     规范化 JSON、SHA-256、Ed25519 签名/验签、随机 ID/令牌
src/scopes.js     用途/地域/期限匹配、条款与撤回范围的唯一规范化形态
src/lineage.js    版本/字段注册、DAG 成环校验、上游闭包与所需许可
src/licenses.js   法律事件（原始/补充/撤回/撤回整条/裁定）、条款回放、撤回集合、传播
src/credentials.js 声明、双人裁决、凭证签名与哈希链、令牌、最小披露核验
src/auth.js       请求体读取、请求签名认证、nonce 防重放、RBAC
src/app.js        Koa 路由、审计接入、错误处理
src/client.js     参考签名客户端（集成方与测试共用）
```

## 开发检查

- `npm test`：node:test 端到端（含并发双批准、撤回传播、裁定、令牌最小披露、两条哈希链的篡改检测）
- `npm run build`：`node --check src/main.js` 语法检查
