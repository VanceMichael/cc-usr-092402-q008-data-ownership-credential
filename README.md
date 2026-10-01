# 数据权属凭证登记处

登记处为数据集和字段责任建立版本化凭证，唯一持久化介质是 SQLite，路径可由 `DATA_CREDENTIAL_DB_PATH` 指定。

执行 `npm install`、`npm run migrate`、`npm test` 和 `npm run start` 可完成迁移、测试与服务启动。Docker 运行不需要其他服务。

## 开发检查

- 安装依赖：`npm install`
- 运行测试：`npm test`
- 编译或构建：`npm run build`

## 凭证链模型

```
datasets ──< dataset_versions ──< fields ──< field_derivations（派生边，可跨版本，构成 DAG）
                                  │
                                  ├─< licenses ──< license_events（grant/amendment/revocation/ruling，逐条签名摘要并前后链接）
                                  │
declarations ──< declaration_approvals ──> credentials ──< credential_dependencies（签发时依赖的许可集合）
                                               │
                                               └─< verification_tokens（只存哈希的可撤销验证凭据）
audit_log（追加式，entry_hash 链接 prev_hash）
```

- **数据集版本**：`dataset_versions` 以 `(dataset_id, version)` 唯一，内容哈希随版本登记。
- **字段派生**：`derived` 字段必须声明上游字段；签发检查沿派生边传递展开到全部 `source` 祖先。
- **许可事件**：原始授权（grant）、补充协议（amendment）、撤回（revocation，可只撤回部分用途/地域）、争议裁定（ruling：suspend/reinstate/invalidate）全部作为事件入链，`signature_digest = HMAC(规范JSON(事件要素 + prev_digest))`，密钥由 `REGISTRY_HMAC_KEY` 注入（缺省为开发用值）。有效授权范围由事件流归约得出，许可表 `status` 只是缓存。
- **签发规则**：source 字段需自身许可覆盖；derived 字段需全部上游源头许可覆盖本次用途（用途、地域、期限三维，且检查时点处于授权期限内、未中止、未终止）。凭证 `chain_hash` 绑定签发时每条依赖许可的事件头摘要。
- **双人批准**：声明需两名不同批准人（`approver`/`admin` 角色）批准；提交人不能批准自己的声明；`(declaration_id, approver)` 主键使同一批准人只生效一次；状态迁移用条件更新（`WHERE status='pending'`）保证并发到达时只生效一次。
- **撤回传播**：许可事件落库后在同一事务内沿 `credential_dependencies` 重估受影响凭证；永久失效（撤回/终止/越界）立即撤销并审计，裁定中止只使验证暂时失败、恢复后自动有效。
- **验证凭据**：`POST /credentials/:id/tokens` 生成一次性返回的 token（库中只存 SHA-256 哈希，可随时撤销）。外部核验者 `POST /verify` 只得到 `{valid, purpose, territory, valid_until}`，看不到授权主体、条款或其他合同。
- **最小范围展示**：许可条款原文（`terms`）任何接口都不返回，只返回 `terms_hash`；版本导出按字段敏感度脱敏，`confidential` 字段仅 `admin` 显式请求可见。
- **审计**：签发、验证（含失败）、批准、撤回、导出、越权访问全部追加到哈希链审计表，`verifyAuditChain` 可重放校验完整性。

## HTTP API 摘要

身份通过请求头传递：`x-actor-id`（操作者）、`x-actor-role`（`admin`/`registrar`/`approver`/`submitter`/`auditor`）。

| 方法 | 路径 | 角色 | 说明 |
| --- | --- | --- | --- |
| GET | `/health` | 公开 | 健康检查 |
| POST | `/datasets` | registrar | 登记数据集 |
| POST | `/datasets/:id/versions` | registrar | 登记版本（内容哈希） |
| POST | `/versions/:id/fields` | registrar | 登记字段；derived 需 `upstream_field_ids` |
| GET | `/versions/:id/export` | 登录 | 按敏感度脱敏导出；`?include=confidential` 仅 admin |
| POST | `/fields/:id/licenses` | registrar | 登记许可（原始授权入事件链） |
| GET | `/licenses/:id` | 登录 | 有效范围 + 事件摘要链（无条款原文） |
| POST | `/licenses/:id/events` | registrar | 补充协议/撤回/裁定，落库即传播 |
| POST | `/declarations` | 登录 | 提交声明（字段+用途+地域+期限） |
| POST | `/declarations/:id/approve` | approver | 双人批准；禁止自批 |
| POST | `/declarations/:id/issue` | registrar | 上游许可全有效才签发 |
| POST | `/credentials/:id/tokens` | registrar | 生成可撤销验证凭据 |
| POST | `/tokens/:id/revoke` | registrar | 撤销验证凭据 |
| POST | `/verify` | 公开 | 外部核验：仅返回该用途是否有效 |
| GET | `/audit` | auditor | 审计链查询 |

## 环境变量

- `DATA_CREDENTIAL_DB_PATH`：SQLite 文件路径（默认 `data/credential.sqlite3`）
- `REGISTRY_HMAC_KEY`：许可事件签名摘要密钥（生产必须设置）
- `PORT` / `HOST`：服务监听地址（默认 `3000` / `0.0.0.0`）
