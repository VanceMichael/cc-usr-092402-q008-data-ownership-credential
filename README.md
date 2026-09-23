# 数据权属凭证登记处

登记处为数据集和字段责任建立版本化凭证，唯一持久化介质是 SQLite，路径可由 `DATA_CREDENTIAL_DB_PATH` 指定。

执行 `npm install`、`npm run migrate`、`npm test` 和 `npm run start` 可完成迁移、测试与服务启动。Docker 运行不需要其他服务。

## 开发检查

- 安装依赖：`npm install`
- 运行测试：`npm test`
- 编译或构建：`npm run build`
