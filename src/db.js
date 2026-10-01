'use strict';

const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const DEFAULT_DB_PATH = 'data/credential.sqlite3';

// 迁移按顺序执行，已应用的版本记录在 schema_version 中。
// 每条迁移在事务内执行，保证半迁移状态不会落库。
const MIGRATIONS = [
  {
    version: 1,
    name: 'credential-chain-schema',
    sql: `
      -- 数据集与其版本
      CREATE TABLE datasets (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        owner       TEXT NOT NULL,
        created_at  TEXT NOT NULL
      );

      CREATE TABLE dataset_versions (
        id           TEXT PRIMARY KEY,
        dataset_id   TEXT NOT NULL REFERENCES datasets(id),
        version      INTEGER NOT NULL,
        content_hash TEXT NOT NULL,
        created_at   TEXT NOT NULL,
        UNIQUE (dataset_id, version)
      );

      -- 字段：source（原始）或 derived（派生）；敏感度用于最小范围展示
      CREATE TABLE fields (
        id                 TEXT PRIMARY KEY,
        dataset_version_id TEXT NOT NULL REFERENCES dataset_versions(id),
        name               TEXT NOT NULL,
        kind               TEXT NOT NULL CHECK (kind IN ('source', 'derived')),
        sensitivity        TEXT NOT NULL DEFAULT 'internal'
                           CHECK (sensitivity IN ('public', 'internal', 'confidential')),
        created_at         TEXT NOT NULL,
        UNIQUE (dataset_version_id, name)
      );

      -- 派生边：derived_field_id 依赖 upstream_field_id（可跨数据集版本，构成 DAG）
      CREATE TABLE field_derivations (
        derived_field_id  TEXT NOT NULL REFERENCES fields(id),
        upstream_field_id TEXT NOT NULL REFERENCES fields(id),
        PRIMARY KEY (derived_field_id, upstream_field_id)
      );

      -- 许可：terms 为敏感材料，任何响应只给 terms_hash
      CREATE TABLE licenses (
        id          TEXT PRIMARY KEY,
        field_id    TEXT NOT NULL REFERENCES fields(id),
        grantor     TEXT NOT NULL,
        grantee     TEXT NOT NULL,
        purposes    TEXT NOT NULL,   -- JSON 数组（授权时快照）
        territories TEXT NOT NULL,   -- JSON 数组（授权时快照）
        valid_from  TEXT NOT NULL,
        valid_until TEXT NOT NULL,
        terms       TEXT NOT NULL,
        terms_hash  TEXT NOT NULL,
        status      TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'suspended', 'terminated')),
        created_by  TEXT NOT NULL,
        created_at  TEXT NOT NULL
      );
      CREATE INDEX idx_licenses_field ON licenses(field_id);

      -- 许可事件：grant / amendment / revocation / ruling，逐条带签名摘要并前后链接
      CREATE TABLE license_events (
        id               TEXT PRIMARY KEY,
        license_id       TEXT NOT NULL REFERENCES licenses(id),
        seq              INTEGER NOT NULL,
        type             TEXT NOT NULL CHECK (type IN ('grant', 'amendment', 'revocation', 'ruling')),
        payload          TEXT NOT NULL,  -- JSON
        signature_digest TEXT NOT NULL,
        prev_digest      TEXT NOT NULL,
        created_by       TEXT NOT NULL,
        created_at       TEXT NOT NULL,
        UNIQUE (license_id, seq)
      );

      -- 声明（登记申请）：需两名不同批准人批准，提交人不得批准
      CREATE TABLE declarations (
        id           TEXT PRIMARY KEY,
        field_id     TEXT NOT NULL REFERENCES fields(id),
        purpose      TEXT NOT NULL,
        territory    TEXT NOT NULL,
        term_from    TEXT NOT NULL,
        term_until   TEXT NOT NULL,
        submitted_by TEXT NOT NULL,
        status       TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'approved', 'rejected', 'issued')),
        created_at   TEXT NOT NULL,
        decided_at   TEXT
      );

      -- 批准记录：主键 (declaration_id, approver) 保证同一批准人只生效一次
      CREATE TABLE declaration_approvals (
        declaration_id TEXT NOT NULL REFERENCES declarations(id),
        approver       TEXT NOT NULL,
        decision       TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
        reason         TEXT,
        created_at     TEXT NOT NULL,
        PRIMARY KEY (declaration_id, approver)
      );

      -- 凭证：chain_hash 绑定签发时所依赖的全部许可事件头摘要
      CREATE TABLE credentials (
        id                 TEXT PRIMARY KEY,
        declaration_id     TEXT NOT NULL UNIQUE REFERENCES declarations(id),
        field_id           TEXT NOT NULL REFERENCES fields(id),
        dataset_version_id TEXT NOT NULL REFERENCES dataset_versions(id),
        purpose            TEXT NOT NULL,
        territory          TEXT NOT NULL,
        valid_from         TEXT NOT NULL,
        valid_until        TEXT NOT NULL,
        chain_hash         TEXT NOT NULL,
        status             TEXT NOT NULL DEFAULT 'active'
                           CHECK (status IN ('active', 'revoked')),
        revoked_reason     TEXT,
        issued_by          TEXT NOT NULL,
        issued_at          TEXT NOT NULL,
        revoked_at         TEXT
      );

      -- 凭证依赖的许可集合：撤回传播沿此表找到受影响凭证
      CREATE TABLE credential_dependencies (
        credential_id TEXT NOT NULL REFERENCES credentials(id),
        license_id    TEXT NOT NULL REFERENCES licenses(id),
        PRIMARY KEY (credential_id, license_id)
      );

      -- 可撤销验证凭据：只存 token 哈希，外部核验者持 token 仅能得知用途是否有效
      CREATE TABLE verification_tokens (
        id            TEXT PRIMARY KEY,
        credential_id TEXT NOT NULL REFERENCES credentials(id),
        token_hash    TEXT NOT NULL UNIQUE,
        label         TEXT,
        status        TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active', 'revoked')),
        expires_at    TEXT NOT NULL,
        created_by    TEXT NOT NULL,
        created_at    TEXT NOT NULL,
        revoked_at    TEXT
      );

      -- 审计：追加式，entry_hash 链接 prev_hash，篡改可被发现
      CREATE TABLE audit_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          TEXT NOT NULL,
        actor       TEXT NOT NULL,
        action      TEXT NOT NULL,
        entity_type TEXT,
        entity_id   TEXT,
        outcome     TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
        detail      TEXT,
        prev_hash   TEXT NOT NULL,
        entry_hash  TEXT NOT NULL
      );
    `,
  },
];

function resolveDbPath(dbPath) {
  return dbPath || process.env.DATA_CREDENTIAL_DB_PATH || DEFAULT_DB_PATH;
}

function openDatabase(dbPath) {
  const file = resolveDbPath(dbPath);
  if (file !== ':memory:') {
    fs.mkdirSync(path.dirname(file), { recursive: true });
  }
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  return db;
}

function appliedVersions(db) {
  db.exec('CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL)');
  return new Set(db.prepare('SELECT version FROM schema_version').all().map((r) => r.version));
}

function migrate(db) {
  const applied = appliedVersions(db);
  for (const migration of MIGRATIONS) {
    if (applied.has(migration.version)) continue;
    const run = db.transaction(() => {
      db.exec(migration.sql);
      db.prepare('INSERT INTO schema_version(version) VALUES (?)').run(migration.version);
    });
    run();
  }
}

module.exports = { openDatabase, migrate, resolveDbPath, MIGRATIONS };
