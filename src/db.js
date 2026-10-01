'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const DB_PATH = process.env.DATA_CREDENTIAL_DB_PATH || 'data/credential.sqlite3';

const MIGRATIONS = [
  // v1: 权属凭证链全量模式
  () => `
CREATE TABLE principals(
  principal_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','submitter','approver','arbitrator','authority')),
  public_key TEXT NOT NULL,            -- Ed25519 SPKI, base64
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  created_at TEXT NOT NULL
);

CREATE TABLE dataset_versions(
  dataset_id TEXT NOT NULL,
  version TEXT NOT NULL,
  submitter_id TEXT NOT NULL REFERENCES principals(principal_id),
  manifest_hash TEXT NOT NULL,        -- 提交人对清单（不含敏感数据）的摘要
  created_at TEXT NOT NULL,
  PRIMARY KEY(dataset_id, version)
);

CREATE TABLE fields(
  field_id TEXT PRIMARY KEY,          -- 确定性编号: dataset:version:name
  dataset_id TEXT NOT NULL,
  version TEXT NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('source','derived')),
  created_at TEXT NOT NULL,
  UNIQUE(dataset_id, version, name),
  FOREIGN KEY(dataset_id, version) REFERENCES dataset_versions(dataset_id, version)
);

CREATE TABLE lineage(
  derived_field_id TEXT NOT NULL REFERENCES fields(field_id),
  upstream_field_id TEXT NOT NULL REFERENCES fields(field_id),
  ordinal INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(derived_field_id, upstream_field_id),
  CHECK(derived_field_id <> upstream_field_id)
);

CREATE TABLE field_licenses(
  field_id TEXT NOT NULL REFERENCES fields(field_id),
  license_id TEXT NOT NULL REFERENCES licenses(license_id),
  PRIMARY KEY(field_id, license_id)
);

CREATE TABLE licenses(
  license_id TEXT PRIMARY KEY,
  family_id TEXT NOT NULL UNIQUE,     -- 原始授权与补充协议共享一个 family
  licensor_id TEXT NOT NULL REFERENCES principals(principal_id),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  terms_json TEXT NOT NULL,           -- 最新有效条款（用途/地域/期限），由事件派生
  created_at TEXT NOT NULL
);

CREATE TABLE legal_events(
  event_id TEXT PRIMARY KEY,
  license_id TEXT NOT NULL REFERENCES licenses(license_id),
  seq INTEGER NOT NULL,               -- family 内单调递增
  type TEXT NOT NULL CHECK(type IN ('original','amendment','withdrawal','revocation','ruling')),
  document_hash TEXT NOT NULL,        -- 法律文件正文（敏感材料）的签名摘要，不存正文
  signature TEXT NOT NULL,            -- 对事件封套的 Ed25519 签名
  signer_id TEXT NOT NULL REFERENCES principals(principal_id),
  payload_json TEXT NOT NULL,         -- 条款 / 撤回范围 / 裁定结论
  effective_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(license_id, seq)
);

CREATE TABLE restrictions(
  restriction_id TEXT PRIMARY KEY,
  license_id TEXT NOT NULL REFERENCES licenses(license_id),
  event_id TEXT NOT NULL REFERENCES legal_events(event_id),
  kind TEXT NOT NULL CHECK(kind IN ('withdraw','reinstate')),
  field_id TEXT REFERENCES fields(field_id),   -- NULL = 不限定字段
  dataset_id TEXT,                              -- NULL = 不限定数据集
  purposes_json TEXT,                           -- NULL = 全部用途
  regions_json TEXT,                            -- NULL = 全部地域
  effective_at TEXT NOT NULL
);

CREATE TABLE claims(
  claim_id TEXT PRIMARY KEY,
  dataset_id TEXT NOT NULL,
  version TEXT NOT NULL,
  field_id TEXT REFERENCES fields(field_id),    -- NULL = 数据集级凭证
  purpose TEXT NOT NULL,
  region TEXT NOT NULL,
  requested_until TEXT,
  submitter_id TEXT NOT NULL REFERENCES principals(principal_id),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending','rejected','blocked','issued')),
  credential_id TEXT,
  reason TEXT,
  created_at TEXT NOT NULL,
  decided_at TEXT,
  FOREIGN KEY(dataset_id, version) REFERENCES dataset_versions(dataset_id, version)
);

CREATE TABLE approvals(
  approval_id TEXT PRIMARY KEY,
  claim_id TEXT NOT NULL REFERENCES claims(claim_id),
  approver_id TEXT NOT NULL REFERENCES principals(principal_id),
  decision TEXT NOT NULL CHECK(decision IN ('approved','rejected')),
  signature TEXT NOT NULL,                   -- 批准动作签名（来自请求签名）
  created_at TEXT NOT NULL,
  UNIQUE(claim_id, approver_id)              -- 同一批准人对同一声明仅一次
);

CREATE TABLE credentials(
  credential_id TEXT PRIMARY KEY,
  claim_id TEXT NOT NULL UNIQUE REFERENCES claims(claim_id),
  dataset_id TEXT NOT NULL,
  version TEXT NOT NULL,
  field_id TEXT REFERENCES fields(field_id),
  purpose TEXT NOT NULL,
  region TEXT NOT NULL,
  valid_from TEXT NOT NULL,
  valid_until TEXT,
  evidence_json TEXT NOT NULL,               -- 上游字段->许可->事件序号快照
  parents_json TEXT NOT NULL,                -- 上游字段既有凭证（凭证链）
  document_hash TEXT NOT NULL,
  signature TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'valid' CHECK(status IN ('valid','revoked')),
  revoke_reason TEXT,
  revoked_event_id TEXT REFERENCES legal_events(event_id),
  revoked_at TEXT,
  chain_seq INTEGER NOT NULL UNIQUE,
  prev_credential_id TEXT,
  prev_hash TEXT,
  issued_at TEXT NOT NULL
);

CREATE TABLE credential_evidence(
  credential_id TEXT NOT NULL REFERENCES credentials(credential_id),
  field_id TEXT NOT NULL,
  license_id TEXT NOT NULL,
  event_seq INTEGER NOT NULL,           -- 签发时该许可的事件序号快照
  PRIMARY KEY(credential_id, field_id, license_id)
);
CREATE INDEX idx_evidence_license ON credential_evidence(license_id);

CREATE TABLE credential_parents(
  credential_id TEXT NOT NULL REFERENCES credentials(credential_id),
  parent_credential_id TEXT NOT NULL REFERENCES credentials(credential_id),
  PRIMARY KEY(credential_id, parent_credential_id)
);
CREATE INDEX idx_cred_parents_parent ON credential_parents(parent_credential_id);

CREATE TABLE verification_tokens(
  token_id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,           -- 仅存 SHA-256(secret)
  credential_id TEXT NOT NULL REFERENCES credentials(credential_id),
  purpose TEXT NOT NULL,
  region TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  expires_at TEXT,
  revoke_reason TEXT,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE consumed_nonces(
  nonce TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  seen_at TEXT NOT NULL
);
CREATE INDEX idx_nonces_seen_at ON consumed_nonces(seen_at);

CREATE TABLE audit_log(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  log_id TEXT NOT NULL,
  prev_hash TEXT,
  entry_hash TEXT NOT NULL,
  ts TEXT NOT NULL,
  actor_id TEXT,
  action TEXT NOT NULL,
  result TEXT NOT NULL CHECK(result IN ('success','denied','error')),
  subject TEXT,
  details_json TEXT NOT NULL,
  request_id TEXT
);

CREATE TABLE server_secrets(
  name TEXT PRIMARY KEY,
  value_json TEXT NOT NULL
);
`,
];

function ensureRegistrySigningKey(db) {
  const row = db.prepare('SELECT value_json FROM server_secrets WHERE name=?').get('signing-key');
  if (row) return JSON.parse(row.value_json);
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const value = {
    public_spki: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    private_pkcs8: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
    created_at: new Date().toISOString(),
  };
  db.prepare('INSERT INTO server_secrets(name,value_json) VALUES(?,?)').run('signing-key', JSON.stringify(value));
  return value;
}

function open() {
  fs.mkdirSync(path.dirname(path.resolve(DB_PATH)), { recursive: true });
  const db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  return db;
}

function migrate(db) {
  let current = db.pragma('user_version', { simple: true });
  for (let v = current; v < MIGRATIONS.length; v++) {
    db.exec(MIGRATIONS[v]());
    current = v + 1;
    db.pragma(`user_version = ${current}`);
  }
  const key = ensureRegistrySigningKey(db);
  // 可选：通过环境变量引导管理员
  const adminId = process.env.REGISTRY_ADMIN_ID;
  const adminKey = process.env.REGISTRY_ADMIN_PUBLIC_KEY;
  if (adminId && adminKey) {
    db.prepare(
      `INSERT INTO principals(principal_id,name,role,public_key,status,created_at)
       VALUES(@id,@name,'admin',@key,'active',@ts)
       ON CONFLICT(principal_id) DO NOTHING`
    ).run({ id: adminId, name: process.env.REGISTRY_ADMIN_NAME || adminId, key: adminKey, ts: new Date().toISOString() });
  }
  return { version: current, signingKey: key };
}

module.exports = { DB_PATH, open, migrate };
