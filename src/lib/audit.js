'use strict';

const { canonicalize, sha256 } = require('./crypto');

const GENESIS_HASH = 'GENESIS';

// 追加一条审计记录。entry_hash 覆盖前一条哈希与全部字段，
// 形成单向链：任何历史篡改都会使后续校验失败。
// 必须在调用方的事务内使用（或独立短事务），保证 prev_hash 读取与插入原子。
function appendAudit(db, { actor, action, entityType = null, entityId = null, outcome, detail = null, ts }) {
  const at = ts || new Date().toISOString();
  const prev = db.prepare('SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1').get();
  const prevHash = prev ? prev.entry_hash : GENESIS_HASH;
  const detailJson = detail === null ? null : JSON.stringify(detail);
  const entryHash = sha256(canonicalize({
    ts: at,
    actor,
    action,
    entity_type: entityType,
    entity_id: entityId,
    outcome,
    detail: detailJson,
    prev_hash: prevHash,
  }));
  const result = db.prepare(`
    INSERT INTO audit_log (ts, actor, action, entity_type, entity_id, outcome, detail, prev_hash, entry_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(at, actor, action, entityType, entityId, outcome, detailJson, prevHash, entryHash);
  return { id: result.lastInsertRowid, entryHash };
}

// 重放全链校验完整性，返回第一个被破坏的位置（null 表示完整）。
function verifyAuditChain(db) {
  const rows = db.prepare('SELECT * FROM audit_log ORDER BY id').all();
  let prevHash = GENESIS_HASH;
  for (const row of rows) {
    const expected = sha256(canonicalize({
      ts: row.ts,
      actor: row.actor,
      action: row.action,
      entity_type: row.entity_type,
      entity_id: row.entity_id,
      outcome: row.outcome,
      detail: row.detail,
      prev_hash: prevHash,
    }));
    if (row.prev_hash !== prevHash || row.entry_hash !== expected) {
      return { intact: false, brokenAt: row.id };
    }
    prevHash = row.entry_hash;
  }
  return { intact: true, entries: rows.length };
}

module.exports = { appendAudit, verifyAuditChain, GENESIS_HASH };
