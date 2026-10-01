'use strict';

const { sha256, canonicalize, randomId } = require('./crypto');

/**
 * 追加式哈希链审计日志。
 * entry_hash = SHA256(prev_hash || canonical(entry-without-hashes))
 * 任何删除、重排或篡改都会在 verifyChain 中暴露。
 */
function append(db, entry) {
  const e = {
    log_id: randomId('log'),
    ts: entry.ts || new Date().toISOString(),
    actor_id: entry.actor_id ?? null,
    action: entry.action,
    result: entry.result, // success | denied | error
    subject: entry.subject ?? null,
    details: entry.details ?? {},
    request_id: entry.request_id ?? null,
  };
  const prev = db.prepare('SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1').get();
  const prevHash = prev ? prev.entry_hash : null;
  const entryHash = sha256(
    canonicalize({
      log_id: e.log_id,
      prev_hash: prevHash,
      ts: e.ts,
      actor_id: e.actor_id,
      action: e.action,
      result: e.result,
      subject: e.subject,
      details: e.details,
      request_id: e.request_id,
    })
  );
  db.prepare(
    `INSERT INTO audit_log(log_id,prev_hash,entry_hash,ts,actor_id,action,result,subject,details_json,request_id)
     VALUES(?,?,?,?,?,?,?,?,?,?)`
  ).run(
    e.log_id, prevHash, entryHash, e.ts, e.actor_id, e.action, e.result, e.subject,
    JSON.stringify(e.details), e.request_id
  );
  return { log_id: e.log_id, entry_hash: entryHash, prev_hash: prevHash };
}

function verifyChain(db) {
  const rows = db.prepare('SELECT * FROM audit_log ORDER BY seq ASC').all();
  let prevHash = null;
  for (const row of rows) {
    if ((row.prev_hash ?? null) !== prevHash) {
      return { ok: false, broken_at: row.seq, reason: 'prev_hash mismatch' };
    }
    const expect = sha256(
      canonicalize({
        log_id: row.log_id,
        prev_hash: row.prev_hash ?? null,
        ts: row.ts,
        actor_id: row.actor_id,
        action: row.action,
        result: row.result,
        subject: row.subject,
        details: JSON.parse(row.details_json),
        request_id: row.request_id,
      })
    );
    if (expect !== row.entry_hash) {
      return { ok: false, broken_at: row.seq, reason: 'entry_hash mismatch' };
    }
    prevHash = row.entry_hash;
  }
  return { ok: true, entries: rows.length, last_hash: prevHash };
}

module.exports = { append, verifyChain };
