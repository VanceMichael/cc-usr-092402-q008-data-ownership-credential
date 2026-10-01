'use strict';

const { randomId, randomToken, sha256, signObject, digestObject } = require('./crypto');
const { requiredLicenses, fieldsOfVersion, uncoveredSources } = require('./lineage');
const { evaluateEdges, currentEventSeq, HttpError } = require('./licenses');

function nowIso(atMs = Date.now()) {
  return new Date(atMs).toISOString();
}

function claimEdges(db, claim) {
  if (claim.field_id) {
    return requiredLicenses(db, claim.field_id);
  }
  const fields = fieldsOfVersion(db, claim.dataset_id, claim.version);
  if (!fields.length) throw new HttpError(404, 'version_not_found', 'dataset version has no fields');
  const seen = new Set();
  const edges = [];
  for (const f of fields) {
    for (const edge of requiredLicenses(db, f.field_id)) {
      const key = `${edge.field_id}|${edge.license_id}`;
      if (!seen.has(key)) {
        seen.add(key);
        edges.push(edge);
      }
    }
  }
  return edges;
}

/** 全量重验：派生字段要求闭包内每条许可都覆盖请求范围且未被撤回/失效 */
function revalidate(db, claim, edges, atMs) {
  const ctx = {
    dataset_id: claim.dataset_id,
    field_id: claim.field_id,
    purpose: claim.purpose,
    region: claim.region,
    valid_until: claim.requested_until,
  };
  return evaluateEdges(db, edges, ctx, atMs, { fullWindow: true });
}

function submitClaim(db, input, submitterId) {
  const at = nowIso();
  const claimId = input.claim_id || randomId('clm');
  const version = db.prepare(
    'SELECT 1 FROM dataset_versions WHERE dataset_id=? AND version=?'
  ).get(input.dataset_id, input.version);
  if (!version) throw new HttpError(404, 'version_not_found', 'register dataset version before claiming');
  if (input.field_id) {
    const f = db.prepare(
      'SELECT 1 FROM fields WHERE field_id=? AND dataset_id=? AND version=?'
    ).get(input.field_id, input.dataset_id, input.version);
    if (!f) throw new HttpError(404, 'field_not_found', 'field does not belong to the claimed version');
  }
  if (!input.purpose || !input.region) throw new HttpError(400, 'bad_scope', 'purpose and region required');
  if (input.requested_until && Number.isNaN(Date.parse(input.requested_until))) {
    throw new HttpError(400, 'bad_requested_until', 'invalid date');
  }
  db.prepare(
    `INSERT INTO claims(claim_id,dataset_id,version,field_id,purpose,region,requested_until,submitter_id,status,created_at)
     VALUES(?,?,?,?,?,?,?,?,'pending',?)`
  ).run(claimId, input.dataset_id, input.version, input.field_id ?? null, input.purpose, input.region,
    input.requested_until ?? null, submitterId, at);
  return getClaim(db, claimId);
}

function nextCredentialChain(db) {
  const row = db.prepare('SELECT COALESCE(MAX(chain_seq),0)+1 AS seq FROM credentials').get();
  return row.seq;
}

function buildCredential(db, claim, edges, evaluation, atMs) {
  const now = nowIso(atMs);
  const credentialId = randomId('cre');

  // 凭证有效期 = 请求期限与所有上游条款到期日的最小值
  let validUntil = claim.requested_until ?? null;
  const evidence = evaluation.checks.map(({ edge, result }) => {
    const terms = result.terms;
    if (terms && terms.valid_until) {
      const t = Date.parse(terms.valid_until);
      if (validUntil == null || t < Date.parse(validUntil)) validUntil = terms.valid_until;
    }
    const ev = db.prepare(
      'SELECT event_id, document_hash FROM legal_events WHERE license_id=? AND seq=?'
    ).get(edge.license_id, result.seq);
    return {
      field_id: edge.field_id,
      license_id: edge.license_id,
      event_seq: result.seq,
      event_id: ev.event_id,
      document_hash: ev.document_hash,
    };
  });

  // 父凭证：同一用途/地域下直接上游字段已有的有效凭证（凭证链）
  let parents = [];
  if (claim.field_id) {
    const directUpstreams = db.prepare(
      'SELECT upstream_field_id FROM lineage WHERE derived_field_id=?'
    ).pluck().all(claim.field_id);
    if (directUpstreams.length) {
      const placeholders = directUpstreams.map(() => '?').join(',');
      parents = db.prepare(
        `SELECT credential_id FROM credentials
          WHERE status='valid' AND purpose=? AND region=? AND field_id IN (${placeholders})`
      ).all(claim.purpose, claim.region, ...directUpstreams).map((r) => r.credential_id);
    }
  }

  const manifest = db.prepare(
    'SELECT manifest_hash FROM dataset_versions WHERE dataset_id=? AND version=?'
  ).get(claim.dataset_id, claim.version);

  const chainSeq = nextCredentialChain(db);
  const prev = db.prepare('SELECT credential_id, document_hash FROM credentials ORDER BY chain_seq DESC LIMIT 1').get();

  const body = {
    credential_id: credentialId,
    claim_id: claim.claim_id,
    dataset_id: claim.dataset_id,
    version: claim.version,
    manifest_hash: manifest.manifest_hash,
    field_id: claim.field_id,
    purpose: claim.purpose,
    region: claim.region,
    valid_from: now,
    valid_until: validUntil,
    evidence,
    parents: parents.sort(),
    chain_seq: chainSeq,
    prev_credential_id: prev ? prev.credential_id : null,
    prev_document_hash: prev ? prev.document_hash : null,
    issued_at: now,
  };
  return { body, evidence, parents };
}

function signAndStoreCredential(db, registry, claim, built) {
  const { body, evidence, parents } = built;
  const documentHash = digestObject(body);
  const signature = signObject(registry.private_key, { document_hash: documentHash, body });

  db.prepare(
    `INSERT INTO credentials(credential_id,claim_id,dataset_id,version,field_id,purpose,region,
       valid_from,valid_until,evidence_json,parents_json,document_hash,signature,status,chain_seq,prev_credential_id,prev_hash,issued_at)
     VALUES(@credential_id,@claim_id,@dataset_id,@version,@field_id,@purpose,@region,
       @valid_from,@valid_until,@evidence_json,@parents_json,@document_hash,@signature,'valid',@chain_seq,@prev_credential_id,@prev_hash,@issued_at)`
  ).run({
    credential_id: body.credential_id,
    claim_id: body.claim_id,
    dataset_id: body.dataset_id,
    version: body.version,
    field_id: body.field_id,
    purpose: body.purpose,
    region: body.region,
    valid_from: body.valid_from,
    valid_until: body.valid_until,
    evidence_json: JSON.stringify(evidence),
    parents_json: JSON.stringify(body.parents),
    document_hash: documentHash,
    signature,
    chain_seq: body.chain_seq,
    prev_credential_id: body.prev_credential_id,
    prev_hash: body.prev_document_hash,
    issued_at: body.issued_at,
  });
  const insEv = db.prepare(
    'INSERT INTO credential_evidence(credential_id,field_id,license_id,event_seq) VALUES(?,?,?,?)'
  );
  for (const e of evidence) insEv.run(body.credential_id, e.field_id, e.license_id, e.event_seq);
  const insParent = db.prepare(
    'INSERT INTO credential_parents(credential_id,parent_credential_id) VALUES(?,?)'
  );
  for (const p of parents) insParent.run(body.credential_id, p);

  db.prepare("UPDATE claims SET status='issued', credential_id=?, decided_at=? WHERE claim_id=?")
    .run(body.credential_id, body.issued_at, claim.claim_id);

  return { credential_id: body.credential_id, document_hash: documentHash, body, signature };
}

/**
 * 双人批准裁决。提交人不可批准自己的声明（SoD）；
 * UNIQUE(claim_id,approver_id) 防止同人重复；
 * 条件式状态迁移 + 写锁保证并发的第二次批准只有一次生效。
 */
function decideClaim(db, registry, claimId, approverId, decision, approvalSignature) {
  if (!['approved', 'rejected'].includes(decision)) throw new HttpError(400, 'bad_decision', 'decision required');
  // BEGIN IMMEDIATE：跨进程下立即取写锁，第二个并发裁决只能在第一个提交后读到最新状态
  db.prepare('BEGIN IMMEDIATE').run();
  try {
    const claim = db.prepare('SELECT * FROM claims WHERE claim_id=?').get(claimId);
    if (!claim) throw new HttpError(404, 'claim_not_found', 'claim not found');
    if (claim.status !== 'pending') {
      throw Object.assign(new HttpError(409, 'claim_decided', `claim already ${claim.status}`), { status_detail: claim.status });
    }
    if (claim.submitter_id === approverId) {
      throw new HttpError(403, 'self_approval_forbidden', 'submitter cannot approve their own claim');
    }
    const approvalId = randomId('apr');
    try {
      db.prepare(
        `INSERT INTO approvals(approval_id,claim_id,approver_id,decision,signature,created_at)
         VALUES(?,?,?,?,?,?)`
      ).run(approvalId, claimId, approverId, decision, approvalSignature, nowIso());
    } catch (err) {
      if (String(err.message).includes('UNIQUE')) {
        throw new HttpError(409, 'duplicate_approval', 'approver already acted on this claim');
      }
      throw err;
    }

    if (decision === 'rejected') {
      db.prepare("UPDATE claims SET status='rejected', reason=?, decided_at=? WHERE claim_id=?")
        .run('rejected by approver', nowIso(), claimId);
      db.prepare('COMMIT').run();
      return { outcome: 'rejected', claim: getClaim(db, claimId) };
    }

    const count = db.prepare(
      "SELECT COUNT(*) AS n FROM approvals WHERE claim_id=? AND decision='approved'"
    ).get(claimId).n;

    if (count < 2) {
      db.prepare('COMMIT').run();
      return { outcome: 'awaiting_second_approval', approvals: count, claim: getClaim(db, claimId) };
    }

    // 第二批准到达：签发前对所有上游许可做一次全量重验
    const edges = claimEdges(db, claim);
    const targets = claim.field_id
      ? [claim.field_id]
      : fieldsOfVersion(db, claim.dataset_id, claim.version).map((f) => f.field_id);
    const uncovered = [...new Set(targets.flatMap((id) => uncoveredSources(db, id)))].sort();
    if (uncovered.length || !edges.length) {
      db.prepare("UPDATE claims SET status='blocked', reason=?, decided_at=? WHERE claim_id=?")
        .run(uncovered.length ? 'uncovered_upstream_source' : 'no_license_evidence', nowIso(), claimId);
      db.prepare('COMMIT').run();
      return {
        outcome: 'blocked',
        reason: uncovered.length ? 'uncovered_upstream_source' : 'no_license_evidence',
        uncovered,
        claim: getClaim(db, claimId),
      };
    }
    const evaluation = revalidate(db, claim, edges, Date.now());
    if (!evaluation.valid) {
      db.prepare("UPDATE claims SET status='blocked', reason=?, decided_at=? WHERE claim_id=?")
        .run(evaluation.failure.reason, nowIso(), claimId);
      db.prepare('COMMIT').run();
      return { outcome: 'blocked', reason: evaluation.failure.reason, failure: evaluation.failure, claim: getClaim(db, claimId) };
    }
    const issued = signAndStoreCredential(db, registry, claim, buildCredential(db, claim, edges, evaluation, Date.now()));
    db.prepare('COMMIT').run();
    return { outcome: 'issued', credential: issued, claim: getClaim(db, claimId) };
  } catch (err) {
    if (db.inTransaction) db.prepare('ROLLBACK').run();
    throw err;
  }
}

/** 为凭证签发不透明可撤销验证凭据；只保存令牌哈希 */
function issueToken(db, credentialId, { ttlSeconds, purpose, region } = {}) {
  const cred = db.prepare("SELECT * FROM credentials WHERE credential_id=?").get(credentialId);
  if (!cred) throw new HttpError(404, 'credential_not_found', 'credential not found');
  if (cred.status !== 'valid') throw new HttpError(409, 'credential_revoked', 'credential is not valid');
  const usePurpose = purpose || cred.purpose;
  const useRegion = region || cred.region;
  if (usePurpose !== cred.purpose || useRegion !== cred.region) {
    throw new HttpError(400, 'token_scope_mismatch', 'token scope must match credential purpose/region');
  }
  const now = Date.now();
  let expiresAt = cred.valid_until;
  if (ttlSeconds != null) {
    const capped = new Date(now + ttlSeconds * 1000).toISOString();
    if (expiresAt == null || Date.parse(capped) < Date.parse(expiresAt)) expiresAt = capped;
  }
  const secret = `dct_${randomToken(32)}`;
  const tokenId = randomId('tok');
  db.prepare(
    `INSERT INTO verification_tokens(token_id,token_hash,credential_id,purpose,region,status,expires_at,created_at)
     VALUES(?,?,?,?,?,'active',?,?)`
  ).run(tokenId, sha256(secret), credentialId, usePurpose, useRegion, expiresAt, nowIso());
  return {
    token: secret, // 明文仅这一次返回
    token_id: tokenId,
    credential_id: credentialId,
    purpose: usePurpose,
    region: useRegion,
    expires_at: expiresAt,
  };
}

/**
 * 外部核验：最小披露。
 * 核验者只能知道“该用途/地域此刻是否有效”，看不到许可方、合同、其他声明或字段细节。
 */
function verifyToken(db, secret, requested = {}, atMs = Date.now()) {
  const tokenHash = sha256(secret);
  const tok = db.prepare('SELECT * FROM verification_tokens WHERE token_hash=?').get(tokenHash);
  if (!tok) return { valid: false, reason: 'unknown_token' };
  if (requested.purpose && requested.purpose !== tok.purpose) return { valid: false, reason: 'scope_mismatch' };
  if (requested.region && requested.region !== tok.region) return { valid: false, reason: 'scope_mismatch' };
  if (tok.status !== 'active') return { valid: false, reason: 'revoked' };
  if (tok.expires_at && atMs > Date.parse(tok.expires_at)) return { valid: false, reason: 'expired' };

  const cred = db.prepare('SELECT * FROM credentials WHERE credential_id=?').get(tok.credential_id);
  if (!cred || cred.status !== 'valid') return { valid: false, reason: 'revoked' };
  if (cred.valid_until && atMs > Date.parse(cred.valid_until)) {
    cascadeRevoke(db, cred.credential_id, 'credential_expired', atMs);
    return { valid: false, reason: 'expired' };
  }

  // 实时再验证据边（传播之外的时间/状态兜底），但不向核验者透露失败细节
  const edges = db.prepare(
    'SELECT field_id, license_id FROM credential_evidence WHERE credential_id=?'
  ).all(cred.credential_id);
  const evaluation = evaluateEdges(db, edges, {
    dataset_id: cred.dataset_id, field_id: cred.field_id, purpose: tok.purpose, region: tok.region,
  }, atMs);
  if (!evaluation.valid) {
    cascadeRevoke(db, cred.credential_id, `lazy:${evaluation.failure.reason}`, atMs);
    return { valid: false, reason: 'not_authorized' };
  }

  return {
    valid: true,
    purpose: tok.purpose,
    region: tok.region,
    expires_at: tok.expires_at,
  };
}

/** 核验路径上的惰性级联作废：凭证失效时连带其令牌 */
function cascadeRevoke(db, credentialId, reason, atMs = Date.now()) {
  const tx = db.transaction(() => {
    const now = new Date(atMs).toISOString();
    db.prepare(
      "UPDATE credentials SET status='revoked', revoke_reason=?, revoked_at=? WHERE credential_id=? AND status='valid'"
    ).run(reason, now, credentialId);
    db.prepare(
      "UPDATE verification_tokens SET status='revoked', revoke_reason='cascade:'||?, revoked_at=? WHERE credential_id=? AND status='active'"
    ).run(reason, now, credentialId);
  });
  tx();
}

function getClaim(db, claimId) {  const claim = db.prepare('SELECT * FROM claims WHERE claim_id=?').get(claimId);
  if (!claim) throw new HttpError(404, 'claim_not_found', 'claim not found');
  const approvals = db.prepare(
    'SELECT approval_id,approver_id,decision,created_at FROM approvals WHERE claim_id=? ORDER BY created_at'
  ).all(claimId);
  return { ...claim, requested_until: claim.requested_until, approvals };
}

/** 校验凭证哈希链：序号连续、prev_hash 链接正确、document_hash 与证据快照一致 */
function verifyCredentialChain(db) {
  const rows = db.prepare('SELECT * FROM credentials ORDER BY chain_seq ASC').all();
  let prevHash = null;
  let prevId = null;
  for (const [i, row] of rows.entries()) {
    if (row.chain_seq !== i + 1) {
      return { ok: false, broken_at: row.chain_seq, credential_id: row.credential_id, reason: 'chain_seq gap' };
    }
    if ((row.prev_hash ?? null) !== prevHash) {
      return { ok: false, broken_at: row.chain_seq, credential_id: row.credential_id, reason: 'prev_hash mismatch' };
    }
    const evidence = JSON.parse(row.evidence_json);
    const parents = JSON.parse(row.parents_json);
    const manifest = db.prepare(
      'SELECT manifest_hash FROM dataset_versions WHERE dataset_id=? AND version=?'
    ).get(row.dataset_id, row.version);
    const rebuilt = {
      credential_id: row.credential_id,
      claim_id: row.claim_id,
      dataset_id: row.dataset_id,
      version: row.version,
      manifest_hash: manifest ? manifest.manifest_hash : null,
      field_id: row.field_id,
      purpose: row.purpose,
      region: row.region,
      valid_from: row.valid_from,
      valid_until: row.valid_until,
      evidence,
      parents,
      chain_seq: row.chain_seq,
      prev_credential_id: prevId,
      prev_document_hash: prevHash,
      issued_at: row.issued_at,
    };
    if (digestObject(rebuilt) !== row.document_hash) {
      return { ok: false, broken_at: row.chain_seq, credential_id: row.credential_id, reason: 'document_hash mismatch' };
    }
    prevHash = row.document_hash;
    prevId = row.credential_id;
  }
  return { ok: true, credentials: rows.length, last_hash: prevHash };
}

module.exports = {
  submitClaim,
  decideClaim,
  issueToken,
  verifyToken,
  getClaim,
  claimEdges,
  revalidate,
  verifyCredentialChain,
};
