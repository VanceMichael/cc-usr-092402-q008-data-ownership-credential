'use strict';

const { canonicalize, sha256, randomId } = require('./crypto');
const { evaluateFieldCoverage, getEffectiveScope, licenseHeadDigest, coverageStatus } = require('./licenses');
const { appendAudit } = require('./audit');

class CoverageError extends Error {
  constructor(missing) {
    super(`upstream license coverage missing for field(s): ${missing.join(', ')}`);
    this.code = 'UPSTREAM_COVERAGE_MISSING';
    this.missing = missing;
  }
}

// 凭证链哈希：绑定字段、用途范围与签发时所依赖的每条许可的事件头摘要。
// 任一上游许可事后被改动，其头摘要变化，链哈希即无法复现。
function computeChainHash({ fieldId, purpose, territory, termFrom, termUntil, dependencies }) {
  const deps = dependencies
    .map((d) => ({ license_id: d.licenseId, head_digest: d.headDigest }))
    .sort((a, b) => a.license_id.localeCompare(b.license_id));
  return sha256(canonicalize({
    field_id: fieldId,
    purpose,
    territory,
    term_from: termFrom,
    term_until: termUntil,
    dependencies: deps,
  }));
}

// 签发凭证：重新评估上游覆盖，全部有效才落库。须在事务内调用。
function issueCredential(db, declaration, actor, ts) {
  const at = ts || new Date().toISOString();
  const use = {
    purpose: declaration.purpose,
    territory: declaration.territory,
    from: declaration.term_from,
    until: declaration.term_until,
    at,
  };
  const coverage = evaluateFieldCoverage(db, declaration.field_id, use);
  if (!coverage.ok) {
    throw new CoverageError(coverage.missing);
  }
  const dependencies = coverage.dependencies.map((d) => ({
    ...d,
    headDigest: licenseHeadDigest(db, d.licenseId),
  }));
  const field = db.prepare('SELECT dataset_version_id FROM fields WHERE id = ?').get(declaration.field_id);
  const id = randomId('cred');
  const chainHash = computeChainHash({
    fieldId: declaration.field_id,
    purpose: declaration.purpose,
    territory: declaration.territory,
    termFrom: declaration.term_from,
    termUntil: declaration.term_until,
    dependencies,
  });
  db.prepare(`
    INSERT INTO credentials (id, declaration_id, field_id, dataset_version_id, purpose, territory,
                             valid_from, valid_until, chain_hash, status, issued_by, issued_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
  `).run(id, declaration.id, declaration.field_id, field.dataset_version_id,
    declaration.purpose, declaration.territory, declaration.term_from, declaration.term_until,
    chainHash, actor, at);
  const depStmt = db.prepare('INSERT INTO credential_dependencies (credential_id, license_id) VALUES (?, ?)');
  for (const d of dependencies) depStmt.run(id, d.licenseId);
  appendAudit(db, {
    actor, action: 'credential_issued', entityType: 'credential', entityId: id, outcome: 'success',
    detail: { declaration_id: declaration.id, field_id: declaration.field_id, chain_hash: chainHash },
    ts: at,
  });
  return db.prepare('SELECT * FROM credentials WHERE id = ?').get(id);
}

// 凭证当前是否仍然有效：状态在册，且签发时依赖的每条许可此刻仍覆盖该用途。
// permanent 区分“永久失效”（撤回/越界/终止，应撤销凭证）与“暂时失效”（裁定中止，恢复后仍可用）。
function credentialIsValid(db, credential, at) {
  if (credential.status !== 'active') {
    return { valid: false, permanent: true, reason: 'credential_revoked' };
  }
  const now = at || new Date().toISOString();
  if (now < credential.valid_from || now > credential.valid_until) {
    return { valid: false, permanent: true, reason: 'outside_term' };
  }
  const deps = db.prepare('SELECT license_id FROM credential_dependencies WHERE credential_id = ?')
    .all(credential.id);
  for (const { license_id: licenseId } of deps) {
    const scope = getEffectiveScope(db, licenseId);
    const status = coverageStatus(scope, {
      purpose: credential.purpose,
      territory: credential.territory,
      from: credential.valid_from,
      until: credential.valid_until,
      at: now,
    });
    if (status === 'uncovered') {
      return { valid: false, permanent: true, reason: 'upstream_license_invalid', licenseId };
    }
    if (status === 'suspended') {
      return { valid: false, permanent: false, reason: 'upstream_suspended', licenseId };
    }
  }
  return { valid: true };
}

// 局部撤回传播：许可事件落库后，沿依赖表找到全部受影响凭证，
// 重新评估其完整依赖集合；仅对永久失效者撤销（裁定中止不撤销，恢复后自动有效）。须在事务内调用。
function propagateLicenseChange(db, licenseId, actor, ts) {
  const at = ts || new Date().toISOString();
  const affected = db.prepare(`
    SELECT c.* FROM credentials c
    JOIN credential_dependencies d ON d.credential_id = c.id
    WHERE d.license_id = ? AND c.status = 'active'
  `).all(licenseId);
  const revoked = [];
  for (const credential of affected) {
    const verdict = credentialIsValid(db, credential, at);
    if (verdict.valid || !verdict.permanent) continue;
    db.prepare(`
      UPDATE credentials SET status = 'revoked', revoked_reason = ?, revoked_at = ?
      WHERE id = ? AND status = 'active'
    `).run(verdict.reason, at, credential.id);
    appendAudit(db, {
      actor, action: 'credential_revoked', entityType: 'credential', entityId: credential.id,
      outcome: 'success',
      detail: { reason: verdict.reason, trigger_license_id: licenseId },
      ts: at,
    });
    revoked.push(credential.id);
  }
  return revoked;
}

module.exports = { CoverageError, computeChainHash, issueCredential, credentialIsValid, propagateLicenseChange };
