'use strict';

const { randomId, verifyObject } = require('./crypto');
const { termsCover, termsCoverWindow, listContains, listCovers, normalizeTerms, normalizeRestriction } = require('./scopes');

class HttpError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    Object.assign(this, extra);
  }
}

/** 法律事件签名封套：登记处只留存 document_hash 与签名，不留存敏感正文。
 *  created_at 由服务器生成，不进入签名；签名覆盖法律实质字段。 */
function legalEnvelope({ type, familyId, seq, documentHash, signerId, payload, effectiveAt }) {
  return {
    type,
    family_id: familyId,
    seq,
    document_hash: documentHash,
    signer_id: signerId,
    payload,
    effective_at: effectiveAt,
  };
}

function validateTerms(terms) {
  if (!terms || typeof terms !== 'object') throw new HttpError(400, 'bad_terms', 'terms required');
  const t = normalizeTerms(terms);
  for (const v of [...(t.purposes || []), ...(t.regions || [])]) {
    if (typeof v !== 'string' || !v) throw new HttpError(400, 'bad_terms', 'purpose/region entries must be non-empty strings');
  }
  if (t.valid_from && Number.isNaN(Date.parse(t.valid_from))) throw new HttpError(400, 'bad_terms', 'bad valid_from');
  if (t.valid_until && Number.isNaN(Date.parse(t.valid_until))) throw new HttpError(400, 'bad_terms', 'bad valid_until');
  if (t.valid_from && t.valid_until && Date.parse(t.valid_from) > Date.parse(t.valid_until)) {
    throw new HttpError(400, 'bad_terms', 'valid_from after valid_until');
  }
  return t;
}

function principal(db, id) {
  const p = db.prepare('SELECT * FROM principals WHERE principal_id=?').get(id);
  if (!p) throw new HttpError(404, 'unknown_principal', `principal ${id} not found`);
  if (p.status !== 'active') throw new HttpError(403, 'principal_revoked', `principal ${id} revoked`);
  return p;
}

function requireSignature(db, signerId, envelope, signature, allowRoles) {
  const p = principal(db, signerId);
  if (allowRoles && !allowRoles.includes(p.role)) {
    throw new HttpError(403, 'role_denied', `role ${p.role} may not sign ${envelope.type}`);
  }
  if (!signature || !verifyObject(p.public_key, envelope, signature)) {
    throw new HttpError(401, 'bad_signature', 'event signature verification failed');
  }
  return p;
}

function nextSeq(db, licenseId) {
  const row = db.prepare('SELECT COALESCE(MAX(seq),0)+1 AS seq FROM legal_events WHERE license_id=?').get(licenseId);
  return row.seq;
}

/** 事件序号必须由客户端按 max(seq)+1 提供（进入签名），服务器校验连续以防缺口/重放 */
function requireNextSeq(db, licenseId, input) {
  const expected = nextSeq(db, licenseId);
  if (input.seq !== expected) {
    throw new HttpError(409, 'seq_conflict', `expected seq ${expected}, got ${input.seq}`, { expected_seq: expected });
  }
  return expected;
}

function lastEvent(db, licenseId) {
  return db.prepare('SELECT * FROM legal_events WHERE license_id=? ORDER BY seq DESC LIMIT 1').get(licenseId);
}

function assertMonotonic(db, licenseId, effectiveAt) {
  const last = lastEvent(db, licenseId);
  if (last && Date.parse(effectiveAt) < Date.parse(last.effective_at)) {
    throw new HttpError(400, 'effective_at_regression', 'event effective_at precedes prior event');
  }
}

function insertEvent(db, licenseId, envelope, signature, createdAt) {
  db.prepare(
    `INSERT INTO legal_events(event_id,license_id,seq,type,document_hash,signature,signer_id,payload_json,effective_at,created_at)
     VALUES(?,?,?,?,?,?,?,?,?,?)`
  ).run(
    randomId('evt'), licenseId, envelope.seq, envelope.type, envelope.document_hash, signature,
    envelope.signer_id, JSON.stringify(envelope.payload), envelope.effective_at, createdAt
  );
}

function insertRestrictions(db, licenseId, eventId, restrictions, effectiveAt) {
  const ins = db.prepare(
    `INSERT INTO restrictions(restriction_id,license_id,event_id,kind,field_id,dataset_id,purposes_json,regions_json,effective_at)
     VALUES(?,?,?,?,?,?,?,?,?)`
  );
  for (const r of restrictions || []) {
    if (!['withdraw', 'reinstate'].includes(r.kind)) throw new HttpError(400, 'bad_restriction', 'kind must be withdraw/reinstate');
    ins.run(
      randomId('rst'), licenseId, eventId, r.kind,
      r.field_id ?? null, r.dataset_id ?? null,
      r.purposes ? JSON.stringify([...new Set(r.purposes)].sort()) : null,
      r.regions ? JSON.stringify([...new Set(r.regions)].sort()) : null,
      effectiveAt
    );
  }
}

/** 时刻 atMs 生效的条款（未来生效的修订暂不适用；裁定 modify 也携带条款） */
function termsAt(db, licenseId, atMs) {
  const rows = db.prepare(
    `SELECT type,payload_json,seq FROM legal_events
      WHERE license_id=? AND type IN ('original','amendment','ruling') AND effective_at<=?
      ORDER BY seq DESC`
  ).all(licenseId, new Date(atMs).toISOString());
  for (const row of rows) {
    const payload = JSON.parse(row.payload_json);
    if (payload.terms) return payload.terms; // ruling 非 modify 事件无 terms，继续向前找
  }
  return null;
}

function currentEventSeq(db, licenseId, atMs) {
  const row = db.prepare(
    'SELECT COALESCE(MAX(seq),0) AS seq FROM legal_events WHERE license_id=? AND effective_at<=?'
  ).get(licenseId, new Date(atMs).toISOString());
  return row.seq;
}

/** 回放 withdraw/reinstate，得到时刻 atMs 仍生效的撤回集合 */
function activeWithdrawals(db, licenseId, atMs) {
  const rows = db.prepare(
    `SELECT r.* FROM restrictions r
       JOIN legal_events e ON e.event_id = r.event_id
      WHERE r.license_id=? AND e.effective_at<=?
      ORDER BY e.seq ASC`
  ).all(licenseId, new Date(atMs).toISOString());
  const active = [];
  for (const r of rows) {
    if (r.kind === 'withdraw') {
      active.push(r);
    } else {
      for (let i = active.length - 1; i >= 0; i--) {
        if (reinstateCovers(r, active[i])) active.splice(i, 1);
      }
    }
  }
  return active;
}

function reinstateCovers(reinstatement, withdrawal) {
  if (reinstatement.field_id != null && reinstatement.field_id !== withdrawal.field_id) return false;
  if (reinstatement.dataset_id != null && reinstatement.dataset_id !== withdrawal.dataset_id) return false;
  if (!listCovers(reinstatement.purposes_json ? JSON.parse(reinstatement.purposes_json) : null,
    withdrawal.purposes_json ? JSON.parse(withdrawal.purposes_json) : null)) return false;
  if (!listCovers(reinstatement.regions_json ? JSON.parse(reinstatement.regions_json) : null,
    withdrawal.regions_json ? JSON.parse(withdrawal.regions_json) : null)) return false;
  return true;
}

function withdrawalBlocks(w, ctx) {
  if (w.field_id != null && w.field_id !== ctx.field_id) return false;
  if (w.dataset_id != null && w.dataset_id !== ctx.dataset_id) return false;
  if (!listContains(w.purposes_json ? JSON.parse(w.purposes_json) : null, ctx.purpose)) return false;
  if (!listContains(w.regions_json ? JSON.parse(w.regions_json) : null, ctx.region)) return false;
  return true;
}

/** 评估单条“字段→许可”边 */
function evaluateEdge(db, edge, ctx, atMs = Date.now(), { fullWindow = false } = {}) {
  const lic = db.prepare('SELECT * FROM licenses WHERE license_id=?').get(edge.license_id);
  if (!lic) return { valid: false, reason: 'license_missing' };
  if (lic.status !== 'active') return { valid: false, reason: `license_${lic.status}`, seq: currentEventSeq(db, lic.license_id, atMs) };
  const terms = termsAt(db, lic.license_id, atMs);
  if (!terms) return { valid: false, reason: 'no_effective_terms' };
  const cover = fullWindow ? termsCoverWindow(terms, ctx, atMs) : termsCover(terms, ctx, atMs);
  if (!cover) return { valid: false, reason: 'terms_not_cover', seq: currentEventSeq(db, lic.license_id, atMs) };
  const blocked = activeWithdrawals(db, lic.license_id, atMs).find((w) => withdrawalBlocks(w, { ...ctx, field_id: edge.field_id }));
  if (blocked) return { valid: false, reason: 'withdrawn', restriction_id: blocked.restriction_id, seq: currentEventSeq(db, lic.license_id, atMs) };
  return { valid: true, seq: currentEventSeq(db, lic.license_id, atMs), terms };
}

/** 评估一组边：全部有效才有效 */
function evaluateEdges(db, edges, ctx, atMs = Date.now(), opts) {
  const checks = edges.map((edge) => ({ edge, result: evaluateEdge(db, edge, ctx, atMs, opts) }));
  const failed = checks.find((c) => !c.result.valid);
  return {
    valid: !failed,
    checks,
    failure: failed ? { field_id: failed.edge.field_id, license_id: failed.edge.license_id, reason: failed.result.reason } : null,
  };
}

/**
 * 事件生效后传播：重新评估所有引用该许可的有效凭证，
 * 撤回/缩限/裁定导致失效的凭证级联作废（其令牌同时作废）。
 */
function propagate(db, licenseId, eventId, reason, atMs = Date.now()) {
  const rows = db.prepare(
    `SELECT DISTINCT c.credential_id, c.dataset_id, c.purpose, c.region, e.field_id
       FROM credentials c
       JOIN credential_evidence e ON e.credential_id = c.credential_id
      WHERE c.status='valid' AND e.license_id=?`
  ).all(licenseId);
  const byCredential = new Map();
  for (const r of rows) {
    if (!byCredential.has(r.credential_id)) {
      byCredential.set(r.credential_id, { credential_id: r.credential_id, dataset_id: r.dataset_id, purpose: r.purpose, region: r.region, edges: [] });
    }
    byCredential.get(r.credential_id).edges.push({ field_id: r.field_id, license_id: licenseId });
  }
  const revoked = [];
  for (const cred of byCredential.values()) {
    // 用凭证的全部证据边重验，避免遗漏同一凭证上的其他失效
    const allEdges = db.prepare(
      'SELECT field_id, license_id FROM credential_evidence WHERE credential_id=?'
    ).all(cred.credential_id);
    const { valid } = evaluateEdges(db, allEdges, cred, atMs);
    if (!valid) revoked.push(cred.credential_id);
  }
  const revokeCred = db.prepare(
    `UPDATE credentials SET status='revoked', revoke_reason=?, revoked_event_id=?, revoked_at=?
     WHERE credential_id=? AND status='valid'`
  );
  const revokeTokens = db.prepare(
    `UPDATE verification_tokens SET status='revoked', revoke_reason='cascade:'||?, revoked_at=?
     WHERE credential_id=? AND status='active'`
  );
  const now = new Date(atMs).toISOString();
  const apply = db.transaction(() => {
    for (const credentialId of revoked) {
      revokeCred.run(reason, eventId, now, credentialId);
      revokeTokens.run(reason, now, credentialId);
    }
  });
  apply();
  return { evaluated: byCredential.size, revoked_credential_ids: revoked };
}

function registerOriginal(db, input) {
  const now = new Date().toISOString();
  const at = input.effective_at || now;
  const licenseId = input.license_id || randomId('lic');
  const terms = validateTerms(input.terms);
  if (!input.document_hash) throw new HttpError(400, 'missing_document_hash', 'document_hash of signed original authorization required');
  principal(db, input.licensor_id); // 须存在且未停用
  const envelope = legalEnvelope({
    type: 'original', familyId: licenseId, seq: 1, documentHash: input.document_hash,
    signerId: input.licensor_id, payload: { terms }, effectiveAt: at,
  });
  requireSignature(db, input.licensor_id, envelope, input.signature);
  if (db.prepare('SELECT 1 FROM licenses WHERE license_id=?').get(licenseId)) {
    throw new HttpError(409, 'license_exists', 'license_id already registered');
  }

  const tx = db.transaction(() => {
    db.prepare(
      `INSERT INTO licenses(license_id,family_id,licensor_id,status,terms_json,created_at)
       VALUES(?,?,?,'active',?,?)`
    ).run(licenseId, licenseId, input.licensor_id, JSON.stringify(terms), now);
    insertEvent(db, licenseId, envelope, input.signature, now);
  });
  tx();
  return { license_id: licenseId, family_id: licenseId, status: 'active', terms, seq: 1 };
}

function recordAmendment(db, licenseId, input) {
  const lic = requireLicense(db, licenseId);
  const now = new Date().toISOString();
  const at = input.effective_at || now;
  const terms = validateTerms(input.terms);
  assertMonotonic(db, licenseId, at);
  const seq = requireNextSeq(db, licenseId, input);
  const envelope = legalEnvelope({
    type: 'amendment', familyId: lic.family_id, seq, documentHash: input.document_hash,
    signerId: lic.licensor_id, payload: { terms }, effectiveAt: at, createdAt: now,
  });
  requireSignature(db, lic.licensor_id, envelope, input.signature);

  const tx = db.transaction(() => {
    insertEvent(db, licenseId, envelope, input.signature, now);
    db.prepare('UPDATE licenses SET terms_json=? WHERE license_id=?').run(JSON.stringify(terms), licenseId);
  });
  tx();
  const effect = propagate(db, licenseId, db.prepare('SELECT event_id FROM legal_events WHERE license_id=? ORDER BY seq DESC LIMIT 1').get(licenseId).event_id, 'amendment_terms_no_longer_cover');
  return { license_id: licenseId, seq, terms, propagation: effect };
}

function recordRevocation(db, licenseId, input) {
  const lic = requireLicense(db, licenseId);
  const now = new Date().toISOString();
  const at = input.effective_at || now;
  assertMonotonic(db, licenseId, at);
  const seq = requireNextSeq(db, licenseId, input);
  const payload = { reason: input.reason || 'licensor revocation' };
  const envelope = legalEnvelope({
    type: 'revocation', familyId: lic.family_id, seq, documentHash: input.document_hash,
    signerId: lic.licensor_id, payload, effectiveAt: at, createdAt: now,
  });
  requireSignature(db, lic.licensor_id, envelope, input.signature, ['authority', 'admin']);

  const tx = db.transaction(() => {
    insertEvent(db, licenseId, envelope, input.signature, now);
    db.prepare("UPDATE licenses SET status='revoked' WHERE license_id=?").run(licenseId);
  });
  tx();
  const eventId = db.prepare('SELECT event_id FROM legal_events WHERE license_id=? ORDER BY seq DESC LIMIT 1').get(licenseId).event_id;
  const effect = propagate(db, licenseId, eventId, 'license_revoked');
  return { license_id: licenseId, seq, status: 'revoked', propagation: effect };
}

/** 许可方局部撤回：可限定字段/数据集/用途/地域；不终止整条许可 */
function recordWithdrawal(db, licenseId, input) {
  const lic = requireLicense(db, licenseId);
  if (lic.status !== 'active') throw new HttpError(409, 'license_revoked', 'license already fully revoked');
  const now = new Date().toISOString();
  const at = input.effective_at || now;
  assertMonotonic(db, licenseId, at);
  const seq = requireNextSeq(db, licenseId, input);
  const restrictions = (input.scope ? [input.scope] : []).map((r) => normalizeRestriction(r, 'withdraw'));
  if (!restrictions.length) {
    throw new HttpError(400, 'scope_required', 'partial withdrawal requires a scope (use revocation to terminate the license)');
  }
  const payload = { reason: input.reason || 'partial withdrawal', restrictions };
  const envelope = legalEnvelope({
    type: 'withdrawal', familyId: lic.family_id, seq, documentHash: input.document_hash,
    signerId: lic.licensor_id, payload, effectiveAt: at,
  });
  requireSignature(db, lic.licensor_id, envelope, input.signature);

  const tx = db.transaction(() => {
    insertEvent(db, licenseId, envelope, input.signature, now);
    const eventId = db.prepare('SELECT event_id FROM legal_events WHERE license_id=? ORDER BY seq DESC LIMIT 1').get(licenseId).event_id;
    insertRestrictions(db, licenseId, eventId, restrictions, at);
    return eventId;
  });
  const eventId = tx();
  const effect = propagate(db, licenseId, eventId, 'partial_withdrawal');
  return { license_id: licenseId, seq, decision: 'withdrawn', propagation: effect };
}

/** 争议裁定：维持 / 变更条款 / 暂停（局部或全部撤回）/ 恢复 / 整条无效 */
function recordRuling(db, licenseId, input) {
  const lic = requireLicense(db, licenseId);
  const now = new Date().toISOString();
  const at = input.effective_at || now;
  assertMonotonic(db, licenseId, at);
  const seq = requireNextSeq(db, licenseId, input);
  const decision = ['uphold', 'modify', 'suspend', 'reinstate', 'void'].includes(input.decision)
    ? input.decision : null;
  if (!decision) throw new HttpError(400, 'bad_decision', 'decision must be uphold/modify/suspend/reinstate/void');
  if (!input.document_hash) throw new HttpError(400, 'missing_document_hash', 'ruling document_hash required');

  const payload = { decision, reason: input.reason || null };
  if (decision === 'modify') payload.terms = validateTerms(input.terms);
  if (['suspend', 'reinstate'].includes(decision)) {
    const restrictions = (input.restrictions || []).map((r) =>
      normalizeRestriction(r, decision === 'suspend' ? 'withdraw' : 'reinstate'));
    if (!restrictions.length) {
      // 不带范围 = 对整条许可生效
      restrictions.push({ kind: decision === 'suspend' ? 'withdraw' : 'reinstate' });
    }
    payload.restrictions = restrictions;
  }
  const envelope = legalEnvelope({
    type: 'ruling', familyId: lic.family_id, seq, documentHash: input.document_hash,
    signerId: input.arbitrator_id, payload, effectiveAt: at, createdAt: now,
  });
  requireSignature(db, input.arbitrator_id, envelope, input.signature, ['arbitrator', 'admin']);

  const tx = db.transaction(() => {
    insertEvent(db, licenseId, envelope, input.signature, now);
    const eventId = db.prepare('SELECT event_id FROM legal_events WHERE license_id=? ORDER BY seq DESC LIMIT 1').get(licenseId).event_id;
    if (decision === 'modify') {
      insertRestrictions(db, licenseId, eventId, [], at);
      db.prepare('UPDATE licenses SET terms_json=? WHERE license_id=?').run(JSON.stringify(payload.terms), licenseId);
    }
    if (decision === 'void') {
      db.prepare("UPDATE licenses SET status='revoked' WHERE license_id=?").run(licenseId);
    }
    if (payload.restrictions) insertRestrictions(db, licenseId, eventId, payload.restrictions, at);
    return eventId;
  });
  const eventId = tx();
  const reason = { modify: 'ruling_modified_terms', void: 'ruling_void', suspend: 'ruling_suspend', reinstate: 'ruling_reinstate' }[decision];
  const effect = decision === 'uphold' ? { evaluated: 0, revoked_credential_ids: [] } : propagate(db, licenseId, eventId, reason);
  return { license_id: licenseId, seq, decision, propagation: effect };
}

function requireLicense(db, licenseId) {
  const lic = db.prepare('SELECT * FROM licenses WHERE license_id=?').get(licenseId);
  if (!lic) throw new HttpError(404, 'unknown_license', 'license not found');
  return lic;
}

function licenseView(db, licenseId) {
  const lic = requireLicense(db, licenseId);
  const events = db.prepare(
    `SELECT event_id,seq,type,document_hash,signer_id,payload_json,effective_at,created_at
       FROM legal_events WHERE license_id=? ORDER BY seq`
  ).all(licenseId).map((e) => ({ ...e, payload: JSON.parse(e.payload_json), payload_json: undefined }));
  return {
    license_id: lic.license_id,
    family_id: lic.family_id,
    licensor_id: lic.licensor_id,
    status: lic.status,
    terms: JSON.parse(lic.terms_json),
    events,
  };
}

module.exports = {
  HttpError,
  legalEnvelope,
  validateTerms,
  principal,
  termsAt,
  currentEventSeq,
  activeWithdrawals,
  evaluateEdge,
  evaluateEdges,
  propagate,
  registerOriginal,
  recordAmendment,
  recordWithdrawal,
  recordRevocation,
  recordRuling,
  requireLicense,
  licenseView,
};
