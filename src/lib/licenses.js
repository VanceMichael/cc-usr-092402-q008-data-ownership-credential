'use strict';

const { digestObject, randomId } = require('./crypto');

// ---------- 许可事件（授权 / 补充协议 / 撤回 / 争议裁定） ----------

// 在许可的摘要链尾部追加一条事件。签名摘要覆盖事件全部要素与前一条摘要，
// 任何一条事件被改动都会使链条校验失败。须在事务内调用。
function recordLicenseEvent(db, { licenseId, type, payload, createdBy, ts }) {
  const at = ts || new Date().toISOString();
  const tail = db.prepare(
    'SELECT seq, signature_digest FROM license_events WHERE license_id = ? ORDER BY seq DESC LIMIT 1'
  ).get(licenseId);
  const seq = tail ? tail.seq + 1 : 1;
  const prevDigest = tail ? tail.signature_digest : '0'.repeat(64);
  const signatureDigest = digestObject({
    license_id: licenseId,
    seq,
    type,
    payload,
    created_by: createdBy,
    created_at: at,
    prev_digest: prevDigest,
  });
  const id = randomId('evt');
  db.prepare(`
    INSERT INTO license_events (id, license_id, seq, type, payload, signature_digest, prev_digest, created_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, licenseId, seq, type, JSON.stringify(payload), signatureDigest, prevDigest, createdBy, at);
  return { id, licenseId, seq, type, payload, signatureDigest, prevDigest, createdBy, createdAt: at };
}

function listLicenseEvents(db, licenseId) {
  return db.prepare('SELECT * FROM license_events WHERE license_id = ? ORDER BY seq').all(licenseId)
    .map((row) => ({ ...row, payload: JSON.parse(row.payload) }));
}

// 将事件流归约为当前有效授权范围：
// 用途集合、地域集合、期限、是否被裁定中止、是否已终止。
function reduceScope(events) {
  const scope = {
    purposes: new Set(),
    territories: new Set(),
    validFrom: null,
    validUntil: null,
    suspended: false,
    terminated: false,
  };
  for (const ev of events) {
    const p = ev.payload;
    switch (ev.type) {
      case 'grant':
        scope.purposes = new Set(p.purposes || []);
        scope.territories = new Set(p.territories || []);
        scope.validFrom = p.valid_from;
        scope.validUntil = p.valid_until;
        break;
      case 'amendment':
        for (const x of p.add_purposes || []) scope.purposes.add(x);
        for (const x of p.remove_purposes || []) scope.purposes.delete(x);
        for (const x of p.add_territories || []) scope.territories.add(x);
        for (const x of p.remove_territories || []) scope.territories.delete(x);
        if (p.valid_from) scope.validFrom = p.valid_from;
        if (p.valid_until) scope.validUntil = p.valid_until;
        break;
      case 'revocation':
        if (p.full) {
          scope.terminated = true;
          scope.purposes.clear();
          scope.territories.clear();
        } else {
          for (const x of p.purposes || []) scope.purposes.delete(x);
          for (const x of p.territories || []) scope.territories.delete(x);
        }
        break;
      case 'ruling':
        if (p.action === 'suspend') scope.suspended = true;
        else if (p.action === 'reinstate') scope.suspended = false;
        else if (p.action === 'invalidate') scope.terminated = true;
        break;
      default:
        throw new Error(`unknown license event type: ${ev.type}`);
    }
  }
  return scope;
}

function getEffectiveScope(db, licenseId) {
  return reduceScope(listLicenseEvents(db, licenseId));
}

function licenseHeadDigest(db, licenseId) {
  const tail = db.prepare(
    'SELECT signature_digest FROM license_events WHERE license_id = ? ORDER BY seq DESC LIMIT 1'
  ).get(licenseId);
  return tail ? tail.signature_digest : null;
}

// 许可当前是否覆盖某次用途：用途与地域在有效集合内、声明期限落在授权期限内、
// 未中止、未终止，且检查时点处于授权期限内。ISO 时间按字典序比较。
// 返回三态：covered（有效）/ suspended（被裁定中止，暂时无效）/ uncovered（范围不再覆盖，永久失效）。
function coverageStatus(scope, { purpose, territory, from, until, at }) {
  if (scope.terminated) return 'uncovered';
  if (!scope.purposes.has(purpose)) return 'uncovered';
  if (!scope.territories.has(territory)) return 'uncovered';
  if (!scope.validFrom || !scope.validUntil) return 'uncovered';
  if (from < scope.validFrom || until > scope.validUntil) return 'uncovered';
  if (at < scope.validFrom || at > scope.validUntil) return 'uncovered';
  if (scope.suspended) return 'suspended';
  return 'covered';
}

function covers(scope, use) {
  return coverageStatus(scope, use) === 'covered';
}

// ---------- 字段派生闭包与覆盖检查 ----------

// 收集字段的全部“源头祖先”：自身为 source 时包含自身；
// derived 字段沿派生边传递展开，直到全部为 source 字段。带环保护。
function gatherSourceAncestors(db, fieldId) {
  const sources = new Set();
  const visited = new Set();
  const queue = [fieldId];
  const upstreamStmt = db.prepare('SELECT upstream_field_id FROM field_derivations WHERE derived_field_id = ?');
  const kindStmt = db.prepare('SELECT kind FROM fields WHERE id = ?');
  while (queue.length > 0) {
    const current = queue.shift();
    if (visited.has(current)) continue;
    visited.add(current);
    const field = kindStmt.get(current);
    if (!field) throw new Error(`field not found: ${current}`);
    if (field.kind === 'source') {
      sources.add(current);
      continue;
    }
    for (const edge of upstreamStmt.all(current)) {
      queue.push(edge.upstream_field_id);
    }
  }
  return [...sources];
}

function findCoveringLicense(db, fieldId, use) {
  const licenses = db.prepare(
    'SELECT id FROM licenses WHERE field_id = ? ORDER BY created_at, id'
  ).all(fieldId);
  for (const { id } of licenses) {
    const scope = getEffectiveScope(db, id);
    if (covers(scope, use)) return id;
  }
  return null;
}

// 派生字段只有在所有上游源头许可都覆盖本次用途时才算可签发。
// 返回每个源头字段所选中的许可（凭证链的依赖集合）。
function evaluateFieldCoverage(db, fieldId, use) {
  const sources = gatherSourceAncestors(db, fieldId);
  const dependencies = [];
  const missing = [];
  for (const sourceFieldId of sources) {
    const licenseId = findCoveringLicense(db, sourceFieldId, use);
    if (licenseId) dependencies.push({ fieldId: sourceFieldId, licenseId });
    else missing.push(sourceFieldId);
  }
  return { ok: missing.length === 0, missing, dependencies };
}

module.exports = {
  recordLicenseEvent,
  listLicenseEvents,
  reduceScope,
  getEffectiveScope,
  licenseHeadDigest,
  coverageStatus,
  covers,
  gatherSourceAncestors,
  findCoveringLicense,
  evaluateFieldCoverage,
};
