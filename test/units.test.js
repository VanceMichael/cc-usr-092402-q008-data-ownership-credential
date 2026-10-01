'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { openDatabase, migrate } = require('../src/db');
const { appendAudit, verifyAuditChain, GENESIS_HASH } = require('../src/lib/audit');
const { recordLicenseEvent, listLicenseEvents, reduceScope } = require('../src/lib/licenses');
const { digestObject } = require('../src/lib/crypto');

function freshDb() {
  const db = openDatabase(':memory:');
  migrate(db);
  return db;
}

// 许可事件依赖完整外键链：dataset → version → field → license
function seedLicense(db, licenseId) {
  const at = '2026-01-01T00:00:00.000Z';
  db.prepare('INSERT INTO datasets (id, name, owner, created_at) VALUES (?, ?, ?, ?)')
    .run(`ds_${licenseId}`, 'ds', 'owner', at);
  db.prepare('INSERT INTO dataset_versions (id, dataset_id, version, content_hash, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(`dsv_${licenseId}`, `ds_${licenseId}`, 1, 'hash', at);
  db.prepare('INSERT INTO fields (id, dataset_version_id, name, kind, sensitivity, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(`fld_${licenseId}`, `dsv_${licenseId}`, 'f', 'source', 'internal', at);
  db.prepare(`INSERT INTO licenses (id, field_id, grantor, grantee, purposes, territories, valid_from, valid_until, terms, terms_hash, status, created_by, created_at)
              VALUES (?, ?, ?, ?, '[]', '[]', ?, ?, 'terms', 'hash', 'active', 'reg', ?)`)
    .run(licenseId, `fld_${licenseId}`, 'g', 'e', at, at, at);
}

test('审计链：追加可校验，篡改历史会被发现', () => {
  const db = freshDb();
  appendAudit(db, { actor: 'a', action: 'one', outcome: 'success' });
  appendAudit(db, { actor: 'b', action: 'two', outcome: 'failure', detail: { x: 1 } });
  appendAudit(db, { actor: 'c', action: 'three', outcome: 'denied' });
  assert.equal(verifyAuditChain(db).intact, true);

  // 篡改历史内容
  db.prepare("UPDATE audit_log SET actor = 'mallory' WHERE action = 'one'").run();
  const verdict = verifyAuditChain(db);
  assert.equal(verdict.intact, false);
  assert.equal(typeof verdict.brokenAt, 'number');
  db.close();
});

test('审计链：删除尾部记录之外的位置也会断链', () => {
  const db = freshDb();
  for (let i = 0; i < 5; i += 1) appendAudit(db, { actor: 'a', action: `act-${i}`, outcome: 'success' });
  assert.equal(verifyAuditChain(db).intact, true);
  db.prepare('DELETE FROM audit_log WHERE id = 2').run();
  assert.equal(verifyAuditChain(db).intact, false);
  db.close();
});

test('许可事件：签名摘要可独立复算，事件流归约出有效范围', () => {
  const db = freshDb();
  seedLicense(db, 'lic_test');
  const at = '2026-10-01T00:00:00.000Z';
  const grant = recordLicenseEvent(db, {
    licenseId: 'lic_test', type: 'grant',
    payload: { purposes: ['analytics'], territories: ['CN'], valid_from: '2026-01-01T00:00:00.000Z', valid_until: '2027-01-01T00:00:00.000Z', terms_hash: 'abc' },
    createdBy: 'reg', ts: at,
  });
  const amend = recordLicenseEvent(db, {
    licenseId: 'lic_test', type: 'amendment',
    payload: { add_purposes: ['marketing'] },
    createdBy: 'reg', ts: '2026-10-01T01:00:00.000Z',
  });
  const revoke = recordLicenseEvent(db, {
    licenseId: 'lic_test', type: 'revocation',
    payload: { purposes: ['analytics'] },
    createdBy: 'reg', ts: '2026-10-01T02:00:00.000Z',
  });

  // 摘要链相互链接且可复算
  assert.equal(amend.prevDigest, grant.signatureDigest);
  assert.equal(revoke.prevDigest, amend.signatureDigest);
  const recomputed = digestObject({
    license_id: 'lic_test',
    seq: amend.seq,
    type: 'amendment',
    payload: { add_purposes: ['marketing'] },
    created_by: 'reg',
    created_at: '2026-10-01T01:00:00.000Z',
    prev_digest: grant.signatureDigest,
  });
  assert.equal(recomputed, amend.signatureDigest);

  // 归约：grant + amendment + 局部撤回 → 只剩 marketing
  const scope = reduceScope(listLicenseEvents(db, 'lic_test'));
  assert.deepEqual([...scope.purposes].sort(), ['marketing']);
  assert.deepEqual([...scope.territories], ['CN']);
  assert.equal(scope.terminated, false);
  assert.equal(scope.suspended, false);

  // 裁定中止与恢复
  recordLicenseEvent(db, { licenseId: 'lic_test', type: 'ruling', payload: { action: 'suspend' }, createdBy: 'reg' });
  assert.equal(reduceScope(listLicenseEvents(db, 'lic_test')).suspended, true);
  recordLicenseEvent(db, { licenseId: 'lic_test', type: 'ruling', payload: { action: 'reinstate' }, createdBy: 'reg' });
  assert.equal(reduceScope(listLicenseEvents(db, 'lic_test')).suspended, false);
  recordLicenseEvent(db, { licenseId: 'lic_test', type: 'ruling', payload: { action: 'invalidate' }, createdBy: 'reg' });
  assert.equal(reduceScope(listLicenseEvents(db, 'lic_test')).terminated, true);
  db.close();
});

test('许可事件：篡改载荷后复算摘要不一致', () => {
  const db = freshDb();
  seedLicense(db, 'lic_x');
  const event = recordLicenseEvent(db, {
    licenseId: 'lic_x', type: 'revocation', payload: { full: true }, createdBy: 'reg',
  });
  const tampered = digestObject({
    license_id: 'lic_x',
    seq: event.seq,
    type: 'revocation',
    payload: { full: false }, // 篡改：把完全撤回改成局部
    created_by: 'reg',
    created_at: event.createdAt,
    prev_digest: event.prevDigest,
  });
  assert.notEqual(tampered, event.signatureDigest);
  db.close();
});

test('审计创世哈希：首条记录链接到 GENESIS', () => {
  const db = freshDb();
  appendAudit(db, { actor: 'a', action: 'first', outcome: 'success' });
  const row = db.prepare('SELECT prev_hash FROM audit_log ORDER BY id LIMIT 1').get();
  assert.equal(row.prev_hash, GENESIS_HASH);
  db.close();
});
