'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../src/app');
const { verifyAuditChain } = require('../src/lib/audit');

let server;
let base;
let db;

const REG = { actor: 'registrar-1', role: 'registrar' };
const WINDOW = { from: '2026-01-01T00:00:00.000Z', until: '2027-12-31T23:59:59.000Z' };
const TERM = { from: '2026-06-01T00:00:00.000Z', until: '2027-05-31T23:59:59.000Z' };

before(async () => {
  const created = createApp({ dbPath: ':memory:' });
  db = created.db;
  server = created.app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.close();
  db.close();
});

async function api(method, path, { actor, role, body } = {}) {
  const headers = {};
  if (actor) headers['x-actor-id'] = actor;
  if (role) headers['x-actor-role'] = role;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const res = await fetch(base + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json().catch(() => null);
  return { status: res.status, body: json };
}

const get = (path, auth = {}) => api('GET', path, auth);
const post = (path, body, auth = {}) => api('POST', path, { ...auth, body });

// ---------- 场景构造辅助 ----------

let seq = 0;

async function createDatasetWithVersion() {
  seq += 1;
  const ds = await post('/datasets', { name: `dataset-${seq}`, owner: 'data-team' }, REG);
  assert.equal(ds.status, 201);
  const ver = await post(`/datasets/${ds.body.id}/versions`, { version: 1, content_hash: `hash-${seq}` }, REG);
  assert.equal(ver.status, 201);
  return { datasetId: ds.body.id, versionId: ver.body.id };
}

async function createSourceField(versionId, name, sensitivity = 'internal') {
  const res = await post(`/versions/${versionId}/fields`, { name, kind: 'source', sensitivity }, REG);
  assert.equal(res.status, 201);
  return res.body.id;
}

async function createDerivedField(versionId, name, upstreamIds) {
  const res = await post(`/versions/${versionId}/fields`, {
    name, kind: 'derived', upstream_field_ids: upstreamIds,
  }, REG);
  assert.equal(res.status, 201);
  return res.body.id;
}

async function createLicense(fieldId, overrides = {}) {
  const res = await post(`/fields/${fieldId}/licenses`, {
    grantor: 'owner-corp',
    grantee: 'data-team',
    purposes: ['analytics'],
    territories: ['CN'],
    valid_from: WINDOW.from,
    valid_until: WINDOW.until,
    terms: `confidential terms for ${fieldId}`,
    ...overrides,
  }, REG);
  assert.equal(res.status, 201);
  return res.body.id;
}

async function submitDeclaration(fieldId, overrides = {}, actor = 'submitter-1') {
  const res = await post('/declarations', {
    field_id: fieldId,
    purpose: 'analytics',
    territory: 'CN',
    term_from: TERM.from,
    term_until: TERM.until,
    ...overrides,
  }, { actor, role: 'submitter' });
  assert.equal(res.status, 201);
  return res.body.id;
}

async function approve(declarationId, actor, decision = 'approve') {
  return post(`/declarations/${declarationId}/approve`, { decision }, { actor, role: 'approver' });
}

async function approveFully(declarationId) {
  const a1 = await approve(declarationId, 'approver-1');
  assert.equal(a1.status, 200);
  const a2 = await approve(declarationId, 'approver-2');
  assert.equal(a2.status, 200);
  assert.equal(a2.body.status, 'approved');
}

async function issue(declarationId) {
  return post(`/declarations/${declarationId}/issue`, {}, REG);
}

async function issueCredentialFor(fieldId, declOverrides = {}) {
  const declId = await submitDeclaration(fieldId, declOverrides);
  await approveFully(declId);
  const res = await issue(declId);
  assert.equal(res.status, 201);
  return res.body;
}

async function mintToken(credentialId) {
  const res = await post(`/credentials/${credentialId}/tokens`, { label: 'external-auditor' }, REG);
  assert.equal(res.status, 201);
  return res.body;
}

const verifyToken = (token) => post('/verify', { token });

// 标准场景：两个源头字段各有许可，一个派生字段依赖两者
async function standardChain(licenseOverridesA = {}, licenseOverridesB = {}) {
  const { versionId } = await createDatasetWithVersion();
  const fieldA = await createSourceField(versionId, 'raw_a');
  const fieldB = await createSourceField(versionId, 'raw_b');
  const licenseA = await createLicense(fieldA, licenseOverridesA);
  const licenseB = await createLicense(fieldB, licenseOverridesB);
  const derived = await createDerivedField(versionId, 'derived_ab', [fieldA, fieldB]);
  return { versionId, fieldA, fieldB, licenseA, licenseB, derived };
}

// ---------- 测试 ----------

test('完整链路：登记→双人批准→签发→验证凭据→外部核验', async () => {
  const { derived, licenseA, licenseB } = await standardChain();
  const credential = await issueCredentialFor(derived);

  assert.equal(credential.status, 'active');
  assert.equal(typeof credential.chain_hash, 'string');
  assert.deepEqual(credential.dependencies.sort(), [licenseA, licenseB].sort());

  const minted = await mintToken(credential.id);
  assert.ok(minted.token.startsWith('vt_'));

  const verdict = await verifyToken(minted.token);
  assert.equal(verdict.status, 200);
  assert.equal(verdict.body.valid, true);
  assert.equal(verdict.body.purpose, 'analytics');
  assert.equal(verdict.body.territory, 'CN');
  // 最小披露：核验结果不得包含合同主体与条款信息
  const leaked = JSON.stringify(verdict.body);
  for (const forbidden of ['grantor', 'grantee', 'terms', 'owner-corp', 'data-team', 'chain_hash']) {
    assert.ok(!leaked.includes(forbidden), `verify response leaks ${forbidden}`);
  }
});

test('派生字段上游许可不全时拒绝签发，声明保持 approved', async () => {
  const { versionId } = await createDatasetWithVersion();
  const fieldA = await createSourceField(versionId, 'raw_a');
  const fieldB = await createSourceField(versionId, 'raw_b');
  await createLicense(fieldA); // fieldB 无许可
  const derived = await createDerivedField(versionId, 'derived_ab', [fieldA, fieldB]);

  const declId = await submitDeclaration(derived);
  await approveFully(declId);
  const res = await issue(declId);
  assert.equal(res.status, 409);
  assert.match(res.body.error.message, /upstream license coverage missing/);

  const decl = await get(`/declarations/${declId}`, REG);
  assert.equal(decl.body.status, 'approved');

  const failures = db.prepare(
    "SELECT * FROM audit_log WHERE action = 'credential_issued' AND outcome = 'failure' AND entity_id = ?"
  ).all(declId);
  assert.equal(failures.length, 1);
});

test('上游许可用途不覆盖本次用途时拒绝签发', async () => {
  const { derived } = await standardChain({ purposes: ['marketing'] });
  const declId = await submitDeclaration(derived, { purpose: 'analytics' });
  await approveFully(declId);
  const res = await issue(declId);
  assert.equal(res.status, 409);
});

test('声明期限超出授权期限时拒绝签发', async () => {
  const { derived } = await standardChain();
  const declId = await submitDeclaration(derived, { term_until: '2028-06-01T00:00:00.000Z' });
  await approveFully(declId);
  const res = await issue(declId);
  assert.equal(res.status, 409);
});

test('许可已过期（当前时点不在授权期限内）时拒绝签发', async () => {
  const { derived } = await standardChain({
    valid_from: '2025-01-01T00:00:00.000Z',
    valid_until: '2025-12-31T23:59:59.000Z',
  });
  const declId = await submitDeclaration(derived, {
    term_from: '2025-06-01T00:00:00.000Z',
    term_until: '2025-12-01T00:00:00.000Z',
  });
  await approveFully(declId);
  const res = await issue(declId);
  assert.equal(res.status, 409);
});

test('提交人不能批准自己的声明，拒绝动作入审计', async () => {
  const { derived } = await standardChain();
  const declId = await submitDeclaration(derived, {}, 'selfish-user');
  const res = await approve(declId, 'selfish-user');
  assert.equal(res.status, 403);

  const denied = db.prepare(
    "SELECT * FROM audit_log WHERE action = 'declaration_approval' AND outcome = 'denied'"
  ).all();
  assert.ok(denied.some((e) => e.detail.includes('self_approval')));
});

test('同一批准人重复批准只生效一次', async () => {
  const { derived } = await standardChain();
  const declId = await submitDeclaration(derived);
  const first = await approve(declId, 'approver-1');
  assert.equal(first.status, 200);
  const dup = await approve(declId, 'approver-1');
  assert.equal(dup.status, 409);

  const decl = await get(`/declarations/${declId}`, REG);
  assert.equal(decl.body.approvals.length, 1);
  assert.equal(decl.body.status, 'pending');
});

test('并发批准：多名批准人同时到达时状态迁移只发生一次', async () => {
  const { derived } = await standardChain();
  const declId = await submitDeclaration(derived);

  const results = await Promise.all([
    approve(declId, 'approver-a'),
    approve(declId, 'approver-b'),
    approve(declId, 'approver-c'),
  ]);
  const statuses = results.map((r) => r.status).sort();
  assert.deepEqual(statuses, [200, 200, 409]);

  const decl = await get(`/declarations/${declId}`, REG);
  assert.equal(decl.body.status, 'approved');
  assert.equal(decl.body.approvals.length, 2);

  const transitions = db.prepare(
    "SELECT * FROM audit_log WHERE action = 'declaration_approved' AND entity_id = ?"
  ).all(declId);
  assert.equal(transitions.length, 1);
});

test('并发重复提交：同一批准人并发双击只记录一次', async () => {
  const { derived } = await standardChain();
  const declId = await submitDeclaration(derived);
  const results = await Promise.all([approve(declId, 'approver-x'), approve(declId, 'approver-x')]);
  const statuses = results.map((r) => r.status).sort();
  assert.deepEqual(statuses, [200, 409]);
  const decl = await get(`/declarations/${declId}`, REG);
  assert.equal(decl.body.approvals.length, 1);
});

test('拒绝决定使声明进入 rejected 且不可再批准', async () => {
  const { derived } = await standardChain();
  const declId = await submitDeclaration(derived);
  const res = await post(`/declarations/${declId}/approve`, { decision: 'reject', reason: 'scope too broad' }, { actor: 'approver-1', role: 'approver' });
  assert.equal(res.status, 200);
  assert.equal(res.body.status, 'rejected');
  const again = await approve(declId, 'approver-2');
  assert.equal(again.status, 409);
});

test('局部撤回只传播到受影响用途的凭证', async () => {
  const { versionId } = await createDatasetWithVersion();
  const fieldA = await createSourceField(versionId, 'raw_a');
  await createLicense(fieldA, { purposes: ['analytics', 'marketing'] });
  const derived = await createDerivedField(versionId, 'derived_a', [fieldA]);

  const analyticsCred = await issueCredentialFor(derived, { purpose: 'analytics' });
  const marketingCred = await issueCredentialFor(derived, { purpose: 'marketing' });
  const analyticsToken = await mintToken(analyticsCred.id);
  const marketingToken = await mintToken(marketingCred.id);

  const licenseId = db.prepare('SELECT id FROM licenses WHERE field_id = ?').get(fieldA).id;
  const revoke = await post(`/licenses/${licenseId}/events`, {
    type: 'revocation',
    payload: { purposes: ['marketing'], note: 'marketing use withdrawn' },
  }, REG);
  assert.equal(revoke.status, 201);
  assert.deepEqual(revoke.body.revoked_credentials, [marketingCred.id]);

  const analyticsVerdict = await verifyToken(analyticsToken.token);
  assert.equal(analyticsVerdict.body.valid, true);
  const marketingVerdict = await verifyToken(marketingToken.token);
  assert.equal(marketingVerdict.body.valid, false);

  const marketingRow = await get(`/credentials/${marketingCred.id}`, REG);
  assert.equal(marketingRow.body.status, 'revoked');
  assert.equal(marketingRow.body.revoked_reason, 'upstream_license_invalid');
});

test('撤回沿派生链传递：源头撤回使下游派生凭证失效', async () => {
  const { versionId } = await createDatasetWithVersion();
  const fieldA = await createSourceField(versionId, 'raw_a');
  const licenseId = await createLicense(fieldA);
  const fieldB = await createDerivedField(versionId, 'derived_b', [fieldA]);
  const fieldC = await createDerivedField(versionId, 'derived_c', [fieldB]);

  const credential = await issueCredentialFor(fieldC);
  const token = await mintToken(credential.id);
  assert.equal((await verifyToken(token.token)).body.valid, true);

  const revoke = await post(`/licenses/${licenseId}/events`, {
    type: 'revocation', payload: { full: true },
  }, REG);
  assert.equal(revoke.status, 201);
  assert.deepEqual(revoke.body.revoked_credentials, [credential.id]);

  const verdict = await verifyToken(token.token);
  assert.equal(verdict.body.valid, false);
});

test('争议裁定中止使验证暂时失败，恢复后重新有效，凭证不被撤销', async () => {
  const { derived, licenseA } = await standardChain();
  const credential = await issueCredentialFor(derived);
  const token = await mintToken(credential.id);

  const suspend = await post(`/licenses/${licenseA}/events`, {
    type: 'ruling', payload: { action: 'suspend', reference: 'dispute-42' },
  }, REG);
  assert.equal(suspend.status, 201);
  assert.deepEqual(suspend.body.revoked_credentials, []);

  const suspended = await verifyToken(token.token);
  assert.equal(suspended.body.valid, false);
  assert.equal(suspended.body.reason, 'upstream_suspended');

  const stillActive = await get(`/credentials/${credential.id}`, REG);
  assert.equal(stillActive.body.status, 'active');

  await post(`/licenses/${licenseA}/events`, {
    type: 'ruling', payload: { action: 'reinstate', reference: 'dispute-42' },
  }, REG);
  const reinstated = await verifyToken(token.token);
  assert.equal(reinstated.body.valid, true);
});

test('补充协议扩大范围后新用途可签发，缩小范围会传播撤销', async () => {
  const { versionId } = await createDatasetWithVersion();
  const fieldA = await createSourceField(versionId, 'raw_a');
  const licenseId = await createLicense(fieldA, { purposes: ['analytics'] });
  const derived = await createDerivedField(versionId, 'derived_a', [fieldA]);

  // marketing 初始不可签发
  const marketingDecl = await submitDeclaration(derived, { purpose: 'marketing' });
  await approveFully(marketingDecl);
  assert.equal((await issue(marketingDecl)).status, 409);

  // 补充协议加入 marketing
  const amend = await post(`/licenses/${licenseId}/events`, {
    type: 'amendment', payload: { add_purposes: ['marketing'] },
  }, REG);
  assert.equal(amend.status, 201);
  const marketingCred = await issue(marketingDecl);
  assert.equal(marketingCred.status, 201);

  // 补充协议移除 analytics → 已签发的 analytics 凭证被传播撤销
  const analyticsCred = await issueCredentialFor(derived, { purpose: 'analytics' });
  const shrink = await post(`/licenses/${licenseId}/events`, {
    type: 'amendment', payload: { remove_purposes: ['analytics'] },
  }, REG);
  assert.equal(shrink.status, 201);
  assert.deepEqual(shrink.body.revoked_credentials, [analyticsCred.id]);

  const marketingRow = await get(`/credentials/${marketingCred.body.id}`, REG);
  assert.equal(marketingRow.body.status, 'active');
});

test('验证凭据可撤销，撤销后核验失败', async () => {
  const { derived } = await standardChain();
  const credential = await issueCredentialFor(derived);
  const minted = await mintToken(credential.id);
  assert.equal((await verifyToken(minted.token)).body.valid, true);

  const revoke = await post(`/tokens/${minted.id}/revoke`, {}, REG);
  assert.equal(revoke.status, 200);
  const verdict = await verifyToken(minted.token);
  assert.equal(verdict.body.valid, false);
  assert.equal(verdict.body.reason, 'token_revoked');
});

test('未知 token 核验失败并留下失败审计', async () => {
  const before = db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'verification' AND outcome = 'failure'").get().n;
  const res = await verifyToken('vt_does_not_exist');
  assert.equal(res.status, 404);
  assert.equal(res.body.valid, false);
  const afterCount = db.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'verification' AND outcome = 'failure'").get().n;
  assert.equal(afterCount, before + 1);
});

test('许可视图最小披露：不出现条款原文，只有哈希；事件链摘要互相链接', async () => {
  const secretTerms = 'highly confidential royalty schedule 7.5%';
  const { versionId } = await createDatasetWithVersion();
  const fieldA = await createSourceField(versionId, 'raw_a');
  const res = await post(`/fields/${fieldA}/licenses`, {
    grantor: 'owner-corp', grantee: 'data-team', purposes: ['analytics'], territories: ['CN'],
    valid_from: WINDOW.from, valid_until: WINDOW.until, terms: secretTerms,
  }, REG);
  assert.equal(res.status, 201);

  const view = await get(`/licenses/${res.body.id}`, REG);
  const serialized = JSON.stringify(view.body);
  assert.ok(!serialized.includes(secretTerms));
  assert.ok(!('terms' in view.body));
  assert.equal(typeof view.body.terms_hash, 'string');

  // 追加事件后校验摘要链
  await post(`/licenses/${res.body.id}/events`, { type: 'amendment', payload: { add_purposes: ['marketing'] } }, REG);
  const after2 = await get(`/licenses/${res.body.id}`, REG);
  const events = after2.body.events;
  assert.equal(events.length, 2);
  assert.equal(events[1].prev_digest, events[0].signature_digest);
  assert.equal(events[0].type, 'grant');
  assert.equal(events[1].type, 'amendment');
  assert.deepEqual(after2.body.effective_scope.purposes, ['analytics', 'marketing']);
});

test('导出按敏感度最小范围展示，越权访问被拒绝并审计', async () => {
  const { versionId } = await createDatasetWithVersion();
  await createSourceField(versionId, 'public_field', 'public');
  await createSourceField(versionId, 'secret_field', 'confidential');

  const plain = await get(`/versions/${versionId}/export`, { actor: 'analyst-1', role: 'submitter' });
  assert.equal(plain.status, 200);
  const secret = plain.body.fields.find((f) => f.sensitivity === 'confidential');
  assert.equal(secret.name, '[redacted]');

  const denied = await get(`/versions/${versionId}/export?include=confidential`, { actor: 'analyst-1', role: 'submitter' });
  assert.equal(denied.status, 403);
  const deniedAudit = db.prepare("SELECT * FROM audit_log WHERE action = 'export' AND outcome = 'denied'").all();
  assert.ok(deniedAudit.length >= 1);

  const admin = await get(`/versions/${versionId}/export?include=confidential`, { actor: 'boss', role: 'admin' });
  assert.equal(admin.status, 200);
  const revealed = admin.body.fields.find((f) => f.sensitivity === 'confidential');
  assert.equal(revealed.name, 'secret_field');
});

test('缺少身份或角色不足被拒绝并审计', async () => {
  const noActor = await post('/datasets', { name: 'x', owner: 'y' });
  assert.equal(noActor.status, 401);

  const wrongRole = await post('/datasets', { name: 'x', owner: 'y' }, { actor: 'intruder', role: 'submitter' });
  assert.equal(wrongRole.status, 403);

  const denied = db.prepare("SELECT * FROM audit_log WHERE outcome = 'denied' AND action = 'dataset_created'").all();
  assert.ok(denied.length >= 2);
  assert.ok(denied.some((e) => e.actor === 'anonymous'));
});

test('非批准角色不能批准声明', async () => {
  const { derived } = await standardChain();
  const declId = await submitDeclaration(derived);
  const res = await post(`/declarations/${declId}/approve`, { decision: 'approve' }, { actor: 'reg-2', role: 'registrar' });
  assert.equal(res.status, 403);
});

test('审计接口仅审计角色可见，且哈希链完整', async () => {
  const forbidden = await get('/audit', { actor: 'registrar-1', role: 'registrar' });
  assert.equal(forbidden.status, 403);

  const res = await get('/audit', { actor: 'auditor-1', role: 'auditor' });
  assert.equal(res.status, 200);
  assert.ok(res.body.entries.length > 0);
  const actions = new Set(res.body.entries.map((e) => e.action));
  for (const expected of ['credential_issued', 'verification', 'token_minted', 'license_event_recorded', 'declaration_approved']) {
    assert.ok(actions.has(expected), `audit missing action ${expected}`);
  }

  const integrity = verifyAuditChain(db);
  assert.equal(integrity.intact, true);
});
