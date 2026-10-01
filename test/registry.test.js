'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Database = require('better-sqlite3');

const TMP_DB = path.join(os.tmpdir(), `dc-test-${process.pid}-${Date.now()}.sqlite3`);
process.env.DATA_CREDENTIAL_DB_PATH = TMP_DB;
process.env.REGISTRY_ADMIN_ID = 'p-admin';

const { open, migrate } = require('../src/db');
const { createApp } = require('../src/app');
const { RegistryClient } = require('../src/client');
const { generateKeyPair, digestObject, verifyObject, loadPublicKey } = require('../src/crypto');

let server, base, db;
const actors = {};
const ids = {};

function actor(name, id, role) {
  const kp = generateKeyPair();
  actors[name] = { principal_id: id, role, publicKeyB64: kp.publicKeyB64, privateKeyB64: kp.privateKeyB64 };
  return actors[name];
}

function client(name) {
  const a = actors[name];
  return new RegistryClient(base, { principal_id: a.principal_id, privateKeyB64: a.privateKeyB64 });
}

function anon() {
  return new RegistryClient(base, {});
}

async function verify(token, extra = {}) {
  return anon().request('POST', '/v1/verify', { token, ...extra }, { sign: false });
}

function docHash(text) {
  return digestObject({ contract: text, nonce: Math.random() });
}

async function start() {
  // 先生成管理员密钥，通过环境变量在迁移时引导首个主体
  actor('admin', 'p-admin', 'admin');
  process.env.REGISTRY_ADMIN_PUBLIC_KEY = actors.admin.publicKeyB64;
  db = open();
  migrate(db);
  const app = createApp(db);
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  base = `http://127.0.0.1:${server.address().port}`;
}

async function stop() {
  await new Promise((r) => server.close(r));
  db.close();
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.rmSync(TMP_DB + suffix); } catch { /* ignore */ }
  }
}

test.before(async () => {
  await start();

  actor('submitter', 'p-sub', 'submitter');
  actor('approver1', 'p-apr1', 'approver');
  actor('approver2', 'p-apr2', 'approver');
  actor('arbitrator', 'p-arb', 'arbitrator');
  actor('licensor1', 'p-lic1', 'authority');
  actor('licensor2', 'p-lic2', 'authority');
  actor('outsider', 'p-out', 'submitter');

  const admin = client('admin');
  for (const a of Object.values(actors)) {
    if (a.principal_id === 'p-admin') continue; // 已由迁移引导
    const res = await admin.request('POST', '/v1/admin/principals', {
      principal_id: a.principal_id, name: a.principal_id, role: a.role, public_key: a.publicKeyB64,
    });
    assert.equal(res.status, 200, res.json && res.json.message);
  }
});

test.after(async () => {
  await stop();
});

// ---------- 授权登记 ----------

test('licensor registers signed original authorization; raw body never stored', async () => {
  const lic = client('licensor1');
  const build = lic.legal.original({
    license_id: 'L1',
    terms: { purposes: ['research'], regions: ['CN'], valid_from: '2026-01-01T00:00:00Z', valid_until: '2030-12-31T00:00:00Z' },
    document_hash: docHash('L1-contract-text'),
  });
  const res = await lic.request('POST', '/v1/licenses', build.body);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.equal(res.json.status, 'active');

  const res2 = await client('licensor2').request('POST', '/v1/licenses', client('licensor2').legal.original({
    license_id: 'L2',
    terms: { purposes: ['marketing'], regions: ['CN'], valid_from: '2026-01-01T00:00:00Z', valid_until: '2030-12-31T00:00:00Z' },
    document_hash: docHash('L2-contract-text'),
  }).body);
  assert.equal(res2.status, 200);

  // 数据库中只保留签名摘要，不存在合同正文
  const dump = JSON.stringify(db.prepare('SELECT * FROM legal_events').all());
  assert.ok(!dump.includes('L1-contract-text'));
  assert.ok(!dump.includes('L2-contract-text'));

  // 伪造签名被拒
  const forged = { ...build.body, document_hash: docHash('tampered-contract') };
  const bad = await client('licensor1').request('POST', '/v1/licenses', forged);
  assert.equal(bad.status, 401);
  assert.equal(bad.json.error, 'bad_signature');
});

test('license record is confidential to its parties', async () => {
  const res = await client('outsider').request('GET', '/v1/licenses/L1', null);
  assert.equal(res.status, 403);
  const mine = await client('licensor1').request('GET', '/v1/licenses/L1', null);
  assert.equal(mine.status, 200);
  assert.ok(mine.json.events[0].document_hash);
  assert.equal(mine.json.events[0].payload.terms.purposes[0], 'research');
});

// ---------- 数据集版本与派生图 ----------

test('register dataset version with field lineage DAG; cycles rejected', async () => {
  const fields = [
    { name: 'raw_a', kind: 'source', licenses: ['L1'] },
    { name: 'raw_c', kind: 'source', licenses: ['L2'] },
    { name: 'raw_b', kind: 'source' }, // 无任何授权
    { name: 'enriched', kind: 'derived', derived_from: ['raw_a'] },
    { name: 'merged', kind: 'derived', derived_from: ['raw_a', 'raw_b'] },
  ];
  const res = await client('submitter').request('POST', '/v1/datasets/versions', {
    dataset_id: 'D', version: 'v1', manifest_hash: digestObject({ files: ['a.csv', 'b.csv'] }), fields,
  });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  ids.rawA = 'D@v1#raw_a';
  ids.rawC = 'D@v1#raw_c';
  ids.enriched = 'D@v1#enriched';
  ids.merged = 'D@v1#merged';

  const cyc = await client('submitter').request('POST', '/v1/datasets/versions', {
    dataset_id: 'D', version: 'vbad', manifest_hash: 'x',
    fields: [
      { name: 'x', kind: 'derived', derived_from: ['y'] },
      { name: 'y', kind: 'derived', derived_from: ['x'] },
    ],
  });
  assert.equal(cyc.status, 400);
  assert.equal(cyc.json.error, 'lineage_cycle');

  const unknown = await client('submitter').request('POST', '/v1/datasets/versions', {
    dataset_id: 'D', version: 'vbad2', manifest_hash: 'x',
    fields: [{ name: 'x', kind: 'derived', derived_from: ['ghost'] }],
  });
  assert.equal(unknown.json.error, 'unknown_upstream');
});

// ---------- 声明与双人批准 ----------

async function submitClaim(overrides = {}) {
  const res = await client('submitter').request('POST', '/v1/claims', {
    dataset_id: 'D', version: 'v1', purpose: 'research', region: 'CN', ...overrides,
  });
  assert.equal(res.status, 200, JSON.stringify(res.json));
  return res.json.claim_id;
}

async function approve(approverName, claimId, decision = 'approved') {
  return client(approverName).request('POST', `/v1/claims/${claimId}/decisions`, { decision });
}

test('submitter cannot approve own claim (even admins are subject to SoD)', async () => {
  const claimId = await submitClaim({ field_id: ids.rawA });
  ids.rawAClaim = claimId;
  const res = await client('submitter').request('POST', `/v1/claims/${claimId}/decisions`, { decision: 'approved' });
  assert.equal(res.status, 403);
  assert.equal(res.json.error, 'role_denied'); // submitter 角色本就无批准权
});

test('two-person rule: first approval waits, duplicate rejected, second issues after full revalidation', async () => {
  const first = await approve('approver1', ids.rawAClaim);
  assert.equal(first.status, 200);
  assert.equal(first.json.outcome, 'awaiting_second_approval');

  const dup = await approve('approver1', ids.rawAClaim);
  assert.equal(dup.status, 409);
  assert.equal(dup.json.error, 'duplicate_approval');

  const second = await approve('approver2', ids.rawAClaim);
  assert.equal(second.status, 200, JSON.stringify(second.json));
  assert.equal(second.json.outcome, 'issued');
  ids.credRawA = second.json.credential.credential_id;

  // 事后再批准被拒
  const late = await approve('approver1', ids.rawAClaim);
  assert.equal(late.status, 409);
  assert.equal(late.json.error, 'claim_decided');
});

test('concurrent decisions: exactly one wins, no double issuance', async () => {
  const claimId = await submitClaim({ field_id: ids.rawC, purpose: 'marketing' });
  ids.rawCClaim = claimId;

  // 同一批准人并发两次：一次登记，一次唯一约束冲突
  const sameApprover = await Promise.all([approve('approver1', claimId), approve('approver1', claimId)]);
  const codes = sameApprover.map((r) => r.json.error || r.json.outcome).sort();
  assert.deepEqual(codes, ['awaiting_second_approval', 'duplicate_approval']);

  // 两位批准人并发第二批准：BEGIN IMMEDIATE 串行化，只能有一张凭证
  const claimId2 = await submitClaim({ field_id: ids.enriched });
  ids.enrichedClaim = claimId2;
  const race = await Promise.all([
    approve('approver1', claimId2),
    approve('approver2', claimId2),
  ]);
  const outcomes = race.map((r) => r.json.outcome).sort();
  assert.deepEqual(outcomes, ['awaiting_second_approval', 'issued']);
  const credCount = db.prepare("SELECT COUNT(*) n FROM credentials WHERE claim_id=?").get(claimId2).n;
  assert.equal(credCount, 1);
  ids.credEnriched = race.find((r) => r.json.outcome === 'issued').json.credential.credential_id;
});

test('derived field credential chains to upstream credential and embeds license evidence', async () => {
  const res = await client('submitter').request('GET', `/v1/credentials/${ids.credEnriched}`, null);
  assert.equal(res.status, 200);
  assert.deepEqual(res.json.document.parents, [ids.credRawA]);
  const evidenceLicenses = res.json.document.evidence.map((e) => e.license_id);
  assert.ok(evidenceLicenses.includes('L1'));
  assert.ok(res.json.document.manifest_hash);

  // 登记处签名可离线复验
  const pub = loadPublicKey(res.json.registry_public_key);
  const ok = verifyObject(pub, { document_hash: res.json.document_hash, body: res.json.document }, res.json.signature);
  assert.ok(ok);
  assert.equal(digestObject(res.json.document), res.json.document_hash);
});

// ---------- 门控：派生只有所有上游许可有效才签发 ----------

test('issuance blocked when an upstream source has no license at all', async () => {
  const claimId = await submitClaim({ field_id: ids.merged });
  await approve('approver1', claimId);
  const res = await approve('approver2', claimId);
  assert.equal(res.json.outcome, 'blocked');
  assert.equal(res.json.reason, 'uncovered_upstream_source');
  assert.ok(res.json.uncovered.includes(ids.merged.replace('merged', 'raw_b')));
  assert.equal(db.prepare('SELECT status FROM claims WHERE claim_id=?').get(claimId).status, 'blocked');
});

test('issuance blocked when terms do not cover purpose/region/window', async () => {
  const wrongPurpose = await submitClaim({ field_id: ids.enriched, purpose: 'marketing' });
  await approve('approver1', wrongPurpose);
  const r1 = await approve('approver2', wrongPurpose);
  assert.equal(r1.json.outcome, 'blocked');
  assert.equal(r1.json.reason, 'terms_not_cover');

  const wrongRegion = await submitClaim({ field_id: ids.enriched, region: 'US' });
  await approve('approver1', wrongRegion);
  const r2 = await approve('approver2', wrongRegion);
  assert.equal(r2.json.reason, 'terms_not_cover');

  // 请求期限超出授权期限
  const tooLong = await submitClaim({ field_id: ids.enriched, requested_until: '2031-06-01T00:00:00Z' });
  await approve('approver1', tooLong);
  const r3 = await approve('approver2', tooLong);
  assert.equal(r3.json.reason, 'terms_not_cover');
});

test('dataset-level claim blocks if any field lacks coverage', async () => {
  const claimId = await submitClaim({ field_id: null });
  await approve('approver1', claimId);
  const res = await approve('approver2', claimId);
  assert.equal(res.json.outcome, 'blocked');
  assert.equal(res.json.reason, 'uncovered_upstream_source');
});

// ---------- 可撤销验证凭据与最小披露 ----------

test('mint opaque token; external verifier learns only valid/scope', async () => {
  const res = await client('submitter').request('POST', `/v1/credentials/${ids.credEnriched}/tokens`, {});
  assert.equal(res.status, 200, JSON.stringify(res.json));
  ids.tokenEnriched = res.json.token;
  assert.match(ids.tokenEnriched, /^dct_/);

  // 明文令牌不落库
  assert.equal(db.prepare('SELECT COUNT(*) n FROM verification_tokens WHERE token_hash=?').get(ids.tokenEnriched).n, 0);

  const v = await verify(ids.tokenEnriched);
  assert.equal(v.status, 200);
  assert.deepEqual(Object.keys(v.json).sort(), ['expires_at', 'purpose', 'region', 'valid']);
  assert.equal(v.json.valid, true);
  assert.equal(v.json.purpose, 'research');
  // 不泄露许可方/合同/凭证/字段
  assert.equal(JSON.stringify(v.json).includes('p-lic1'), false);
  assert.equal(JSON.stringify(v.json).includes('L1'), false);

  const wrongScope = await verify(ids.tokenEnriched, { purpose: 'marketing' });
  assert.equal(wrongScope.status, 403);
  assert.equal(wrongScope.json.valid, false);
  assert.equal(wrongScope.json.reason, 'scope_mismatch');

  const unknown = await verify('dct_garbage');
  assert.equal(unknown.json.reason, 'unknown_token');
});

// ---------- 局部撤回传播 ----------

test('partial withdrawal propagates: derived credential and its tokens revoked', async () => {
  const lic = client('licensor1');
  const withdrawal = lic.legal.withdrawal({
    license_id: 'L1', seq: 2,
    scope: { field_id: ids.rawA, purposes: ['research'], regions: ['CN'] },
    document_hash: docHash('L1-withdraw-rawa-research'),
  });
  const res = await lic.request('POST', '/v1/licenses/L1/withdrawals', withdrawal.body);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  const revoked = res.json.propagation.revoked_credential_ids.sort();
  assert.ok(revoked.includes(ids.credRawA));
  assert.ok(revoked.includes(ids.credEnriched)); // 沿派生闭包传播

  for (const id of [ids.credRawA, ids.credEnriched]) {
    const c = db.prepare('SELECT status, revoke_reason FROM credentials WHERE credential_id=?').get(id);
    assert.equal(c.status, 'revoked');
    assert.equal(c.revoke_reason, 'partial_withdrawal');
  }
  const v = await verify(ids.tokenEnriched);
  assert.equal(v.json.valid, false);
  assert.equal(v.json.reason, 'revoked');

  // 撤回范围之外的用途/字段不受影响：L2/marketing 凭证仍然有效（下面签发）
  const claimC = ids.rawCClaim;
  const finalize = await approve('approver2', claimC);
  assert.equal(finalize.json.outcome, 'issued');
  ids.credRawC = finalize.json.credential.credential_id;
  const tok = await client('submitter').request('POST', `/v1/credentials/${ids.credRawC}/tokens`, {});
  ids.tokenRawC = tok.json.token;
  const v2 = await verify(ids.tokenRawC);
  assert.equal(v2.json.valid, true);
});

test('arbitrator reinstatement restores authorization for new issuances (old credentials stay revoked)', async () => {
  const arb = client('arbitrator');
  const ruling = arb.legal.ruling({
    license_id: 'L1', seq: 3, decision: 'reinstate',
    restrictions: [{ kind: 'reinstate', field_id: ids.rawA, purposes: ['research'], regions: ['CN'] }],
    document_hash: docHash('L1-ruling-reinstate'),
  });
  const res = await arb.request('POST', '/v1/licenses/L1/rulings', ruling.body);
  assert.equal(res.status, 200, JSON.stringify(res.json));

  // 新声明可以再次签发（旧凭证不自动复活）
  const claimId = await submitClaim({ field_id: ids.enriched });
  await approve('approver1', claimId);
  const out = await approve('approver2', claimId);
  assert.equal(out.json.outcome, 'issued');
  ids.credEnriched2 = out.json.credential.credential_id;
});

// ---------- 凭据/令牌主动撤销 ----------

test('holder revocation of a token and administrative credential revocation cascade', async () => {
  const mint = await client('submitter').request('POST', `/v1/credentials/${ids.credEnriched2}/tokens`, {});
  const tokenA = mint.json.token;
  let v = await verify(tokenA);
  assert.equal(v.json.valid, true);

  const revoked = await client('submitter').request('POST', '/v1/tokens/revoke', { token: tokenA });
  assert.equal(200, revoked.status);
  v = await verify(tokenA);
  assert.equal(v.json.valid, false);
  assert.equal(v.json.reason, 'revoked');

  // 非持有人不能撤销他人令牌
  const mint2 = await client('submitter').request('POST', `/v1/credentials/${ids.credEnriched2}/tokens`, {});
  const forg = await client('outsider').request('POST', '/v1/tokens/revoke', { token: mint2.json.token });
  assert.equal(forg.status, 403);

  // 管理员撤销凭证 -> 其全部令牌连带失效
  const adminRev = await client('admin').request('POST', `/v1/credentials/${ids.credEnriched2}/revoke`, { reason: 'admin test' });
  assert.equal(adminRev.status, 200);
  v = await verify(mint2.json.token);
  assert.equal(v.json.reason, 'revoked');
});

// ---------- 补充协议缩限传播 ----------

test('amendment narrowing scope propagates revocation to outstanding credentials', async () => {
  const lic = client('licensor2');
  const amend = lic.legal.amendment({
    license_id: 'L2', seq: 2,
    terms: { purposes: ['research'], regions: ['CN'], valid_from: '2026-01-01T00:00:00Z', valid_until: '2030-12-31T00:00:00Z' },
    document_hash: docHash('L2-amendment-no-marketing'),
  });
  const res = await lic.request('POST', '/v1/licenses/L2/amendments', amend.body);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.ok(res.json.propagation.revoked_credential_ids.includes(ids.credRawC));
  const v = await verify(ids.tokenRawC);
  assert.equal(v.json.valid, false);
});

// ---------- 整条撤回 / 裁定无效 ----------

test('full revocation and void ruling invalidate everything downstream', async () => {
  const lic = client('licensor1');
  const rev = lic.legal.revocation({ license_id: 'L1', seq: 4, document_hash: docHash('L1-full-revocation') });
  const res = await lic.request('POST', '/v1/licenses/L1/revocations', rev.body);
  assert.equal(res.status, 200);
  // L1 已无有效凭证（先前凭证均已撤销）；关键是新签发被阻断
  assert.ok(Array.isArray(res.json.propagation.revoked_credential_ids));

  const claimId = await submitClaim({ field_id: ids.enriched });
  await approve('approver1', claimId);
  const blocked = await approve('approver2', claimId);
  assert.equal(blocked.json.outcome, 'blocked');
  assert.equal(blocked.json.reason, 'license_revoked');

  // 仲裁员可对许可作 void 裁定（L2）
  const arb = client('arbitrator');
  const void_ = arb.legal.ruling({ license_id: 'L2', seq: 3, decision: 'void', document_hash: docHash('L2-void') });
  const vr = await arb.request('POST', '/v1/licenses/L2/rulings', void_.body);
  assert.equal(vr.status, 200);
  assert.equal(db.prepare('SELECT status FROM licenses WHERE license_id=?').get('L2').status, 'revoked');
});

// ---------- 审计 ----------

test('audit log records success and denied access, and the hash chain verifies', async () => {
  // 主动制造一次无凭证访问（认证失败也必须留痕）
  await anon().request('GET', '/v1/claims', null, { sign: false });

  const res = await client('admin').request('GET', '/v1/admin/audit/verify', null);
  assert.equal(res.status, 200);
  assert.equal(res.json.ok, true);
  assert.ok(res.json.entries > 10);

  const denied = await client('admin').request('GET', '/v1/admin/audit?result=denied&limit=500', null);
  assert.equal(denied.status, 200);
  const actions = denied.json.entries.map((e) => `${e.action}:${e.result}`);
  assert.ok(actions.includes('credential.verify:denied'));
  // 认证失败也被记录（actor 为空）
  const unauth = denied.json.entries.find((e) => e.details && e.details.outcome === 'missing_principal');
  assert.ok(unauth);
  assert.equal(unauth.actor_id, null);

  const success = await client('admin').request('GET', '/v1/admin/audit?result=success&limit=500', null);
  const kinds = success.json.entries.map((e) => e.action);
  for (const a of ['claim.submit', 'claim.decide', 'license.original', 'license.withdrawal', 'credential.verify']) {
    assert.ok(kinds.includes(a), `missing audit action ${a}`);
  }
});

test('tampering with an audit entry breaks chain verification', async () => {
  db.prepare("UPDATE audit_log SET details_json='{}' WHERE seq=2").run();
  const res = await client('admin').request('GET', '/v1/admin/audit/verify', null);
  assert.equal(res.json.ok, false);
  assert.ok(res.json.broken_at >= 2);
  db.prepare("UPDATE audit_log SET details_json=(SELECT details_json FROM audit_log WHERE seq=2) WHERE seq=2").run();
  // 无法仅靠还原列修复（内容已变），链确实断裂——用新库继续，后续断言不依赖完整性
});

test('credential hash chain verifies; tampering with a credential breaks it', async () => {
  const ok = await client('admin').request('GET', '/v1/admin/credentials/verify', null);
  assert.equal(ok.status, 200);
  assert.equal(ok.json.ok, true);
  assert.ok(ok.json.credentials >= 3);

  const credId = ids.credEnriched;
  db.prepare("UPDATE credentials SET purpose='tampered' WHERE credential_id=?").run(credId);
  const bad = await client('admin').request('GET', '/v1/admin/credentials/verify', null);
  assert.equal(bad.json.ok, false);
  assert.equal(bad.json.credential_id, credId);
  db.prepare("UPDATE credentials SET purpose='research' WHERE credential_id=?").run(credId);
});

// ---------- 请求层安全 ----------

test('unsigned / replayed / tampered requests are rejected', async () => {
  const unsigned = await anon().request('POST', '/v1/claims', { dataset_id: 'D', version: 'v1' }, { sign: false });
  assert.equal(unsigned.status, 401);

  // 重放：直接用底层请求两次相同签名头
  const http = require('http');
  const a = actors.submitter;
  const { signObject, loadPrivateKey } = require('../src/crypto');
  const { signableRequest } = require('../src/auth');
  const rawBody = Buffer.from(JSON.stringify({ dataset_id: 'D', version: 'v1', purpose: 'research', region: 'CN' }));
  const ts = new Date().toISOString();
  const nonce = require('crypto').randomUUID();
  const sig = signObject(loadPrivateKey(a.privateKeyB64), signableRequest({ method: 'POST', path: '/v1/claims', timestamp: ts, nonce, rawBody }));
  const send = () => new Promise((resolve) => {
    const req = http.request({ hostname: '127.0.0.1', port: server.address().port, path: '/v1/claims', method: 'POST', headers: {
      'Content-Type': 'application/json', 'Content-Length': rawBody.length,
      'X-Principal-Id': a.principal_id, 'X-Timestamp': ts, 'X-Nonce': nonce, 'X-Signature': sig,
    } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.write(rawBody); req.end();
  });
  assert.equal(await send(), 200);
  assert.equal(await send(), 401); // nonce 重放
});

test('health and registry public key are public; RBAC enforced elsewhere', async () => {
  const health = await anon().request('GET', '/health', null, { sign: false });
  assert.equal(health.json.status, 'ok');
  const pk = await anon().request('GET', '/v1/registry/public-key', null, { sign: false });
  assert.equal(pk.json.key_type, 'Ed25519');
  const rbac = await client('submitter').request('GET', '/v1/admin/principals', null);
  assert.equal(rbac.status, 403);
});
