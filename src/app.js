'use strict';

const Koa = require('koa');
const crypto = require('crypto');
const { sha256 } = require('./crypto');
const audit = require('./audit');
const { authenticate, requireRole, loadRegistryKey } = require('./auth');
const { registerDatasetVersion, fieldId } = require('./lineage');
const licenses = require('./licenses');
const creds = require('./credentials');
const { HttpError } = licenses;

function parseJson(raw) {
  if (!raw || !raw.length) return {};
  try {
    const v = JSON.parse(raw.toString('utf8'));
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

function createApp(db) {
  const app = new Koa();
  const registry = loadRegistryKey(db);

  const auth = authenticate(db);

  app.use(async (ctx) => {
    ctx.state.rawBody = Buffer.alloc(0);
    ctx.state.requestId = crypto.randomUUID();
    ctx.state.startedAt = new Date().toISOString();
    try {
      await dispatch(ctx);
    } catch (err) {
      const status = err.status || 500;
      if (status >= 500) ctx.app.emit('error', err, ctx);
      ctx.status = status;
      ctx.body = {
        error: err.code || 'internal_error',
        message: status >= 500 ? 'internal error' : err.message,
        request_id: ctx.state.requestId,
      };
      const result = status < 500 ? 'denied' : 'error';
      if (ctx.path !== '/health') {
        tryAudit(ctx, result, err.code || 'internal_error');
      }
    }
  });

  function tryAudit(ctx, result, outcome, extra = {}) {
    try {
      audit.append(db, {
        actor_id: ctx.state.principal ? ctx.state.principal.principal_id : null,
        action: ctx.state.auditAction || `${ctx.method} ${ctx.path}`,
        result,
        subject: ctx.state.auditSubject || null,
        details: { outcome, method: ctx.method, path: ctx.path, ...extra },
        request_id: ctx.state.requestId,
      });
    } catch (e) {
      ctx.app.emit('error', e, ctx);
    }
  }

  async function dispatch(ctx) {
    if (ctx.method === 'GET' && ctx.path === '/health') {
      ctx.body = { status: 'ok' };
      return;
    }
    // 公开端点：登记处签名公钥与外部最小披露核验
    if (ctx.method === 'GET' && ctx.path === '/v1/registry/public-key') {
      ctx.body = { key_type: 'Ed25519', public_key: registry.public_spki };
      return;
    }
    if (ctx.method === 'POST' && ctx.path === '/v1/verify') {
      await handlePublicVerify(ctx);
      return;
    }

    await auth(ctx, async () => {
      await route(ctx);
      if (ctx.status < 400 && ctx.state.auditAction) {
        tryAudit(ctx, 'success', ctx.state.auditOutcome || 'ok');
      }
    });
  }

  async function handlePublicVerify(ctx) {
    // 认证中间件之外读取原始 body
    ctx.state.rawBody = await readBody(ctx.req);
    const body = parseJson(ctx.state.rawBody) || {};
    const authHeader = ctx.get('Authorization');
    const secret = body.token || (authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null);

    ctx.state.auditAction = 'credential.verify';
    // 审计只记令牌摘要，绝不记录明文
    ctx.state.auditSubject = secret ? `token:${sha256(secret).slice(0, 16)}` : null;

    if (!secret) {
      ctx.status = 400;
      ctx.body = { valid: false, reason: 'missing_token' };
      tryAudit(ctx, 'denied', 'missing_token');
      return;
    }
    const result = creds.verifyToken(db, secret, { purpose: body.purpose, region: body.region });
    if (result.valid) {
      ctx.body = result; // {valid, purpose, region, expires_at} —— 最小披露
      tryAudit(ctx, 'success', 'valid', { purpose: body.purpose || null, region: body.region || null });
    } else {
      ctx.status = 403;
      ctx.body = { valid: false, reason: result.reason };
      tryAudit(ctx, 'denied', result.reason, { purpose: body.purpose || null, region: body.region || null });
    }
  }

  async function route(ctx) {
    const p = ctx.state.principal;
    const body = () => {
      const v = parseJson(ctx.state.rawBody);
      if (v === null) throw new HttpError(400, 'bad_json', 'request body must be a JSON object');
      return v;
    };
    const setAudit = (action, subject, outcome = 'ok') => {
      ctx.state.auditAction = action;
      ctx.state.auditSubject = subject;
      ctx.state.auditOutcome = outcome;
    };

    // ---- 主体管理 ----
    if (ctx.method === 'POST' && ctx.path === '/v1/admin/principals') {
      requireRole('admin')(ctx);
      const b = body();
      if (!b.principal_id || !b.name || !b.role || !b.public_key) {
        throw new HttpError(400, 'bad_principal', 'principal_id,name,role,public_key required');
      }
      if (!['admin', 'submitter', 'approver', 'arbitrator', 'authority'].includes(b.role)) {
        throw new HttpError(400, 'bad_role', 'unknown role');
      }
      db.prepare(
        `INSERT INTO principals(principal_id,name,role,public_key,status,created_at)
         VALUES(?,?,?,?,'active',?)`
      ).run(b.principal_id, b.name, b.role, b.public_key, new Date().toISOString());
      setAudit('principal.register', b.principal_id, `role:${b.role}`);
      ctx.body = { principal_id: b.principal_id, name: b.name, role: b.role, status: 'active' };
      return;
    }
    if (ctx.method === 'GET' && ctx.path === '/v1/admin/principals') {
      requireRole('admin')(ctx);
      ctx.body = {
        principals: db.prepare(
          'SELECT principal_id,name,role,status,created_at FROM principals ORDER BY created_at'
        ).all(),
      };
      setAudit('principal.list', null);
      return;
    }
    let m;
    if ((m = ctx.path.match(/^\/v1\/admin\/principals\/([^/]+)\/revoke$/)) && ctx.method === 'POST') {
      requireRole('admin')(ctx);
      const id = m[1];
      const info = db.prepare("UPDATE principals SET status='revoked' WHERE principal_id=?").run(id);
      if (!info.changes) throw new HttpError(404, 'unknown_principal', 'principal not found');
      setAudit('principal.revoke', id);
      ctx.body = { principal_id: id, status: 'revoked' };
      return;
    }

    // ---- 数据集版本与字段派生 ----
    if (ctx.method === 'POST' && ctx.path === '/v1/datasets/versions') {
      requireRole('submitter', 'admin')(ctx);
      const b = body();
      if (!b.dataset_id || !b.version || !b.manifest_hash) {
        throw new HttpError(400, 'bad_dataset', 'dataset_id,version,manifest_hash required');
      }
      const out = registerDatasetVersion(db, {
        dataset_id: b.dataset_id,
        version: b.version,
        submitter_id: p.principal_id,
        manifest_hash: b.manifest_hash,
        fields: b.fields || [],
      });
      setAudit('dataset.version.register', `${b.dataset_id}@${b.version}`, `fields:${out.fields.length}`);
      ctx.body = out;
      return;
    }
    if ((m = ctx.path.match(/^\/v1\/datasets\/([^/]+)\/versions\/([^/]+)$/)) && ctx.method === 'GET') {
      const fields = db.prepare(
        'SELECT field_id,name,kind FROM fields WHERE dataset_id=? AND version=? ORDER BY name'
      ).all(m[1], m[2]);
      if (!fields.length) throw new HttpError(404, 'version_not_found', 'version not found');
      const lineage = db.prepare(
        `SELECT d.name AS derived, u.name AS upstream, l.ordinal
           FROM lineage l JOIN fields d ON d.field_id=l.derived_field_id
                         JOIN fields u ON u.field_id=l.upstream_field_id
          WHERE d.dataset_id=? AND d.version=? ORDER BY d.name, l.ordinal`
      ).all(m[1], m[2]);
      ctx.body = { dataset_id: m[1], version: m[2], fields, lineage };
      setAudit('dataset.version.read', `${m[1]}@${m[2]}`);
      return;
    }

    // ---- 授权与法律事件 ----
    if (ctx.method === 'POST' && ctx.path === '/v1/licenses') {
      requireRole('authority', 'admin')(ctx);
      const b = body();
      const out = licenses.registerOriginal(db, {
        ...b,
        licensor_id: p.principal_id, // 签名主体取自认证身份，请求体无法伪造
      });
      setAudit('license.original', out.license_id);
      ctx.body = out;
      return;
    }
    if ((m = ctx.path.match(/^\/v1\/licenses\/([^/]+)$/)) && ctx.method === 'GET') {
      const lic = licenses.requireLicense(db, m[1]);
      if (!['admin', 'arbitrator'].includes(p.role) && lic.licensor_id !== p.principal_id) {
        throw new HttpError(403, 'license_confidential', 'license record visible only to its parties');
      }
      setAudit('license.read', m[1]);
      ctx.body = licenses.licenseView(db, m[1]); // 仅含签名摘要，不含合同正文
      return;
    }
    if ((m = ctx.path.match(/^\/v1\/licenses\/([^/]+)\/amendments$/)) && ctx.method === 'POST') {
      requireRole('authority', 'admin')(ctx);
      const lic = licenses.requireLicense(db, m[1]);
      if (lic.licensor_id !== p.principal_id && p.role !== 'admin') {
        throw new HttpError(403, 'not_licensor', 'only the licensor may amend');
      }
      const b = body();
      const out = licenses.recordAmendment(db, m[1], { ...b, licensor_id: p.principal_id });
      setAudit('license.amendment', m[1], `seq:${out.seq}`);
      ctx.body = out;
      return;
    }
    if ((m = ctx.path.match(/^\/v1\/licenses\/([^/]+)\/revocations$/)) && ctx.method === 'POST') {
      requireRole('authority', 'admin')(ctx);
      const lic = licenses.requireLicense(db, m[1]);
      if (lic.licensor_id !== p.principal_id && p.role !== 'admin') {
        throw new HttpError(403, 'not_licensor', 'only the licensor may revoke');
      }
      const b = body();
      const out = licenses.recordRevocation(db, m[1], { ...b, licensor_id: p.principal_id });
      setAudit('license.revocation', m[1], `seq:${out.seq},revoked:${out.propagation.revoked_credential_ids.length}`);
      ctx.body = out;
      return;
    }
    if ((m = ctx.path.match(/^\/v1\/licenses\/([^/]+)\/rulings$/)) && ctx.method === 'POST') {
      requireRole('arbitrator', 'admin')(ctx);
      const b = body();
      const out = licenses.recordRuling(db, m[1], { ...b, arbitrator_id: p.principal_id });
      setAudit('license.ruling', m[1], `seq:${out.seq},${out.decision}`);
      ctx.body = out;
      return;
    }
    // 局部撤回/恢复直接作为裁定的 restrictions 提交；另提供许可方的便捷局部撤回
    if ((m = ctx.path.match(/^\/v1\/licenses\/([^/]+)\/withdrawals$/)) && ctx.method === 'POST') {
      requireRole('authority', 'admin')(ctx);
      const lic = licenses.requireLicense(db, m[1]);
      if (lic.licensor_id !== p.principal_id && p.role !== 'admin') {
        throw new HttpError(403, 'not_licensor', 'only the licensor may withdraw');
      }
      const b = body();
      const out = licenses.recordWithdrawal(db, m[1], { ...b, licensor_id: p.principal_id });
      setAudit('license.withdrawal', m[1], `revoked:${out.propagation.revoked_credential_ids.length}`);
      ctx.body = out;
      return;
    }

    // ---- 声明与双人批准 ----
    if (ctx.method === 'POST' && ctx.path === '/v1/claims') {
      requireRole('submitter', 'admin')(ctx);
      const b = body();
      const out = creds.submitClaim(db, b, p.principal_id);
      setAudit('claim.submit', out.claim_id, b.purpose ? `purpose:${b.purpose}` : null);
      ctx.body = out;
      return;
    }
    if ((m = ctx.path.match(/^\/v1\/claims$/)) && ctx.method === 'GET') {
      let rows;
      if (p.role === 'admin') {
        rows = db.prepare('SELECT claim_id FROM claims ORDER BY created_at DESC LIMIT 200').all();
      } else if (p.role === 'approver' && ctx.query.status === 'pending') {
        // 批准人待批队列（不含提交人身份之外的敏感合同信息，声明体本身最小化）
        rows = db.prepare("SELECT claim_id FROM claims WHERE status='pending' ORDER BY created_at LIMIT 200").all();
      } else {
        rows = db.prepare('SELECT claim_id FROM claims WHERE submitter_id=? ORDER BY created_at DESC LIMIT 200').all(p.principal_id);
      }
      setAudit('claim.list', null, `n:${rows.length}`);
      ctx.body = { claims: rows.map((r) => creds.getClaim(db, r.claim_id)) };
      return;
    }
    if ((m = ctx.path.match(/^\/v1\/claims\/([^/]+)$/)) && ctx.method === 'GET') {
      const claim = creds.getClaim(db, m[1]);
      const acted = claim.approvals.some((a) => a.approver_id === p.principal_id);
      // 批准人需要用途/地域/字段这些最小必要信息才能作出批准决策
      const canView = p.role === 'admin' || claim.submitter_id === p.principal_id || acted
        || (p.role === 'approver' && claim.status === 'pending');
      if (!canView) {
        throw new HttpError(403, 'claim_confidential', 'claim visible only to its parties');
      }
      setAudit('claim.read', m[1]);
      ctx.body = claim;
      return;
    }
    if ((m = ctx.path.match(/^\/v1\/claims\/([^/]+)\/decisions$/)) && ctx.method === 'POST') {
      requireRole('approver', 'admin')(ctx);
      const b = body();
      const out = creds.decideClaim(db, registry, m[1], p.principal_id, b.decision, ctx.state.requestSignature);
      setAudit('claim.decide', m[1], `${b.decision}->${out.outcome}`);
      ctx.body = out;
      return;
    }

    // ---- 凭证与验证凭据 ----
    if ((m = ctx.path.match(/^\/v1\/credentials\/([^/]+)$/)) && ctx.method === 'GET') {
      const row = db.prepare('SELECT c.*, cl.submitter_id FROM credentials c JOIN claims cl ON cl.claim_id=c.claim_id WHERE c.credential_id=?').get(m[1]);
      if (!row) throw new HttpError(404, 'credential_not_found', 'credential not found');
      if (p.role !== 'admin' && row.submitter_id !== p.principal_id) {
        throw new HttpError(403, 'credential_confidential', 'credential visible only to its holder');
      }
      setAudit('credential.read', m[1], row.status);
      const manifest = db.prepare(
        'SELECT manifest_hash FROM dataset_versions WHERE dataset_id=? AND version=?'
      ).get(row.dataset_id, row.version);
      const evidence = JSON.parse(row.evidence_json);
      const parents = JSON.parse(row.parents_json);
      // 精确重建被签名的文档，供持有人离线验证签名与凭证链
      const document = {
        credential_id: row.credential_id,
        claim_id: row.claim_id,
        dataset_id: row.dataset_id,
        version: row.version,
        manifest_hash: manifest.manifest_hash,
        field_id: row.field_id,
        purpose: row.purpose,
        region: row.region,
        valid_from: row.valid_from,
        valid_until: row.valid_until,
        evidence,
        parents,
        chain_seq: row.chain_seq,
        prev_credential_id: row.prev_credential_id,
        prev_document_hash: row.prev_hash,
        issued_at: row.issued_at,
      };
      ctx.body = {
        credential_id: row.credential_id,
        claim_id: row.claim_id,
        dataset_id: row.dataset_id,
        version: row.version,
        field_id: row.field_id,
        purpose: row.purpose,
        region: row.region,
        valid_from: row.valid_from,
        valid_until: row.valid_until,
        status: row.status,
        revoke_reason: row.revoke_reason,
        revoked_at: row.revoked_at,
        chain_seq: row.chain_seq,
        document,
        document_hash: row.document_hash,
        signature: row.signature,
        registry_public_key: registry.public_spki,
      };
      return;
    }
    if ((m = ctx.path.match(/^\/v1\/credentials\/([^/]+)\/tokens$/)) && ctx.method === 'POST') {
      const row = db.prepare('SELECT c.*, cl.submitter_id FROM credentials c JOIN claims cl ON cl.claim_id=c.claim_id WHERE c.credential_id=?').get(m[1]);
      if (!row) throw new HttpError(404, 'credential_not_found', 'credential not found');
      if (p.role !== 'admin' && row.submitter_id !== p.principal_id) {
        throw new HttpError(403, 'not_credential_holder', 'only the credential holder may mint tokens');
      }
      const b = body();
      const out = creds.issueToken(db, m[1], { ttlSeconds: b.ttl_seconds, purpose: b.purpose, region: b.region });
      setAudit('credential.token.issue', m[1], `token:${out.token_id}`);
      ctx.body = out;
      return;
    }
    if ((m = ctx.path.match(/^\/v1\/credentials\/([^/]+)\/revoke$/)) && ctx.method === 'POST') {
      requireRole('admin')(ctx);
      const b = body();
      const now = new Date().toISOString();
      const info = db.prepare(
        "UPDATE credentials SET status='revoked', revoke_reason=?, revoked_at=? WHERE credential_id=? AND status='valid'"
      ).run(b.reason || 'administrative_revocation', now, m[1]);
      if (!info.changes) throw new HttpError(409, 'not_revocable', 'credential missing or already revoked');
      db.prepare(
        "UPDATE verification_tokens SET status='revoked', revoke_reason='administrative_revocation', revoked_at=? WHERE credential_id=? AND status='active'"
      ).run(now, m[1]);
      setAudit('credential.revoke', m[1], b.reason || 'administrative_revocation');
      ctx.body = { credential_id: m[1], status: 'revoked' };
      return;
    }
    if (ctx.method === 'POST' && ctx.path === '/v1/tokens/revoke') {
      const b = body();
      if (!b.token && !b.token_id) throw new HttpError(400, 'bad_token', 'token or token_id required');
      const tokenHash = b.token ? sha256(b.token) : null;
      const row = tokenHash
        ? db.prepare('SELECT t.*, cl.submitter_id FROM verification_tokens t JOIN credentials c ON c.credential_id=t.credential_id JOIN claims cl ON cl.claim_id=c.claim_id WHERE t.token_hash=?').get(tokenHash)
        : db.prepare('SELECT t.*, cl.submitter_id FROM verification_tokens t JOIN credentials c ON c.credential_id=t.credential_id JOIN claims cl ON cl.claim_id=c.claim_id WHERE t.token_id=?').get(b.token_id);
      if (!row) throw new HttpError(404, 'token_not_found', 'token not found');
      if (p.role !== 'admin' && row.submitter_id !== p.principal_id) {
        throw new HttpError(403, 'not_token_holder', 'only the token holder may revoke it');
      }
      const info = db.prepare(
        "UPDATE verification_tokens SET status='revoked', revoke_reason=?, revoked_at=? WHERE token_id=? AND status='active'"
      ).run(b.reason || 'holder_revocation', new Date().toISOString(), row.token_id);
      setAudit('credential.token.revoke', row.token_id, info.changes ? 'revoked' : 'already_revoked');
      ctx.body = { token_id: row.token_id, status: 'revoked' };
      return;
    }

    // ---- 审计 ----
    if (ctx.method === 'GET' && ctx.path === '/v1/admin/audit') {
      requireRole('admin')(ctx);
      const limit = Math.min(Number(ctx.query.limit) || 100, 500);
      const result = ctx.query.result; // success|denied|error
      const rows = result
        ? db.prepare('SELECT * FROM audit_log WHERE result=? ORDER BY seq DESC LIMIT ?').all(result, limit)
        : db.prepare('SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?').all(limit);
      setAudit('audit.read', null, `n:${rows.length}`);
      ctx.body = {
        entries: rows.map((r) => ({
          seq: r.seq, log_id: r.log_id, ts: r.ts, actor_id: r.actor_id, action: r.action,
          result: r.result, subject: r.subject, details: JSON.parse(r.details_json),
          prev_hash: r.prev_hash ? r.prev_hash.slice(0, 16) : null,
          entry_hash: r.entry_hash.slice(0, 16),
          request_id: r.request_id,
        })),
      };
      return;
    }
    if (ctx.method === 'GET' && ctx.path === '/v1/admin/audit/verify') {
      requireRole('admin')(ctx);
      const out = audit.verifyChain(db);
      setAudit('audit.verify', null, out.ok ? 'intact' : 'broken');
      ctx.body = out;
      return;
    }
    if (ctx.method === 'GET' && ctx.path === '/v1/admin/credentials/verify') {
      requireRole('admin')(ctx);
      const out = creds.verifyCredentialChain(db);
      setAudit('credential.chain.verify', null, out.ok ? 'intact' : 'broken');
      ctx.body = out;
      return;
    }

    throw new HttpError(404, 'not_found', 'route not found');
  }

  return app;
}

const AUDITED_PUBLIC = new Set(['/v1/verify']);

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

module.exports = { createApp };
