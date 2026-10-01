'use strict';

const Koa = require('koa');
const { openDatabase, migrate } = require('./db');
const { sha256, randomId, randomToken } = require('./lib/crypto');
const { appendAudit } = require('./lib/audit');
const {
  recordLicenseEvent,
  listLicenseEvents,
  reduceScope,
  getEffectiveScope,
} = require('./lib/licenses');
const { CoverageError, issueCredential, credentialIsValid, propagateLicenseChange } = require('./lib/credentials');

const REQUIRED_APPROVALS = 2;
const MAX_BODY_BYTES = 1024 * 1024;
const DEFAULT_TOKEN_TTL_SECONDS = 30 * 24 * 3600;
const MAX_TOKEN_TTL_SECONDS = 365 * 24 * 3600;

// ---------- 通用工具 ----------

function now() {
  return new Date().toISOString();
}

function normalizeTime(value, field) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) {
    throw badRequest(`${field} must be an ISO-8601 timestamp`);
  }
  return new Date(value).toISOString();
}

function badRequest(message) {
  const err = new Error(message);
  err.status = 400;
  err.expose = true;
  return err;
}

function requireString(body, field) {
  const value = body[field];
  if (typeof value !== 'string' || value.trim() === '') {
    throw badRequest(`${field} is required and must be a non-empty string`);
  }
  return value.trim();
}

function requireStringArray(body, field) {
  const value = body[field];
  if (!Array.isArray(value) || value.length === 0 || value.some((v) => typeof v !== 'string' || v.trim() === '')) {
    throw badRequest(`${field} must be a non-empty array of strings`);
  }
  return [...new Set(value.map((v) => v.trim()))];
}

function optionalStringArray(body, field) {
  if (body[field] === undefined) return [];
  const value = body[field];
  if (!Array.isArray(value) || value.some((v) => typeof v !== 'string' || v.trim() === '')) {
    throw badRequest(`${field} must be an array of strings`);
  }
  return [...new Set(value.map((v) => v.trim()))];
}

// ---------- 请求体解析（无额外依赖的 JSON body parser） ----------

async function bodyParser(ctx, next) {
  if (!['POST', 'PUT', 'PATCH'].includes(ctx.method)) return next();
  const chunks = [];
  let size = 0;
  for await (const chunk of ctx.req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      ctx.throw(413, 'request body too large');
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (raw === '') {
    ctx.request.body = {};
    return next();
  }
  try {
    ctx.request.body = JSON.parse(raw);
  } catch {
    ctx.throw(400, 'request body must be valid JSON');
  }
  if (typeof ctx.request.body !== 'object' || ctx.request.body === null || Array.isArray(ctx.request.body)) {
    ctx.throw(400, 'request body must be a JSON object');
  }
  return next();
}

// ---------- 极简路由器 ----------

function compilePath(pattern) {
  const keys = [];
  const regex = new RegExp(`^${pattern.split('/').map((seg) => {
    if (seg.startsWith(':')) {
      keys.push(seg.slice(1));
      return '([^/]+)';
    }
    return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }).join('/')}$`);
  return { regex, keys };
}

function createRouter() {
  const routes = [];
  const add = (method, pattern, handler) => routes.push({ method, ...compilePath(pattern), handler });
  const match = (method, path) => {
    for (const route of routes) {
      if (route.method !== method) continue;
      const m = route.regex.exec(path);
      if (!m) continue;
      const params = {};
      route.keys.forEach((key, i) => { params[key] = decodeURIComponent(m[i + 1]); });
      return { handler: route.handler, params };
    }
    return null;
  };
  return { add, match };
}

// ---------- 视图（最小范围展示：敏感材料只出哈希，不出原文） ----------

function licenseView(db, row) {
  const events = listLicenseEvents(db, row.id);
  const scope = reduceScope(events);
  return {
    id: row.id,
    field_id: row.field_id,
    grantor: row.grantor,
    grantee: row.grantee,
    status: row.status,
    effective_scope: {
      purposes: [...scope.purposes].sort(),
      territories: [...scope.territories].sort(),
      valid_from: scope.validFrom,
      valid_until: scope.validUntil,
      suspended: scope.suspended,
      terminated: scope.terminated,
    },
    terms_hash: row.terms_hash,
    created_by: row.created_by,
    created_at: row.created_at,
    events: events.map((ev) => ({
      seq: ev.seq,
      type: ev.type,
      payload: ev.payload,
      signature_digest: ev.signature_digest,
      prev_digest: ev.prev_digest,
      created_by: ev.created_by,
      created_at: ev.created_at,
    })),
  };
}

function declarationView(db, row) {
  const approvals = db.prepare(
    'SELECT approver, decision, reason, created_at FROM declaration_approvals WHERE declaration_id = ? ORDER BY created_at, approver'
  ).all(row.id);
  return {
    id: row.id,
    field_id: row.field_id,
    purpose: row.purpose,
    territory: row.territory,
    term_from: row.term_from,
    term_until: row.term_until,
    submitted_by: row.submitted_by,
    status: row.status,
    created_at: row.created_at,
    decided_at: row.decided_at,
    approvals,
  };
}

function credentialView(db, row) {
  const deps = db.prepare('SELECT license_id FROM credential_dependencies WHERE credential_id = ? ORDER BY license_id')
    .all(row.id).map((d) => d.license_id);
  return {
    id: row.id,
    declaration_id: row.declaration_id,
    field_id: row.field_id,
    dataset_version_id: row.dataset_version_id,
    purpose: row.purpose,
    territory: row.territory,
    valid_from: row.valid_from,
    valid_until: row.valid_until,
    status: row.status,
    revoked_reason: row.revoked_reason,
    chain_hash: row.chain_hash,
    issued_by: row.issued_by,
    issued_at: row.issued_at,
    revoked_at: row.revoked_at,
    dependencies: deps,
  };
}

// ---------- 应用工厂 ----------

function createApp(options = {}) {
  const db = options.db || openDatabase(options.dbPath);
  migrate(db);
  const app = new Koa();
  const router = createRouter();

  // 统一错误格式
  app.use(async (ctx, next) => {
    try {
      await next();
    } catch (err) {
      const status = err.status || 500;
      ctx.status = status;
      ctx.body = { error: { code: err.code || 'error', message: status === 500 ? 'internal error' : err.message } };
      if (status === 500) ctx.app.emit('error', err, ctx);
    }
  });
  app.use(bodyParser);

  // 操作者身份：x-actor-id / x-actor-role
  app.use(async (ctx, next) => {
    ctx.state.actor = {
      id: ctx.get('x-actor-id') || null,
      role: ctx.get('x-actor-role') || null,
    };
    await next();
  });

  const auditDenied = (ctx, action, detail) => {
    appendAudit(db, {
      actor: (ctx.state.actor && ctx.state.actor.id) || 'anonymous',
      action, outcome: 'denied', detail,
    });
  };

  const requireActor = (ctx, action) => {
    if (!ctx.state.actor.id) {
      auditDenied(ctx, action, { reason: 'missing_actor' });
      ctx.throw(401, 'x-actor-id header is required');
    }
  };

  const requireRole = (ctx, action, roles) => {
    requireActor(ctx, action);
    if (!roles.includes(ctx.state.actor.role)) {
      auditDenied(ctx, action, { reason: 'insufficient_role', role: ctx.state.actor.role });
      ctx.throw(403, `role must be one of: ${roles.join(', ')}`);
    }
  };

  const REGISTRAR = ['registrar', 'admin'];

  // ---------- 路由表 ----------

  router.add('GET', '/health', (ctx) => { ctx.body = { status: 'ok' }; });

  router.add('POST', '/datasets', (ctx) => {
    requireRole(ctx, 'dataset_created', REGISTRAR);
    const name = requireString(ctx.request.body, 'name');
    const owner = requireString(ctx.request.body, 'owner');
    const id = randomId('ds');
    const at = now();
    db.transaction(() => {
      db.prepare('INSERT INTO datasets (id, name, owner, created_at) VALUES (?, ?, ?, ?)').run(id, name, owner, at);
      appendAudit(db, { actor: ctx.state.actor.id, action: 'dataset_created', entityType: 'dataset', entityId: id, outcome: 'success', detail: { name, owner } });
    })();
    ctx.status = 201;
    ctx.body = db.prepare('SELECT * FROM datasets WHERE id = ?').get(id);
  });

  router.add('GET', '/datasets/:id', (ctx) => {
    requireActor(ctx, 'dataset_read');
    const row = db.prepare('SELECT * FROM datasets WHERE id = ?').get(ctx.params.id);
    if (!row) ctx.throw(404, 'dataset not found');
    ctx.body = row;
  });

  router.add('POST', '/datasets/:id/versions', (ctx) => {
    requireRole(ctx, 'version_created', REGISTRAR);
    const dataset = db.prepare('SELECT id FROM datasets WHERE id = ?').get(ctx.params.id);
    if (!dataset) ctx.throw(404, 'dataset not found');
    const { version, content_hash: contentHash } = ctx.request.body;
    if (!Number.isInteger(version) || version < 1) throw badRequest('version must be a positive integer');
    if (typeof contentHash !== 'string' || contentHash.trim() === '') throw badRequest('content_hash is required');
    const id = randomId('dsv');
    const at = now();
    try {
      db.transaction(() => {
        db.prepare('INSERT INTO dataset_versions (id, dataset_id, version, content_hash, created_at) VALUES (?, ?, ?, ?, ?)')
          .run(id, dataset.id, version, contentHash.trim(), at);
        appendAudit(db, { actor: ctx.state.actor.id, action: 'version_created', entityType: 'dataset_version', entityId: id, outcome: 'success', detail: { dataset_id: dataset.id, version } });
      })();
    } catch (err) {
      if (String(err.message).includes('UNIQUE')) ctx.throw(409, 'version already exists for this dataset');
      throw err;
    }
    ctx.status = 201;
    ctx.body = db.prepare('SELECT * FROM dataset_versions WHERE id = ?').get(id);
  });

  router.add('GET', '/versions/:id', (ctx) => {
    requireActor(ctx, 'version_read');
    const row = db.prepare('SELECT * FROM dataset_versions WHERE id = ?').get(ctx.params.id);
    if (!row) ctx.throw(404, 'dataset version not found');
    const fields = db.prepare('SELECT id, name, kind, sensitivity FROM fields WHERE dataset_version_id = ? ORDER BY name').all(row.id);
    ctx.body = { ...row, fields };
  });

  // 字段登记：derived 必须给出上游字段；派生边可跨数据集版本
  router.add('POST', '/versions/:id/fields', (ctx) => {
    requireRole(ctx, 'field_created', REGISTRAR);
    const version = db.prepare('SELECT id FROM dataset_versions WHERE id = ?').get(ctx.params.id);
    if (!version) ctx.throw(404, 'dataset version not found');
    const name = requireString(ctx.request.body, 'name');
    const kind = requireString(ctx.request.body, 'kind');
    if (!['source', 'derived'].includes(kind)) throw badRequest('kind must be source or derived');
    const sensitivity = ctx.request.body.sensitivity || 'internal';
    if (!['public', 'internal', 'confidential'].includes(sensitivity)) throw badRequest('invalid sensitivity');
    const upstreamIds = ctx.request.body.upstream_field_ids || [];
    if (!Array.isArray(upstreamIds) || upstreamIds.some((u) => typeof u !== 'string')) {
      throw badRequest('upstream_field_ids must be an array of field ids');
    }
    if (kind === 'derived' && upstreamIds.length === 0) throw badRequest('derived field requires upstream_field_ids');
    if (kind === 'source' && upstreamIds.length > 0) throw badRequest('source field cannot have upstream fields');
    for (const upstreamId of upstreamIds) {
      if (!db.prepare('SELECT id FROM fields WHERE id = ?').get(upstreamId)) {
        throw badRequest(`upstream field not found: ${upstreamId}`);
      }
    }
    const id = randomId('fld');
    const at = now();
    try {
      db.transaction(() => {
        db.prepare('INSERT INTO fields (id, dataset_version_id, name, kind, sensitivity, created_at) VALUES (?, ?, ?, ?, ?, ?)')
          .run(id, version.id, name, kind, sensitivity, at);
        const edge = db.prepare('INSERT INTO field_derivations (derived_field_id, upstream_field_id) VALUES (?, ?)');
        for (const upstreamId of new Set(upstreamIds)) edge.run(id, upstreamId);
        appendAudit(db, {
          actor: ctx.state.actor.id, action: 'field_created', entityType: 'field', entityId: id,
          outcome: 'success', detail: { dataset_version_id: version.id, name, kind, upstream_field_ids: [...new Set(upstreamIds)] },
        });
      })();
    } catch (err) {
      if (String(err.message).includes('UNIQUE')) ctx.throw(409, 'field name already exists in this version');
      throw err;
    }
    ctx.status = 201;
    ctx.body = db.prepare('SELECT id, dataset_version_id, name, kind, sensitivity, created_at FROM fields WHERE id = ?').get(id);
  });

  router.add('GET', '/fields/:id', (ctx) => {
    requireActor(ctx, 'field_read');
    const row = db.prepare('SELECT id, dataset_version_id, name, kind, sensitivity, created_at FROM fields WHERE id = ?')
      .get(ctx.params.id);
    if (!row) ctx.throw(404, 'field not found');
    const upstream = db.prepare('SELECT upstream_field_id FROM field_derivations WHERE derived_field_id = ?').all(row.id)
      .map((e) => e.upstream_field_id);
    ctx.body = { ...row, upstream_field_ids: upstream };
  });

  // 许可登记：原始授权作为首条事件入链，terms 只留哈希
  router.add('POST', '/fields/:id/licenses', (ctx) => {
    requireRole(ctx, 'license_created', REGISTRAR);
    const field = db.prepare('SELECT id FROM fields WHERE id = ?').get(ctx.params.id);
    if (!field) ctx.throw(404, 'field not found');
    const body = ctx.request.body;
    const grantor = requireString(body, 'grantor');
    const grantee = requireString(body, 'grantee');
    const purposes = requireStringArray(body, 'purposes');
    const territories = requireStringArray(body, 'territories');
    const validFrom = normalizeTime(body.valid_from, 'valid_from');
    const validUntil = normalizeTime(body.valid_until, 'valid_until');
    if (validFrom >= validUntil) throw badRequest('valid_from must be before valid_until');
    const terms = requireString(body, 'terms');
    const termsHash = sha256(terms);
    const id = randomId('lic');
    const at = now();
    db.transaction(() => {
      db.prepare(`
        INSERT INTO licenses (id, field_id, grantor, grantee, purposes, territories, valid_from, valid_until, terms, terms_hash, status, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
      `).run(id, field.id, grantor, grantee, JSON.stringify(purposes), JSON.stringify(territories),
        validFrom, validUntil, terms, termsHash, ctx.state.actor.id, at);
      recordLicenseEvent(db, {
        licenseId: id, type: 'grant',
        payload: { purposes, territories, valid_from: validFrom, valid_until: validUntil, terms_hash: termsHash },
        createdBy: ctx.state.actor.id, ts: at,
      });
      appendAudit(db, {
        actor: ctx.state.actor.id, action: 'license_created', entityType: 'license', entityId: id,
        outcome: 'success', detail: { field_id: field.id, grantor, grantee, terms_hash: termsHash },
      });
    })();
    ctx.status = 201;
    ctx.body = licenseView(db, db.prepare('SELECT * FROM licenses WHERE id = ?').get(id));
  });

  router.add('GET', '/licenses/:id', (ctx) => {
    requireActor(ctx, 'license_read');
    const row = db.prepare('SELECT * FROM licenses WHERE id = ?').get(ctx.params.id);
    if (!row) ctx.throw(404, 'license not found');
    ctx.body = licenseView(db, row);
  });

  // 许可事件：补充协议 / 撤回（可局部）/ 争议裁定；落库后立即传播影响
  router.add('POST', '/licenses/:id/events', (ctx) => {
    requireRole(ctx, 'license_event_recorded', REGISTRAR);
    const license = db.prepare('SELECT * FROM licenses WHERE id = ?').get(ctx.params.id);
    if (!license) ctx.throw(404, 'license not found');
    const { type } = ctx.request.body;
    const payload = ctx.request.body.payload || {};
    if (!['amendment', 'revocation', 'ruling'].includes(type)) {
      throw badRequest('type must be amendment, revocation or ruling (grant is created with the license)');
    }
    if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
      throw badRequest('payload must be an object');
    }
    const normalized = {};
    if (type === 'amendment') {
      normalized.add_purposes = optionalStringArray(payload, 'add_purposes');
      normalized.remove_purposes = optionalStringArray(payload, 'remove_purposes');
      normalized.add_territories = optionalStringArray(payload, 'add_territories');
      normalized.remove_territories = optionalStringArray(payload, 'remove_territories');
      if (payload.valid_from !== undefined) normalized.valid_from = normalizeTime(payload.valid_from, 'payload.valid_from');
      if (payload.valid_until !== undefined) normalized.valid_until = normalizeTime(payload.valid_until, 'payload.valid_until');
      if (payload.note !== undefined) normalized.note = String(payload.note);
    } else if (type === 'revocation') {
      normalized.full = payload.full === true;
      normalized.purposes = optionalStringArray(payload, 'purposes');
      normalized.territories = optionalStringArray(payload, 'territories');
      if (!normalized.full && normalized.purposes.length === 0 && normalized.territories.length === 0) {
        throw badRequest('partial revocation requires purposes and/or territories, or set full=true');
      }
      if (payload.note !== undefined) normalized.note = String(payload.note);
    } else {
      if (!['suspend', 'reinstate', 'invalidate'].includes(payload.action)) {
        throw badRequest('ruling payload.action must be suspend, reinstate or invalidate');
      }
      normalized.action = payload.action;
      if (payload.reference !== undefined) normalized.reference = String(payload.reference);
      if (payload.note !== undefined) normalized.note = String(payload.note);
    }
    const at = now();
    let event;
    let revokedCredentialIds = [];
    db.transaction(() => {
      event = recordLicenseEvent(db, {
        licenseId: license.id, type, payload: normalized, createdBy: ctx.state.actor.id, ts: at,
      });
      const scope = getEffectiveScope(db, license.id);
      const status = scope.terminated ? 'terminated' : (scope.suspended ? 'suspended' : 'active');
      db.prepare('UPDATE licenses SET status = ? WHERE id = ?').run(status, license.id);
      revokedCredentialIds = propagateLicenseChange(db, license.id, ctx.state.actor.id, at);
      appendAudit(db, {
        actor: ctx.state.actor.id, action: 'license_event_recorded', entityType: 'license', entityId: license.id,
        outcome: 'success',
        detail: { event_id: event.id, type, signature_digest: event.signatureDigest, revoked_credentials: revokedCredentialIds },
      });
    })();
    ctx.status = 201;
    ctx.body = {
      event: {
        id: event.id, license_id: license.id, seq: event.seq, type: event.type,
        payload: event.payload, signature_digest: event.signatureDigest, prev_digest: event.prevDigest,
        created_by: event.createdBy, created_at: event.createdAt,
      },
      revoked_credentials: revokedCredentialIds,
    };
  });

  // 声明提交
  router.add('POST', '/declarations', (ctx) => {
    requireActor(ctx, 'declaration_submitted');
    const body = ctx.request.body;
    const fieldId = requireString(body, 'field_id');
    const field = db.prepare('SELECT id FROM fields WHERE id = ?').get(fieldId);
    if (!field) ctx.throw(404, 'field not found');
    const purpose = requireString(body, 'purpose');
    const territory = requireString(body, 'territory');
    const termFrom = normalizeTime(body.term_from, 'term_from');
    const termUntil = normalizeTime(body.term_until, 'term_until');
    if (termFrom >= termUntil) throw badRequest('term_from must be before term_until');
    const id = randomId('decl');
    const at = now();
    db.transaction(() => {
      db.prepare(`
        INSERT INTO declarations (id, field_id, purpose, territory, term_from, term_until, submitted_by, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
      `).run(id, fieldId, purpose, territory, termFrom, termUntil, ctx.state.actor.id, at);
      appendAudit(db, {
        actor: ctx.state.actor.id, action: 'declaration_submitted', entityType: 'declaration', entityId: id,
        outcome: 'success', detail: { field_id: fieldId, purpose, territory },
      });
    })();
    ctx.status = 201;
    ctx.body = declarationView(db, db.prepare('SELECT * FROM declarations WHERE id = ?').get(id));
  });

  router.add('GET', '/declarations/:id', (ctx) => {
    requireActor(ctx, 'declaration_read');
    const row = db.prepare('SELECT * FROM declarations WHERE id = ?').get(ctx.params.id);
    if (!row) ctx.throw(404, 'declaration not found');
    ctx.body = declarationView(db, row);
  });

  // 双人批准：提交人不得批准自己；同一批准人只生效一次；
  // 并发到达时靠主键与状态条件更新保证状态迁移只发生一次。
  router.add('POST', '/declarations/:id/approve', (ctx) => {
    requireRole(ctx, 'declaration_approval', ['approver', 'admin']);
    const actor = ctx.state.actor.id;
    const decl = db.prepare('SELECT * FROM declarations WHERE id = ?').get(ctx.params.id);
    if (!decl) ctx.throw(404, 'declaration not found');
    if (decl.submitted_by === actor) {
      auditDenied(ctx, 'declaration_approval', { declaration_id: decl.id, reason: 'self_approval' });
      ctx.throw(403, 'submitter cannot approve their own declaration');
    }
    const decision = requireString(ctx.request.body, 'decision');
    if (!['approve', 'reject'].includes(decision)) throw badRequest('decision must be approve or reject');
    const reason = ctx.request.body.reason !== undefined ? String(ctx.request.body.reason) : null;
    const at = now();
    let result;
    try {
      result = db.transaction(() => {
        const current = db.prepare('SELECT * FROM declarations WHERE id = ?').get(decl.id);
        if (current.status !== 'pending') {
          const err = new Error(`declaration already ${current.status}`);
          err.status = 409;
          throw err;
        }
        db.prepare('INSERT INTO declaration_approvals (declaration_id, approver, decision, reason, created_at) VALUES (?, ?, ?, ?, ?)')
          .run(decl.id, actor, decision, reason, at);
        appendAudit(db, {
          actor, action: 'declaration_approval_recorded', entityType: 'declaration', entityId: decl.id,
          outcome: 'success', detail: { decision },
        });
        if (decision === 'reject') {
          db.prepare("UPDATE declarations SET status = 'rejected', decided_at = ? WHERE id = ? AND status = 'pending'").run(at, decl.id);
          appendAudit(db, {
            actor, action: 'declaration_rejected', entityType: 'declaration', entityId: decl.id,
            outcome: 'success', detail: { reason },
          });
          return { status: 'rejected' };
        }
        const approvals = db.prepare(
          "SELECT COUNT(*) AS n FROM declaration_approvals WHERE declaration_id = ? AND decision = 'approve'"
        ).get(decl.id).n;
        if (approvals >= REQUIRED_APPROVALS) {
          // 状态条件更新：并发下只有一笔事务能把 pending 推进为 approved
          const changed = db.prepare(
            "UPDATE declarations SET status = 'approved', decided_at = ? WHERE id = ? AND status = 'pending'"
          ).run(at, decl.id).changes;
          if (changed === 1) {
            appendAudit(db, {
              actor, action: 'declaration_approved', entityType: 'declaration', entityId: decl.id,
              outcome: 'success', detail: { approvals },
            });
          }
          return { status: 'approved' };
        }
        return { status: 'pending', approvals };
      })();
    } catch (err) {
      if (err.code === 'SQLITE_CONSTRAINT_PRIMARYKEY' || String(err.message).includes('declaration_approvals')) {
        ctx.throw(409, 'approver has already decided on this declaration');
      }
      throw err;
    }
    ctx.body = { declaration_id: decl.id, ...result };
  });

  // 签发：仅当全部上游许可覆盖本次用途；失败留审计，声明保持 approved 可重试
  router.add('POST', '/declarations/:id/issue', (ctx) => {
    requireRole(ctx, 'credential_issued', REGISTRAR);
    const actor = ctx.state.actor.id;
    const decl = db.prepare('SELECT * FROM declarations WHERE id = ?').get(ctx.params.id);
    if (!decl) ctx.throw(404, 'declaration not found');
    if (decl.status !== 'approved') ctx.throw(409, `declaration is ${decl.status}, must be approved before issuance`);
    let credential;
    try {
      credential = db.transaction(() => {
        const changed = db.prepare(
          "UPDATE declarations SET status = 'issued' WHERE id = ? AND status = 'approved'"
        ).run(decl.id).changes;
        if (changed !== 1) {
          const err = new Error('declaration already issued');
          err.status = 409;
          throw err;
        }
        return issueCredential(db, decl, actor);
      })();
    } catch (err) {
      if (err instanceof CoverageError) {
        appendAudit(db, {
          actor, action: 'credential_issued', entityType: 'declaration', entityId: decl.id,
          outcome: 'failure', detail: { reason: err.code, missing_upstream_fields: err.missing },
        });
        ctx.throw(409, err.message);
      }
      throw err;
    }
    ctx.status = 201;
    ctx.body = credentialView(db, credential);
  });

  router.add('GET', '/credentials/:id', (ctx) => {
    requireActor(ctx, 'credential_read');
    const row = db.prepare('SELECT * FROM credentials WHERE id = ?').get(ctx.params.id);
    if (!row) ctx.throw(404, 'credential not found');
    ctx.body = credentialView(db, row);
  });

  // 生成可撤销验证凭据：token 只返回一次，库中只存哈希
  router.add('POST', '/credentials/:id/tokens', (ctx) => {
    requireRole(ctx, 'token_minted', REGISTRAR);
    const credential = db.prepare('SELECT * FROM credentials WHERE id = ?').get(ctx.params.id);
    if (!credential) ctx.throw(404, 'credential not found');
    if (credential.status !== 'active') ctx.throw(409, 'cannot mint token for a revoked credential');
    const label = ctx.request.body.label !== undefined ? String(ctx.request.body.label) : null;
    let ttl = ctx.request.body.ttl_seconds === undefined ? DEFAULT_TOKEN_TTL_SECONDS : Number(ctx.request.body.ttl_seconds);
    if (!Number.isFinite(ttl) || ttl <= 0) throw badRequest('ttl_seconds must be a positive number');
    ttl = Math.min(ttl, MAX_TOKEN_TTL_SECONDS);
    const at = now();
    const expiresAt = new Date(Math.min(
      Date.parse(at) + ttl * 1000,
      Date.parse(credential.valid_until),
    )).toISOString();
    const token = randomToken();
    const id = randomId('vt');
    db.transaction(() => {
      db.prepare(`
        INSERT INTO verification_tokens (id, credential_id, token_hash, label, status, expires_at, created_by, created_at)
        VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
      `).run(id, credential.id, sha256(token), label, expiresAt, ctx.state.actor.id, at);
      appendAudit(db, {
        actor: ctx.state.actor.id, action: 'token_minted', entityType: 'verification_token', entityId: id,
        outcome: 'success', detail: { credential_id: credential.id, label, expires_at: expiresAt },
      });
    })();
    ctx.status = 201;
    ctx.body = { id, credential_id: credential.id, token, expires_at: expiresAt };
  });

  router.add('POST', '/tokens/:id/revoke', (ctx) => {
    requireRole(ctx, 'token_revoked', REGISTRAR);
    const row = db.prepare('SELECT * FROM verification_tokens WHERE id = ?').get(ctx.params.id);
    if (!row) ctx.throw(404, 'verification token not found');
    const at = now();
    db.transaction(() => {
      db.prepare("UPDATE verification_tokens SET status = 'revoked', revoked_at = ? WHERE id = ? AND status = 'active'")
        .run(at, row.id);
      appendAudit(db, {
        actor: ctx.state.actor.id, action: 'token_revoked', entityType: 'verification_token', entityId: row.id,
        outcome: 'success', detail: { credential_id: row.credential_id },
      });
    })();
    ctx.body = { id: row.id, status: 'revoked' };
  });

  // 外部核验：只回答该用途是否有效，不暴露任何合同细节；成功与失败都入审计
  router.add('POST', '/verify', (ctx) => {
    const token = ctx.request.body && ctx.request.body.token;
    const at = now();
    const fail = (status, body, detail) => {
      appendAudit(db, {
        actor: 'external-verifier', action: 'verification', entityType: 'verification_token',
        entityId: detail.tokenId || null, outcome: 'failure', detail,
      });
      ctx.status = status;
      ctx.body = body;
    };
    if (typeof token !== 'string' || token.trim() === '') {
      return fail(400, { valid: false, reason: 'token_required' }, { reason: 'token_required' });
    }
    const row = db.prepare('SELECT * FROM verification_tokens WHERE token_hash = ?').get(sha256(token.trim()));
    if (!row) {
      return fail(404, { valid: false, reason: 'unknown_token' }, { reason: 'unknown_token' });
    }
    if (row.status !== 'active') {
      return fail(200, { valid: false, reason: 'token_revoked' }, { tokenId: row.id, reason: 'token_revoked' });
    }
    if (row.expires_at < at) {
      return fail(200, { valid: false, reason: 'token_expired' }, { tokenId: row.id, reason: 'token_expired' });
    }
    const credential = db.prepare('SELECT * FROM credentials WHERE id = ?').get(row.credential_id);
    const verdict = credentialIsValid(db, credential, at);
    if (!verdict.valid) {
      db.transaction(() => {
        // 仅永久失效（撤回/终止/越界）才落撤销；裁定中止只是暂时无效，不改动凭证状态
        if (credential.status === 'active' && verdict.permanent && verdict.reason === 'upstream_license_invalid') {
          db.prepare("UPDATE credentials SET status = 'revoked', revoked_reason = ?, revoked_at = ? WHERE id = ? AND status = 'active'")
            .run(verdict.reason, at, credential.id);
          appendAudit(db, {
            actor: 'system:verify', action: 'credential_revoked', entityType: 'credential', entityId: credential.id,
            outcome: 'success', detail: { reason: verdict.reason, trigger_license_id: verdict.licenseId },
          });
        }
        appendAudit(db, {
          actor: 'external-verifier', action: 'verification', entityType: 'verification_token', entityId: row.id,
          outcome: 'failure', detail: { credential_id: credential.id, reason: verdict.reason },
        });
      })();
      ctx.body = { valid: false, reason: verdict.reason };
      return;
    }
    appendAudit(db, {
      actor: 'external-verifier', action: 'verification', entityType: 'verification_token', entityId: row.id,
      outcome: 'success', detail: { credential_id: credential.id },
    });
    // 最小披露：只有用途有效性与期限，不含授权主体、条款或其他合同信息
    ctx.body = {
      valid: true,
      purpose: credential.purpose,
      territory: credential.territory,
      valid_until: credential.valid_until,
      checked_at: at,
    };
  });

  // 数据集版本导出：按敏感度最小范围展示；越权请求被拒绝并审计
  router.add('GET', '/versions/:id/export', (ctx) => {
    requireActor(ctx, 'export');
    const version = db.prepare('SELECT * FROM dataset_versions WHERE id = ?').get(ctx.params.id);
    if (!version) ctx.throw(404, 'dataset version not found');
    const includeConfidential = ctx.query.include === 'confidential';
    if (includeConfidential && ctx.state.actor.role !== 'admin') {
      auditDenied(ctx, 'export', { dataset_version_id: version.id, reason: 'confidential_requires_admin' });
      ctx.throw(403, 'include=confidential requires admin role');
    }
    const fields = db.prepare('SELECT id, name, kind, sensitivity FROM fields WHERE dataset_version_id = ? ORDER BY name')
      .all(version.id);
    const masked = fields.map((f) => {
      if (f.sensitivity === 'confidential' && !includeConfidential) {
        return { id: f.id, name: '[redacted]', kind: f.kind, sensitivity: f.sensitivity };
      }
      if (f.sensitivity === 'internal') {
        return { id: f.id, name: f.name, kind: f.kind, sensitivity: f.sensitivity };
      }
      return f;
    });
    appendAudit(db, {
      actor: ctx.state.actor.id, action: 'export', entityType: 'dataset_version', entityId: version.id,
      outcome: 'success', detail: { include_confidential: includeConfidential, field_count: masked.length },
    });
    ctx.body = {
      dataset_version_id: version.id,
      dataset_id: version.dataset_id,
      version: version.version,
      content_hash: version.content_hash,
      fields: masked,
    };
  });

  router.add('GET', '/audit', (ctx) => {
    requireRole(ctx, 'audit_read', ['auditor', 'admin']);
    const limit = Math.min(Number(ctx.query.limit) || 100, 1000);
    const rows = db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?').all(limit);
    ctx.body = { entries: rows.reverse() };
  });

  // 路由分发
  app.use(async (ctx) => {
    const matched = router.match(ctx.method, ctx.path);
    if (!matched) ctx.throw(404, 'not found');
    ctx.params = matched.params;
    await matched.handler(ctx);
  });

  app.on('error', () => { /* 测试环境保持静默；生产可接日志 */ });
  return { app, db };
}

module.exports = { createApp, REQUIRED_APPROVALS };
