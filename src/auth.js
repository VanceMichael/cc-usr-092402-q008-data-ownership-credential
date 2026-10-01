'use strict';

const crypto = require('crypto');
const { loadPublicKey, verifyObject, sha256, loadPrivateKey } = require('./crypto');
const { HttpError } = require('./licenses');

const SKEW_MS = 5 * 60 * 1000;
const MAX_BODY_BYTES = 1024 * 1024;

/**
 * 请求签名：Ed25519 over canonical({method,path,timestamp,nonce,body_sha256})
 * 头：X-Principal-Id / X-Timestamp / X-Nonce / X-Signature
 */
function signableRequest({ method, path, timestamp, nonce, rawBody }) {
  return {
    method,
    path,
    timestamp,
    nonce,
    body_sha256: sha256(rawBody || Buffer.alloc(0)),
  };
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(new HttpError(413, 'body_too_large', 'request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function authenticate(db) {
  return async (ctx, next) => {
    ctx.state.rawBody = await readRawBody(ctx.req);
    ctx.state.requestId = crypto.randomUUID();
    ctx.state.startedAt = new Date().toISOString();

    const pid = ctx.get('X-Principal-Id');
    if (!pid) throw new HttpError(401, 'missing_principal', 'authentication required');
    const p = db.prepare('SELECT * FROM principals WHERE principal_id=?').get(pid);
    if (!p) throw new HttpError(401, 'unknown_principal', 'principal not registered');
    if (p.status !== 'active') throw new HttpError(403, 'principal_revoked', 'principal is revoked');

    const timestamp = ctx.get('X-Timestamp');
    const nonce = ctx.get('X-Nonce');
    const signature = ctx.get('X-Signature');
    if (!timestamp || !nonce || !signature) throw new HttpError(401, 'missing_signature_headers', 'timestamp/nonce/signature required');
    const ts = Date.parse(timestamp);
    if (Number.isNaN(ts) || Math.abs(Date.now() - ts) > SKEW_MS) {
      throw new HttpError(401, 'bad_timestamp', 'timestamp missing or outside skew window');
    }

    const envelope = signableRequest({
      method: ctx.method,
      path: ctx.path,
      timestamp,
      nonce,
      rawBody: ctx.state.rawBody,
    });
    let ok = false;
    try {
      ok = verifyObject(loadPublicKey(p.public_key), envelope, signature);
    } catch {
      ok = false;
    }
    if (!ok) throw new HttpError(401, 'bad_signature', 'request signature verification failed');

    // 防重放：nonce 唯一，时间窗外的旧请求自然失效；顺带清理过期 nonce
    db.prepare("DELETE FROM consumed_nonces WHERE seen_at < datetime('now','-15 minutes')").run();
    try {
      db.prepare('INSERT INTO consumed_nonces(nonce,principal_id,seen_at) VALUES(?,?,?)')
        .run(nonce, pid, new Date().toISOString());
    } catch (err) {
      if (String(err.message).includes('UNIQUE')) {
        throw new HttpError(401, 'nonce_replayed', 'nonce already used');
      }
      throw err;
    }

    ctx.state.principal = p;
    ctx.state.requestSignature = signature;
    await next();
  };
}

function requireRole(...roles) {
  return (ctx) => {
    if (!ctx.state.principal || !roles.includes(ctx.state.principal.role)) {
      throw new HttpError(403, 'role_denied', `requires role ${roles.join('/')}`);
    }
  };
}

function loadRegistryKey(db) {
  const row = db.prepare("SELECT value_json FROM server_secrets WHERE name='signing-key'").get();
  const value = JSON.parse(row.value_json);
  return {
    public_spki: value.public_spki,
    private_key: loadPrivateKey(value.private_pkcs8),
  };
}

module.exports = { authenticate, requireRole, loadRegistryKey, signableRequest, SKEW_MS };
