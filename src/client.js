'use strict';

const http = require('http');
const crypto = require('crypto');
const { signObject, loadPrivateKey } = require('./crypto');
const { signableRequest } = require('./auth');
const { legalEnvelope } = require('./licenses');
const { normalizeRestriction, normalizeTerms } = require('./scopes');

/** 对法律事件封套签名（与登记处验签封套严格一致） */
function signLegalEvent(input, privateKeyB64) {
  const envelope = legalEnvelope({
    type: input.type,
    familyId: input.family_id,
    seq: input.seq,
    documentHash: input.document_hash,
    signerId: input.signer_id,
    payload: input.payload,
    effectiveAt: input.effective_at,
  });
  return signObject(loadPrivateKey(privateKeyB64), envelope);
}

function licenseRequestBuilders(actor) {
  const base = ({ licenseId, seq = 1, effectiveAt, documentHash }) => ({
    family_id: licenseId,
    seq,
    signer_id: actor.principal_id,
    effective_at: effectiveAt || new Date().toISOString(),
    document_hash: documentHash,
  });
  return {
    original({ license_id: licenseId, terms, document_hash: documentHash, effective_at: effectiveAt }) {
      const b = base({ licenseId, effectiveAt, documentHash });
      const payload = { terms: normalizeTerms(terms) };
      return {
        body: { license_id: licenseId, seq: 1, terms, document_hash: documentHash, effective_at: b.effective_at, signature: signLegalEvent({ ...b, type: 'original', payload }, actor.privateKeyB64) },
      };
    },
    amendment({ license_id: licenseId, seq, terms, document_hash: documentHash, effective_at: effectiveAt }) {
      const b = base({ licenseId, seq, effectiveAt, documentHash });
      const payload = { terms: normalizeTerms(terms) };
      return { body: { seq, terms, document_hash: documentHash, effective_at: b.effective_at, signature: signLegalEvent({ ...b, type: 'amendment', payload }, actor.privateKeyB64) } };
    },
    withdrawal({ license_id: licenseId, seq, scope, reason, document_hash: documentHash, effective_at: effectiveAt }) {
      const b = base({ licenseId, seq, effectiveAt, documentHash });
      const restrictions = [normalizeRestriction(scope, 'withdraw')];
      const payload = { reason: reason || 'partial withdrawal', restrictions };
      const bodyScope = { ...restrictions[0] };
      delete bodyScope.kind;
      return { body: { seq, scope: bodyScope, reason: payload.reason, document_hash: documentHash, effective_at: b.effective_at, signature: signLegalEvent({ ...b, type: 'withdrawal', payload }, actor.privateKeyB64) } };
    },
    revocation({ license_id: licenseId, seq, reason, document_hash: documentHash, effective_at: effectiveAt }) {
      const b = base({ licenseId, seq, effectiveAt, documentHash });
      const payload = { reason: reason || 'licensor revocation' };
      return { body: { seq, reason: payload.reason, document_hash: documentHash, effective_at: b.effective_at, signature: signLegalEvent({ ...b, type: 'revocation', payload }, actor.privateKeyB64) } };
    },
    ruling({ license_id: licenseId, seq, decision, terms, restrictions, reason, document_hash: documentHash, effective_at: effectiveAt }) {
      const b = base({ licenseId, seq, effectiveAt, documentHash });
      const payload = { decision, reason: reason || null };
      if (terms) payload.terms = normalizeTerms(terms);
      if (restrictions) {
        payload.restrictions = restrictions.map((r) =>
          normalizeRestriction(r, decision === 'suspend' ? 'withdraw' : 'reinstate'));
      }
      return { body: { seq, decision, terms, restrictions: payload.restrictions || null, reason: payload.reason, document_hash: documentHash, effective_at: b.effective_at, signature: signLegalEvent({ ...b, type: 'ruling', payload }, actor.privateKeyB64) } };
    },
  };
}

class RegistryClient {
  constructor(baseUrl, actor) {
    this.baseUrl = baseUrl;
    this.actor = actor; // {principal_id, privateKeyB64}
    this.legal = licenseRequestBuilders(actor);
  }

  request(method, urlPath, bodyObj, { sign = true, rawToken = null } = {}) {
    const rawBody = bodyObj == null ? Buffer.alloc(0) : Buffer.from(JSON.stringify(bodyObj));
    const timestamp = new Date().toISOString();
    const nonce = crypto.randomUUID();
    const headers = { 'Content-Type': 'application/json', 'Content-Length': rawBody.length };
    const signPath = urlPath.split('?')[0]; // 签名只覆盖 path，query 不进入封套（与服务端 ctx.path 一致）
    if (sign) {
      if (!this.actor || !this.actor.privateKeyB64) {
        throw new Error('unauthenticated client must be called with { sign: false }');
      }
      headers['X-Principal-Id'] = this.actor.principal_id;
      headers['X-Timestamp'] = timestamp;
      headers['X-Nonce'] = nonce;
      headers['X-Signature'] = signObject(loadPrivateKey(this.actor.privateKeyB64),
        signableRequest({ method, path: signPath, timestamp, nonce, rawBody }));
    }
    if (rawToken) headers.Authorization = `Bearer ${rawToken}`;
    const u = new URL(urlPath, this.baseUrl);
    return new Promise((resolve, reject) => {
      const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try { json = text ? JSON.parse(text) : null; } catch { json = text; }
          resolve({ status: res.statusCode, json });
        });
      });
      req.on('error', reject);
      if (rawBody.length) req.write(rawBody);
      req.end();
    });
  }
}

module.exports = { RegistryClient, signLegalEvent };
