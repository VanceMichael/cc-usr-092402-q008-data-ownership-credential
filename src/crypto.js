'use strict';

const crypto = require('crypto');

/**
 * 规范化 JSON：对象键按 UTF-16 码点排序后递归序列化，
 * 保证跨进程、跨语言的签名/摘要输入完全一致。
 */
function canonicalize(value) {
  if (value === null || typeof value !== 'object') {
    if (value === undefined) throw new TypeError('undefined is not canonicalizable');
    if (Number.isNaN(value)) throw new TypeError('NaN is not canonicalizable');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((v) => canonicalize(v)).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

function sha256(value, encoding = 'hex') {
  const buf = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === 'string' ? value : canonicalize(value), 'utf8');
  return crypto.createHash('sha256').update(buf).digest(encoding);
}

function digestObject(value) {
  return sha256(canonicalize(value), 'hex');
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function randomId(prefix) {
  return `${prefix}_${crypto.randomBytes(16).toString('hex')}`;
}

function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKey,
    privateKey,
    publicKeyB64: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    privateKeyB64: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
  };
}

function loadPublicKey(b64) {
  return crypto.createPublicKey({ format: 'der', type: 'spki', key: Buffer.from(b64, 'base64') });
}

function loadPrivateKey(b64) {
  return crypto.createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.from(b64, 'base64') });
}

/** 对规范化后的对象做 Ed25519 签名，返回 base64 */
function signObject(privateKey, value) {
  const key = typeof privateKey === 'string' ? loadPrivateKey(privateKey) : privateKey;
  return crypto.sign(null, Buffer.from(canonicalize(value), 'utf8'), key).toString('base64');
}

function verifyObject(publicKey, value, signatureB64) {
  try {
    const key = typeof publicKey === 'string' ? loadPublicKey(publicKey) : publicKey;
    return crypto.verify(null, Buffer.from(canonicalize(value), 'utf8'), key, Buffer.from(signatureB64, 'base64'));
  } catch {
    return false;
  }
}

/** 常量时间字符串比较 */
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

module.exports = {
  canonicalize,
  sha256,
  digestObject,
  randomToken,
  randomId,
  generateKeyPair,
  loadPublicKey,
  loadPrivateKey,
  signObject,
  verifyObject,
  timingSafeEqual,
};
