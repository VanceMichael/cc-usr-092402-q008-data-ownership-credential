'use strict';

const crypto = require('crypto');

// 服务端签名密钥：用于许可事件签名摘要与验证 token 摘要。
// 生产环境必须通过 REGISTRY_HMAC_KEY 注入；缺省值仅供本地开发。
const HMAC_KEY = process.env.REGISTRY_HMAC_KEY || 'dev-only-insecure-registry-key';

// 确定性 JSON：键排序，保证同一对象始终得到同一摘要输入。
function canonicalize(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  const body = keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',');
  return `{${body}}`;
}

function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function hmacDigest(input) {
  return crypto.createHmac('sha256', HMAC_KEY).update(input).digest('hex');
}

function digestObject(obj) {
  return hmacDigest(canonicalize(obj));
}

function randomId(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function randomToken() {
  return `vt_${crypto.randomBytes(32).toString('hex')}`;
}

module.exports = { canonicalize, sha256, hmacDigest, digestObject, randomId, randomToken };
