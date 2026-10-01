'use strict';

/**
 * 用途范围 / 地域 / 期限匹配。
 * 列表中 '*' 表示通配；undefined/null 列表视为不受限。
 */

function listContains(list, value) {
  if (list == null) return true; // 未声明 = 不限制
  return list.includes('*') || list.includes(value);
}

/** term 列表 a 是否覆盖 b（用于恢复撤回时判定恢复范围） */
function listCovers(a, b) {
  if (a == null) return true; // a 不限制 => 覆盖一切
  if (b == null) return false; // a 有限制而 b 无限制 => 不能覆盖
  if (a.includes('*')) return true;
  return b.every((v) => a.includes(v));
}

function toTime(value) {
  if (value == null) return null;
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
}

/** 条款在时刻 atMs 是否处于有效期内 */
function withinWindow(terms, atMs) {
  const from = toTime(terms.valid_from);
  const until = toTime(terms.valid_until); // null = 长期有效
  if (from != null && atMs < from) return false;
  if (until != null && atMs > until) return false;
  return true;
}

/** 静态条款（不含撤回限制）是否覆盖请求的用途/地域/时刻 */
function termsCover(terms, requested, atMs = Date.now()) {
  if (!withinWindow(terms, atMs)) return false;
  if (!listContains(terms.purposes, requested.purpose)) return false;
  if (!listContains(terms.regions, requested.region)) return false;
  return true;
}

/** 要求条款覆盖整个请求窗口（签发时使用）：到期日不得早于 requestedUntil */
function termsCoverWindow(terms, requested, atMs = Date.now()) {
  if (!termsCover(terms, requested, atMs)) return false;
  const requestedUntil = toTime(requested.valid_until);
  if (requestedUntil != null) {
    const until = toTime(terms.valid_until);
    if (until != null && until < requestedUntil) return false;
  }
  return true;
}

/** 条款的唯一规范化形态（签名与存储都用它） */
function normalizeTerms(terms) {
  return {
    purposes: terms.purposes == null ? null : [...new Set(terms.purposes)].sort(),
    regions: terms.regions == null ? null : [...new Set(terms.regions)].sort(),
    valid_from: terms.valid_from || null,
    valid_until: terms.valid_until || null,
  };
}

/** 客户端签名与服务端验签必须逐字节一致的撤回/恢复范围规范化 */
function normalizeRestriction(r, fallbackKind) {
  return {
    kind: r.kind || fallbackKind,
    field_id: r.field_id ?? null,
    dataset_id: r.dataset_id ?? null,
    purposes: r.purposes ? [...new Set(r.purposes)].sort() : null,
    regions: r.regions ? [...new Set(r.regions)].sort() : null,
  };
}

module.exports = { listContains, listCovers, withinWindow, termsCover, termsCoverWindow, toTime, normalizeTerms, normalizeRestriction };
