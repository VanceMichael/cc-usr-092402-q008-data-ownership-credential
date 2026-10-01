'use strict';

/**
 * 数据集版本、字段与派生关系（DAG）。
 * source 字段直接挂接授权；derived 字段通过派生边传递授权义务。
 */

function fieldId(datasetId, version, name) {
  return `${datasetId}@${version}#${name}`;
}

function registerDatasetVersion(db, input) {
  const { dataset_id: datasetId, version, submitter_id: submitterId, manifest_hash: manifestHash, fields = [], at = new Date().toISOString() } = input;
  const byName = new Map(fields.map((f) => [f.name, f]));
  if (byName.size !== fields.length) throw Object.assign(new Error('duplicate field name'), { status: 400, code: 'duplicate_field' });

  // 校验派生图：上游必须存在、不得成环
  const color = new Map(); // 0=white 1=gray 2=black
  const visit = (name, stack = []) => {
    const c = color.get(name) || 0;
    if (c === 1) throw Object.assign(new Error(`lineage cycle through ${name}`), { status: 400, code: 'lineage_cycle', cycle: [...stack, name] });
    if (c === 2) return;
    color.set(name, 1);
    for (const up of byName.get(name).derived_from || []) {
      if (!byName.has(up)) throw Object.assign(new Error(`unknown upstream field ${up}`), { status: 400, code: 'unknown_upstream' });
      visit(up, [...stack, name]);
    }
    color.set(name, 2);
  };
  for (const f of fields) {
    if (!['source', 'derived'].includes(f.kind)) throw Object.assign(new Error(`bad kind for ${f.name}`), { status: 400 });
    if (f.kind === 'derived' && !(f.derived_from || []).length) {
      throw Object.assign(new Error(`derived field ${f.name} requires upstream`), { status: 400, code: 'derived_without_upstream' });
    }
    if (f.kind === 'source' && (f.derived_from || []).length) {
      throw Object.assign(new Error(`source field ${f.name} cannot declare upstream`), { status: 400, code: 'source_with_upstream' });
    }
    visit(f.name);
  }

  const insVersion = db.prepare(
    `INSERT INTO dataset_versions(dataset_id,version,submitter_id,manifest_hash,created_at)
     VALUES(?,?,?,?,?)`
  );
  const insField = db.prepare(
    `INSERT INTO fields(field_id,dataset_id,version,name,kind,created_at) VALUES(?,?,?,?,?,?)`
  );
  const insLineage = db.prepare(
    `INSERT INTO lineage(derived_field_id,upstream_field_id,ordinal) VALUES(?,?,?)`
  );
  const insAttach = db.prepare(
    `INSERT INTO field_licenses(field_id,license_id) VALUES(?,?)`
  );
  const licenseExists = db.prepare('SELECT 1 FROM licenses WHERE license_id=? AND status=\'active\'');

  const tx = db.transaction(() => {
    insVersion.run(datasetId, version, submitterId, manifestHash, at);
    for (const f of fields) {
      const id = fieldId(datasetId, version, f.name);
      insField.run(id, datasetId, version, f.name, f.kind, at);
    }
    for (const f of fields) {
      const id = fieldId(datasetId, version, f.name);
      (f.derived_from || []).forEach((up, ordinal) => {
        insLineage.run(id, fieldId(datasetId, version, up), ordinal);
      });
      for (const licenseId of f.licenses || []) {
        if (!licenseExists.get(licenseId)) {
          throw Object.assign(new Error(`license ${licenseId} not active`), { status: 400, code: 'unknown_license' });
        }
        insAttach.run(id, licenseId);
      }
    }
  });
  tx();
  return {
    dataset_id: datasetId,
    version,
    fields: fields.map((f) => ({ field_id: fieldId(datasetId, version, f.name), name: f.name, kind: f.kind, derived_from: f.derived_from || [] })),
  };
}

/** 字段的全部上游闭包（含自身），按 field_id 排序返回 */
function upstreamClosure(db, targetFieldId) {
  const edges = db.prepare('SELECT upstream_field_id FROM lineage WHERE derived_field_id=? ORDER BY ordinal').pluck();
  const seen = new Set();
  const stack = [targetFieldId];
  while (stack.length) {
    const id = stack.pop();
    if (seen.has(id)) continue;
    seen.add(id);
    for (const up of edges.all(id)) stack.push(up);
  }
  return [...seen].sort();
}

/** 版本下所有字段 */
function fieldsOfVersion(db, datasetId, version) {
  return db.prepare('SELECT field_id,name,kind FROM fields WHERE dataset_id=? AND version=? ORDER BY name').all(datasetId, version);
}

/**
 * 计算一个字段需要满足的全部“字段→许可”边：
 * 沿派生闭包收集所有 source 字段挂接的许可。
 * 保守策略：闭包内每一条许可都必须对请求范围有效。
 */
function requiredLicenses(db, targetFieldId) {
  const closure = upstreamClosure(db, targetFieldId);
  const placeholders = closure.map(() => '?').join(',');
  return db.prepare(
    `SELECT fl.field_id, fl.license_id
       FROM field_licenses fl
       JOIN fields f ON f.field_id = fl.field_id
      WHERE fl.field_id IN (${placeholders})
      ORDER BY fl.field_id, fl.license_id`
  ).all(...closure);
}

/** 闭包内完全没有挂接任何许可的 source 字段（无授权证据） */
function uncoveredSources(db, targetFieldId) {
  const closure = upstreamClosure(db, targetFieldId);
  const placeholders = closure.map(() => '?').join(',');
  const sources = db.prepare(
    `SELECT field_id FROM fields WHERE kind='source' AND field_id IN (${placeholders})`
  ).all(...closure).map((r) => r.field_id);
  const covered = new Set(requiredLicenses(db, targetFieldId).map((e) => e.field_id));
  return sources.filter((id) => !covered.has(id)).sort();
}

module.exports = { fieldId, registerDatasetVersion, upstreamClosure, fieldsOfVersion, requiredLicenses, uncoveredSources };
