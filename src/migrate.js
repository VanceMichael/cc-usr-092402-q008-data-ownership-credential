'use strict';

const { openDatabase, migrate, resolveDbPath } = require('./db');

const db = openDatabase();
migrate(db);
const versions = db.prepare('SELECT version FROM schema_version ORDER BY version').all();
db.close();

console.log(`migrated ${resolveDbPath()} to schema version(s): ${versions.map((v) => v.version).join(', ') || '(none)'}`);
