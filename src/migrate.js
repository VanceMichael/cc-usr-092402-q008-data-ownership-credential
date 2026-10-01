'use strict';

const { open, migrate, DB_PATH } = require('./db');

const db = open();
const { version, signingKey } = migrate(db);
console.log(JSON.stringify({
  ok: true,
  db: DB_PATH,
  schema_version: version,
  registry_public_key: signingKey.public_spki,
}));
db.close();
