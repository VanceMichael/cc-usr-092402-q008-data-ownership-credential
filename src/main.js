'use strict';

const { open, migrate } = require('./db');
const { createApp } = require('./app');

const db = open();
migrate(db);

const app = createApp(db);
const port = process.env.PORT || 3000;
const host = process.env.HOST || '0.0.0.0';

const server = app.listen(port, host, () => {
  console.log(JSON.stringify({ status: 'listening', host, port }));
});

function shutdown(signal) {
  server.close(() => {
    try { db.close(); } catch { /* already closed */ }
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 5000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

module.exports = { app, server, db };
