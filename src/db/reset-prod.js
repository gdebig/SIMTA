require('dotenv').config();
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { pool } = require('./index');
const { seedDatabase } = require('./seed');
const { startPostgresServer } = require('./pg-server');

const PGHOST = process.env.PGHOST || '127.0.0.1';
const PGPORT = Number(process.env.PGPORT) || 5432;

function isPortOpen(host, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(1000);
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.once('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, host);
  });
}

async function resetProductionDatabase() {
  let pgHandle = null;
  try {
    const running = await isPortOpen(PGHOST, PGPORT);
    if (!running) {
      pgHandle = await startPostgresServer();
    }

    const schemaPath = path.join(__dirname, '../../db/schema.sql');
    const schemaSql = fs.readFileSync(schemaPath, 'utf8');
    await pool.query(schemaSql);

    await seedDatabase({ closePool: true, resetAll: true });
    console.log('Reset database Production berhasil: Seluruh data sampel dikosongkan dan hanya menyisakan akun Admin.');
  } finally {
    if (pgHandle) {
      await pgHandle.server.stop();
      await pgHandle.db.close();
    }
  }
}

if (require.main === module) {
  resetProductionDatabase().catch((err) => {
    console.error('Gagal mereset database Production:', err.message);
    process.exit(1);
  });
}

module.exports = { resetProductionDatabase };
