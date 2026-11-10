require('dotenv').config();
const path = require('node:path');
const fs = require('node:fs');
const { PGlite } = require('@electric-sql/pglite');
const { PGLiteSocketServer } = require('@electric-sql/pglite-socket');
const { reconfigurePool } = require('./index');
const { seedDatabase } = require('./seed');

const DEFAULT_PORT = Number(process.env.PGPORT) || 5432;
const DEFAULT_HOST = process.env.PGHOST || '127.0.0.1';
const DATA_DIR = path.join(__dirname, '../../pgdata');

async function startPostgresServer(options = {}) {
  const port = options.port !== undefined ? Number(options.port) : DEFAULT_PORT;
  const host = options.host || (options.inMemory ? '127.0.0.1' : DEFAULT_HOST);
  const inMemory = Boolean(options.inMemory);

  if (!inMemory && !fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  console.log(
    `Menyiapkan engine PostgreSQL pada ${inMemory ? 'memori terisolasi (In-Memory)' : `direktori: ${DATA_DIR}`}`
  );
  const db = inMemory ? new PGlite() : new PGlite(DATA_DIR);
  await db.waitReady;

  // Terapkan skema secara otomatis saat server database menyala
  const schemaPath = path.join(__dirname, '../../db/schema.sql');
  if (fs.existsSync(schemaPath)) {
    const schemaSql = fs.readFileSync(schemaPath, 'utf8');
    await db.exec(schemaSql);
    console.log('Skema PostgreSQL (schema.sql) telah diterapkan.');
  }

  const server = new PGLiteSocketServer({
    db,
    port,
    host,
    maxConnections: 25
  });

  try {
    await server.start();
  } catch (err) {
    console.error('Gagal menyalakan PGLiteSocketServer:', err.message);
    await db.close();
    throw err;
  }

  const boundPort = server.port || port;
  if (boundPort !== DEFAULT_PORT || inMemory) {
    await reconfigurePool({ host: '127.0.0.1', port: boundPort });
  }

  console.log(`=============================================================`);
  console.log(`  PostgreSQL Server (PGlite Wire Protocol) Aktif`);
  console.log(`  Listening on: ${host}:${boundPort}`);
  console.log(`=============================================================`);

  // Pastikan akun Admin awal tersedia
  await seedDatabase({ closePool: false });

  if (!inMemory) {
    const shutdown = async () => {
      console.log('\nMenghentikan PostgreSQL Server...');
      await server.stop();
      await db.close();
      process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  }

  return { db, server, port: boundPort };
}

if (require.main === module) {
  startPostgresServer().catch((err) => {
    console.error('Gagal menjalankan PostgreSQL server:', err);
    process.exit(1);
  });
}

module.exports = { startPostgresServer };
