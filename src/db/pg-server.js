require('dotenv').config();
const path = require('node:path');
const fs = require('node:fs');
const { PGlite } = require('@electric-sql/pglite');
const { PGLiteSocketServer } = require('@electric-sql/pglite-socket');
const { seedDatabase } = require('./seed');

const PORT = Number(process.env.PGPORT) || 5432;
const HOST = process.env.PGHOST || '127.0.0.1';
const DATA_DIR = path.join(__dirname, '../../pgdata');

async function startPostgresServer() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  console.log(`Menyiapkan engine PostgreSQL pada direktori: ${DATA_DIR}`);
  const db = new PGlite(DATA_DIR);
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
    port: PORT,
    host: HOST,
    maxConnections: 25
  });

  await server.start();
  console.log(`=============================================================`);
  console.log(`  PostgreSQL Server (PGlite Wire Protocol) Aktif`);
  console.log(`  Listening on: ${HOST}:${PORT}`);
  console.log(`=============================================================`);

  // Pastikan data seed awal selalu tersinkronisasi (idempotent via ON CONFLICT)
  await seedDatabase({ closePool: false });

  const shutdown = async () => {
    console.log('\nMenghentikan PostgreSQL Server...');
    await server.stop();
    await db.close();
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  return { db, server };
}

if (require.main === module) {
  startPostgresServer().catch((err) => {
    console.error('Gagal menjalankan PostgreSQL server:', err);
    process.exit(1);
  });
}

module.exports = { startPostgresServer };
