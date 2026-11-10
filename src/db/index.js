require('dotenv').config();
const { Pool } = require('pg');

function buildPoolConfig(overrides = {}) {
  if (overrides.port || overrides.host) {
    return {
      host: overrides.host || process.env.PGHOST || '127.0.0.1',
      port: Number(overrides.port) || Number(process.env.PGPORT) || 5432,
      user: process.env.PGUSER || 'postgres',
      password: process.env.PGPASSWORD || 'postgres',
      database: process.env.PGDATABASE || 'simta_db'
    };
  }
  if (process.env.DATABASE_URL) {
    return { connectionString: process.env.DATABASE_URL };
  }
  return {
    host: process.env.PGHOST || '127.0.0.1',
    port: Number(process.env.PGPORT) || 5432,
    user: process.env.PGUSER || 'postgres',
    password: process.env.PGPASSWORD || 'postgres',
    database: process.env.PGDATABASE || 'simta_db'
  };
}

let currentPool = new Pool(buildPoolConfig());

async function reconfigurePool(overrides = {}) {
  try {
    await currentPool.end();
  } catch {
    // Abaikan jika pool sebelumnya sudah tertutup
  }
  currentPool = new Pool(buildPoolConfig(overrides));
  return currentPool;
}

const poolProxy = new Proxy(
  {},
  {
    get(_target, prop) {
      const val = currentPool[prop];
      return typeof val === 'function' ? val.bind(currentPool) : val;
    }
  }
);

/**
 * Jalankan query PostgreSQL menggunakan pg.Pool aktif
 * @param {string} text
 * @param {any[]} [params]
 */
async function query(text, params) {
  return currentPool.query(text, params);
}

/**
 * Ambil client dari pool untuk transaksi
 */
async function getClient() {
  return currentPool.connect();
}

module.exports = {
  pool: poolProxy,
  query,
  getClient,
  reconfigurePool
};
