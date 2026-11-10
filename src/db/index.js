require('dotenv').config();
const { Pool } = require('pg');

const poolConfig = process.env.DATABASE_URL
  ? { connectionString: process.env.DATABASE_URL }
  : {
      host: process.env.PGHOST || 'localhost',
      port: Number(process.env.PGPORT) || 5432,
      user: process.env.PGUSER || 'postgres',
      password: process.env.PGPASSWORD || 'postgres',
      database: process.env.PGDATABASE || 'simta_db'
    };

const pool = new Pool(poolConfig);

/**
 * Jalankan query PostgreSQL menggunakan pg.Pool
 * @param {string} text
 * @param {any[]} [params]
 */
async function query(text, params) {
  return pool.query(text, params);
}

/**
 * Ambil client dari pool untuk transaksi
 */
async function getClient() {
  return pool.connect();
}

module.exports = {
  pool,
  query,
  getClient
};

