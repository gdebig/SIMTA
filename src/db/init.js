const fs = require('node:fs');
const path = require('node:path');
const { pool } = require('./index');

async function initDatabase() {
  const schemaPath = path.join(__dirname, '../../db/schema.sql');
  const sql = fs.readFileSync(schemaPath, 'utf8');

  console.log('Menginisialisasi skema database PostgreSQL (SIMTA)...');
  try {
    await pool.query(sql);
    console.log('Skema database PostgreSQL berhasil diterapkan.');
  } catch (err) {
    console.error('Gagal menginisialisasi skema database:', err.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

if (require.main === module) {
  initDatabase();
}

module.exports = { initDatabase };

