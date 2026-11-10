require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { pool, getClient } = require('./index');
const { hashPassword } = require('../utils/auth');
const { validateUserRoles } = require('../utils/validators');

const DEFAULT_ADMIN = {
  nip: process.env.ADMIN_NIP || '198911032015042002',
  name: process.env.ADMIN_NAME || 'Administrator SIMTA DTE UI',
  email: process.env.ADMIN_EMAIL || 'admin.dte@ui.ac.id',
  password: process.env.ADMIN_PASSWORD || 'simta123'
};

function cleanUploadsFolder(uploadDir) {
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
    return;
  }
  const entries = fs.readdirSync(uploadDir);
  for (const entry of entries) {
    if (entry === '.gitkeep') continue;
    const fullPath = path.join(uploadDir, entry);
    try {
      if (typeof fs.rmSync === 'function') {
        fs.rmSync(fullPath, { recursive: true, force: true });
      } else {
        fs.unlinkSync(fullPath);
      }
    } catch {
      // Abaikan jika gagal menghapus file sementara
    }
  }
}

async function seedDatabase({ closePool = true, resetAll = false } = {}) {
  const client = await getClient();
  try {
    await client.query('BEGIN');

    const uploadDir = path.join(__dirname, '../../uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }

    if (resetAll) {
      console.log('Mengosongkan seluruh tabel database dan berkas lampiran untuk mode Production...');
      await client.query(`
        TRUNCATE TABLE
          activity_logs,
          progress_attachments,
          progress_feedback,
          progress_reports,
          mahasiswa_profiles,
          user_roles,
          users
        RESTART IDENTITY CASCADE
      `);
      cleanUploadsFolder(uploadDir);
    }

    // Pastikan akun Administrator utama tersedia untuk pengelolaan pengguna
    const adminRoles = ['ADMIN'];
    validateUserRoles(adminRoles);
    const adminPasswordHash = hashPassword(DEFAULT_ADMIN.password);

    const adminRes = await client.query(
      `INSERT INTO users (nip_or_npm, name, email, password_hash, is_active, approval_status, must_change_password)
       VALUES ($1, $2, $3, $4, TRUE, 'APPROVED', TRUE)
       ON CONFLICT (nip_or_npm) DO UPDATE
       SET is_active = TRUE,
           approval_status = 'APPROVED'
       RETURNING id`,
      [DEFAULT_ADMIN.nip, DEFAULT_ADMIN.name, DEFAULT_ADMIN.email, adminPasswordHash]
    );
    const adminId = adminRes.rows[0].id;

    await client.query(
      `INSERT INTO user_roles (user_id, role) VALUES ($1, 'ADMIN') ON CONFLICT (user_id, role) DO NOTHING`,
      [adminId]
    );

    await client.query('COMMIT');
    console.log(
      `Inisialisasi database selesai. Akun Admin siap digunakan: ${DEFAULT_ADMIN.email} (NIP: ${DEFAULT_ADMIN.nip}).`
    );
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Gagal melakukan inisialisasi akun Admin pada database:', err.message);
    process.exitCode = 1;
    throw err;
  } finally {
    client.release();
    if (closePool) {
      await pool.end();
    }
  }
}

if (require.main === module) {
  const resetFlag = process.argv.includes('--reset');
  seedDatabase({ closePool: true, resetAll: resetFlag }).catch(() => {
    process.exit(1);
  });
}

module.exports = { seedDatabase, DEFAULT_ADMIN };
