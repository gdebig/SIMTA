const fs = require('node:fs');
const path = require('node:path');
const { pool, getClient } = require('./index');
const { hashPassword } = require('../utils/auth');
const { validateUserRoles, sanitizeEditorContent } = require('../utils/validators');

async function seedDatabase({ closePool = true } = {}) {
  const client = await getClient();
  try {
    console.log('Memulai proses seeding data awal SIMTA pada PostgreSQL...');
    await client.query('BEGIN');

    const uploadDir = path.join(__dirname, '../../uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }

    const defaultPasswordHash = hashPassword('simta123');

    // 1. Akun Dual-Role: ADMIN + DOSEN (Kaprodi / Koordinator TA - Aktif)
    const adminDosenRoles = ['ADMIN', 'DOSEN'];
    validateUserRoles(adminDosenRoles);

    const adminDosenRes = await client.query(
      `INSERT INTO users (nip_or_npm, name, email, password_hash, is_active, approval_status)
       VALUES ($1, $2, $3, $4, TRUE, 'APPROVED')
       ON CONFLICT (nip_or_npm) DO UPDATE SET name = EXCLUDED.name, is_active = TRUE, approval_status = 'APPROVED'
       RETURNING id`,
      ['197805122005011001', 'Prof. Dr. Ir. Budi Santoso, M.T.', 'budi.santoso@ui.ac.id', defaultPasswordHash]
    );
    const adminDosenId = adminDosenRes.rows[0].id;

    for (const role of adminDosenRoles) {
      await client.query(
        `INSERT INTO user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT (user_id, role) DO NOTHING`,
        [adminDosenId, role]
      );
    }

    // 2. Akun ADMIN Murni (Sekretariat Prodi - Aktif)
    const adminOnlyRoles = ['ADMIN'];
    validateUserRoles(adminOnlyRoles);

    const adminRes = await client.query(
      `INSERT INTO users (nip_or_npm, name, email, password_hash, is_active, approval_status)
       VALUES ($1, $2, $3, $4, TRUE, 'APPROVED')
       ON CONFLICT (nip_or_npm) DO UPDATE SET name = EXCLUDED.name, is_active = TRUE, approval_status = 'APPROVED'
       RETURNING id`,
      ['198911032015042002', 'Rina Kartika, S.Kom.', 'admin.dte@ui.ac.id', defaultPasswordHash]
    );
    await client.query(
      `INSERT INTO user_roles (user_id, role) VALUES ($1, 'ADMIN') ON CONFLICT (user_id, role) DO NOTHING`,
      [adminRes.rows[0].id]
    );

    // 3. Akun DOSEN Pembimbing (Aktif)
    const dosenRoles = ['DOSEN'];
    validateUserRoles(dosenRoles);

    const dosenRes = await client.query(
      `INSERT INTO users (nip_or_npm, name, email, password_hash, is_active, approval_status)
       VALUES ($1, $2, $3, $4, TRUE, 'APPROVED')
       ON CONFLICT (nip_or_npm) DO UPDATE SET name = EXCLUDED.name, is_active = TRUE, approval_status = 'APPROVED'
       RETURNING id`,
      ['198402192010121003', 'Dr. Eng. Ardiansyah Wijaya, S.T., M.Sc.', 'ardiansyah.w@ui.ac.id', defaultPasswordHash]
    );
    const dosenId = dosenRes.rows[0].id;
    await client.query(
      `INSERT INTO user_roles (user_id, role) VALUES ($1, 'DOSEN') ON CONFLICT (user_id, role) DO NOTHING`,
      [dosenId]
    );

    // 4. Akun DOSEN (Tidak Aktif / Cuti Tugas Belajar)
    const dosenInactiveRes = await client.query(
      `INSERT INTO users (nip_or_npm, name, email, password_hash, is_active, approval_status)
       VALUES ($1, $2, $3, $4, FALSE, 'APPROVED')
       ON CONFLICT (nip_or_npm) DO UPDATE SET name = EXCLUDED.name, is_active = FALSE, approval_status = 'APPROVED'
       RETURNING id`,
      ['198607212012121004', 'Dr. Ir. Wahyu Nugroho, S.T., M.T.', 'wahyu.nugroho@ui.ac.id', defaultPasswordHash]
    );
    await client.query(
      `INSERT INTO user_roles (user_id, role) VALUES ($1, 'DOSEN') ON CONFLICT (user_id, role) DO NOTHING`,
      [dosenInactiveRes.rows[0].id]
    );

    // 5. Akun MAHASISWA (S1, S2, S3) - Role terisolasi dengan status bimbingan lengkap
    const mahasiswaSeeds = [
      {
        npm: '2106701234',
        name: 'Dimas Pratama',
        email: 'dimas.pratama@ui.ac.id',
        degree: 'S1',
        year: '2025/2026',
        supervisionStatus: 'DALAM_BIMBINGAN',
        thesis: 'Desain Sistem Kendali Inverter Tiga Fasa Berbasis Model Predictive Control pada Microgrid DC-AC',
        pembimbingId: adminDosenId
      },
      {
        npm: '2306198810',
        name: 'Nadia Putri Maharani',
        email: 'nadia.putri@ui.ac.id',
        degree: 'S2',
        year: '2025/2026',
        supervisionStatus: 'DALAM_BIMBINGAN',
        thesis: 'Optimasi Alokasi Sumber Daya Radio Jaringan 6G Menggunakan Deep Reinforcement Learning',
        pembimbingId: dosenId
      },
      {
        npm: '2206009912',
        name: 'Ir. Hendra Kusuma, M.T.',
        email: 'hendra.kusuma@ui.ac.id',
        degree: 'S3',
        year: '2023/2024',
        supervisionStatus: 'LULUS',
        thesis: 'Arsitektur Komputasi Neuromorfik Daya Rendah untuk Deteksi Anomali Sinyal Biomedis Real-Time',
        pembimbingId: adminDosenId
      },
      {
        npm: '2006481120',
        name: 'Rizky Ramadhan',
        email: 'rizky.ramadhan@ui.ac.id',
        degree: 'S1',
        year: '2022/2023',
        supervisionStatus: 'TIDAK_SELESAI',
        thesis: 'Purwarupa Sensor Serat Optik untuk Pemantauan Suhu Transformator Daya',
        pembimbingId: dosenId
      }
    ];

    for (const mhs of mahasiswaSeeds) {
      validateUserRoles(['MAHASISWA']);
      const mhsRes = await client.query(
        `INSERT INTO users (nip_or_npm, name, email, password_hash, is_active, approval_status)
         VALUES ($1, $2, $3, $4, TRUE, 'APPROVED')
         ON CONFLICT (nip_or_npm) DO UPDATE SET name = EXCLUDED.name, approval_status = 'APPROVED'
         RETURNING id`,
        [mhs.npm, mhs.name, mhs.email, defaultPasswordHash]
      );
      const mhsId = mhsRes.rows[0].id;

      await client.query(
        `INSERT INTO user_roles (user_id, role) VALUES ($1, 'MAHASISWA') ON CONFLICT (user_id, role) DO NOTHING`,
        [mhsId]
      );

      await client.query(
        `INSERT INTO mahasiswa_profiles (user_id, degree, start_academic_year, thesis_title, dosen_pembimbing_id, supervision_status)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (user_id) DO UPDATE
         SET degree = EXCLUDED.degree,
             start_academic_year = EXCLUDED.start_academic_year,
             thesis_title = EXCLUDED.thesis_title,
             dosen_pembimbing_id = EXCLUDED.dosen_pembimbing_id,
             supervision_status = EXCLUDED.supervision_status`,
        [mhsId, mhs.degree, mhs.year, mhs.thesis, mhs.pembimbingId, mhs.supervisionStatus]
      );

      const existingRep = await client.query(
        `SELECT id FROM progress_reports WHERE mahasiswa_id = $1 LIMIT 1`,
        [mhsId]
      );

      let reportId;
      if (existingRep.rows.length === 0) {
        const cleanReport = sanitizeEditorContent(
          `<h3>Bab 1 &amp; Studi Literatur</h3><p>Telah diselesaikan pemodelan matematis dan simulasi awal untuk topik <strong>${mhs.thesis}</strong>.</p><ul><li>Rumusan masalah tervalidasi</li><li>Dataset pengujian telah dikumpulkan</li></ul>`
        );
        const reportStatus = mhs.supervisionStatus === 'LULUS' ? 'APPROVED' : 'REVIEWED';
        const reportRes = await client.query(
          `INSERT INTO progress_reports (mahasiswa_id, academic_year_id, title, report_html, status)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id`,
          [mhsId, mhs.year, 'Laporan Kemajuan 1 - Studi Literatur & Pemodelan', cleanReport, reportStatus]
        );
        reportId = reportRes.rows[0].id;

        const cleanFeedback = sanitizeEditorContent(
          `<p>Progres sangat baik. Mohon tambahkan analisis sensitivitas parameter pada <em>bab metodologi</em> sebelum masuk ke tahap eksperimen perangkat keras.</p>`
        );
        const cleanFollowup = sanitizeEditorContent(
          `<ol><li>Revisi diagram blok arsitektur</li><li>Lampirkan hasil simulasi skenario beban puncak pada laporan berikutnya</li></ol>`
        );

        await client.query(
          `INSERT INTO progress_feedback (report_id, dosen_id, feedback_html, followup_notes_html)
           VALUES ($1, $2, $3, $4)`,
          [reportId, mhs.pembimbingId, cleanFeedback, cleanFollowup]
        );
      } else {
        reportId = existingRep.rows[0].id;
      }

      const existingAtt = await client.query(
        `SELECT COUNT(*)::int AS cnt FROM progress_attachments WHERE report_id = $1`,
        [reportId]
      );
      if (existingAtt.rows[0].cnt === 0) {
        const sampleFileName = `Laporan_Bab1_${mhs.npm}.pdf`;
        const diskFilePath = path.join(uploadDir, sampleFileName);
        const dummyContent = Buffer.from(
          `%PDF-1.4\n% Dokumen Lampiran Tugas Akhir SIMTA DTE UI\n% Mahasiswa: ${mhs.name} (${mhs.npm})\n% Topik: ${mhs.thesis}\n`,
          'utf8'
        );
        if (!fs.existsSync(diskFilePath)) {
          fs.writeFileSync(diskFilePath, dummyContent);
        }
        await client.query(
          `INSERT INTO progress_attachments (report_id, file_name, file_path, file_size_bytes)
           VALUES ($1, $2, $3, $4)`,
          [reportId, sampleFileName, `/uploads/${sampleFileName}`, dummyContent.length]
        );
      }
    }

    // 6. Contoh Log Aktivitas Awal (jika tabel activity_logs masih kosong)
    const logCountRes = await client.query(`SELECT COUNT(*)::int AS cnt FROM activity_logs`);
    if (logCountRes.rows[0].cnt === 0) {
      const dimasRes = await client.query(`SELECT id FROM users WHERE nip_or_npm = '2106701234'`);
      const dimasId = dimasRes.rows[0]?.id || null;

      const nadiaRes = await client.query(`SELECT id FROM users WHERE nip_or_npm = '2306198810'`);
      const nadiaId = nadiaRes.rows[0]?.id || null;

      await client.query(
        `INSERT INTO activity_logs (user_id, actor_name, actor_identifier, actor_roles, action_type, description, target_user_id)
         VALUES
           ($1, 'Dimas Pratama', '2106701234', 'MAHASISWA', 'LOGIN', 'Mahasiswa Dimas Pratama berhasil login ke sistem SIMTA.', $1),
           ($1, 'Dimas Pratama', '2106701234', 'MAHASISWA', 'CREATE_REPORT', 'Memasukkan laporan kemajuan: "Laporan Kemajuan 1 - Studi Literatur & Pemodelan" (T.A. 2025/2026).', $1),
           ($2, 'Prof. Dr. Ir. Budi Santoso, M.T.', '197805122005011001', 'ADMIN, DOSEN', 'CREATE_FEEDBACK', 'Memasukkan komentar evaluasi pada laporan mahasiswa Dimas Pratama serta memperbarui status menjadi REVIEWED.', $1),
           ($3, 'Nadia Putri Maharani', '2306198810', 'MAHASISWA', 'CREATE_REPORT', 'Memasukkan laporan kemajuan: "Laporan Kemajuan 1 - Studi Literatur & Pemodelan" (T.A. 2025/2026).', $3),
           ($4, 'Dr. Eng. Ardiansyah Wijaya, S.T., M.Sc.', '198402192010121003', 'DOSEN', 'CREATE_FEEDBACK', 'Memasukkan komentar evaluasi pada laporan mahasiswa Nadia Putri Maharani.', $3),
           ($2, 'Prof. Dr. Ir. Budi Santoso, M.T.', '197805122005011001', 'ADMIN, DOSEN', 'UPDATE_USER', 'Admin memperbarui status bimbingan Ir. Hendra Kusuma, M.T. menjadi LULUS.', NULL)`,
        [dimasId, adminDosenId, nadiaId, dosenId]
      );
    }

    await client.query('COMMIT');
    console.log('Seeding database PostgreSQL berhasil diselesaikan (Password default: simta123).');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Gagal melakukan seeding database:', err.message);
    process.exitCode = 1;
  } finally {
    client.release();
    if (closePool) {
      await pool.end();
    }
  }
}

if (require.main === module) {
  seedDatabase();
}

module.exports = { seedDatabase };
