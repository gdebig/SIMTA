const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const {
  VALID_SUPERVISION_STATUSES,
  validateUserRoles,
  validateFileSize,
  sanitizeEditorContent,
  sanitizePlainText,
  resolveSafeUploadPath,
  validateSafeUploadFiles
} = require('../src/utils/validators');
const { hashPassword, verifyPassword, createToken, verifyToken } = require('../src/utils/auth');
const app = require('../src/app');
const { startPostgresServer } = require('../src/db/pg-server');
const { pool } = require('../src/db');

const UPLOAD_DIR = path.resolve(__dirname, '../uploads');

describe('Sistem Informasi Tugas Akhir - Core Rule Tests', () => {
  test('Role: Admin dan Dosen diizinkan dalam satu akun', () => {
    assert.doesNotThrow(() => validateUserRoles(['ADMIN', 'DOSEN']));
  });

  test('Role: Mahasiswa dilarang bersamaan memiliki role Dosen atau Admin', () => {
    assert.throws(() => validateUserRoles(['MAHASISWA', 'DOSEN']), /tidak boleh digabung/);
    assert.throws(() => validateUserRoles(['MAHASISWA', 'ADMIN']), /tidak boleh digabung/);
    assert.throws(() => validateUserRoles(['MAHASISWA', 'ADMIN', 'DOSEN']), /tidak boleh digabung/);
  });

  test('Role: Mahasiswa tunggal diizinkan', () => {
    assert.strictEqual(validateUserRoles(['MAHASISWA']), true);
  });

  test('Status Bimbingan Mahasiswa mencakup Sedang Dalam Bimbingan, Sudah Lulus, dan Tidak Selesai', () => {
    assert.deepStrictEqual(VALID_SUPERVISION_STATUSES, [
      'DALAM_BIMBINGAN',
      'LULUS',
      'TIDAK_SELESAI'
    ]);
  });

  test('Upload: Total berkas di bawah 10MB harus lolos', () => {
    const files = [{ size: 2 * 1024 * 1024 }, { size: 5 * 1024 * 1024 }];
    assert.strictEqual(validateFileSize(files), true);
  });

  test('Upload: Total berkas melebihi 10MB harus ditolak', () => {
    const files = [{ size: 6 * 1024 * 1024 }, { size: 5 * 1024 * 1024 }]; // 11MB
    assert.throws(() => validateFileSize(files), /Batas 10MB terlampaui|melebihi batas maksimal 10MB/);
  });

  test('Keamanan Anti-XSS: Tag berbahaya (<script>, onclick, iframe, javascript:) harus dibuang dan tag format aman dipertahankan', () => {
    const dirty = `<h2>Bab 1</h2><script>alert("xss")</script><p onclick="steal()">Teks <strong>penting</strong> dan <a href="javascript:alert(1)" onclick="evil()">JS Link</a> serta <a href="https://ee.ui.ac.id" target="_blank">Tautan Aman</a></p><iframe src="https://evil.com"></iframe><svg onload="alert(1)"></svg>`;
    const clean = sanitizeEditorContent(dirty);

    assert.ok(!clean.includes('<script>'));
    assert.ok(!clean.includes('onclick'));
    assert.ok(!clean.includes('javascript:'));
    assert.ok(!clean.includes('<iframe'));
    assert.ok(!clean.includes('<svg'));
    assert.ok(clean.includes('<h2>Bab 1</h2>'));
    assert.ok(clean.includes('<strong>penting</strong>'));
    assert.ok(clean.includes('<a href="https://ee.ui.ac.id" target="_blank">Tautan Aman</a>'));
  });

  test('Keamanan Plain-Text: Field teks biasa tidak boleh menyimpan tag HTML atau script', () => {
    const dirtyName = `Dimas <script>fetch("http://evil.com")</script><img src=x onerror=alert(1)> Pratama`;
    const cleanName = sanitizePlainText(dirtyName);
    assert.strictEqual(cleanName, 'Dimas  Pratama');
  });

  test('Keamanan File Upload (Unit): Blokir ekstensi berbahaya, double extension, payload script/ELF/EXE, dan Path Traversal', () => {
    // 1. Ekstensi berbahaya (.php, .js, .sh, .exe, .html, .svg) harus ditolak
    for (const badFile of ['shell.php', 'payload.js', 'hack.sh', 'trojan.exe', 'xss.html', 'vector.svg']) {
      assert.throws(
        () => validateSafeUploadFiles([{ originalname: badFile, mimetype: 'application/pdf' }], UPLOAD_DIR),
        /Berkas ditolak/
      );
    }

    // 2. Double extension berbahaya (contoh: laporan.php.pdf, script.js.png) harus ditolak
    assert.throws(
      () => validateSafeUploadFiles([{ originalname: 'laporan.php.pdf', mimetype: 'application/pdf' }], UPLOAD_DIR),
      /Ekstensi berbahaya/
    );
    assert.throws(
      () => validateSafeUploadFiles([{ originalname: 'image.js.png', mimetype: 'image/png' }], UPLOAD_DIR),
      /Ekstensi berbahaya/
    );

    // 3. Path traversal pada nama berkas (../../etc/passwd, ..\..\src\server.js, null byte) harus ditolak
    assert.throws(
      () => validateSafeUploadFiles([{ originalname: '../../../etc/passwd.pdf' }], UPLOAD_DIR),
      /Path Traversal/
    );
    assert.throws(
      () => validateSafeUploadFiles([{ originalname: '..\\..\\src\\server.pdf' }], UPLOAD_DIR),
      /Path Traversal/
    );
    assert.throws(
      () => resolveSafeUploadPath('laporan\0.pdf', UPLOAD_DIR),
      /null byte/
    );

    // 4. Isi berkas palsu yang menyisipkan script PHP / HTML XSS / ELF binary di dalam ekstensi .pdf harus ditolak
    assert.throws(
      () =>
        validateSafeUploadFiles(
          [
            {
              originalname: 'dokumen.pdf',
              mimetype: 'application/pdf',
              buffer: Buffer.from('<?php system($_GET["cmd"]); ?>')
            }
          ],
          UPLOAD_DIR
        ),
      /mengandung kode script/
    );

    assert.throws(
      () =>
        validateSafeUploadFiles(
          [
            {
              originalname: 'dokumen.pdf',
              mimetype: 'application/pdf',
              buffer: Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01]) // ELF binary
            }
          ],
          UPLOAD_DIR
        ),
      /binary executable/
    );

    // 5. Berkas PDF akademik yang valid harus lolos dan berada tepat di dalam folder uploads
    const validPdf = {
      originalname: 'Laporan_Kemajuan_Bab_2.pdf',
      mimetype: 'application/pdf',
      buffer: Buffer.from('%PDF-1.4\n% Valid PDF content')
    };
    assert.strictEqual(validateSafeUploadFiles([validPdf], UPLOAD_DIR), true);
    const { targetPath } = resolveSafeUploadPath(validPdf.originalname, UPLOAD_DIR);
    assert.ok(targetPath.startsWith(UPLOAD_DIR + path.sep));
  });

  test('Autentikasi: Hash password dan verifikasi token berjalan akurat', () => {
    const hash = hashPassword('simta123');
    assert.strictEqual(verifyPassword('simta123', hash), true);
    assert.strictEqual(verifyPassword('salah123', hash), false);

    const token = createToken({ id: '123', roles: ['ADMIN', 'DOSEN'] });
    const decoded = verifyToken(token);
    assert.deepStrictEqual(decoded.roles, ['ADMIN', 'DOSEN']);
  });
});

describe('Sistem Informasi Tugas Akhir - End-to-End API, PostgreSQL & Cybersecurity Tests', () => {
  let pgHandle;
  let httpServer;
  let baseUrl;
  let adminToken;
  let mahasiswaToken;
  let tempUserId;

  before(async () => {
    pgHandle = await startPostgresServer({ keepPoolOpen: true });
    httpServer = http.createServer(app);
    await new Promise((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
    const { port } = httpServer.address();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(async () => {
    if (httpServer) {
      await new Promise((resolve) => httpServer.close(resolve));
    }
    await pool.end();
    if (pgHandle) {
      await pgHandle.server.stop();
      await pgHandle.db.close();
    }
  });

  test('Login akun Dual-Role (ADMIN + DOSEN) & Mahasiswa berhasil', async () => {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        identifier: 'budi.santoso@ui.ac.id',
        password: 'simta123'
      })
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    adminToken = data.token;

    const mhsRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        identifier: 'dimas.pratama@ui.ac.id',
        password: 'simta123'
      })
    });
    assert.strictEqual(mhsRes.status, 200);
    const mhsData = await mhsRes.json();
    mahasiswaToken = mhsData.token;
  });

  test('Cybersecurity - Anti-SQL Injection (SQLi): Serangan injeksi SQL pada Login, Filter User, dan Filter Laporan ditolak sepenuhnya', async () => {
    // 1. SQL Injection pada endpoint Login
    const sqliLoginPayloads = [
      "' OR '1'='1' --",
      "admin' --",
      "budi.santoso@ui.ac.id' OR 1=1;--",
      "' UNION SELECT id, nip_or_npm, name, email, password_hash, true, 'APPROVED', NOW() FROM users--"
    ];

    for (const payload of sqliLoginPayloads) {
      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: payload, password: "' OR '1'='1" })
      });
      assert.strictEqual(res.status, 401, `Payload SQLi seharusnya ditolak: ${payload}`);
    }

    // 2. SQL Injection pada parameter UUID (?mahasiswa_id= & ?dosen_pembimbing_id=)
    const sqliReportRes = await fetch(
      `${baseUrl}/api/reports?mahasiswa_id=${encodeURIComponent("1' OR '1'='1'; DROP TABLE users;--")}`,
      { headers: { Authorization: `Bearer ${adminToken}` } }
    );
    assert.strictEqual(sqliReportRes.status, 400);

    const sqliUserRes = await fetch(
      `${baseUrl}/api/users?dosen_pembimbing_id=${encodeURIComponent("1' UNION SELECT * FROM users--")}`,
      { headers: { Authorization: `Bearer ${adminToken}` } }
    );
    assert.strictEqual(sqliUserRes.status, 400);

    // 3. Pastikan tabel users tetap utuh
    const checkUsers = await fetch(`${baseUrl}/api/users`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(checkUsers.status, 200);
    const usersList = await checkUsers.json();
    assert.ok(usersList.length >= 6);
  });

  test('Cybersecurity - Anti-Malicious Upload & Path Traversal (HTTP Multipart): Menolak upload script berbahaya dan akses di luar folder uploads', async () => {
    // 1. Mahasiswa mencoba mengunggah file script berbahaya (.php / .js)
    const badForm = new FormData();
    badForm.append('academic_year_id', '2025/2026');
    badForm.append('title', 'Laporan Uji Keamanan Upload');
    badForm.append('report_html', '<p>Isi laporan</p>');
    badForm.append(
      'attachments',
      new Blob(['<?php echo shell_exec($_GET["cmd"]); ?>'], { type: 'application/x-php' }),
      'backdoor.php'
    );

    const badUploadRes = await fetch(`${baseUrl}/api/reports`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${mahasiswaToken}` },
      body: badForm
    });
    assert.strictEqual(badUploadRes.status, 400);
    const badUploadErr = await badUploadRes.json();
    assert.match(badUploadErr.error, /Berkas ditolak|Ekstensi berbahaya/);

    // 2. Mahasiswa mencoba mengunggah file .pdf palsu yang berisi payload <script> XSS
    const fakePdfForm = new FormData();
    fakePdfForm.append('academic_year_id', '2025/2026');
    fakePdfForm.append('title', 'Laporan Fake PDF');
    fakePdfForm.append('report_html', '<p>Isi laporan</p>');
    fakePdfForm.append(
      'attachments',
      new Blob(['<html><script>alert("XSS")</script></html>'], { type: 'application/pdf' }),
      'xss_disguised.pdf'
    );

    const fakePdfRes = await fetch(`${baseUrl}/api/reports`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${mahasiswaToken}` },
      body: fakePdfForm
    });
    assert.strictEqual(fakePdfRes.status, 400);

    // 3. Percobaan Path Traversal membaca file sistem melalui URL /uploads/..%2Fpackage.json
    const traversalRes = await fetch(`${baseUrl}/uploads/..%2Fpackage.json`);
    assert.ok([400, 403, 404].includes(traversalRes.status));
  });

  test('Cybersecurity - Stored XSS Prevention: Input script berbahaya pada laporan dan komentar dibersihkan sebelum masuk database', async () => {
    const form = new FormData();
    form.append('academic_year_id', '2025/2026');
    form.append('title', 'Laporan Bab 2 <script>alert("hacked")</script>');
    form.append(
      'report_html',
      '<h3>Hasil Eksperimen</h3><script>stealCookie()</script><img src="x" onerror="alert(1)" /><p>Data <b>valid</b>.</p>'
    );
    form.append(
      'attachments',
      new Blob(['%PDF-1.4\n% Lampiran Aman'], { type: 'application/pdf' }),
      'Lampiran_Aman.pdf'
    );

    const res = await fetch(`${baseUrl}/api/reports`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${mahasiswaToken}` },
      body: form
    });
    assert.strictEqual(res.status, 201);
    const createdReport = await res.json();

    assert.strictEqual(createdReport.title, 'Laporan Bab 2');
    assert.ok(!createdReport.report_html.includes('<script>'));
    assert.ok(!createdReport.report_html.includes('onerror'));
    assert.ok(createdReport.report_html.includes('<h3>Hasil Eksperimen</h3>'));
    assert.ok(createdReport.report_html.includes('<b>valid</b>'));
  });

  test('Mode Admin: Menampilkan seluruh user lengkap dengan role, tahun ajaran, dan status (Aktif/Tidak Aktif atau Bimbingan/Lulus/Tidak Selesai)', async () => {
    const res = await fetch(`${baseUrl}/api/users`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(res.status, 200);
    const users = await res.json();
    assert.ok(Array.isArray(users));
    assert.ok(users.length >= 6);

    const mhs = users.find((u) => u.nip_or_npm === '2106701234');
    assert.ok(mhs);
    assert.strictEqual(mhs.start_academic_year, '2025/2026');
    assert.strictEqual(mhs.supervision_status, 'DALAM_BIMBINGAN');

    const lulusMhs = users.find((u) => u.nip_or_npm === '2206009912');
    assert.ok(lulusMhs);
    assert.strictEqual(lulusMhs.supervision_status, 'LULUS');

    const inactiveDosen = users.find((u) => u.nip_or_npm === '198607212012121004');
    assert.ok(inactiveDosen);
    assert.strictEqual(inactiveDosen.is_active, false);

    // Uji fitur pencarian nama pengguna / mahasiswa (?search=...)
    const searchRes = await fetch(`${baseUrl}/api/users?search=Dimas`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(searchRes.status, 200);
    const searchList = await searchRes.json();
    assert.strictEqual(searchList.length, 1);
    assert.strictEqual(searchList[0].name, 'Dimas Pratama');
  });

  test('Mode Admin: Tambah, Ubah (Edit), dan Hapus (Delete) akun berjalan akurat', async () => {
    const createRes = await fetch(`${baseUrl}/api/users`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        nip_or_npm: '2406999888',
        name: 'Mahasiswa Uji Coba',
        email: 'uji.coba@ui.ac.id',
        password: 'simta123',
        roles: ['MAHASISWA'],
        degree: 'S2',
        start_academic_year: '2025/2026',
        supervision_status: 'DALAM_BIMBINGAN',
        thesis_title: '<p>Judul <b>Riset Uji</b><script>alert(1)</script></p>'
      })
    });
    assert.strictEqual(createRes.status, 201);
    const created = await createRes.json();
    tempUserId = created.id;

    const editRes = await fetch(`${baseUrl}/api/users/${tempUserId}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        nip_or_npm: '2406999888',
        name: 'Mahasiswa Uji Coba Updated',
        email: 'uji.coba@ui.ac.id',
        roles: ['MAHASISWA'],
        degree: 'S2',
        start_academic_year: '2024/2025',
        supervision_status: 'LULUS',
        thesis_title: '<p>Judul Riset Final</p>'
      })
    });
    assert.strictEqual(editRes.status, 200);

    const delRes = await fetch(`${baseUrl}/api/users/${tempUserId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(delRes.status, 200);
    const delData = await delRes.json();
    assert.strictEqual(delData.deleted, true);
  });

  test('Statistik Spesifik Role (Admin, Dosen, Mahasiswa) & Unduh Progress Excel (.xlsx) lengkap dengan Nama File dan Link Unduhan', async () => {
    const statsRes = await fetch(`${baseUrl}/api/stats`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(statsRes.status, 200);
    const stats = await statsRes.json();
    assert.ok(typeof stats.dosenStats.supervisedStudentsCount === 'number');
    assert.ok(typeof stats.dosenStats.inProgressReportsCount === 'number');
    assert.ok(typeof stats.mahasiswaStats.inProgressReportsCount === 'number');

    const excelRes = await fetch(`${baseUrl}/api/reports/export/excel?token=${encodeURIComponent(adminToken)}`);
    assert.strictEqual(excelRes.status, 200);
    assert.match(
      excelRes.headers.get('content-type') || '',
      /application\/vnd\.openxmlformats-officedocument\.spreadsheetml\.sheet/
    );
    const arrayBuf = await excelRes.arrayBuffer();
    const buf = Buffer.from(arrayBuf);
    assert.strictEqual(buf[0], 0x50);
    assert.strictEqual(buf[1], 0x4b);
    assert.ok(buf.length > 500);
  });

  test('Pendaftaran Akun Mandiri (Self-Registration) membutuhkan Approval Admin sebelum bisa Login & Tercatat pada Activity Log', async () => {
    const regNpm = `2506${Math.floor(100000 + Math.random() * 900000)}`;
    const regEmail = `mhs.${regNpm}@ui.ac.id`;

    const regRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        role: 'MAHASISWA',
        nip_or_npm: regNpm,
        name: 'Mahasiswa Pendaftar Mandiri',
        email: regEmail,
        password: 'simta123',
        degree: 'S1',
        start_academic_year: '2025/2026',
        thesis_title: '<p>Sistem Kendali Cerdas</p>'
      })
    });
    assert.strictEqual(regRes.status, 201);
    const regData = await regRes.json();
    assert.strictEqual(regData.user.is_active, false);
    assert.strictEqual(regData.user.approval_status, 'PENDING');
    const newId = regData.user.id;

    const loginBeforeRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: regEmail, password: 'simta123' })
    });
    assert.strictEqual(loginBeforeRes.status, 403);

    const approveRes = await fetch(`${baseUrl}/api/users/${newId}/approve`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(approveRes.status, 200);
    const approvedData = await approveRes.json();
    assert.strictEqual(approvedData.is_active, true);
    assert.strictEqual(approvedData.approval_status, 'APPROVED');

    const loginAfterRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: regEmail, password: 'simta123' })
    });
    assert.strictEqual(loginAfterRes.status, 200);

    const adminLogsRes = await fetch(`${baseUrl}/api/logs?mode=ADMIN`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(adminLogsRes.status, 200);
    const adminLogs = await adminLogsRes.json();
    assert.ok(adminLogs.some((l) => l.action_type === 'REGISTER'));
    assert.ok(adminLogs.some((l) => l.action_type === 'APPROVE_USER'));
    assert.ok(adminLogs.some((l) => l.action_type === 'LOGIN'));

    await fetch(`${baseUrl}/api/users/${newId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${adminToken}` }
    });
  });
});
