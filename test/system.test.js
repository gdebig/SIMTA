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
const {
  SESSION_IDLE_TIMEOUT_MS,
  hashPassword,
  verifyPassword,
  createToken,
  verifyToken,
  revokeToken,
  simulateSessionInactivity,
  createCaptchaChallenge,
  verifyCaptchaChallenge,
  peekCaptchaAnswerForTest
} = require('../src/utils/auth');
const app = require('../src/app');
const { startPostgresServer } = require('../src/db/pg-server');
const { seedDatabase, DEFAULT_ADMIN } = require('../src/db/seed');
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

  test('Keamanan Sesi (Unit): Batas waktu tidak aktif tepat 30 menit & blokir Session Injection / Tampering', () => {
    // 1. Pastikan konstanta timeout sesi adalah 30 menit (1.800.000 ms)
    assert.strictEqual(SESSION_IDLE_TIMEOUT_MS, 30 * 60 * 1000);

    // 2. Sesi yang tidak aktif lebih dari 30 menit otomatis kedaluwarsa dan dihapus
    const token = createToken(
      { id: 'user-mhs-1', roles: ['MAHASISWA'] },
      { userAgent: 'Mozilla/5.0 (X11; Linux x86_64)' }
    );
    assert.ok(verifyToken(token, { userAgent: 'Mozilla/5.0 (X11; Linux x86_64)' }));

    // Simulasikan pengguna tidak aktif selama 30 menit + 1 detik
    simulateSessionInactivity(token, 30 * 60 * 1000 + 1000);
    assert.strictEqual(verifyToken(token, { userAgent: 'Mozilla/5.0 (X11; Linux x86_64)' }), null);

    // 3. Blokir Cross-Client Session Hijacking / Injection (User-Agent berbeda)
    const boundToken = createToken(
      { id: 'user-dosen-1', roles: ['DOSEN'] },
      { userAgent: 'Browser-Asli-Dosen/1.0' }
    );
    assert.strictEqual(
      verifyToken(boundToken, { userAgent: 'Attacker-Injector-Client/9.9' }),
      null
    );

    // 4. Blokir Token Payload Tampering (eskalasi paksa role MAHASISWA -> ADMIN)
    const mhsToken = createToken({ id: 'user-mhs-2', roles: ['MAHASISWA'] });
    const [, validSig] = mhsToken.split('.');
    const forgedPayload = Buffer.from(
      JSON.stringify({ id: 'user-mhs-2', roles: ['ADMIN'], jti: 'fake-jti' })
    ).toString('base64url');
    assert.strictEqual(verifyToken(`${forgedPayload}.${validSig}`), null);

    // 5. Blokir injeksi karakter kontrol / CRLF / Null-Byte pada token
    assert.strictEqual(verifyToken(`${mhsToken}\r\nSet-Cookie: hacked=1`), null);
    assert.strictEqual(verifyToken(`${mhsToken}\0`), null);
  });

  test('Keamanan CAPTCHA & Anti-Bot Honeypot (Unit): Tantangan SVG valid, sekali pakai (Single-Use), dan menolak pengisian Honeypot', () => {
    const ch1 = createCaptchaChallenge();
    assert.ok(ch1.captchaId);
    assert.ok(ch1.imageDataUrl.startsWith('data:image/svg+xml;base64,'));
    const answer1 = peekCaptchaAnswerForTest(ch1.captchaId);
    assert.strictEqual(answer1.length, 5);

    // 1. Jawaban benar diterima (case-insensitive)
    const verifyOk = verifyCaptchaChallenge(ch1.captchaId, answer1.toLowerCase());
    assert.strictEqual(verifyOk.valid, true);

    // 2. Replay attack menggunakan captchaId yang sama harus ditolak karena Single-Use
    const replayAttempt = verifyCaptchaChallenge(ch1.captchaId, answer1);
    assert.strictEqual(replayAttempt.valid, false);

    // 3. Pengisian field Honeypot oleh bot otomatis ditolak meskipun kode CAPTCHA benar
    const ch2 = createCaptchaChallenge();
    const answer2 = peekCaptchaAnswerForTest(ch2.captchaId);
    const botAttempt = verifyCaptchaChallenge(ch2.captchaId, answer2, {
      honeypot: 'http://spam-bot.example.com'
    });
    assert.strictEqual(botAttempt.valid, false);
    assert.match(botAttempt.error, /bot/i);
  });
});

describe('Sistem Informasi Tugas Akhir - End-to-End API, PostgreSQL & Cybersecurity Tests', () => {
  let pgHandle;
  let httpServer;
  let baseUrl;
  let adminToken;
  let mahasiswaToken;
  let tempUserId;

  async function issueTestCaptcha() {
    const res = await fetch(`${baseUrl}/api/auth/captcha`);
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    const answer = peekCaptchaAnswerForTest(data.captchaId);
    return {
      captcha_id: data.captchaId,
      captcha_answer: answer
    };
  }

  before(async () => {
    pgHandle = await startPostgresServer({ port: 0, inMemory: true });
    await seedDatabase({ closePool: false, resetAll: true });
    httpServer = http.createServer(app);
    await new Promise((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
    const { port } = httpServer.address();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(async () => {
    if (httpServer) {
      await new Promise((resolve) => httpServer.close(resolve));
    }
    // Kembalikan database ke kondisi bersih Production (hanya menyisakan akun Admin)
    await seedDatabase({ closePool: false, resetAll: true });
    await pool.end();
    if (pgHandle) {
      await pgHandle.server.stop();
      await pgHandle.db.close();
    }
  });

  test('Login akun Admin utama serta penyiapan akun uji Dual-Role & Mahasiswa berhasil', async () => {
    // 1. Login menggunakan akun Admin utama yang disisakan di database
    const adminCaptcha = await issueTestCaptcha();
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        identifier: DEFAULT_ADMIN.email,
        password: DEFAULT_ADMIN.password,
        ...adminCaptcha
      })
    });
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    adminToken = data.token;

    // 2. Buat akun uji sementara melalui API Admin untuk kebutuhan pengujian E2E
    const createDualRes = await fetch(`${baseUrl}/api/users`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        nip_or_npm: '197805122005011001',
        name: 'Prof. Dr. Ir. Budi Santoso, M.T.',
        email: 'budi.santoso@ui.ac.id',
        password: 'simta123',
        is_active: true,
        roles: ['ADMIN', 'DOSEN']
      })
    });
    assert.strictEqual(createDualRes.status, 201);
    const dualDosen = await createDualRes.json();

    await fetch(`${baseUrl}/api/users`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        nip_or_npm: '198607212012121004',
        name: 'Dr. Ir. Wahyu Nugroho, S.T., M.T.',
        email: 'wahyu.nugroho@ui.ac.id',
        password: 'simta123',
        is_active: false,
        roles: ['DOSEN']
      })
    });

    await fetch(`${baseUrl}/api/users`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        nip_or_npm: '2106701234',
        name: 'Dimas Pratama',
        email: 'dimas.pratama@ui.ac.id',
        password: 'simta123',
        is_active: true,
        roles: ['MAHASISWA'],
        degree: 'S1',
        start_academic_year: '2025/2026',
        supervision_status: 'DALAM_BIMBINGAN',
        dosen_pembimbing_id: dualDosen.id,
        thesis_title: '<p>Desain Sistem Kendali Inverter Tiga Fasa</p>'
      })
    });

    await fetch(`${baseUrl}/api/users`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        nip_or_npm: '2206009912',
        name: 'Ir. Hendra Kusuma, M.T.',
        email: 'hendra.kusuma@ui.ac.id',
        password: 'simta123',
        is_active: true,
        roles: ['MAHASISWA'],
        degree: 'S3',
        start_academic_year: '2023/2024',
        supervision_status: 'LULUS',
        dosen_pembimbing_id: dualDosen.id,
        thesis_title: '<p>Arsitektur Komputasi Neuromorfik</p>'
      })
    });

    const mhsCaptcha = await issueTestCaptcha();
    const mhsRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        identifier: 'dimas.pratama@ui.ac.id',
        password: 'simta123',
        ...mhsCaptcha
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
      const sqliCaptcha = await issueTestCaptcha();
      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identifier: payload,
          password: "' OR '1'='1",
          ...sqliCaptcha
        })
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
    assert.ok(usersList.length >= 5);
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
    assert.ok(users.length >= 5);

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

    // Uji fitur pencarian berdasarkan nama mahasiswa (?search=Dimas) maupun judul tugas akhir (?search=Inverter Tiga Fasa)
    const searchRes = await fetch(`${baseUrl}/api/users?search=Dimas`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(searchRes.status, 200);
    const searchList = await searchRes.json();
    assert.strictEqual(searchList.length, 1);
    assert.strictEqual(searchList[0].name, 'Dimas Pratama');

    const searchThesisRes = await fetch(
      `${baseUrl}/api/users?search=${encodeURIComponent('Inverter Tiga Fasa')}`,
      { headers: { Authorization: `Bearer ${adminToken}` } }
    );
    assert.strictEqual(searchThesisRes.status, 200);
    const searchThesisList = await searchThesisRes.json();
    assert.strictEqual(searchThesisList.length, 1);
    assert.strictEqual(searchThesisList[0].nip_or_npm, '2106701234');

    const searchReportsByThesisRes = await fetch(
      `${baseUrl}/api/reports?search=${encodeURIComponent('Inverter Tiga Fasa')}`,
      { headers: { Authorization: `Bearer ${adminToken}` } }
    );
    assert.strictEqual(searchReportsByThesisRes.status, 200);
    const reportsByThesis = await searchReportsByThesisRes.json();
    assert.ok(reportsByThesis.length >= 1);
    assert.strictEqual(reportsByThesis[0].mahasiswa_npm, '2106701234');
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

    // 0. Bot mencoba mendaftar tanpa CAPTCHA atau mengisi Honeypot harus ditolak
    const botRegRes = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        role: 'MAHASISWA',
        nip_or_npm: regNpm,
        name: 'Bot Spammer',
        email: regEmail,
        password: 'simta123',
        degree: 'S1',
        start_academic_year: '2025/2026',
        website_url: 'http://spam-link.com'
      })
    });
    assert.strictEqual(botRegRes.status, 400);

    // 1. Pendaftar organik dengan CAPTCHA valid
    const regCaptcha = await issueTestCaptcha();
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
        thesis_title: '<p>Sistem Kendali Cerdas</p>',
        ...regCaptcha
      })
    });
    assert.strictEqual(regRes.status, 201);
    const regData = await regRes.json();
    assert.strictEqual(regData.user.is_active, false);
    assert.strictEqual(regData.user.approval_status, 'PENDING');
    const newId = regData.user.id;

    const loginBeforeCaptcha = await issueTestCaptcha();
    const loginBeforeRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: regEmail, password: 'simta123', ...loginBeforeCaptcha })
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

    const loginAfterCaptcha = await issueTestCaptcha();
    const loginAfterRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: regEmail, password: 'simta123', ...loginAfterCaptcha })
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

  test('Cybersecurity - Session Idle Timeout 30 Menit (E2E): Sesi login Admin, Dosen, dan Mahasiswa otomatis habis jika tidak aktif > 30 menit dan menolak submit form', async () => {
    // 1. Login untuk ketiga mode (Admin, Dosen, dan Mahasiswa)
    const capAdmin = await issueTestCaptcha();
    const loginAdmin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'SIMTA-Test-Browser/1.0' },
      body: JSON.stringify({ identifier: DEFAULT_ADMIN.email, password: DEFAULT_ADMIN.password, ...capAdmin })
    });
    assert.strictEqual(loginAdmin.status, 200);
    const adminSession = await loginAdmin.json();
    assert.strictEqual(adminSession.sessionTimeoutMs, 30 * 60 * 1000);

    const capDosen = await issueTestCaptcha();
    const loginDosen = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'SIMTA-Test-Browser/1.0' },
      body: JSON.stringify({ identifier: 'budi.santoso@ui.ac.id', password: 'simta123', ...capDosen })
    });
    assert.strictEqual(loginDosen.status, 200);
    const dosenSession = await loginDosen.json();

    const capMhs = await issueTestCaptcha();
    const loginMhs = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'SIMTA-Test-Browser/1.0' },
      body: JSON.stringify({ identifier: 'dimas.pratama@ui.ac.id', password: 'simta123', ...capMhs })
    });
    assert.strictEqual(loginMhs.status, 200);
    const mhsSession = await loginMhs.json();

    // 2. Simulasikan ketiga sesi tidak aktif selama 31 menit (> 30 menit)
    const thirtyOneMinutesMs = 31 * 60 * 1000;
    assert.strictEqual(simulateSessionInactivity(adminSession.token, thirtyOneMinutesMs), true);
    assert.strictEqual(simulateSessionInactivity(dosenSession.token, thirtyOneMinutesMs), true);
    assert.strictEqual(simulateSessionInactivity(mhsSession.token, thirtyOneMinutesMs), true);

    // 3. Pastikan akses dashboard maupun pengisian form pada ketiga mode langsung ditolak (401 SESSION_EXPIRED)
    const expiredAdminRes = await fetch(`${baseUrl}/api/users`, {
      headers: {
        Authorization: `Bearer ${adminSession.token}`,
        'User-Agent': 'SIMTA-Test-Browser/1.0'
      }
    });
    assert.strictEqual(expiredAdminRes.status, 401);
    const expiredAdminBody = await expiredAdminRes.json();
    assert.strictEqual(expiredAdminBody.code, 'SESSION_EXPIRED');

    const expiredDosenRes = await fetch(`${baseUrl}/api/reports`, {
      headers: {
        Authorization: `Bearer ${dosenSession.token}`,
        'User-Agent': 'SIMTA-Test-Browser/1.0'
      }
    });
    assert.strictEqual(expiredDosenRes.status, 401);

    const expiredMhsForm = new FormData();
    expiredMhsForm.append('academic_year_id', '2025/2026');
    expiredMhsForm.append('title', 'Laporan Setelah Sesi Habis');
    expiredMhsForm.append('report_html', '<p>Isi laporan</p>');
    const expiredMhsRes = await fetch(`${baseUrl}/api/reports`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${mhsSession.token}`,
        'User-Agent': 'SIMTA-Test-Browser/1.0'
      },
      body: expiredMhsForm
    });
    assert.strictEqual(expiredMhsRes.status, 401);
  });

  test('Cybersecurity - Anti-Session Injection & Session Fixation (E2E): Menolak injeksi sesi pada login, header sesi palsu, pembajakan sesi lintas client, dan replay token pasca-logout', async () => {
    // 1. Serangan Session Fixation / Session Injection saat proses Login (menyisipkan sessionId / jti / roles di body)
    const fixationLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        identifier: 'dimas.pratama@ui.ac.id',
        password: 'simta123',
        sessionId: 'attacker-fixed-session-id-999',
        roles: ['ADMIN']
      })
    });
    assert.strictEqual(fixationLoginRes.status, 400);
    const fixationErr = await fixationLoginRes.json();
    assert.match(fixationErr.error, /Session Injection|Session Fixation/);

    // 2. Serangan HTTP Header Session Injection (X-Session-Id / X-Authenticated-User / X-Forwarded-User)
    const headerInjRes = await fetch(`${baseUrl}/api/users`, {
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'X-Session-Id': 'injected-session-12345'
      }
    });
    assert.strictEqual(headerInjRes.status, 400);

    // 3. Serangan Cross-Client Session Hijacking / Injection (menggunakan token curian dari User-Agent berbeda)
    const vicCap = await issueTestCaptcha();
    const victimLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VictimBrowser/120.0'
      },
      body: JSON.stringify({ identifier: 'dimas.pratama@ui.ac.id', password: 'simta123', ...vicCap })
    });
    assert.strictEqual(victimLogin.status, 200);
    const { token: victimToken } = await victimLogin.json();

    const hijackedRes = await fetch(`${baseUrl}/api/auth/me`, {
      headers: {
        Authorization: `Bearer ${victimToken}`,
        'User-Agent': 'curl/8.5.0 AttackerSessionInjector'
      }
    });
    assert.strictEqual(hijackedRes.status, 401);

    // 4. Serangan Session Replay setelah Logout (menyuntikkan kembali token yang sudah logout)
    const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${victimToken}`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VictimBrowser/120.0'
      }
    });
    assert.strictEqual(logoutRes.status, 200);

    const replayAfterLogoutRes = await fetch(`${baseUrl}/api/auth/me`, {
      headers: {
        Authorization: `Bearer ${victimToken}`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VictimBrowser/120.0'
      }
    });
    assert.strictEqual(replayAfterLogoutRes.status, 401);
  });

  test('Wajib Ubah Initial Password Admin saat Pertama Kali Login & Edit Profil/Password untuk Admin, Dosen, dan Mahasiswa', async () => {
    // 1. Saat Admin login pertama kali menggunakan initial password, flag must_change_password bernilai true
    const initCap = await issueTestCaptcha();
    const initLoginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        identifier: DEFAULT_ADMIN.email,
        password: DEFAULT_ADMIN.password,
        ...initCap
      })
    });
    assert.strictEqual(initLoginRes.status, 200);
    const initLoginData = await initLoginRes.json();
    assert.strictEqual(initLoginData.user.must_change_password, true);

    // 2. Percobaan menyimpan profil Admin tanpa mengubah initial password harus ditolak (400)
    const noPassChangeRes = await fetch(`${baseUrl}/api/profile`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${initLoginData.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        nip_or_npm: DEFAULT_ADMIN.nip,
        name: DEFAULT_ADMIN.name,
        email: DEFAULT_ADMIN.email
      })
    });
    assert.strictEqual(noPassChangeRes.status, 400);

    // 3. Percobaan mengganti initial password dengan password yang sama persis harus ditolak (400)
    const samePassRes = await fetch(`${baseUrl}/api/profile`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${initLoginData.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        nip_or_npm: DEFAULT_ADMIN.nip,
        name: DEFAULT_ADMIN.name,
        email: DEFAULT_ADMIN.email,
        current_password: DEFAULT_ADMIN.password,
        new_password: DEFAULT_ADMIN.password
      })
    });
    assert.strictEqual(samePassRes.status, 400);

    // 4. Admin berhasil mengubah initial password ke password baru dan memperbarui profilnya
    const newAdminPass = 'AdminBaru#2026';
    const changeAdminPassRes = await fetch(`${baseUrl}/api/profile`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${initLoginData.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        nip_or_npm: DEFAULT_ADMIN.nip,
        name: 'Administrator Utama DTE UI',
        email: DEFAULT_ADMIN.email,
        current_password: DEFAULT_ADMIN.password,
        new_password: newAdminPass
      })
    });
    assert.strictEqual(changeAdminPassRes.status, 200);
    const updatedAdminData = await changeAdminPassRes.json();
    assert.strictEqual(updatedAdminData.user.must_change_password, false);
    assert.strictEqual(updatedAdminData.user.name, 'Administrator Utama DTE UI');

    // 5. Dosen dan Mahasiswa juga dapat mengedit profil dan password masing-masing melalui PUT /api/profile
    const mhsProfileRes = await fetch(`${baseUrl}/api/profile`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${mahasiswaToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        nip_or_npm: '2106701234',
        name: 'Dimas Pratama, S.T.',
        email: 'dimas.pratama@ui.ac.id',
        degree: 'S1',
        start_academic_year: '2025/2026',
        thesis_title: '<p>Desain Sistem Kendali Inverter Tiga Fasa Generasi Baru</p>',
        current_password: 'simta123',
        new_password: 'mhsBaru123'
      })
    });
    assert.strictEqual(mhsProfileRes.status, 200);
    const mhsProfileData = await mhsProfileRes.json();
    assert.strictEqual(mhsProfileData.user.name, 'Dimas Pratama, S.T.');
    assert.ok(mhsProfileData.user.mahasiswa_profile.thesis_title.includes('Generasi Baru'));
  });
});
