const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const db = require('./db');
const {
  VALID_ROLES,
  VALID_DEGREES,
  VALID_STATUSES,
  VALID_SUPERVISION_STATUSES,
  MAX_UPLOAD_BYTES,
  isValidUuid,
  validateUserRoles,
  sanitizeEditorContent,
  sanitizePlainText,
  validateFileSize,
  resolveSafeUploadPath,
  validateSafeUploadFiles
} = require('./utils/validators');
const {
  SESSION_IDLE_TIMEOUT_MS,
  hashPassword,
  verifyPassword,
  createToken,
  verifyToken,
  revokeToken,
  revokeAllUserSessions,
  createCaptchaChallenge,
  verifyCaptchaChallenge
} = require('./utils/auth');
const { generateProgressExcelBuffer } = require('./utils/excel');

const app = express();

// Pastikan direktori uploads tersedia dan terisolasi
const uploadDir = path.resolve(__dirname, '../uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, file, cb) => {
    try {
      resolveSafeUploadPath(file.originalname, uploadDir);
      cb(null, uploadDir);
    } catch (err) {
      cb(err);
    }
  },
  filename: (_req, file, cb) => {
    try {
      const { safeBaseName } = resolveSafeUploadPath(file.originalname, uploadDir);
      cb(null, `${Date.now()}-${safeBaseName}`);
    } catch (err) {
      cb(err);
    }
  }
});

const upload = multer({
  storage,
  fileFilter: (_req, file, cb) => {
    try {
      validateSafeUploadFiles([file], uploadDir);
      cb(null, true);
    } catch (err) {
      cb(err);
    }
  }
});

// Middleware Header Keamanan HTTP (Anti-XSS, Clickjacking, MIME Sniffing & Anti-Session Injection)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');

  // Tolak percobaan injeksi header sesi kustom (Session Fixation / Header Injection)
  if (
    req.headers['x-session-id'] ||
    req.headers['x-forwarded-user'] ||
    req.headers['x-authenticated-user']
  ) {
    return res.status(400).json({
      error: 'Terdeteksi percobaan Session Header Injection yang tidak diizinkan.'
    });
  }
  next();
});

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// Proteksi ketat akses folder /uploads (Anti-Path Traversal & Sandbox CSP)
app.use('/uploads', (req, res, next) => {
  try {
    const requestedFile = decodeURIComponent(req.path || '').replace(/^\/+/, '');
    if (
      !requestedFile ||
      requestedFile.includes('\0') ||
      requestedFile.includes('..') ||
      requestedFile.includes('/') ||
      requestedFile.includes('\\')
    ) {
      return res.status(403).json({ error: 'Akses jalur direktori ditolak.' });
    }
    const resolvedTarget = path.resolve(uploadDir, requestedFile);
    if (!resolvedTarget.startsWith(uploadDir + path.sep)) {
      return res.status(403).json({ error: 'Akses di luar folder uploads dilarang.' });
    }
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
    next();
  } catch {
    return res.status(400).json({ error: 'Permintaan berkas tidak valid.' });
  }
}, express.static(uploadDir));

app.use(express.static(path.join(__dirname, '../public')));

/**
 * Helper pencatat log aktivitas pengguna ke tabel activity_logs
 */
async function recordActivityLog(
  {
    userId = null,
    actorName = 'Sistem',
    actorIdentifier = '-',
    actorRoles = '',
    actionType,
    description,
    targetUserId = null
  },
  queryRunner = db
) {
  try {
    const rolesStr = Array.isArray(actorRoles) ? actorRoles.join(', ') : String(actorRoles || '');
    await queryRunner.query(
      `INSERT INTO activity_logs (user_id, actor_name, actor_identifier, actor_roles, action_type, description, target_user_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        isValidUuid(userId) ? userId : null,
        sanitizePlainText(actorName) || 'Sistem',
        sanitizePlainText(actorIdentifier) || '-',
        sanitizePlainText(rolesStr),
        sanitizePlainText(actionType),
        sanitizePlainText(description),
        isValidUuid(targetUserId) ? targetUserId : null
      ]
    );
  } catch (err) {
    console.error('Gagal mencatat log aktivitas:', err.message);
  }
}

// Middleware autentikasi (mendukung Bearer header maupun query ?token= untuk unduhan berkas)
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  let token = null;
  if (authHeader) {
    if (typeof authHeader !== 'string' || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Format header Authorization tidak valid.' });
    }
    token = authHeader.slice(7).trim();
  } else if (req.query && typeof req.query.token === 'string') {
    token = req.query.token;
  }
  if (!token) {
    return res.status(401).json({ error: 'Token autentikasi tidak ditemukan.' });
  }
  const userAgent = req.headers['user-agent'] || 'default-client';
  const payload = verifyToken(token, { userAgent });
  if (!payload) {
    return res.status(401).json({
      code: 'SESSION_EXPIRED',
      error:
        'Sesi Anda tidak valid atau telah berakhir karena tidak aktif lebih dari 30 menit. Silakan login kembali.'
    });
  }
  res.setHeader('X-Session-Timeout-Minutes', '30');
  req.user = payload;
  req.sessionToken = token;
  next();
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !Array.isArray(req.user.roles)) {
      return res.status(403).json({ error: 'Akses ditolak.' });
    }
    const hasAccess = req.user.roles.some((r) => allowedRoles.includes(r));
    if (!hasAccess) {
      return res.status(403).json({
        error: `Akses ditolak. Membutuhkan salah satu role: ${allowedRoles.join(', ')}`
      });
    }
    next();
  };
}

// Health check & status koneksi PostgreSQL
app.get('/api/health', async (_req, res) => {
  try {
    const result = await db.query('SELECT NOW() AS server_time');
    res.json({
      status: 'ok',
      database: 'connected',
      serverTime: result.rows[0].server_time
    });
  } catch (err) {
    res.status(503).json({
      status: 'error',
      database: 'disconnected',
      error: err.message
    });
  }
});

// Endpoint publik daftar Dosen Pembimbing aktif
app.get('/api/public/dosen', async (_req, res) => {
  try {
    const result = await db.query(
      `SELECT u.id, u.name, u.nip_or_npm
       FROM users u
       JOIN user_roles ur ON ur.user_id = u.id
       WHERE ur.role = 'DOSEN' AND u.is_active = TRUE
       ORDER BY u.name ASC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Endpoint Utilitas Validasi & Sanitasi
app.post('/api/utils/validate-roles', (req, res) => {
  try {
    const { roles } = req.body;
    validateUserRoles(roles);
    res.json({ valid: true, roles });
  } catch (err) {
    res.status(400).json({ valid: false, error: err.message });
  }
});

app.post('/api/utils/sanitize', (req, res) => {
  const { html } = req.body;
  const sanitized = sanitizeEditorContent(html || '');
  res.json({ sanitized });
});

// ==========================================
// AUTHENTICATION, CAPTCHA & SELF-REGISTRATION
// ==========================================

// Endpoint untuk menghasilkan tantangan CAPTCHA Anti-Bot baru (berlaku 5 menit & sekali pakai)
app.get('/api/auth/captcha', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  const challenge = createCaptchaChallenge();
  res.json(challenge);
});

app.post('/api/auth/register', async (req, res) => {
  const {
    nip_or_npm,
    name,
    email,
    password,
    role,
    degree,
    start_academic_year,
    thesis_title,
    dosen_pembimbing_id,
    captcha_id,
    captcha_answer,
    website_url
  } = req.body;

  // Verifikasi CAPTCHA & Honeypot Anti-Bot sebelum memproses pendaftaran akun baru
  const captchaCheck = verifyCaptchaChallenge(captcha_id, captcha_answer, {
    honeypot: website_url
  });
  if (!captchaCheck.valid) {
    return res.status(400).json({
      code: 'CAPTCHA_INVALID',
      error: captchaCheck.error
    });
  }

  const cleanNipNpm = sanitizePlainText(nip_or_npm);
  const cleanName = sanitizePlainText(name);
  const cleanEmail = sanitizePlainText(email);
  const cleanYear = sanitizePlainText(start_academic_year);

  if (!cleanNipNpm || !cleanName || !cleanEmail || !password) {
    return res.status(400).json({ error: 'NIP/NPM, nama lengkap, email, dan password wajib diisi.' });
  }

  if (dosen_pembimbing_id && !isValidUuid(dosen_pembimbing_id)) {
    return res.status(400).json({ error: 'ID Dosen Pembimbing tidak valid.' });
  }

  const selectedRole = role === 'DOSEN' ? 'DOSEN' : 'MAHASISWA';
  const roles = [selectedRole];

  try {
    validateUserRoles(roles);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  if (selectedRole === 'MAHASISWA') {
    if (!degree || !VALID_DEGREES.includes(degree) || !cleanYear) {
      return res.status(400).json({
        error: 'Untuk pendaftaran Mahasiswa, jenjang studi (S1/S2/S3) dan tahun ajaran mulai wajib diisi.'
      });
    }
  }

  const client = await db.getClient();
  try {
    await client.query('BEGIN');
    const passwordHash = hashPassword(password);

    const userInsert = await client.query(
      `INSERT INTO users (nip_or_npm, name, email, password_hash, is_active, approval_status)
       VALUES ($1, $2, $3, $4, FALSE, 'PENDING')
       RETURNING id, nip_or_npm, name, email, is_active, approval_status, created_at`,
      [cleanNipNpm, cleanName, cleanEmail, passwordHash]
    );
    const newUser = userInsert.rows[0];

    await client.query(
      `INSERT INTO user_roles (user_id, role) VALUES ($1, $2)`,
      [newUser.id, selectedRole]
    );

    if (selectedRole === 'MAHASISWA') {
      const cleanThesis = thesis_title ? sanitizeEditorContent(thesis_title) : null;
      await client.query(
        `INSERT INTO mahasiswa_profiles (user_id, degree, start_academic_year, thesis_title, dosen_pembimbing_id, supervision_status)
         VALUES ($1, $2, $3, $4, $5, 'DALAM_BIMBINGAN')`,
        [
          newUser.id,
          degree,
          cleanYear,
          cleanThesis,
          dosen_pembimbing_id || null
        ]
      );
    }

    await recordActivityLog(
      {
        userId: newUser.id,
        actorName: newUser.name,
        actorIdentifier: newUser.nip_or_npm,
        actorRoles: roles,
        actionType: 'REGISTER',
        description: `Pendaftaran akun mandiri baru sebagai ${selectedRole} (${newUser.name} - ${newUser.nip_or_npm}). Menunggu approval Admin.`,
        targetUserId: newUser.id
      },
      client
    );

    await client.query('COMMIT');
    res.status(201).json({
      message: 'Pendaftaran akun berhasil dikirim. Akun Anda menunggu persetujuan (approval) dari Admin sebelum dapat digunakan login.',
      user: {
        ...newUser,
        roles
      }
    });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: `Gagal mendaftarkan akun: ${err.message}` });
  } finally {
    client.release();
  }
});

app.post('/api/auth/login', async (req, res) => {
  // Tolak percobaan Session Fixation / Session Injection melalui body atau query saat login
  if (
    req.body?.sessionId ||
    req.body?.jti ||
    req.body?.token ||
    req.body?.roles ||
    req.query?.sessionId ||
    req.query?.token
  ) {
    return res.status(400).json({
      error: 'Percobaan Session Injection / Session Fixation pada proses login ditolak.'
    });
  }

  const { identifier, password, captcha_id, captcha_answer, website_url } = req.body;
  if (!identifier || !password || typeof identifier !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Email / NIP / NPM dan password wajib diisi.' });
  }

  // Verifikasi CAPTCHA & Honeypot Anti-Bot pada proses Login
  const captchaCheck = verifyCaptchaChallenge(captcha_id, captcha_answer, {
    honeypot: website_url
  });
  if (!captchaCheck.valid) {
    return res.status(400).json({
      code: 'CAPTCHA_INVALID',
      error: captchaCheck.error
    });
  }

  try {
    const userRes = await db.query(
      `SELECT u.*,
              COALESCE(ARRAY_AGG(ur.role::text) FILTER (WHERE ur.role IS NOT NULL), '{}') AS roles,
              mp.degree, mp.start_academic_year, mp.thesis_title, mp.dosen_pembimbing_id,
              mp.supervision_status,
              dp.name AS dosen_pembimbing_name
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN mahasiswa_profiles mp ON mp.user_id = u.id
       LEFT JOIN users dp ON dp.id = mp.dosen_pembimbing_id
       WHERE (LOWER(u.email) = LOWER($1) OR u.nip_or_npm = $1)
       GROUP BY u.id, mp.user_id, dp.name`,
      [identifier.trim()]
    );

    if (userRes.rows.length === 0) {
      return res.status(401).json({ error: 'Kredensial tidak valid.' });
    }

    const user = userRes.rows[0];
    const validPass = verifyPassword(password, user.password_hash);
    if (!validPass) {
      return res.status(401).json({ error: 'Kredensial tidak valid.' });
    }

    if (!user.is_active) {
      if (user.approval_status === 'PENDING') {
        return res.status(403).json({
          error: 'Akun Anda masih menunggu persetujuan (approval) dari Administrator sebelum dapat aktif digunakan.'
        });
      }
      return res.status(403).json({ error: 'Akun pengguna sedang berstatus Tidak Aktif.' });
    }

    validateUserRoles(user.roles);

    const mustChangePassword = Boolean(user.must_change_password);
    const payload = {
      id: user.id,
      nip_or_npm: user.nip_or_npm,
      name: user.name,
      email: user.email,
      roles: user.roles,
      must_change_password: mustChangePassword
    };
    const userAgent = req.headers['user-agent'] || 'default-client';
    const token = createToken(payload, { userAgent, ttlMs: SESSION_IDLE_TIMEOUT_MS });

    await recordActivityLog({
      userId: user.id,
      actorName: user.name,
      actorIdentifier: user.nip_or_npm,
      actorRoles: user.roles,
      actionType: 'LOGIN',
      description: `Pengguna ${user.name} (${user.nip_or_npm}) berhasil login ke aplikasi SIMTA${mustChangePassword ? ' (Wajib ubah password awal)' : ''}.`,
      targetUserId: user.id
    });

    res.json({
      token,
      sessionTimeoutMs: SESSION_IDLE_TIMEOUT_MS,
      user: {
        ...payload,
        is_active: user.is_active,
        approval_status: user.approval_status || 'APPROVED',
        must_change_password: mustChangePassword,
        mahasiswa_profile: user.roles.includes('MAHASISWA')
          ? {
              degree: user.degree,
              start_academic_year: user.start_academic_year,
              thesis_title: user.thesis_title,
              dosen_pembimbing_id: user.dosen_pembimbing_id,
              dosen_pembimbing_name: user.dosen_pembimbing_name,
              supervision_status: user.supervision_status || 'DALAM_BIMBINGAN'
            }
          : null
      }
    });
  } catch (err) {
    res.status(500).json({ error: `Gagal memproses login: ${err.message}` });
  }
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
  revokeToken(req.sessionToken);
  res.json({ loggedOut: true, message: 'Sesi berhasil diakhiri.' });
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const userRes = await db.query(
      `SELECT u.id, u.nip_or_npm, u.name, u.email, u.is_active, u.approval_status,
              COALESCE(u.must_change_password, FALSE) AS must_change_password,
              u.created_at,
              COALESCE(ARRAY_AGG(ur.role::text) FILTER (WHERE ur.role IS NOT NULL), '{}') AS roles,
              mp.degree, mp.start_academic_year, mp.thesis_title, mp.dosen_pembimbing_id,
              mp.supervision_status,
              dp.name AS dosen_pembimbing_name
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN mahasiswa_profiles mp ON mp.user_id = u.id
       LEFT JOIN users dp ON dp.id = mp.dosen_pembimbing_id
       WHERE u.id = $1
       GROUP BY u.id, mp.user_id, dp.name`,
      [req.user.id]
    );
    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: 'Pengguna tidak ditemukan.' });
    }
    const u = userRes.rows[0];
    res.json({
      id: u.id,
      nip_or_npm: u.nip_or_npm,
      name: u.name,
      email: u.email,
      is_active: u.is_active,
      approval_status: u.approval_status || 'APPROVED',
      must_change_password: Boolean(u.must_change_password),
      roles: u.roles,
      mahasiswa_profile: u.roles.includes('MAHASISWA')
        ? {
            degree: u.degree,
            start_academic_year: u.start_academic_year,
            thesis_title: u.thesis_title,
            dosen_pembimbing_id: u.dosen_pembimbing_id,
            dosen_pembimbing_name: u.dosen_pembimbing_name,
            supervision_status: u.supervision_status || 'DALAM_BIMBINGAN'
          }
        : null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Endpoint Edit Profil & Ubah Password Mandiri (Admin, Dosen, Mahasiswa)
// Sekaligus menyelesaikan kewajiban ubah initial/general password bagi Admin
app.put('/api/profile', authenticate, async (req, res) => {
  const {
    nip_or_npm,
    name,
    email,
    current_password,
    new_password,
    degree,
    start_academic_year,
    dosen_pembimbing_id,
    thesis_title
  } = req.body;

  const cleanNipNpm = sanitizePlainText(nip_or_npm);
  const cleanName = sanitizePlainText(name);
  const cleanEmail = sanitizePlainText(email);
  const cleanYear = sanitizePlainText(start_academic_year);

  if (!cleanNipNpm || !cleanName || !cleanEmail) {
    return res.status(400).json({ error: 'NIP/NPM, nama lengkap, dan email wajib diisi.' });
  }

  if (dosen_pembimbing_id && !isValidUuid(dosen_pembimbing_id)) {
    return res.status(400).json({ error: 'ID Dosen Pembimbing tidak valid.' });
  }

  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    const existingRes = await client.query(`SELECT * FROM users WHERE id = $1 FOR UPDATE`, [req.user.id]);
    if (existingRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Akun pengguna tidak ditemukan.' });
    }
    const currentUser = existingRes.rows[0];
    const mustChange = Boolean(currentUser.must_change_password);
    const wantsPasswordChange = typeof new_password === 'string' && new_password.trim().length > 0;

    if (mustChange && !wantsPasswordChange) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'Anda wajib mengubah password awal (initial password) terlebih dahulu sebelum dapat mengoperasikan aplikasi.'
      });
    }

    let updatedPasswordHash = currentUser.password_hash;
    let nextMustChangePassword = mustChange;

    if (wantsPasswordChange) {
      if (!current_password || typeof current_password !== 'string') {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Password saat ini wajib diisi untuk mengubah password.' });
      }
      if (!verifyPassword(current_password, currentUser.password_hash)) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Password saat ini yang Anda masukkan tidak sesuai.' });
      }
      const trimmedNew = new_password.trim();
      if (trimmedNew.length < 6) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Password baru minimal harus terdiri dari 6 karakter.' });
      }
      if (trimmedNew === current_password.trim() || verifyPassword(trimmedNew, currentUser.password_hash)) {
        await client.query('ROLLBACK');
        return res.status(400).json({
          error: 'Password baru tidak boleh sama dengan password awal / password saat ini.'
        });
      }
      updatedPasswordHash = hashPassword(trimmedNew);
      nextMustChangePassword = false;
    }

    await client.query(
      `UPDATE users
       SET nip_or_npm = $2,
           name = $3,
           email = $4,
           password_hash = $5,
           must_change_password = $6
       WHERE id = $1`,
      [req.user.id, cleanNipNpm, cleanName, cleanEmail, updatedPasswordHash, nextMustChangePassword]
    );

    if (req.user.roles.includes('MAHASISWA')) {
      const validDegree = degree && VALID_DEGREES.includes(degree) ? degree : null;
      const cleanThesis =
        thesis_title !== undefined && thesis_title !== null ? sanitizeEditorContent(thesis_title) : null;

      await client.query(
        `UPDATE mahasiswa_profiles
         SET degree = COALESCE($2, degree),
             start_academic_year = COALESCE($3, start_academic_year),
             thesis_title = COALESCE($4, thesis_title),
             dosen_pembimbing_id = CASE WHEN $5::boolean THEN $6::uuid ELSE dosen_pembimbing_id END
         WHERE user_id = $1`,
        [
          req.user.id,
          validDegree,
          cleanYear || null,
          cleanThesis,
          dosen_pembimbing_id !== undefined,
          dosen_pembimbing_id || null
        ]
      );
    }

    await recordActivityLog(
      {
        userId: req.user.id,
        actorName: cleanName,
        actorIdentifier: cleanNipNpm,
        actorRoles: req.user.roles,
        actionType: wantsPasswordChange ? 'CHANGE_PASSWORD' : 'UPDATE_PROFILE',
        description: wantsPasswordChange
          ? `Pengguna ${cleanName} (${cleanNipNpm}) memperbarui profil dan mengubah password akun.`
          : `Pengguna ${cleanName} (${cleanNipNpm}) memperbarui data profil akun.`,
        targetUserId: req.user.id
      },
      client
    );

    await client.query('COMMIT');

    const refreshedRes = await db.query(
      `SELECT u.id, u.nip_or_npm, u.name, u.email, u.is_active, u.approval_status,
              COALESCE(u.must_change_password, FALSE) AS must_change_password,
              COALESCE(ARRAY_AGG(ur.role::text) FILTER (WHERE ur.role IS NOT NULL), '{}') AS roles,
              mp.degree, mp.start_academic_year, mp.thesis_title, mp.dosen_pembimbing_id,
              mp.supervision_status,
              dp.name AS dosen_pembimbing_name
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN mahasiswa_profiles mp ON mp.user_id = u.id
       LEFT JOIN users dp ON dp.id = mp.dosen_pembimbing_id
       WHERE u.id = $1
       GROUP BY u.id, mp.user_id, dp.name`,
      [req.user.id]
    );
    const u = refreshedRes.rows[0];

    const newPayload = {
      id: u.id,
      nip_or_npm: u.nip_or_npm,
      name: u.name,
      email: u.email,
      roles: u.roles,
      must_change_password: Boolean(u.must_change_password)
    };
    const userAgent = req.headers['user-agent'] || 'default-client';
    revokeToken(req.sessionToken);
    const newToken = createToken(newPayload, { userAgent, ttlMs: SESSION_IDLE_TIMEOUT_MS });

    res.json({
      message: wantsPasswordChange
        ? 'Profil dan password berhasil diperbarui.'
        : 'Profil pengguna berhasil diperbarui.',
      token: newToken,
      user: {
        ...newPayload,
        is_active: u.is_active,
        approval_status: u.approval_status || 'APPROVED',
        must_change_password: Boolean(u.must_change_password),
        mahasiswa_profile: u.roles.includes('MAHASISWA')
          ? {
              degree: u.degree,
              start_academic_year: u.start_academic_year,
              thesis_title: u.thesis_title,
              dosen_pembimbing_id: u.dosen_pembimbing_id,
              dosen_pembimbing_name: u.dosen_pembimbing_name,
              supervision_status: u.supervision_status || 'DALAM_BIMBINGAN'
            }
          : null
      }
    });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: `Gagal memperbarui profil: ${err.message}` });
  } finally {
    client.release();
  }
});

// ========================
// STATISTIK DASHBOARD (Per-Role: Admin, Dosen, Mahasiswa)
// ========================
app.get('/api/stats', authenticate, async (req, res) => {
  try {
    const roleCounts = await db.query(
      `SELECT role::text AS role, COUNT(*)::int AS count FROM user_roles GROUP BY role`
    );
    const degreeCounts = await db.query(
      `SELECT degree::text AS degree, COUNT(*)::int AS count FROM mahasiswa_profiles GROUP BY degree`
    );
    const statusCounts = await db.query(
      `SELECT status::text AS status, COUNT(*)::int AS count FROM progress_reports GROUP BY status`
    );
    const supervisionCounts = await db.query(
      `SELECT COALESCE(supervision_status::text, 'DALAM_BIMBINGAN') AS supervision_status, COUNT(*)::int AS count
       FROM mahasiswa_profiles GROUP BY supervision_status`
    );

    const dosenSupervisedRes = await db.query(
      `SELECT COUNT(*)::int AS count FROM mahasiswa_profiles WHERE dosen_pembimbing_id = $1`,
      [req.user.id]
    );
    const dosenInProgressRes = await db.query(
      `SELECT COUNT(*)::int AS count
       FROM progress_reports pr
       JOIN mahasiswa_profiles mp ON mp.user_id = pr.mahasiswa_id
       WHERE mp.dosen_pembimbing_id = $1
         AND pr.status IN ('DRAFT', 'SUBMITTED', 'REVIEWED', 'REVISION_NEEDED')`,
      [req.user.id]
    );

    const mhsInProgressRes = await db.query(
      `SELECT COUNT(*)::int AS count
       FROM progress_reports
       WHERE mahasiswa_id = $1
         AND status IN ('DRAFT', 'SUBMITTED', 'REVIEWED', 'REVISION_NEEDED')`,
      [req.user.id]
    );

    res.json({
      roles: roleCounts.rows,
      degrees: degreeCounts.rows,
      reportStatuses: statusCounts.rows,
      supervisionStatuses: supervisionCounts.rows,
      dosenStats: {
        supervisedStudentsCount: dosenSupervisedRes.rows[0].count,
        inProgressReportsCount: dosenInProgressRes.rows[0].count
      },
      mahasiswaStats: {
        inProgressReportsCount: mhsInProgressRes.rows[0].count
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========================
// ACTIVITY LOGS ENDPOINT
// ========================
app.get('/api/logs', authenticate, requireRole('ADMIN', 'DOSEN'), async (req, res) => {
  const { mode, action_type } = req.query;
  try {
    const params = [];
    const conditions = [];

    const isAdminMode = req.user.roles.includes('ADMIN') && mode !== 'DOSEN';
    if (!isAdminMode) {
      params.push(req.user.id);
      conditions.push(
        `(al.user_id = $${params.length} OR al.user_id IN (SELECT mp.user_id FROM mahasiswa_profiles mp WHERE mp.dosen_pembimbing_id = $${params.length}))`
      );
    }

    if (action_type && typeof action_type === 'string') {
      params.push(sanitizePlainText(action_type));
      conditions.push(`al.action_type = $${params.length}`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const logsRes = await db.query(
      `SELECT al.id,
              al.user_id,
              al.actor_name,
              al.actor_identifier,
              al.actor_roles,
              al.action_type,
              al.description,
              al.target_user_id,
              al.created_at
       FROM activity_logs al
       ${whereClause}
       ORDER BY al.created_at DESC
       LIMIT 200`,
      params
    );

    res.json(logsRes.rows);
  } catch (err) {
    res.status(500).json({ error: `Gagal memuat log aktivitas: ${err.message}` });
  }
});

// ========================
// USER & RBAC MANAGEMENT
// ========================
app.get('/api/users', authenticate, async (req, res) => {
  const { role, degree, dosen_pembimbing_id, supervision_status, approval_status, search } = req.query;
  try {
    const params = [];
    const conditions = [];

    if (role && VALID_ROLES.includes(role)) {
      params.push(role);
      conditions.push(`EXISTS (SELECT 1 FROM user_roles ur2 WHERE ur2.user_id = u.id AND ur2.role = $${params.length})`);
    }

    if (degree && VALID_DEGREES.includes(degree)) {
      params.push(degree);
      conditions.push(`mp.degree = $${params.length}`);
    }

    if (dosen_pembimbing_id) {
      if (!isValidUuid(dosen_pembimbing_id)) {
        return res.status(400).json({ error: 'Parameter dosen_pembimbing_id tidak valid.' });
      }
      params.push(dosen_pembimbing_id);
      conditions.push(`mp.dosen_pembimbing_id = $${params.length}`);
    }

    if (supervision_status && VALID_SUPERVISION_STATUSES.includes(supervision_status)) {
      params.push(supervision_status);
      conditions.push(`mp.supervision_status = $${params.length}`);
    }

    if (approval_status && ['PENDING', 'APPROVED', 'REJECTED'].includes(approval_status)) {
      params.push(approval_status);
      conditions.push(`COALESCE(u.approval_status, 'APPROVED') = $${params.length}`);
    }

    if (search && typeof search === 'string' && search.trim().length > 0) {
      const cleanSearch = `%${sanitizePlainText(search.trim())}%`;
      params.push(cleanSearch);
      conditions.push(
        `(u.name ILIKE $${params.length} OR u.nip_or_npm ILIKE $${params.length} OR u.email ILIKE $${params.length} OR COALESCE(REGEXP_REPLACE(mp.thesis_title, '<[^>]+>', ' ', 'g'), '') ILIKE $${params.length})`
      );
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const result = await db.query(
      `SELECT u.id, u.nip_or_npm, u.name, u.email, u.is_active,
              COALESCE(u.approval_status, 'APPROVED') AS approval_status,
              u.created_at,
              COALESCE(ARRAY_AGG(ur.role::text) FILTER (WHERE ur.role IS NOT NULL), '{}') AS roles,
              mp.degree, mp.start_academic_year, mp.thesis_title, mp.dosen_pembimbing_id,
              COALESCE(mp.supervision_status::text, 'DALAM_BIMBINGAN') AS supervision_status,
              dp.name AS dosen_pembimbing_name,
              (SELECT COUNT(*)::int FROM progress_reports pr WHERE pr.mahasiswa_id = u.id) AS report_count
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN mahasiswa_profiles mp ON mp.user_id = u.id
       LEFT JOIN users dp ON dp.id = mp.dosen_pembimbing_id
       ${whereClause}
       GROUP BY u.id, mp.user_id, dp.name
       ORDER BY (CASE WHEN COALESCE(u.approval_status, 'APPROVED') = 'PENDING' THEN 0 ELSE 1 END), u.created_at DESC`,
      params
    );

    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin menyetujui (approve) pendaftaran akun mandiri
app.post('/api/users/:id/approve', authenticate, requireRole('ADMIN'), async (req, res) => {
  const { id } = req.params;
  if (!isValidUuid(id)) {
    return res.status(400).json({ error: 'ID pengguna tidak valid.' });
  }

  try {
    const result = await db.query(
      `UPDATE users
       SET is_active = TRUE, approval_status = 'APPROVED'
       WHERE id = $1
       RETURNING id, nip_or_npm, name, email, is_active, approval_status`,
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pengguna tidak ditemukan.' });
    }
    const approvedUser = result.rows[0];

    await recordActivityLog({
      userId: req.user.id,
      actorName: req.user.name,
      actorIdentifier: req.user.nip_or_npm,
      actorRoles: req.user.roles,
      actionType: 'APPROVE_USER',
      description: `Admin menyetujui (approve) dan mengaktifkan akun pengguna: ${approvedUser.name} (${approvedUser.nip_or_npm}).`,
      targetUserId: approvedUser.id
    });

    res.json(approvedUser);
  } catch (err) {
    res.status(400).json({ error: `Gagal menyetujui akun: ${err.message}` });
  }
});

// Admin membuat pengguna baru
app.post('/api/users', authenticate, requireRole('ADMIN'), async (req, res) => {
  const {
    nip_or_npm,
    name,
    email,
    password,
    is_active,
    roles,
    degree,
    start_academic_year,
    thesis_title,
    dosen_pembimbing_id,
    supervision_status
  } = req.body;

  const cleanNipNpm = sanitizePlainText(nip_or_npm);
  const cleanName = sanitizePlainText(name);
  const cleanEmail = sanitizePlainText(email);
  const cleanYear = sanitizePlainText(start_academic_year);

  if (!cleanNipNpm || !cleanName || !cleanEmail || !password) {
    return res.status(400).json({ error: 'NIP/NPM, nama, email, dan password wajib diisi.' });
  }

  if (dosen_pembimbing_id && !isValidUuid(dosen_pembimbing_id)) {
    return res.status(400).json({ error: 'ID Dosen Pembimbing tidak valid.' });
  }

  try {
    validateUserRoles(roles);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  if (roles.includes('MAHASISWA')) {
    if (!degree || !VALID_DEGREES.includes(degree) || !cleanYear) {
      return res.status(400).json({
        error: 'Untuk pengguna MAHASISWA, jenjang (S1/S2/S3) dan tahun ajaran mulai wajib diisi.'
      });
    }
  }

  const client = await db.getClient();
  try {
    await client.query('BEGIN');
    const passwordHash = hashPassword(password);
    const activeFlag = typeof is_active === 'boolean' ? is_active : true;

    const userInsert = await client.query(
      `INSERT INTO users (nip_or_npm, name, email, password_hash, is_active, approval_status)
       VALUES ($1, $2, $3, $4, $5, 'APPROVED')
       RETURNING id, nip_or_npm, name, email, is_active, approval_status, created_at`,
      [cleanNipNpm, cleanName, cleanEmail, passwordHash, activeFlag]
    );
    const newUser = userInsert.rows[0];

    const uniqueRoles = [...new Set(roles)];
    for (const r of uniqueRoles) {
      await client.query(
        `INSERT INTO user_roles (user_id, role) VALUES ($1, $2)`,
        [newUser.id, r]
      );
    }

    if (uniqueRoles.includes('MAHASISWA')) {
      const cleanThesis = thesis_title ? sanitizeEditorContent(thesis_title) : null;
      const supStatus = VALID_SUPERVISION_STATUSES.includes(supervision_status)
        ? supervision_status
        : 'DALAM_BIMBINGAN';

      await client.query(
        `INSERT INTO mahasiswa_profiles (user_id, degree, start_academic_year, thesis_title, dosen_pembimbing_id, supervision_status)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          newUser.id,
          degree,
          cleanYear,
          cleanThesis,
          dosen_pembimbing_id || null,
          supStatus
        ]
      );
    }

    await recordActivityLog(
      {
        userId: req.user.id,
        actorName: req.user.name,
        actorIdentifier: req.user.nip_or_npm,
        actorRoles: req.user.roles,
        actionType: 'CREATE_USER',
        description: `Admin membuat akun pengguna baru: ${newUser.name} (${newUser.nip_or_npm}) dengan role [${uniqueRoles.join(', ')}].`,
        targetUserId: newUser.id
      },
      client
    );

    await client.query('COMMIT');
    res.status(201).json({
      ...newUser,
      roles: uniqueRoles
    });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: `Gagal membuat pengguna: ${err.message}` });
  } finally {
    client.release();
  }
});

// Admin mengubah data akun pengguna lengkap
app.put('/api/users/:id', authenticate, requireRole('ADMIN'), async (req, res) => {
  const { id } = req.params;
  if (!isValidUuid(id)) {
    return res.status(400).json({ error: 'ID pengguna tidak valid.' });
  }

  const {
    nip_or_npm,
    name,
    email,
    password,
    is_active,
    roles,
    degree,
    start_academic_year,
    thesis_title,
    dosen_pembimbing_id,
    supervision_status
  } = req.body;

  const cleanNipNpm = sanitizePlainText(nip_or_npm);
  const cleanName = sanitizePlainText(name);
  const cleanEmail = sanitizePlainText(email);
  const cleanYear = sanitizePlainText(start_academic_year || '2025/2026');

  if (!cleanNipNpm || !cleanName || !cleanEmail) {
    return res.status(400).json({ error: 'NIP/NPM, nama, dan email wajib diisi.' });
  }

  if (dosen_pembimbing_id && !isValidUuid(dosen_pembimbing_id)) {
    return res.status(400).json({ error: 'ID Dosen Pembimbing tidak valid.' });
  }

  try {
    validateUserRoles(roles);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    const activeFlag = typeof is_active === 'boolean' ? is_active : true;
    const approvalStatus = activeFlag ? 'APPROVED' : undefined;

    if (password && password.trim().length > 0) {
      const passwordHash = hashPassword(password.trim());
      await client.query(
        `UPDATE users
         SET nip_or_npm = $2, name = $3, email = $4, password_hash = $5, is_active = $6,
             approval_status = COALESCE($7, approval_status)
         WHERE id = $1`,
        [id, cleanNipNpm, cleanName, cleanEmail, passwordHash, activeFlag, approvalStatus || null]
      );
    } else {
      await client.query(
        `UPDATE users
         SET nip_or_npm = $2, name = $3, email = $4, is_active = $5,
             approval_status = COALESCE($6, approval_status)
         WHERE id = $1`,
        [id, cleanNipNpm, cleanName, cleanEmail, activeFlag, approvalStatus || null]
      );
    }

    await client.query(`DELETE FROM user_roles WHERE user_id = $1`, [id]);
    const uniqueRoles = [...new Set(roles)];
    for (const r of uniqueRoles) {
      await client.query(`INSERT INTO user_roles (user_id, role) VALUES ($1, $2)`, [id, r]);
    }

    if (uniqueRoles.includes('MAHASISWA')) {
      const cleanThesis = thesis_title !== undefined ? sanitizeEditorContent(thesis_title || '') : null;
      const supStatus = VALID_SUPERVISION_STATUSES.includes(supervision_status)
        ? supervision_status
        : 'DALAM_BIMBINGAN';
      const validDegree = VALID_DEGREES.includes(degree) ? degree : 'S1';

      await client.query(
        `INSERT INTO mahasiswa_profiles (user_id, degree, start_academic_year, thesis_title, dosen_pembimbing_id, supervision_status)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (user_id) DO UPDATE
         SET degree = EXCLUDED.degree,
             start_academic_year = EXCLUDED.start_academic_year,
             thesis_title = EXCLUDED.thesis_title,
             dosen_pembimbing_id = EXCLUDED.dosen_pembimbing_id,
             supervision_status = EXCLUDED.supervision_status`,
        [
          id,
          validDegree,
          cleanYear,
          cleanThesis,
          dosen_pembimbing_id || null,
          supStatus
        ]
      );
    } else {
      await client.query(`DELETE FROM mahasiswa_profiles WHERE user_id = $1`, [id]);
    }

    await recordActivityLog(
      {
        userId: req.user.id,
        actorName: req.user.name,
        actorIdentifier: req.user.nip_or_npm,
        actorRoles: req.user.roles,
        actionType: 'UPDATE_USER',
        description: `Mengubah data akun pengguna: ${cleanName} (${cleanNipNpm}), Role: [${uniqueRoles.join(', ')}]${uniqueRoles.includes('MAHASISWA') ? `, Status Bimbingan: ${supervision_status || 'DALAM_BIMBINGAN'}` : `, Status Aktif: ${activeFlag ? 'Aktif' : 'Tidak Aktif'}`}.`,
        targetUserId: id
      },
      client
    );

    await client.query('COMMIT');
    if (!activeFlag || (password && password.trim().length > 0)) {
      revokeAllUserSessions(id);
    }
    res.json({ id, nip_or_npm: cleanNipNpm, name: cleanName, email: cleanEmail, is_active: activeFlag, roles: uniqueRoles });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: `Gagal memperbarui akun: ${err.message}` });
  } finally {
    client.release();
  }
});

// Admin menghapus akun pengguna
app.delete('/api/users/:id', authenticate, requireRole('ADMIN'), async (req, res) => {
  const { id } = req.params;
  if (!isValidUuid(id)) {
    return res.status(400).json({ error: 'ID pengguna tidak valid.' });
  }
  if (req.user.id === id) {
    return res.status(400).json({ error: 'Anda tidak dapat menghapus akun yang sedang Anda gunakan.' });
  }

  try {
    await db.query(`UPDATE mahasiswa_profiles SET dosen_pembimbing_id = NULL WHERE dosen_pembimbing_id = $1`, [id]);
    await db.query(`DELETE FROM progress_feedback WHERE dosen_id = $1`, [id]);

    const delRes = await db.query(`DELETE FROM users WHERE id = $1 RETURNING id, name, nip_or_npm`, [id]);
    if (delRes.rows.length === 0) {
      return res.status(404).json({ error: 'Akun pengguna tidak ditemukan.' });
    }
    const deletedUser = delRes.rows[0];
    revokeAllUserSessions(id);

    await recordActivityLog({
      userId: req.user.id,
      actorName: req.user.name,
      actorIdentifier: req.user.nip_or_npm,
      actorRoles: req.user.roles,
      actionType: 'DELETE_USER',
      description: `Admin menghapus akun pengguna: ${deletedUser.name} (${deletedUser.nip_or_npm}).`,
      targetUserId: null
    });

    res.json({ deleted: true, user: deletedUser });
  } catch (err) {
    res.status(400).json({ error: `Gagal menghapus akun: ${err.message}` });
  }
});

app.put('/api/users/:id/roles', authenticate, requireRole('ADMIN'), async (req, res) => {
  const { id } = req.params;
  if (!isValidUuid(id)) {
    return res.status(400).json({ error: 'ID pengguna tidak valid.' });
  }
  const { roles } = req.body;

  try {
    validateUserRoles(roles);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  const client = await db.getClient();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM user_roles WHERE user_id = $1`, [id]);

    const uniqueRoles = [...new Set(roles)];
    for (const r of uniqueRoles) {
      await client.query(
        `INSERT INTO user_roles (user_id, role) VALUES ($1, $2)`,
        [id, r]
      );
    }

    await recordActivityLog(
      {
        userId: req.user.id,
        actorName: req.user.name,
        actorIdentifier: req.user.nip_or_npm,
        actorRoles: req.user.roles,
        actionType: 'UPDATE_USER',
        description: `Mengubah penetapan role pengguna ID ${id} menjadi [${uniqueRoles.join(', ')}].`,
        targetUserId: id
      },
      client
    );

    await client.query('COMMIT');
    res.json({ user_id: id, roles: uniqueRoles });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: err.message });
  } finally {
    client.release();
  }
});

// Update profil & status bimbingan mahasiswa
app.put('/api/mahasiswa/:userId', authenticate, async (req, res) => {
  const { userId } = req.params;
  if (!isValidUuid(userId)) {
    return res.status(400).json({ error: 'ID mahasiswa tidak valid.' });
  }

  const {
    degree,
    start_academic_year,
    thesis_title,
    dosen_pembimbing_id,
    supervision_status
  } = req.body;

  if (dosen_pembimbing_id && !isValidUuid(dosen_pembimbing_id)) {
    return res.status(400).json({ error: 'ID Dosen Pembimbing tidak valid.' });
  }

  const isAdmin = req.user.roles.includes('ADMIN');
  const isDosen = req.user.roles.includes('DOSEN');
  if (!isAdmin && !isDosen && req.user.id !== userId) {
    return res.status(403).json({ error: 'Tidak memiliki izin untuk mengubah profil mahasiswa ini.' });
  }

  try {
    const targetUserRes = await db.query(`SELECT name, nip_or_npm FROM users WHERE id = $1`, [userId]);
    const targetName = targetUserRes.rows[0]
      ? `${targetUserRes.rows[0].name} (${targetUserRes.rows[0].nip_or_npm})`
      : userId;

    if (isAdmin || isDosen) {
      if (degree && !VALID_DEGREES.includes(degree)) {
        return res.status(400).json({ error: 'Jenjang studi harus S1, S2, atau S3.' });
      }
      if (supervision_status && !VALID_SUPERVISION_STATUSES.includes(supervision_status)) {
        return res.status(400).json({ error: 'Status bimbingan tidak valid.' });
      }
      const cleanThesis = thesis_title !== undefined && thesis_title !== null
        ? sanitizeEditorContent(thesis_title)
        : null;
      const cleanYear = start_academic_year ? sanitizePlainText(start_academic_year) : null;

      const result = await db.query(
        `UPDATE mahasiswa_profiles
         SET degree = COALESCE($2, degree),
             start_academic_year = COALESCE($3, start_academic_year),
             thesis_title = COALESCE($4, thesis_title),
             dosen_pembimbing_id = CASE WHEN $5::boolean THEN $6::uuid ELSE dosen_pembimbing_id END,
             supervision_status = COALESCE($7, supervision_status)
         WHERE user_id = $1
         RETURNING *`,
        [
          userId,
          degree || null,
          cleanYear,
          cleanThesis,
          dosen_pembimbing_id !== undefined,
          dosen_pembimbing_id || null,
          supervision_status || null
        ]
      );

      await recordActivityLog({
        userId: req.user.id,
        actorName: req.user.name,
        actorIdentifier: req.user.nip_or_npm,
        actorRoles: req.user.roles,
        actionType: 'UPDATE_MAHASISWA',
        description: `Memperbarui data bimbingan mahasiswa ${targetName}${supervision_status ? ` (Status Bimbingan: ${supervision_status})` : ''}.`,
        targetUserId: userId
      });

      return res.json(result.rows[0]);
    } else {
      const cleanThesis = sanitizeEditorContent(thesis_title || '');
      const result = await db.query(
        `UPDATE mahasiswa_profiles
         SET thesis_title = $2
         WHERE user_id = $1
         RETURNING *`,
        [userId, cleanThesis]
      );

      await recordActivityLog({
        userId: req.user.id,
        actorName: req.user.name,
        actorIdentifier: req.user.nip_or_npm,
        actorRoles: req.user.roles,
        actionType: 'UPDATE_MAHASISWA',
        description: `Mahasiswa ${targetName} memperbarui judul Tugas Akhir.`,
        targetUserId: userId
      });

      return res.json(result.rows[0]);
    }
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ========================
// PROGRESS REPORTS & FEEDBACK
// ========================
app.get('/api/reports/export/excel', authenticate, async (req, res) => {
  const { mahasiswa_id, dosen_pembimbing_id, degree, status, academic_year_id, report_id } = req.query;

  try {
    const params = [];
    const conditions = [];

    if (req.user.roles.includes('MAHASISWA')) {
      params.push(req.user.id);
      conditions.push(`pr.mahasiswa_id = $${params.length}`);
    } else if (mahasiswa_id) {
      if (!isValidUuid(mahasiswa_id)) {
        return res.status(400).json({ error: 'Parameter mahasiswa_id tidak valid.' });
      }
      params.push(mahasiswa_id);
      conditions.push(`pr.mahasiswa_id = $${params.length}`);
    }

    if (report_id) {
      if (!isValidUuid(report_id)) {
        return res.status(400).json({ error: 'Parameter report_id tidak valid.' });
      }
      params.push(report_id);
      conditions.push(`pr.id = $${params.length}`);
    }

    if (dosen_pembimbing_id) {
      if (!isValidUuid(dosen_pembimbing_id)) {
        return res.status(400).json({ error: 'Parameter dosen_pembimbing_id tidak valid.' });
      }
      params.push(dosen_pembimbing_id);
      conditions.push(`mp.dosen_pembimbing_id = $${params.length}`);
    }

    if (degree && VALID_DEGREES.includes(degree)) {
      params.push(degree);
      conditions.push(`mp.degree = $${params.length}`);
    }

    if (status && VALID_STATUSES.includes(status)) {
      params.push(status);
      conditions.push(`pr.status = $${params.length}`);
    }

    if (academic_year_id) {
      params.push(sanitizePlainText(academic_year_id));
      conditions.push(`pr.academic_year_id = $${params.length}`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const reportsRes = await db.query(
      `SELECT pr.*,
              u.name AS mahasiswa_name,
              u.nip_or_npm AS mahasiswa_npm,
              mp.degree,
              mp.start_academic_year,
              mp.thesis_title,
              mp.dosen_pembimbing_id,
              COALESCE(mp.supervision_status::text, 'DALAM_BIMBINGAN') AS supervision_status,
              dp.name AS dosen_pembimbing_name,
              COALESCE(
                (SELECT json_agg(json_build_object(
                  'id', pa.id,
                  'file_name', pa.file_name,
                  'file_path', pa.file_path,
                  'file_size_bytes', pa.file_size_bytes
                )) FROM progress_attachments pa WHERE pa.report_id = pr.id),
                '[]'::json
              ) AS attachments,
              COALESCE(
                (SELECT json_agg(json_build_object(
                  'id', pf.id,
                  'dosen_id', pf.dosen_id,
                  'dosen_name', du.name,
                  'feedback_html', pf.feedback_html,
                  'followup_notes_html', pf.followup_notes_html,
                  'created_at', pf.created_at
                ) ORDER BY pf.created_at ASC)
                FROM progress_feedback pf
                JOIN users du ON du.id = pf.dosen_id
                WHERE pf.report_id = pr.id),
                '[]'::json
              ) AS feedbacks
       FROM progress_reports pr
       JOIN users u ON u.id = pr.mahasiswa_id
       LEFT JOIN mahasiswa_profiles mp ON mp.user_id = pr.mahasiswa_id
       LEFT JOIN users dp ON dp.id = mp.dosen_pembimbing_id
       ${whereClause}
       ORDER BY pr.created_at DESC`,
      params
    );

    const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
    const host = req.get('host') || 'localhost:3000';
    const baseUrl = `${protocol}://${host}`;

    const excelBuffer = generateProgressExcelBuffer(reportsRes.rows, baseUrl);
    const filename = `Laporan_Progress_SIMTA_${new Date().toISOString().slice(0, 10)}.xlsx`;

    await recordActivityLog({
      userId: req.user.id,
      actorName: req.user.name,
      actorIdentifier: req.user.nip_or_npm,
      actorRoles: req.user.roles,
      actionType: 'EXPORT_EXCEL',
      description: `Mengunduh laporan progress dalam format Excel (${reportsRes.rows.length} laporan).`,
      targetUserId: req.user.id
    });

    res.setHeader(
      'Content-Type',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    );
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(excelBuffer);
  } catch (err) {
    res.status(500).json({ error: `Gagal mengekspor Excel: ${err.message}` });
  }
});

app.get('/api/reports', authenticate, async (req, res) => {
  const { mahasiswa_id, dosen_pembimbing_id, degree, status, academic_year_id, search } = req.query;

  try {
    const params = [];
    const conditions = [];

    if (req.user.roles.includes('MAHASISWA')) {
      params.push(req.user.id);
      conditions.push(`pr.mahasiswa_id = $${params.length}`);
    } else if (mahasiswa_id) {
      if (!isValidUuid(mahasiswa_id)) {
        return res.status(400).json({ error: 'Parameter mahasiswa_id tidak valid.' });
      }
      params.push(mahasiswa_id);
      conditions.push(`pr.mahasiswa_id = $${params.length}`);
    }

    if (dosen_pembimbing_id) {
      if (!isValidUuid(dosen_pembimbing_id)) {
        return res.status(400).json({ error: 'Parameter dosen_pembimbing_id tidak valid.' });
      }
      params.push(dosen_pembimbing_id);
      conditions.push(`mp.dosen_pembimbing_id = $${params.length}`);
    }

    if (degree && VALID_DEGREES.includes(degree)) {
      params.push(degree);
      conditions.push(`mp.degree = $${params.length}`);
    }

    if (status && VALID_STATUSES.includes(status)) {
      params.push(status);
      conditions.push(`pr.status = $${params.length}`);
    }

    if (academic_year_id) {
      params.push(sanitizePlainText(academic_year_id));
      conditions.push(`pr.academic_year_id = $${params.length}`);
    }

    if (search && typeof search === 'string' && search.trim().length > 0) {
      const cleanSearch = `%${sanitizePlainText(search.trim())}%`;
      params.push(cleanSearch);
      conditions.push(
        `(u.name ILIKE $${params.length} OR u.nip_or_npm ILIKE $${params.length} OR pr.title ILIKE $${params.length} OR COALESCE(REGEXP_REPLACE(mp.thesis_title, '<[^>]+>', ' ', 'g'), '') ILIKE $${params.length})`
      );
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const reportsRes = await db.query(
      `SELECT pr.*,
              u.name AS mahasiswa_name,
              u.nip_or_npm AS mahasiswa_npm,
              mp.degree,
              mp.start_academic_year,
              mp.thesis_title,
              mp.dosen_pembimbing_id,
              COALESCE(mp.supervision_status::text, 'DALAM_BIMBINGAN') AS supervision_status,
              dp.name AS dosen_pembimbing_name,
              COALESCE(
                (SELECT json_agg(json_build_object(
                  'id', pa.id,
                  'file_name', pa.file_name,
                  'file_path', pa.file_path,
                  'file_size_bytes', pa.file_size_bytes
                )) FROM progress_attachments pa WHERE pa.report_id = pr.id),
                '[]'::json
              ) AS attachments,
              COALESCE(
                (SELECT json_agg(json_build_object(
                  'id', pf.id,
                  'dosen_id', pf.dosen_id,
                  'dosen_name', du.name,
                  'feedback_html', pf.feedback_html,
                  'followup_notes_html', pf.followup_notes_html,
                  'created_at', pf.created_at
                ) ORDER BY pf.created_at ASC)
                FROM progress_feedback pf
                JOIN users du ON du.id = pf.dosen_id
                WHERE pf.report_id = pr.id),
                '[]'::json
              ) AS feedbacks
       FROM progress_reports pr
       JOIN users u ON u.id = pr.mahasiswa_id
       LEFT JOIN mahasiswa_profiles mp ON mp.user_id = pr.mahasiswa_id
       LEFT JOIN users dp ON dp.id = mp.dosen_pembimbing_id
       ${whereClause}
       ORDER BY pr.created_at DESC`,
      params
    );

    res.json(reportsRes.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Middleware pembungkus upload multer agar error validasi file dikembalikan sebagai HTTP 400 JSON
function handleReportUpload(req, res, next) {
  upload.array('attachments', 10)(req, res, (err) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    next();
  });
}

app.post(
  '/api/reports',
  authenticate,
  requireRole('MAHASISWA'),
  handleReportUpload,
  async (req, res) => {
    const uploadedFiles = req.files || [];
    const cleanupUploadedFiles = () => {
      for (const f of uploadedFiles) {
        if (f.path && fs.existsSync(f.path)) {
          fs.unlinkSync(f.path);
        }
      }
    };

    try {
      validateFileSize(uploadedFiles, MAX_UPLOAD_BYTES);
      validateSafeUploadFiles(uploadedFiles, uploadDir);
    } catch (err) {
      cleanupUploadedFiles();
      return res.status(400).json({ error: err.message });
    }

    const { academic_year_id, title, report_html, status } = req.body;
    const cleanAcademicYear = sanitizePlainText(academic_year_id);
    const cleanTitle = sanitizePlainText(title);

    if (!cleanAcademicYear || !cleanTitle || !report_html) {
      cleanupUploadedFiles();
      return res.status(400).json({
        error: 'Tahun akademik, judul laporan, dan isi laporan (HTML) wajib diisi.'
      });
    }

    const cleanReportHtml = sanitizeEditorContent(report_html);
    const reportStatus = VALID_STATUSES.includes(status) ? status : 'SUBMITTED';

    const client = await db.getClient();
    try {
      await client.query('BEGIN');

      const reportInsert = await client.query(
        `INSERT INTO progress_reports (mahasiswa_id, academic_year_id, title, report_html, status)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *`,
        [req.user.id, cleanAcademicYear, cleanTitle, cleanReportHtml, reportStatus]
      );
      const report = reportInsert.rows[0];

      const attachments = [];
      for (const f of uploadedFiles) {
        const { safeBaseName } = resolveSafeUploadPath(f.originalname, uploadDir);
        const attRes = await client.query(
          `INSERT INTO progress_attachments (report_id, file_name, file_path, file_size_bytes)
           VALUES ($1, $2, $3, $4)
           RETURNING *`,
          [report.id, safeBaseName, `/uploads/${path.basename(f.filename)}`, f.size]
        );
        attachments.push(attRes.rows[0]);
      }

      await recordActivityLog(
        {
          userId: req.user.id,
          actorName: req.user.name,
          actorIdentifier: req.user.nip_or_npm,
          actorRoles: req.user.roles,
          actionType: 'CREATE_REPORT',
          description: `Mahasiswa memasukkan laporan kemajuan: "${report.title}" (T.A. ${report.academic_year_id}, Status: ${report.status}, ${attachments.length} lampiran).`,
          targetUserId: req.user.id
        },
        client
      );

      await client.query('COMMIT');
      res.status(201).json({
        ...report,
        attachments
      });
    } catch (err) {
      await client.query('ROLLBACK');
      cleanupUploadedFiles();
      res.status(400).json({ error: `Gagal menyimpan laporan progres: ${err.message}` });
    } finally {
      client.release();
    }
  }
);

app.post(
  '/api/reports/:id/feedback',
  authenticate,
  requireRole('DOSEN', 'ADMIN'),
  async (req, res) => {
    const { id } = req.params;
    if (!isValidUuid(id)) {
      return res.status(400).json({ error: 'ID laporan tidak valid.' });
    }
    const { feedback_html, followup_notes_html, status } = req.body;

    if (!feedback_html) {
      return res.status(400).json({ error: 'Isi komentar / umpan balik (feedback_html) wajib diisi.' });
    }

    const cleanFeedbackHtml = sanitizeEditorContent(feedback_html);
    const cleanFollowupHtml = followup_notes_html
      ? sanitizeEditorContent(followup_notes_html)
      : null;

    const client = await db.getClient();
    try {
      await client.query('BEGIN');

      const repInfoRes = await client.query(
        `SELECT pr.title, pr.mahasiswa_id, u.name AS mahasiswa_name, u.nip_or_npm AS mahasiswa_npm
         FROM progress_reports pr
         JOIN users u ON u.id = pr.mahasiswa_id
         WHERE pr.id = $1`,
        [id]
      );
      const repInfo = repInfoRes.rows[0];

      const feedbackRes = await client.query(
        `INSERT INTO progress_feedback (report_id, dosen_id, feedback_html, followup_notes_html)
         VALUES ($1, $2, $3, $4)
         RETURNING *`,
        [id, req.user.id, cleanFeedbackHtml, cleanFollowupHtml]
      );

      if (status && VALID_STATUSES.includes(status)) {
        await client.query(
          `UPDATE progress_reports SET status = $2 WHERE id = $1`,
          [id, status]
        );
      }

      await recordActivityLog(
        {
          userId: req.user.id,
          actorName: req.user.name,
          actorIdentifier: req.user.nip_or_npm,
          actorRoles: req.user.roles,
          actionType: 'CREATE_FEEDBACK',
          description: `Memasukkan komentar evaluasi pada laporan "${repInfo?.title || id}" milik mahasiswa ${repInfo?.mahasiswa_name || '-'} (${repInfo?.mahasiswa_npm || '-'})${status ? ` serta mengubah status laporan menjadi ${status}` : ''}.`,
          targetUserId: repInfo?.mahasiswa_id || null
        },
        client
      );

      await client.query('COMMIT');
      res.status(201).json(feedbackRes.rows[0]);
    } catch (err) {
      await client.query('ROLLBACK');
      res.status(400).json({ error: `Gagal menyimpan feedback: ${err.message}` });
    } finally {
      client.release();
    }
  }
);

app.put(
  '/api/reports/:id/status',
  authenticate,
  requireRole('DOSEN', 'ADMIN'),
  async (req, res) => {
    const { id } = req.params;
    if (!isValidUuid(id)) {
      return res.status(400).json({ error: 'ID laporan tidak valid.' });
    }
    const { status } = req.body;

    if (!status || !VALID_STATUSES.includes(status)) {
      return res.status(400).json({ error: 'Status progres tidak valid.' });
    }

    try {
      const result = await db.query(
        `UPDATE progress_reports SET status = $2 WHERE id = $1 RETURNING *`,
        [id, status]
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Laporan progres tidak ditemukan.' });
      }
      const rep = result.rows[0];

      await recordActivityLog({
        userId: req.user.id,
        actorName: req.user.name,
        actorIdentifier: req.user.nip_or_npm,
        actorRoles: req.user.roles,
        actionType: 'UPDATE_REPORT_STATUS',
        description: `Mengubah status laporan "${rep.title}" menjadi ${status}.`,
        targetUserId: rep.mahasiswa_id
      });

      res.json(rep);
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }
);

module.exports = app;
