const crypto = require('node:crypto');
const { validateUserRoles } = require('./validators');

/**
 * Batas waktu ketidakaktifan sesi (Idle Session Timeout): 30 Menit
 */
const SESSION_IDLE_TIMEOUT_MS = 30 * 60 * 1000; // 30 menit (1.800.000 ms)

/**
 * Penyimpanan sesi aktif di sisi server (Server-Side Session Store)
 * Mencegah serangan Session Injection, Session Fixation, dan Replay Token setelah Logout/Timeout
 */
const activeSessions = new Map();

/**
 * Hash Fingerprint konteks client (User-Agent) untuk mencegah Session Hijacking / Cross-Client Injection
 */
function computeClientFingerprint(userAgent = '') {
  const normalized = String(userAgent || 'default-client').trim();
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

/**
 * Hash password menggunakan scrypt bawaan Node.js
 * @param {string} password
 * @returns {string}
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derivedKey}`;
}

/**
 * Verifikasi password terhadap hash secara timing-safe
 * @param {string} password
 * @param {string} storedHash
 * @returns {boolean}
 */
function verifyPassword(password, storedHash) {
  if (!storedHash || typeof storedHash !== 'string' || !storedHash.includes(':')) return false;
  const [salt, key] = storedHash.split(':');
  if (!salt || !key) return false;
  const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
  const keyBuf = Buffer.from(key, 'hex');
  const derivedBuf = Buffer.from(derivedKey, 'hex');
  if (keyBuf.length !== derivedBuf.length) return false;
  return crypto.timingSafeEqual(keyBuf, derivedBuf);
}

const SECRET = process.env.AUTH_SECRET || 'simta-dte-ui-secret-key-2026';

/**
 * Buat signed session token berbasis HMAC-SHA256 yang terdaftar di server-side session store
 * dengan batas waktu idle 30 menit dan proteksi Session Injection / Fixation.
 * @param {object} payload
 * @param {object} [options]
 * @param {number} [options.ttlMs]
 * @param {string} [options.userAgent]
 * @returns {string}
 */
function createToken(payload, options = {}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('Payload sesi tidak valid.');
  }

  // Pastikan kombinasi role pada sesi valid (Anti-Role Escalation Injection)
  if (Array.isArray(payload.roles)) {
    validateUserRoles(payload.roles);
  }

  const now = Date.now();
  const ttlMs =
    typeof options.ttlMs === 'number' && Number.isFinite(options.ttlMs)
      ? options.ttlMs
      : SESSION_IDLE_TIMEOUT_MS;

  // Selalu buat ID sesi baru yang acak secara kriptografis (Anti-Session Fixation)
  const jti = crypto.randomUUID();
  const fingerprint = options.userAgent ? computeClientFingerprint(options.userAgent) : null;

  const sessionPayload = {
    id: String(payload.id || ''),
    nip_or_npm: payload.nip_or_npm ? String(payload.nip_or_npm) : undefined,
    name: payload.name ? String(payload.name) : undefined,
    email: payload.email ? String(payload.email) : undefined,
    roles: Array.isArray(payload.roles) ? [...payload.roles] : [],
    jti,
    iat: now,
    exp: now + ttlMs,
    fp: fingerprint
  };

  const data = Buffer.from(JSON.stringify(sessionPayload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', SECRET)
    .update(data)
    .digest('base64url');

  activeSessions.set(jti, {
    jti,
    userId: sessionPayload.id,
    roles: sessionPayload.roles,
    fingerprint,
    ttlMs,
    createdAt: now,
    lastActivityAt: now,
    expiresAt: now + ttlMs,
    revoked: false
  });

  return `${data}.${signature}`;
}

/**
 * Verifikasi token sesi dengan pengecekan:
 * 1. Format & karakter berbahaya (Anti-Header/Cookie CRLF & Null-byte Injection)
 * 2. Timing-safe HMAC-SHA256 signature (Anti-Token Forgery / Tampering)
 * 3. Anti-Prototype Pollution & Validasi RBAC
 * 4. Keberadaan sesi di Server-Side Store (Anti-Session Fixation / Stateless Injection)
 * 5. Batas waktu tidak aktif 30 menit (30-Minute Idle Session Timeout)
 * 6. Kesesuaian Fingerprint Client (Anti-Session Hijacking / Cross-Client Injection)
 */
function verifyToken(token, options = {}) {
  if (!token || typeof token !== 'string') return null;

  // Tolak token terlalu panjang atau mengandung karakter kontrol / CRLF / spasi / null-byte
  if (token.length > 2048 || /[\0\r\n\s]/.test(token)) {
    return null;
  }

  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [data, signature] = parts;
  if (!data || !signature) return null;

  // Validasi hanya karakter base64url yang diizinkan
  if (!/^[A-Za-z0-9_-]+$/.test(data) || !/^[A-Za-z0-9_-]+$/.test(signature)) {
    return null;
  }

  const expectedSig = crypto
    .createHmac('sha256', SECRET)
    .update(data)
    .digest('base64url');

  const sigBuf = Buffer.from(signature, 'utf8');
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return null;
  }

  let decodedJson;
  try {
    decodedJson = Buffer.from(data, 'base64url').toString('utf8');
  } catch {
    return null;
  }

  // Blokir percobaan Prototype Pollution Injection di dalam JSON token
  if (
    decodedJson.includes('__proto__') ||
    decodedJson.includes('constructor') ||
    decodedJson.includes('prototype')
  ) {
    return null;
  }

  let parsed;
  try {
    parsed = JSON.parse(decodedJson);
  } catch {
    return null;
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return null;
  }

  if (!parsed.id || typeof parsed.id !== 'string' || !parsed.jti || typeof parsed.jti !== 'string') {
    return null;
  }

  // Validasi ulang kombinasi role di dalam token
  try {
    validateUserRoles(parsed.roles);
  } catch {
    return null;
  }

  // Cek sesi pada Server-Side Session Store
  const session = activeSessions.get(parsed.jti);
  if (!session || session.revoked) {
    return null;
  }

  // Pastikan identitas dan role pada token identik dengan catatan sesi di server
  if (session.userId !== parsed.id || JSON.stringify(session.roles) !== JSON.stringify(parsed.roles)) {
    return null;
  }

  // Cek kesesuaian fingerprint client jika diaktifkan
  if (session.fingerprint && options.userAgent) {
    const currentFp = computeClientFingerprint(options.userAgent);
    if (session.fingerprint !== currentFp) {
      return null;
    }
  }

  const now = Date.now();
  const idleElapsed = now - session.lastActivityAt;

  // Jika tidak aktif melebihi batas waktu (30 menit) atau melewati waktu kedaluwarsa
  if (
    session.ttlMs <= 0 ||
    idleElapsed > session.ttlMs ||
    now > session.expiresAt ||
    (typeof parsed.exp === 'number' && now > parsed.exp && idleElapsed > session.ttlMs)
  ) {
    activeSessions.delete(parsed.jti);
    return null;
  }

  // Perbarui aktivitas terakhir (Sliding 30-Minute Idle Window)
  if (options.touch !== false) {
    session.lastActivityAt = now;
    session.expiresAt = now + session.ttlMs;
  }

  return parsed;
}

/**
 * Hapus / cabut sesi aktif (digunakan saat Logout atau saat akun dinonaktifkan/dihapus)
 */
function revokeToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return false;
  try {
    const [data] = token.split('.');
    const parsed = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (parsed && parsed.jti && activeSessions.has(parsed.jti)) {
      activeSessions.delete(parsed.jti);
      return true;
    }
  } catch {
    // Abaikan jika token rusak
  }
  return false;
}

/**
 * Cabut seluruh sesi milik user tertentu (misal saat user dihapus atau dinonaktifkan Admin)
 */
function revokeAllUserSessions(userId) {
  for (const [jti, session] of activeSessions.entries()) {
    if (session.userId === String(userId)) {
      activeSessions.delete(jti);
    }
  }
}

/**
 * Helper khusus pengujian untuk mensimulasikan sesi yang sudah tidak aktif selama `idleMs`
 */
function simulateSessionInactivity(token, idleMs = SESSION_IDLE_TIMEOUT_MS + 60000) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return false;
  try {
    const [data] = token.split('.');
    const parsed = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    const session = parsed?.jti ? activeSessions.get(parsed.jti) : null;
    if (!session) return false;
    const pastTime = Date.now() - idleMs;
    session.lastActivityAt = pastTime;
    session.expiresAt = pastTime + session.ttlMs;
    return true;
  } catch {
    return false;
  }
}

module.exports = {
  SESSION_IDLE_TIMEOUT_MS,
  hashPassword,
  verifyPassword,
  createToken,
  verifyToken,
  revokeToken,
  revokeAllUserSessions,
  simulateSessionInactivity
};
