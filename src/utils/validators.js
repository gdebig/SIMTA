const path = require('node:path');
const fs = require('node:fs');
const sanitizeHtml = require('sanitize-html');

const VALID_ROLES = ['ADMIN', 'DOSEN', 'MAHASISWA'];
const VALID_DEGREES = ['S1', 'S2', 'S3'];
const VALID_STATUSES = ['DRAFT', 'SUBMITTED', 'REVIEWED', 'REVISION_NEEDED', 'APPROVED'];
const VALID_SUPERVISION_STATUSES = ['DALAM_BIMBINGAN', 'LULUS', 'TIDAK_SELESAI'];
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024; // 10 MB

// Daftar ekstensi berkas akademik yang diizinkan
const ALLOWED_FILE_EXTENSIONS = new Set([
  '.pdf',
  '.doc',
  '.docx',
  '.xls',
  '.xlsx',
  '.ppt',
  '.pptx',
  '.txt',
  '.csv',
  '.zip',
  '.png',
  '.jpg',
  '.jpeg'
]);

// Daftar ekstensi berbahaya yang dilarang keras (termasuk pada double-extension)
const FORBIDDEN_EXTENSIONS = new Set([
  '.php', '.phtml', '.php3', '.php4', '.php5', '.phps',
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx',
  '.sh', '.bash', '.zsh', '.csh', '.ksh',
  '.exe', '.msi', '.dll', '.so', '.dylib', '.elf', '.bin',
  '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.wsf', '.scr', '.com',
  '.html', '.htm', '.xhtml', '.svg', '.xml',
  '.py', '.pyc', '.rb', '.pl', '.cgi', '.jar', '.war', '.class',
  '.jsp', '.jspx', '.asp', '.aspx', '.htaccess', '.env'
]);

const ALLOWED_MIME_TYPES = new Set([
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'text/plain',
  'text/csv',
  'application/zip',
  'application/x-zip-compressed',
  'image/png',
  'image/jpeg',
  'application/octet-stream'
]);

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isValidUuid(value) {
  return typeof value === 'string' && UUID_REGEX.test(value.trim());
}

/**
 * Validasi aturan penetapan Role (RBAC):
 * 1. Satu akun diperbolehkan memiliki role ADMIN dan DOSEN sekaligus (Dual-role).
 * 2. Pengguna dengan role MAHASISWA dilarang keras memiliki role ADMIN maupun DOSEN.
 *
 * @param {string[]} roles
 * @returns {boolean}
 */
function validateUserRoles(roles) {
  if (!Array.isArray(roles) || roles.length === 0) {
    throw new Error('Pengguna harus memiliki minimal satu role.');
  }

  for (const role of roles) {
    if (!VALID_ROLES.includes(role)) {
      throw new Error(`Role tidak valid: ${role}`);
    }
  }

  const hasMahasiswa = roles.includes('MAHASISWA');
  const hasAdminOrDosen = roles.includes('ADMIN') || roles.includes('DOSEN');

  if (hasMahasiswa && hasAdminOrDosen) {
    throw new Error('Role MAHASISWA tidak boleh digabung dengan role ADMIN atau DOSEN.');
  }

  return true;
}

/**
 * Sanitasi konten HTML dari WYSIWYG Editor untuk mencegah XSS & Script Injection.
 *
 * @param {string} dirtyHtml
 * @returns {string}
 */
function sanitizeEditorContent(dirtyHtml) {
  if (typeof dirtyHtml !== 'string') {
    return '';
  }
  return sanitizeHtml(dirtyHtml, {
    allowedTags: [
      'b', 'i', 'em', 'strong', 'a', 'p', 'ul', 'ol', 'li',
      'h1', 'h2', 'h3', 'code', 'pre', 'blockquote'
    ],
    allowedAttributes: {
      a: ['href', 'target', 'rel']
    },
    allowedSchemes: ['http', 'https', 'mailto'],
    allowProtocolRelative: false,
    disallowedTagsMode: 'discard'
  });
}

/**
 * Sanitasi field teks biasa (Nama, Judul Laporan, NIP/NPM, Tahun Ajaran)
 * agar tidak dapat disisipi tag HTML atau script berbahaya.
 *
 * @param {string} input
 * @returns {string}
 */
function sanitizePlainText(input) {
  if (typeof input !== 'string') {
    return '';
  }
  const withoutNullBytes = input.replace(/\0/g, '');
  const stripped = sanitizeHtml(withoutNullBytes, {
    allowedTags: [],
    allowedAttributes: {},
    disallowedTagsMode: 'discard'
  });
  return stripped.trim();
}

/**
 * Validasi kuota ukuran berkas lampiran (Maksimal 10 MB).
 *
 * @param {Array<{size: number}>} files
 * @param {number} maxBytes
 * @returns {boolean}
 */
function validateFileSize(files, maxBytes = MAX_UPLOAD_BYTES) {
  if (!Array.isArray(files)) {
    return true;
  }

  for (const f of files) {
    const fileSize = typeof f.size === 'number' ? f.size : f.file_size_bytes || 0;
    if (fileSize > maxBytes) {
      throw new Error('Total berkas melebihi batas maksimal 10MB (Batas 10MB terlampaui).');
    }
  }

  const totalSize = files.reduce((acc, f) => {
    const fileSize = typeof f.size === 'number' ? f.size : f.file_size_bytes || 0;
    return acc + fileSize;
  }, 0);

  if (totalSize > maxBytes) {
    throw new Error('Total berkas melebihi batas maksimal 10MB (Batas 10MB terlampaui).');
  }

  return true;
}

/**
 * Sanitasi nama file lampiran dan cegah serangan Path Traversal / Directory Escape.
 *
 * @param {string} originalName
 * @param {string} uploadDir
 * @returns {{ safeBaseName: string, targetPath: string }}
 */
function resolveSafeUploadPath(originalName, uploadDir) {
  if (!originalName || typeof originalName !== 'string') {
    throw new Error('Nama berkas tidak valid.');
  }
  if (originalName.includes('\0')) {
    throw new Error('Nama berkas mengandung karakter null byte berbahaya.');
  }

  // Ambil hanya basename untuk menggagalkan ../../ atau ..\..\
  const normalizedRaw = originalName.replace(/\\/g, '/');
  const base = path.basename(normalizedRaw);

  if (!base || base === '.' || base === '..') {
    throw new Error('Nama berkas tidak valid atau melanggar batas direktori.');
  }

  // Bersihkan karakter aneh selain huruf, angka, titik, garis bawah, dan strip
  const cleanBase = base
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/\.{2,}/g, '_');

  const resolvedUploadDir = path.resolve(uploadDir);
  const targetPath = path.resolve(resolvedUploadDir, cleanBase);

  // Pastikan targetPath benar-benar berada di dalam resolvedUploadDir
  if (!targetPath.startsWith(resolvedUploadDir + path.sep)) {
    throw new Error('Pelanggaran keamanan jalur direktori (Path Traversal terdeteksi).');
  }

  return {
    safeBaseName: cleanBase,
    targetPath
  };
}

/**
 * Periksa apakah isi awal berkas (magic bytes / signature) mengandung script atau executable berbahaya.
 *
 * @param {Buffer} bufferHead
 * @param {string} ext
 */
function inspectFileContentSignature(bufferHead, ext) {
  if (!Buffer.isBuffer(bufferHead) || bufferHead.length === 0) return;

  // 1. Deteksi binary executable ELF (\x7fELF) atau Windows PE/MZ (MZ)
  if (
    bufferHead.length >= 4 &&
    bufferHead[0] === 0x7f &&
    bufferHead[1] === 0x45 &&
    bufferHead[2] === 0x4c &&
    bufferHead[3] === 0x46
  ) {
    throw new Error('Berkas ditolak: Terdeteksi binary executable Linux (ELF) berbahaya.');
  }

  if (bufferHead.length >= 2 && bufferHead[0] === 0x4d && bufferHead[1] === 0x5a) {
    throw new Error('Berkas ditolak: Terdeteksi binary executable Windows (PE/EXE) berbahaya.');
  }

  // 2. Deteksi script berbahaya di dalam isi berkas (PHP, HTML/XSS, Shell script)
  const textSample = bufferHead.subarray(0, 512).toString('utf8').toLowerCase();
  if (
    textSample.includes('<?php') ||
    textSample.includes('<script') ||
    textSample.includes('javascript:') ||
    textSample.includes('onerror=') ||
    textSample.includes('onload=') ||
    textSample.startsWith('#!/')
  ) {
    throw new Error('Berkas ditolak: Isi berkas mengandung kode script atau payload berbahaya.');
  }

  // 3. Jika ekstensi .pdf namun memiliki tag HTML di awalnya
  if (ext === '.pdf' && (textSample.includes('<!doctype html') || textSample.includes('<html'))) {
    throw new Error('Berkas ditolak: Berkas PDF palsu mengandung dokumen HTML.');
  }
}

/**
 * Validasi keamanan berkas yang diunggah:
 * - Cegah Path Traversal
 * - Tolak ekstensi berbahaya & double extension (misal: malware.php.pdf, xss.js)
 * - Validasi daftar putih (whitelist) ekstensi & MIME type
 * - Periksa signature isi berkas
 *
 * @param {Array<Object>} files
 * @param {string} uploadDir
 * @returns {boolean}
 */
function validateSafeUploadFiles(files, uploadDir) {
  if (!Array.isArray(files) || files.length === 0) {
    return true;
  }

  for (const file of files) {
    const rawName = file.originalname || file.file_name || '';

    // Deteksi upaya path traversal pada originalname
    if (
      rawName.includes('\0') ||
      rawName.includes('../') ||
      rawName.includes('..\\') ||
      rawName.startsWith('/') ||
      rawName.startsWith('\\')
    ) {
      throw new Error('Berkas ditolak: Terdeteksi upaya Path Traversal pada nama berkas.');
    }

    const { safeBaseName } = resolveSafeUploadPath(rawName, uploadDir);
    const lowerName = safeBaseName.toLowerCase();
    const ext = path.extname(lowerName);

    if (!ext) {
      throw new Error('Berkas ditolak: Berkas harus memiliki ekstensi yang jelas.');
    }

    // Cek seluruh segmen titik untuk mencegah double extension berbahaya (contoh: shell.php.pdf, xss.js.png)
    const parts = lowerName.split('.').slice(1);
    for (const part of parts) {
      const dotPart = `.${part}`;
      if (FORBIDDEN_EXTENSIONS.has(dotPart)) {
        throw new Error(`Berkas ditolak: Ekstensi berbahaya (${dotPart}) tidak diizinkan.`);
      }
    }

    if (!ALLOWED_FILE_EXTENSIONS.has(ext)) {
      throw new Error(
        `Berkas ditolak: Ekstensi ${ext} tidak diizinkan. Hanya dokumen akademik (.pdf, .doc, .docx, .xls, .xlsx, .ppt, .pptx, .txt, .csv, .zip, .png, .jpg) yang diperbolehkan.`
      );
    }

    if (file.mimetype && !ALLOWED_MIME_TYPES.has(file.mimetype.toLowerCase())) {
      throw new Error(`Berkas ditolak: Tipe MIME (${file.mimetype}) tidak diizinkan.`);
    }

    // Inspeksi isi berkas jika tersedia di buffer atau di disk
    if (Buffer.isBuffer(file.buffer)) {
      inspectFileContentSignature(file.buffer, ext);
    } else if (file.path && fs.existsSync(file.path)) {
      const fd = fs.openSync(file.path, 'r');
      try {
        const headBuf = Buffer.alloc(512);
        const bytesRead = fs.readSync(fd, headBuf, 0, 512, 0);
        inspectFileContentSignature(headBuf.subarray(0, bytesRead), ext);
      } finally {
        fs.closeSync(fd);
      }
    }
  }

  return true;
}

module.exports = {
  VALID_ROLES,
  VALID_DEGREES,
  VALID_STATUSES,
  VALID_SUPERVISION_STATUSES,
  MAX_UPLOAD_BYTES,
  ALLOWED_FILE_EXTENSIONS,
  FORBIDDEN_EXTENSIONS,
  ALLOWED_MIME_TYPES,
  isValidUuid,
  validateUserRoles,
  sanitizeEditorContent,
  sanitizePlainText,
  validateFileSize,
  resolveSafeUploadPath,
  validateSafeUploadFiles
};
