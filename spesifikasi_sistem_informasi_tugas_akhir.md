# Agent Context & Specification: Sistem Informasi Manajemen Tugas Akhir (SIMTA)

Dokumen ini memuat spesifikasi arsitektur, basis data, aturan bisnis *Role-Based Access Control* (RBAC), standar keamanan, serta suite pengujian unit (*test suite*) untuk diuji via `npm test`.

---

## 1. Project Overview & Architecture
Sistem Informasi Manajemen Tugas Akhir memfasilitasi monitoring, asistensi, pelaporan progres, dan manajemen tugas akhir bagi mahasiswa (S1, S2, S3), dosen pembimbing, serta administrator program studi.

### Tech Stack
* **Backend:** Node.js (Express / Fastify)
* **Frontend:** Flutter (Web / Desktop / Mobile)
* **Database:** PostgreSQL
* **Rich Text Component:** HTML Editor / WYSIWYG
* **Visual Theme:** Terinspirasi dari identitas Departemen Teknik Elektro UI ([ee.ui.ac.id](https://ee.ui.ac.id))
  * Navy Blue: `#002B49`
  * UI Makara Yellow: `#F8C300`
  * Surface Neutral: `#F8F9FA`

---

## 2. Role-Based Access Control (RBAC) & Business Rules

### Aturan Penetapan Role
1. **Admin & Dosen:** Satu akun diperbolehkan memiliki role **Admin** dan **Dosen** sekaligus (*Dual-role*).
2. **Mahasiswa:** Role **Mahasiswa** bersifat terisolasi. Pengguna dengan role Mahasiswa **dilarang keras** memiliki role Admin maupun Dosen.

```javascript
// Aturan Validasi Role (Logic Validator)
function validateUserRoles(roles) {
  const hasMahasiswa = roles.includes('MAHASISWA');
  const hasAdminOrDosen = roles.includes('ADMIN') || roles.includes('DOSEN');

  if (hasMahasiswa && hasAdminOrDosen) {
    throw new Error('Role MAHASISWA tidak boleh digabung dengan role ADMIN atau DOSEN.');
  }
  return true;
}
```

---

## 3. Database Schema Blueprint (PostgreSQL)

```sql
-- Role & Degree Enums
CREATE TYPE user_role AS ENUM ('ADMIN', 'DOSEN', 'MAHASISWA');
CREATE TYPE student_degree AS ENUM ('S1', 'S2', 'S3');
CREATE TYPE progress_status AS ENUM ('DRAFT', 'SUBMITTED', 'REVIEWED', 'REVISION_NEEDED', 'APPROVED');

-- Core Tables
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nip_or_npm VARCHAR(32) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role user_role NOT NULL,
    CONSTRAINT unique_user_role UNIQUE (user_id, role)
);

CREATE TABLE mahasiswa_profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    degree student_degree NOT NULL,
    start_academic_year VARCHAR(10) NOT NULL,
    thesis_title TEXT,
    dosen_pembimbing_id UUID REFERENCES users(id)
);

CREATE TABLE progress_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mahasiswa_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    academic_year_id VARCHAR(10) NOT NULL,
    title VARCHAR(255) NOT NULL,
    report_html TEXT NOT NULL,
    status progress_status DEFAULT 'SUBMITTED',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE progress_feedback (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id UUID NOT NULL REFERENCES progress_reports(id) ON DELETE CASCADE,
    dosen_id UUID NOT NULL REFERENCES users(id),
    feedback_html TEXT NOT NULL,
    followup_notes_html TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE progress_attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id UUID NOT NULL REFERENCES progress_reports(id) ON DELETE CASCADE,
    file_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    CONSTRAINT max_attachment_size CHECK (file_size_bytes <= 10485760) -- 10 MB per file
);
```

---

## 4. Keamanan & Sanitasi (Anti-XSS & File Upload)

### Sanitasi HTML (Anti-XSS)
Input dari komponen HTML Editor harus dibersihkan di server Node.js sebelum disimpan ke database:

```javascript
const sanitizeHtml = require('sanitize-html');

function sanitizeEditorContent(dirtyHtml) {
  return sanitizeHtml(dirtyHtml, {
    allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'code', 'pre', 'blockquote'],
    allowedAttributes: {
      'a': ['href', 'target', 'rel']
    },
    disallowedTagsMode: 'discard'
  });
}
```

### Validasi Kuota File (Maksimal 10 MB)
```javascript
function validateFileSize(files, maxBytes = 10 * 1024 * 1024) {
  const totalSize = files.reduce((acc, f) => acc + f.size, 0);
  if (totalSize > maxBytes) {
    throw new Error('Total berkas melebihi batas maksimal 10MB.');
  }
  return true;
}
```

---

## 5. Implementasi & Suite Pengujian (npm test)

Untuk memvalidasi fungsi di mesin lokal Anda:

### File: `package.json`
```json
{
  "name": "simta-backend",
  "version": "1.0.0",
  "scripts": {
    "test": "node --test"
  },
  "dependencies": {
    "sanitize-html": "^2.13.0"
  }
}
```

### File: `test/system.test.js`
```javascript
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

// Import / define logic
function validateUserRoles(roles) {
  const hasMahasiswa = roles.includes('MAHASISWA');
  const hasAdminOrDosen = roles.includes('ADMIN') || roles.includes('DOSEN');
  if (hasMahasiswa && hasAdminOrDosen) {
    throw new Error('Role MAHASISWA tidak boleh digabung dengan role ADMIN atau DOSEN.');
  }
  return true;
}

function validateFileSize(files, maxBytes = 10 * 1024 * 1024) {
  const total = files.reduce((acc, file) => acc + file.size, 0);
  if (total > maxBytes) throw new Error('Batas 10MB terlampaui');
  return true;
}

describe('Sistem Informasi Tugas Akhir - Core Rule Tests', () => {
  test('Role: Admin dan Dosen diizinkan dalam satu akun', () => {
    assert.doesNotThrow(() => validateUserRoles(['ADMIN', 'DOSEN']));
  });

  test('Role: Mahasiswa dilarang bersamaan memiliki role Dosen atau Admin', () => {
    assert.throws(() => validateUserRoles(['MAHASISWA', 'DOSEN']), /tidak boleh digabung/);
    assert.throws(() => validateUserRoles(['MAHASISWA', 'ADMIN']), /tidak boleh digabung/);
  });

  test('Upload: Total berkas di bawah 10MB harus lolos', () => {
    const files = [{ size: 2 * 1024 * 1024 }, { size: 5 * 1024 * 1024 }];
    assert.strictEqual(validateFileSize(files), true);
  });

  test('Upload: Total berkas melebihi 10MB harus ditolak', () => {
    const files = [{ size: 6 * 1024 * 1024 }, { size: 5 * 1024 * 1024 }]; // 11MB
    assert.throws(() => validateFileSize(files), /Batas 10MB terlampaui/);
  });
});
```

---

## 6. Panduan Menjalankan di Server Lokal
1. Simpan dependensi:
   ```bash
   npm install sanitize-html
   ```
2. Jalankan pengujian unit:
   ```bash
   npm test
   ```