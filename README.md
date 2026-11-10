# SIMTA — Sistem Informasi Manajemen Tugas Akhir
**Departemen Teknik Elektro, Fakultas Teknik Universitas Indonesia (DTE FTUI)**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.x-339933?logo=node.js)](https://nodejs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql)](https://www.postgresql.org/)

**SIMTA** adalah aplikasi web *full-stack* untuk pengelolaan, pemantauan kemajuan (*progress report*), dan evaluasi bimbingan Tugas Akhir mahasiswa pada jenjang **S1 (Skripsi)**, **S2 (Tesis)**, dan **S3 (Disertasi)**.

---

## Fitur Utama

### 1. Manajemen Peran & Akses (Role-Based Access Control / RBAC)
- **Dual-Role (`ADMIN` + `DOSEN`):** Satu akun dosen dapat sekaligus memiliki hak akses sebagai Administrator dan Dosen Pembimbing dengan fitur *Role Switcher* di *navbar*.
- **Isolasi Role `MAHASISWA`:** Akun mahasiswa diisolasi secara ketat dan tidak dapat digabungkan dengan role `ADMIN` maupun `DOSEN`.
- **Pendaftaran Akun Mandiri (*Self-Registration*) & Approval Admin:** Mahasiswa dan Dosen dapat mendaftarkan akunnya sendiri dari halaman awal. Akun baru berstatus `PENDING` dan baru dapat digunakan login setelah disetujui (*Approve*) oleh Admin.

### 2. Mode Pengguna
- **Pengaturan Profil & Password Mandiri (Seluruh Role):**
  - Setiap pengguna (**Admin**, **Dosen**, dan **Mahasiswa**) memiliki menu **👤 Profil & Password** di *navbar* untuk memperbarui profil dan mengganti kata sandi masing-masing.
  - **Wajib Ubah Initial Password Admin:** Saat aplikasi baru diinstal dan Admin login pertama kali menggunakan *initial/general password*, sistem otomatis meminta Admin mengubah *password* awal tersebut sebelum dapat mengoperasikan website.
- **Mode Administrator (`ADMIN`):**
  - Mengelola seluruh akun pengguna (Tambah, Ubah, Hapus, dan Setujui pendaftaran mandiri).
  - melakukan pencarian berdasarkan **nama mahasiswa/pengguna** maupun **judul tugas akhir**.
  - Memantau status keaktifan Dosen/Admin (`Aktif` / `Tidak Aktif`) serta status bimbingan Mahasiswa (`Sedang Dalam Bimbingan`, `Sudah Lulus`, `Tidak Selesai`).
  - Mengklik nama mahasiswa untuk meninjau riwayat laporan kemajuan, lampiran berkas, dan komentar evaluasi dosen pembimbing.
  - Melihat seluruh **Log Aktivitas** sistem dilengkapi fitur pencarian pengguna dan *pagination* dinamis (5, 10, 25, 50 baris).
- **Mode Dosen Pembimbing (`DOSEN`):**
  - Melihat daftar mahasiswa bimbingan beserta tahun ajaran mulai, jenjang studi (`S1`/`S2`/`S3`), judul tugas akhir, dan status bimbingan.
  - Melakukan pencarian mahasiswa maupun laporan berdasarkan **nama mahasiswa** atau **judul tugas akhir**.
  - Memberikan komentar evaluasi, catatan tindak lanjut (*follow-up notes*), dan memperbarui status laporan (`SUBMITTED`, `REVIEWED`, `APPROVED`).
  - Memantau log aktivitas untuk akunnya sendiri maupun mahasiswa di bawah bimbingannya.
- **Mode Mahasiswa (`MAHASISWA`):**
  - Mengirimkan laporan kemajuan berkala menggunakan **Rich Text HTML Editor (WYSIWYG)**.
  - Mengunggah dokumen pendukung/lampiran hingga **maksimal total 10 MB per laporan**.
  - Melihat umpan balik serta catatan evaluasi dari Dosen Pembimbing.

### 3. Ekspor Laporan ke Microsoft Excel (`.xlsx`)
- Baik **Admin**, **Dosen Pembimbing**, maupun **Mahasiswa** dapat mengunduh rekapitulasi laporan kemajuan dalam format `.xlsx` standar OpenXML.
- Di dalam file Excel, kolom lampiran menampilkan **nama berkas** disertai **tautan aktif (`HYPERLINK`)** untuk mengunduh berkas secara langsung.

### 4. Keamanan Siber (*Cybersecurity Hardening*)
- **Batas Waktu Sesi 30 Menit (*30-Minute Session Idle Timeout*):** Sesi login pada mode Admin, Dosen, dan Mahasiswa maupun sesi pengisian form dibatasi maksimal **30 menit**. Jika pengguna tidak aktif selama lebih dari 30 menit, sesi di sisi server dan *browser* otomatis berakhir, seluruh form dibersihkan, dan pengguna dikembalikan ke halaman login.
- **Anti-Session Injection, Session Fixation & Session Hijacking:**
  - *Server-Side Active Session Registry* dengan ID sesi kriptografis (`jti` UUID) dan verifikasi tanda tangan HMAC-SHA256 secara *timing-safe* (`crypto.timingSafeEqual`).
  - Pemblokiran injeksi atribut sesi pada proses login (`sessionId`, `jti`, `roles`), pemblokiran header sesi palsu (`X-Session-Id`, `X-Authenticated-User`, `X-Forwarded-User`), pengikatan *fingerprint* `User-Agent` (mencegah pembajakan token lintas klien), serta pencabutan sesi instan (*session revocation*) saat *logout* atau saat akun dinonaktifkan/dihapus.
- **Anti-XSS (*Cross-Site Scripting*):** Seluruh konten Rich Text HTML disanitasi di sisi server menggunakan *whitelist* tag aman (`sanitize-html`), dan *field* teks biasa dibersihkan dari injeksi tag HTML/script.
- **Anti-SQL Injection (SQLi):** Seluruh interaksi database menggunakan *parameterized queries* (`$1, $2, ...`) dan validasi format UUID ketat.
- **Keamanan Unggahan Berkas & Anti-Path Traversal:**
  - *Whitelist* ekstensi dokumen akademik (`.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`, `.txt`, `.csv`, `.zip`, `.png`, `.jpg`, `.jpeg`).
  - Pemblokiran *double extension* berbahaya (mis. `file.php.pdf`), inspeksi *magic bytes* / *script signature* (PHP, `<script>`, ELF/PE *binary executable*), penamaan ulang berbasis UUID, serta proteksi direktori `uploads/` dari serangan *path traversal* (`../`) dan eksekusi skrip (`Content-Security-Policy: sandbox`).

---

## Struktur Proyek

```text
SimTA/
├── db/
│   └── schema.sql              # Skema tabel & enum PostgreSQL
├── public/                     # Frontend (HTML5, CSS3 DTE UI Theme, Vanilla JS)
│   ├── css/styles.css
│   ├── js/app.js
│   └── index.html
├── src/
│   ├── db/
│   │   ├── index.js            # Koneksi Pool PostgreSQL (pg)
│   │   ├── init.js             # Inisialisasi skema database
│   │   ├── pg-server.js        # Embedded PostgreSQL 16 wire-protocol server (opsional)
│   │   ├── reset-prod.js       # Script pengosongan database & reset akun Admin
│   │   └── seed.js             # Inisialisasi akun Admin utama
│   ├── utils/
│   │   ├── auth.js             # Scrypt password hashing & HMAC-SHA256 token
│   │   ├── excel.js            # Generator file OpenXML Excel (.xlsx)
│   │   └── validators.js       # Validator RBAC, Anti-XSS, Kuota 10MB & Anti-Path Traversal
│   ├── app.js                  # Express REST API & middleware keamanan
│   └── server.js               # Bootstrapper aplikasi & database
├── test/
│   └── system.test.js          # 18 pengujian otomatis (Unit, API E2E & Cybersecurity)
├── uploads/                    # Direktori penyimpanan berkas lampiran laporan
├── .env.example                # Template variabel lingkungan (Environment Variables)
├── deploy-production.sh        # Script otomatisasi instalasi & startup server production
├── ecosystem.config.cjs        # Konfigurasi process manager PM2 untuk production
└── package.json
```

---

## Kredensial Awal Administrator (Initial Admin Credentials)

Saat database diinisialisasi untuk pertama kali (atau setelah dijalankan `npm run db:reset`), seluruh tabel data sampel dikosongkan dan sistem hanya menyisakan **1 akun Administrator utama** untuk pengelolaan pengguna awal:

| Atribut | Nilai Default | Variabel `.env` (Opsional untuk Kustomisasi) |
| :--- | :--- | :--- |
| **Email Login** | `admin.dte@ui.ac.id` | `ADMIN_EMAIL` |
| **NIP Login** | `198911032015042002` | `ADMIN_NIP` |
| **Nama Akun** | `Administrator SIMTA DTE UI` | `ADMIN_NAME` |
| **Role** | `ADMIN` | — |
| **Password Awal** | `simta123` | `ADMIN_PASSWORD` |

> **Catatan Keamanan Production:**
> Segera ubah nilai `ADMIN_PASSWORD` pada file `.env` sebelum menjalankan `npm run db:seed` / `npm run db:reset`, atau ubah kata sandi akun Admin langsung melalui menu **Ubah** pada **Panel Administrator** setelah berhasil login pertama kali.

---

## Tahap-Tahap Setup & Instalasi di Server Production

### 1. Prasyarat Server (Prerequisites)
- **Sistem Operasi:** Linux (Ubuntu 20.04/22.04/24.04 LTS, Debian, atau RHEL/Rocky Linux).
- **Runtime:** [Node.js](https://nodejs.org/) versi **18.x LTS** atau **20.x LTS** beserta `npm`.
- **Database:**
  - **Opsi A (PostgreSQL Server Eksternal / Native):** PostgreSQL >= 14 yang berjalan pada port `5432`.
  - **Opsi B (Built-in Embedded PostgreSQL):** Jika di server belum terinstal layanan PostgreSQL eksternal, aplikasi secara otomatis menyalakan *embedded PostgreSQL 16 wire-protocol server* yang menyimpan data persisten di folder `./pgdata`.
- **Process Manager (Disarankan):** `pm2` (`npm install -g pm2`) dan web server *reverse proxy* seperti **Nginx** atau **Caddy** untuk HTTPS/SSL.

---

### 2. Clone Repository
```bash
git clone https://github.com/gdebig/SIMTA.git
cd SIMTA
```

---

### 3. Setup Otomatis Menggunakan Script Production (Cara Tercepat)
Proyek ini telah dilengkapi script [`deploy-production.sh`](./deploy-production.sh) yang otomatis memeriksa Node.js, membuat `.env` dengan `AUTH_SECRET` kriptografis acak, menginstal *dependencies* production, menyiapkan database bersih (hanya akun Admin), dan menjalankan aplikasi:

```bash
chmod +x deploy-production.sh

# Untuk instalasi awal atau mengosongkan database & menyisakan akun Admin:
./deploy-production.sh --reset-db

# Untuk update/restart berikutnya tanpa menghapus data yang sudah berjalan:
./deploy-production.sh
```

---

### 4. Setup Manual Langkah demi Langkah (Kustomisasi Penuh)

#### Langkah 4.1 — Konfigurasi File `.env`
Salin template `.env.example` menjadi `.env` dan batasi izin akses file hanya untuk pemilik proses:

```bash
cp .env.example .env
chmod 600 .env
```

Buka file `.env` dan sesuaikan nilainya untuk server production Anda:

```dotenv
NODE_ENV=production
PORT=3000

# Konfigurasi koneksi PostgreSQL
DATABASE_URL=postgresql://postgres:PASSWORD_DB_ANDA@localhost:5432/simta_db
PGHOST=localhost
PGPORT=5432
PGUSER=postgres
PGPASSWORD=PASSWORD_DB_ANDA
PGDATABASE=simta_db

# Kunci rahasia tanda tangan token autentikasi (gunakan string acak minimal 64 karakter)
AUTH_SECRET=ISI_DENGAN_SECRET_ACAK_KRIPTOGRAFIS_YANG_KUAT

# Kredensial Awal Akun Administrator Utama
ADMIN_NIP=198911032015042002
ADMIN_NAME=Administrator SIMTA DTE UI
ADMIN_EMAIL=admin.dte@ui.ac.id
ADMIN_PASSWORD=GANTI_PASSWORD_ADMIN_YANG_KUAT
```

> **Tip Membuat `AUTH_SECRET` Acak:**
> ```bash
> node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
> ```

#### Langkah 4.2 — Instalasi Paket Node.js
```bash
npm ci --omit=dev
```

#### Langkah 4.3 — Inisialisasi Skema Database & Akun Admin
- Jika Anda menggunakan **PostgreSQL Native/Eksternal**, buat database terlebih dahulu (`CREATE DATABASE simta_db;`), lalu jalankan:
  ```bash
  npm run db:init
  npm run db:seed
  ```
- Jika Anda ingin **mengosongkan seluruh isi database** (menghapus semua data lama & berkas di `uploads/`) dan **hanya menyisakan 1 akun Admin**:
  ```bash
  npm run db:reset
  ```

#### Langkah 4.4 — Menjalankan Server Aplikasi
- **Menggunakan PM2 (Direkomendasikan untuk Production):**
  ```bash
  npm install -g pm2
  pm2 start ecosystem.config.cjs --env production
  pm2 save
  pm2 startup
  ```
- **Menjalankan Langsung dengan Node.js:**
  ```bash
  npm run start:prod
  ```

Aplikasi akan aktif dan mendengarkan pada `http://localhost:3000`.

---

### 5. Konfigurasi Reverse Proxy Nginx (Opsional — Disarankan untuk Domain & HTTPS)
Agar aplikasi dapat diakses melalui domain kampus (mis. `https://simta.ee.ui.ac.id`) dan mendukung unggahan lampiran hingga **10 MB**, tambahkan konfigurasi blok `server` berikut pada Nginx (`/etc/nginx/sites-available/simta`):

```nginx
server {
    listen 80;
    server_name simta.ee.ui.ac.id;

    # Izinkan unggahan lampiran laporan hingga 12MB (batas aplikasi: 10MB)
    client_max_body_size 12M;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Aktifkan konfigurasi Nginx dan pasang sertifikat SSL (misalnya dengan Certbot Let's Encrypt):
```bash
sudo ln -s /etc/nginx/sites-available/simta /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d simta.ee.ui.ac.id
```

---

## Perintah NPM yang Tersedia

| Perintah | Deskripsi |
| :--- | :--- |
| `npm start` | Menjalankan server aplikasi SIMTA (beserta PostgreSQL lokal jika port `5432` belum aktif). |
| `npm run start:prod` | Menjalankan server dalam mode `NODE_ENV=production`. |
| `npm run db:init` | Menerapkan skema tabel dan tipe enum dari [`db/schema.sql`](./db/schema.sql) ke PostgreSQL. |
| `npm run db:seed` | Memastikan akun Administrator utama tersedia di database tanpa menghapus data yang ada. |
| `npm run db:reset` | Mengosongkan seluruh tabel database & folder `uploads/`, lalu hanya menyisakan 1 akun Admin. |
| `npm test` | Menjalankan 18 pengujian otomatis (RBAC, Anti-XSS, Anti-SQLi, Upload Security, & API E2E). |

---

## Lisensi
Didistribusikan di bawah lisensi **Apache License 2.0**. Lihat file [`LICENSE`](./LICENSE) untuk informasi selengkapnya.

