# SIMTA — Sistem Informasi Manajemen Tugas Akhir

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

### 2. Mode Pengguna & Pengaturan Website
- **Pengaturan Website Dinamis (Khusus Mode Admin):**
  - Mengubah **Nama Sistem Informasi** dan **Subtitle / Kepanjangan** yang tampil di bagian *navbar* dan *title* tab peramban secara *real-time*.
  - Mengubah **Logo Header Aplikasi** dengan mengunggah berkas gambar (`*.png`, `*.jpg`, `*.jpeg`, `*.webp`) berukuran proporsional yang menggantikan ikon bawaan di header navbar.
  - Mengubah **Icon Website (*.ico)** dengan mengunggah berkas `*.ico` langsung dari Panel Administrator.
  - Mengubah **Label Footer** serta mengelola konten **Kebijakan Privasi (Privacy Policy)** dan **Penyangkalan (Disclaimer)** melalui *HTML Rich Text Editor*.
  - Tautan klausul **Kebijakan Privasi** dan **Penyangkalan** muncul langsung di samping teks footer dan dapat dibuka oleh siapa saja dalam bentuk modal *popup*.
  - **Proteksi Sanitasi Keamanan Siber Penuh:** Seluruh input form pengaturan disanitasi ketat terhadap injeksi tag skrip / payload berbahaya (Anti-Stored XSS) dan disimpan menggunakan kueri terparameterisasi (Anti-SQL Injection).
  - Seluruh konfigurasi disimpan secara persisten di tabel database `app_settings`.
- **Pengaturan Profil & Password Mandiri (Seluruh Role):**
  - Setiap pengguna (**Admin**, **Dosen**, dan **Mahasiswa**) memiliki menu **👤 Profil & Password** di *navbar* untuk memperbarui profil dan mengganti kata sandi masing-masing.
  - **Wajib Ubah Initial Password Admin:** Saat aplikasi baru diinstal dan Admin login pertama kali menggunakan *initial/general password*, sistem otomatis meminta Admin mengubah *password* awal tersebut sebelum dapat mengoperasikan website.
- **Mode Administrator (`ADMIN`):**
  - Mengelola seluruh akun pengguna (Tambah, Ubah, Hapus, dan Setujui pendaftaran mandiri).
  - Melakukan pencarian berdasarkan **nama mahasiswa/pengguna** maupun **judul tugas akhir**.
  - Memantau status keaktifan Dosen/Admin (`Aktif` / `Tidak Aktif`) serta status bimbingan Mahasiswa (`Sedang Dalam Bimbingan`, `Sudah Lulus`, `Tidak Selesai`).
  - Mengklik nama mahasiswa untuk meninjau riwayat laporan kemajuan, lampiran berkas, dan komentar evaluasi dosen pembimbing.
  - Melihat seluruh **Log Aktivitas** sistem dilengkapi fitur pencarian pengguna dan *pagination* dinamis (5, 10, 25, 50 baris). Log secara otomatis dibersihkan dari frasa instansi/departemen lama.
- **Mode Dosen Pembimbing (`DOSEN`):**
  - Melihat daftar mahasiswa bimbingan beserta tahun ajaran mulai, jenjang studi (`S1`/`S2`/`S3`), judul tugas akhir, dan status bimbingan.
  - **Menambahkan Laporan Kemajuan untuk Satu atau Lebih Mahasiswa Bimbingan:** Dosen dapat memasukkan laporan kemajuan atau catatan evaluasi resmi secara langsung baik untuk satu mahasiswa terpilih maupun sekaligus untuk beberapa mahasiswa bimbingan (fitur batch). Isian laporan sama lengkapnya dengan mode mahasiswa (Tahun Ajaran, Status Pengajuan, Judul Laporan, Editor Rich Text HTML, dan Lampiran Berkas maks. 10 MB).
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
- **Verifikasi CAPTCHA Anti-Bot & Anti-Non-Organic User:**
  - Dilengkapi fitur CAPTCHA visual terdistorsi (SVG dengan derau garis, titik *noise*, dan rotasi huruf) pada **Halaman Login** dan **Pendaftaran Akun Baru**.
  - Kode tantangan bersifat *Single-Use* (sekali pakai langsung dihapus dari memori server) dan memiliki masa aktif kedaluwarsa maksimal 5 menit untuk mencegah *replay attack* atau *brute force*.
  - Dilengkapi mekanisme perangkap *Honeypot field* yang tak terlihat oleh manusia, sehingga jika bot/skrip otomatis mengisi formulir, pendaftaran atau login langsung dibatalkan secara otomatis.
- **Batas Waktu Sesi 30 Menit (*30-Minute Session Idle Timeout*):** Sesi login pada mode Admin, Dosen, dan Mahasiswa maupun sesi pengisian form dibatasi maksimal **30 menit**. Jika pengguna tidak aktif selama lebih dari 30 menit, sesi di sisi server dan *browser* otomatis berakhir, seluruh form dibersihkan, dan pengguna dikembalikan ke halaman login.
- **Anti-Session Injection, Session Fixation & Session Hijacking:**
  - *Server-Side Active Session Registry* dengan ID sesi kriptografis (`jti` UUID) dan verifikasi tanda tangan HMAC-SHA256 secara *timing-safe* (`crypto.timingSafeEqual`).
  - Pemblokiran injeksi atribut sesi pada proses login (`sessionId`, `jti`, `roles`), pemblokiran header sesi palsu (`X-Session-Id`, `X-Authenticated-User`, `X-Forwarded-User`), pengikatan *fingerprint* `User-Agent` (mencegah pembajakan token lintas klien), serta pencabutan sesi instan (*session revocation*) saat *logout* atau saat akun dinonaktifkan/dihapus.
- **Anti-XSS (*Cross-Site Scripting*):** Seluruh konten Rich Text HTML disanitasi di sisi server menggunakan *whitelist* tag aman bawaan (`src/utils/validators.js`), dan *field* teks biasa dibersihkan dari injeksi tag HTML/script.
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

## Prasyarat Aplikasi, Library & Environment

Sebelum menginstal dan menjalankan **SIMTA**, pastikan server atau komputer Anda memenuhi prasyarat lingkungan (*environment*) dan *library* berikut:

### 1. Sistem Operasi & Utilitas Sistem
- **Sistem Operasi:** Linux (Ubuntu 20.04 / 22.04 / 24.04 LTS, Debian 11/12, RHEL/Rocky Linux), macOS, atau Windows.
- **Utilitas Sistem Linux (untuk script deploy otomatis):** `bash`, `curl`, `tar`, `xz-utils` (`xz`), `git`, dan `procps` (`pkill`).
- **Instalasi Utilitas Dasar (Ubuntu/Debian):**
  ```bash
  sudo apt-get update && sudo apt-get install -y curl git xz-utils procps
  ```

### 2. Runtime Environment (Node.js & NPM)
- **Node.js:** Versi **>= 18.0.0** (Sangat direkomendasikan **Node.js v20.x LTS**).
  > **Penting:** Node.js versi lawas (seperti `v10.x` atau `v12.x` bawaan apt Ubuntu lama) **tidak didukung**. Jika server Anda masih menggunakan Node.js versi lama, jalankan script `./deploy-production.sh` (yang akan menginstal Node.js v20.18.0 LTS secara otomatis ke `/usr/local`), atau instal manual dengan perintah:
  > ```bash
  > curl -fsSL https://nodejs.org/dist/v20.18.0/node-v20.18.0-linux-x64.tar.xz -o /tmp/node.tar.xz
  > sudo rm -rf /usr/local/lib/node_modules /usr/local/bin/node /usr/local/bin/npm /usr/local/bin/npx
  > sudo tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1
  > hash -r
  > node -v && npm -v
  > ```
- **NPM:** Versi **>= 9.0.0** (otomatis terinstal bersama bundel Node.js LTS).

### 3. Database Engine (PostgreSQL)
Aplikasi mendukung dua mode operasional database:
- **Opsi A — PostgreSQL Server Eksternal / Native (Direkomendasikan untuk Production):**
  - Mendukung **PostgreSQL versi 12, 13, 14, 15, hingga 16** yang berjalan pada port `5432`.
  - Khusus untuk **PostgreSQL 12 ke bawah** (misalnya bawaan Ubuntu 20.04), pastikan paket `postgresql-contrib` terinstal agar ekstensi `pgcrypto` tersedia:
    ```bash
    sudo apt-get install -y postgresql postgresql-contrib
    sudo -u postgres psql -d simta_db -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
    ```
    *(File [`db/schema.sql`](./db/schema.sql) juga telah dilengkapi fungsi fallback `gen_random_uuid()` otomatis jika ekstensi belum aktif).*
- **Opsi B — Built-in Embedded PostgreSQL 16:**
  - Jika pada port `5432` belum ada layanan PostgreSQL aktif, `src/server.js` secara otomatis menyalakan *embedded PostgreSQL 16 wire-protocol server* yang menyimpan data secara persisten di direktori `./pgdata`.

### 4. Library & Dependencies Node.js (`package.json`)
Seluruh *library* aplikasi diinstal secara otomatis melalui `npm install` atau `npm ci --omit=dev`:

| Nama Library | Versi | Fungsi dalam Aplikasi |
| :--- | :--- | :--- |
| `express` | `^4.19.2` | Framework HTTP REST API, routing, dan *static file server* frontend. |
| `pg` | `^8.12.0` | Driver klien dan *connection pool* PostgreSQL untuk Node.js. |
| `multer` | `^1.4.5-lts.1` | Middleware pemrosesan unggahan lampiran `multipart/form-data` (batas total 10 MB/laporan). |
| `dotenv` | `^16.4.5` | Memuat konfigurasi variabel lingkungan dari file `.env` ke `process.env`. |
| `cors` | `^2.8.5` | Middleware pengaturan kebijakan *Cross-Origin Resource Sharing* (CORS). |
| `@electric-sql/pglite` | `^0.5.15` | Engine PostgreSQL 16 berbasis WebAssembly untuk mode *embedded* & pengujian terisolasi. |
| `@electric-sql/pglite-socket` | `^0.2.18` | Penyedia *wire-protocol socket* TCP untuk *embedded* PostgreSQL. |
| **Modul Bawaan Node.js** | *Built-in* | `crypto` (*scrypt* password hashing & HMAC-SHA256 session token), `zlib` (kompresi generator Excel `.xlsx`), `fs`, `path`, `net`. |

### 5. Variabel Environment (`.env`) yang Dibutuhkan
Aplikasi membaca konfigurasi dari file `.env` di direktori utama proyek:

| Variabel `.env` | Wajib? | Nilai Default | Keterangan |
| :--- | :---: | :--- | :--- |
| `NODE_ENV` | Disarankan | `development` | Mode eksekusi aplikasi (`production` untuk server produksi). |
| `PORT` | Opsional | `3000` | Port HTTP tempat `src/server.js` berjalan. |
| `DATABASE_URL` | Ya (Prod) | `postgresql://postgres:postgres@localhost:5432/simta_db` | URI koneksi lengkap ke database PostgreSQL. |
| `PGHOST` | Opsional | `127.0.0.1` | Host server PostgreSQL. |
| `PGPORT` | Opsional | `5432` | Port TCP server PostgreSQL. |
| `PGUSER` | Opsional | `postgres` | Nama pengguna (*username*) database PostgreSQL. |
| `PGPASSWORD` | Ya (Prod) | `postgres` | Kata sandi database PostgreSQL. |
| `PGDATABASE` | Opsional | `simta_db` | Nama database PostgreSQL untuk aplikasi SIMTA. |
| `AUTH_SECRET` | **Wajib (Prod)** | *Dev fallback* | Kunci rahasia HMAC-SHA256 untuk tanda tangan token sesi (minimal 64 karakter acak). |
| `ADMIN_NIP` | Opsional | `198911032015042002` | NIP akun Administrator awal saat `npm run db:seed` / `npm run db:reset`. |
| `ADMIN_NAME` | Opsional | `Administrator SIMTA DTE UI` | Nama tampilan akun Administrator awal. |
| `ADMIN_EMAIL` | Opsional | `admin.dte@ui.ac.id` | Email login akun Administrator awal. |
| `ADMIN_PASSWORD` | Opsional | `simta123` | *Initial password* akun Administrator awal (wajib diubah saat login pertama). |

---

## Tahap-Tahap Setup & Instalasi di Server Production

### 1. Prasyarat Process Manager & Reverse Proxy (Opsional untuk Production)
- **Process Manager:** `pm2` (`sudo npm install -g pm2`) untuk menjaga proses `src/server.js` tetap berjalan di latar belakang (*daemon*) dan otomatis menyala saat server *reboot*.
- **Web Server / Reverse Proxy:** **Nginx** atau **Caddy** untuk mengarahkan domain kampus dan menangani sertifikat HTTPS/SSL.

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

#### Langkah 4.3 — Inisialisasi Skema Database, Upgrade & Akun Admin
- Jika Anda menggunakan **PostgreSQL Native/Eksternal**, buat database terlebih dahulu (`CREATE DATABASE simta_db;`), lalu jalankan:
  ```bash
  npm run db:init
  npm run db:seed
  ```
- **Petunjuk Upgrade / Alter Database yang Sudah Berjalan:**
  Jika Anda meng-upgrade database dari versi sebelumnya (agar mendukung fitur Pengaturan Website dinamis, klausul legal, dan icon `app_settings` tanpa menghapus data pengguna yang ada):
  ```bash
  # Cara 1: Cukup jalankan kembali inisialisasi skema (aman dan idempotent)
  npm run db:init

  # Cara 2: Atau jalankan script ALTER / CREATE TABLE via psql di server:
  psql -d simta_db -c "
  CREATE TABLE IF NOT EXISTS app_settings (
      id INT PRIMARY KEY DEFAULT 1,
      app_name VARCHAR(255) NOT NULL DEFAULT 'SIMTA',
      app_subtitle VARCHAR(255) NOT NULL DEFAULT 'Sistem Informasi Manajemen Tugas Akhir (S1 • S2 • S3)',
      footer_text TEXT NOT NULL DEFAULT 'Sistem Informasi Manajemen Tugas Akhir (SIMTA)',
      privacy_policy_html TEXT DEFAULT '<h3>Kebijakan Privasi</h3><p>Website SIMTA digunakan secara khusus untuk evaluasi Tugas Akhir.</p>',
      disclaimer_html TEXT DEFAULT '<h3>Penyangkalan</h3><p>Informasi dan dokumen yang diunggah merupakan dokumen akademik resmi.</p>',
      favicon_path VARCHAR(512) DEFAULT NULL,
      logo_path VARCHAR(512) DEFAULT NULL,
      updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT single_row_app_settings CHECK (id = 1)
  );
  ALTER TABLE app_settings ADD COLUMN IF NOT EXISTS logo_path VARCHAR(512) DEFAULT NULL;
  INSERT INTO app_settings (id, app_name, app_subtitle, footer_text)
  VALUES (1, 'SIMTA', 'Sistem Informasi Manajemen Tugas Akhir (S1 • S2 • S3)', 'Sistem Informasi Manajemen Tugas Akhir (SIMTA)')
  ON CONFLICT (id) DO NOTHING;
  "
  ```
- Jika Anda ingin **mengosongkan seluruh isi database** (menghapus semua data lama & berkas di `uploads/`) dan **hanya menyisakan 1 akun Admin**:
  ```bash
  npm run db:reset
  ```

#### Langkah 4.4 — Menjalankan, Menghentikan, dan Merestart Server Aplikasi (`src/server.js`)
- **Menggunakan PM2 (Direkomendasikan untuk Production):**
  ```bash
  npm install -g pm2
  pm2 start ecosystem.config.cjs --env production
  pm2 save
  pm2 startup
  ```
- **Menjalankan Langsung dengan NPM (`src/server.js`):**
  ```bash
  # Mode standar
  npm start

  # Mode Production
  npm run start:prod
  ```
- **Menghentikan Server (`src/server.js`):**
  ```bash
  npm stop
  # atau: npm run stop
  ```
- **Merestart Server (`src/server.js`):**
  ```bash
  # Restart mode standar (otomatis mendeteksi PM2 atau proses node src/server.js)
  npm restart
  # atau: npm run restart

  # Restart mode Production (memuat ulang variabel .env)
  npm run restart:prod
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
| `npm start` | Menjalankan `src/server.js` (beserta PostgreSQL lokal jika port `5432` belum aktif). |
| `npm run start:prod` | Menjalankan `src/server.js` dalam mode `NODE_ENV=production`. |
| `npm stop` / `npm run stop` | Menghentikan proses `src/server.js` yang sedang berjalan (baik via PM2 maupun proses Node.js langsung). |
| `npm restart` / `npm run restart` | Menghentikan dan menjalankan ulang (`restart`) `src/server.js`. |
| `npm run restart:prod` | Merestart `src/server.js` dalam mode `NODE_ENV=production` serta memuat ulang konfigurasi `.env`. |
| `npm run db:init` | Menerapkan skema tabel dan tipe enum dari [`db/schema.sql`](./db/schema.sql) ke PostgreSQL. |
| `npm run db:seed` | Memastikan akun Administrator utama tersedia di database tanpa menghapus data yang ada. |
| `npm run db:reset` | Mengosongkan seluruh tabel database & folder `uploads/`, lalu hanya menyisakan 1 akun Admin. |
| `npm test` | Menjalankan 22 pengujian otomatis (RBAC, Anti-XSS, Anti-SQLi, Session Security, Upload Security, & API E2E). |

---

## Lisensi
Didistribusikan di bawah lisensi **Apache License 2.0**. Lihat file [`LICENSE`](./LICENSE) untuk informasi selengkapnya.

