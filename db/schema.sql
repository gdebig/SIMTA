-- Sistem Informasi Manajemen Tugas Akhir (SIMTA)
-- PostgreSQL Schema Blueprint

-- Kompatibilitas PostgreSQL <= 12: Aktifkan pgcrypto atau buat fungsi fallback gen_random_uuid()
DO $$ BEGIN
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";
EXCEPTION
    WHEN OTHERS THEN null;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'gen_random_uuid') THEN
        CREATE FUNCTION gen_random_uuid() RETURNS uuid AS $func$
            SELECT (
                substr(h, 1, 8) || '-' ||
                substr(h, 9, 4) || '-4' ||
                substr(h, 14, 3) || '-' ||
                substr('89ab', (get_byte(decode(substr(h, 17, 2), 'hex'), 0) & 3) + 1, 1) ||
                substr(h, 18, 3) || '-' ||
                substr(h, 21, 12)
            )::uuid
            FROM (SELECT md5(random()::text || clock_timestamp()::text) AS h) AS s;
        $func$ LANGUAGE SQL VOLATILE;
    END IF;
END $$;

DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('ADMIN', 'DOSEN', 'MAHASISWA');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE student_degree AS ENUM ('S1', 'S2', 'S3');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE progress_status AS ENUM ('DRAFT', 'SUBMITTED', 'REVIEWED', 'REVISION_NEEDED', 'APPROVED');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE supervision_status AS ENUM ('DALAM_BIMBINGAN', 'LULUS', 'TIDAK_SELESAI');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Core Tables
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nip_or_npm VARCHAR(32) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    approval_status VARCHAR(20) DEFAULT 'APPROVED',
    must_change_password BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20) DEFAULT 'APPROVED';

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role user_role NOT NULL,
    CONSTRAINT unique_user_role UNIQUE (user_id, role)
);

CREATE TABLE IF NOT EXISTS mahasiswa_profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    degree student_degree NOT NULL,
    start_academic_year VARCHAR(10) NOT NULL,
    thesis_title TEXT,
    dosen_pembimbing_id UUID REFERENCES users(id),
    supervision_status supervision_status DEFAULT 'DALAM_BIMBINGAN'
);

ALTER TABLE mahasiswa_profiles
    ADD COLUMN IF NOT EXISTS supervision_status supervision_status DEFAULT 'DALAM_BIMBINGAN';

CREATE TABLE IF NOT EXISTS progress_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mahasiswa_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    academic_year_id VARCHAR(10) NOT NULL,
    title VARCHAR(255) NOT NULL,
    report_html TEXT NOT NULL,
    status progress_status DEFAULT 'SUBMITTED',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS progress_feedback (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id UUID NOT NULL REFERENCES progress_reports(id) ON DELETE CASCADE,
    dosen_id UUID NOT NULL REFERENCES users(id),
    feedback_html TEXT NOT NULL,
    followup_notes_html TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS progress_attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id UUID NOT NULL REFERENCES progress_reports(id) ON DELETE CASCADE,
    file_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    CONSTRAINT max_attachment_size CHECK (file_size_bytes <= 10485760) -- 10 MB per file
);

-- Tabel Log Aktivitas Pengguna (Audit Trail)
CREATE TABLE IF NOT EXISTS activity_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_name VARCHAR(255) NOT NULL,
    actor_identifier VARCHAR(64),
    actor_roles VARCHAR(64),
    action_type VARCHAR(64) NOT NULL,
    description TEXT NOT NULL,
    target_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Tabel Konfigurasi Website Dinamis (App Settings)
CREATE TABLE IF NOT EXISTS app_settings (
    id INT PRIMARY KEY DEFAULT 1,
    app_name VARCHAR(255) NOT NULL DEFAULT 'SIMTA',
    app_subtitle VARCHAR(255) NOT NULL DEFAULT 'Sistem Informasi Manajemen Tugas Akhir (S1 • S2 • S3)',
    footer_text TEXT NOT NULL DEFAULT 'Sistem Informasi Manajemen Tugas Akhir (SIMTA)',
    privacy_policy_html TEXT DEFAULT '<h3>Kebijakan Privasi (Privacy Policy)</h3><p>Website SIMTA ini digunakan secara khusus untuk keperluan pencatatan dan evaluasi kemajuan Tugas Akhir. Seluruh data identitas pengguna, laporan kemajuan, dan dokumen lampiran disimpan dan dilindungi secara aman serta hanya dapat diakses oleh pihak yang berwenang (Administrator, Dosen Pembimbing, dan Mahasiswa bersangkutan).</p>',
    disclaimer_html TEXT DEFAULT '<h3>Penyangkalan (Disclaimer)</h3><p>Informasi dan dokumen yang diunggah ke dalam sistem ini merupakan dokumen akademik resmi. Pengguna bertanggung jawab penuh atas keaslian dokumen dan laporan yang diunggah ke dalam portal ini.</p>',
    favicon_path VARCHAR(512) DEFAULT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT single_row_app_settings CHECK (id = 1)
);

INSERT INTO app_settings (id, app_name, app_subtitle, footer_text, privacy_policy_html, disclaimer_html, favicon_path)
VALUES (
    1,
    'SIMTA',
    'Sistem Informasi Manajemen Tugas Akhir (S1 • S2 • S3)',
    'Sistem Informasi Manajemen Tugas Akhir (SIMTA)',
    '<h3>Kebijakan Privasi (Privacy Policy)</h3><p>Website SIMTA ini digunakan secara khusus untuk keperluan pencatatan dan evaluasi kemajuan Tugas Akhir. Seluruh data identitas pengguna, laporan kemajuan, dan dokumen lampiran disimpan dan dilindungi secara aman serta hanya dapat diakses oleh pihak yang berwenang (Administrator, Dosen Pembimbing, dan Mahasiswa bersangkutan).</p>',
    '<h3>Penyangkalan (Disclaimer)</h3><p>Informasi dan dokumen yang diunggah ke dalam sistem ini merupakan dokumen akademik resmi. Pengguna bertanggung jawab penuh atas keaslian dokumen dan laporan yang diunggah ke dalam portal ini.</p>',
    NULL
)
ON CONFLICT (id) DO NOTHING;
