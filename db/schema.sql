-- Sistem Informasi Manajemen Tugas Akhir (SIMTA)
-- PostgreSQL Schema Blueprint

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
