#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Script Deployment & Startup Server Production - SIMTA DTE UI
# Penggunaan:
#   ./deploy-production.sh              # Deploy & jalankan server production
#   ./deploy-production.sh --reset-db   # Kosongkan database (sisakan akun Admin) & jalankan
# ==============================================================================

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

RESET_DB=false
for arg in "$@"; do
  if [[ "$arg" == "--reset-db" ]]; then
    RESET_DB=true
  fi
done

echo "============================================================="
echo "  SIMTA DTE UI - Persiapan Server Production"
echo "============================================================="

# 1. Validasi & Auto-Upgrade Node.js >= 18 LTS (khusus Ubuntu/Debian dengan Node lama)
NEED_NODE_UPGRADE=false
if ! command -v node >/dev/null 2>&1; then
  NEED_NODE_UPGRADE=true
else
  NODE_MAJOR="$(node -v | sed 's/^v//' | cut -d. -f1)"
  if [[ "$NODE_MAJOR" -lt 18 ]]; then
    echo "[PERINGATAN] Versi Node.js saat ini ($(node -v)) terlalu lama (bawaan apt Ubuntu)."
    NEED_NODE_UPGRADE=true
  fi
fi

if [[ "$NEED_NODE_UPGRADE" == "true" ]]; then
  if command -v apt-get >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
    echo "[1/5] Menginstal / memperbarui ke Node.js 20 LTS melalui repositori resmi NodeSource..."
    sudo apt-get update -y
    sudo apt-get install -y ca-certificates curl gnupg
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
    hash -r
  else
    echo "[ERROR] Dibutuhkan Node.js >= 18 LTS. Silakan jalankan perintah berikut:"
    echo "  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -"
    echo "  sudo apt-get install -y nodejs"
    exit 1
  fi
fi

echo "[1/5] Terdeteksi Node.js $(node -v) & npm $(npm -v)"

# 2. Pastikan file .env tersedia dan memiliki AUTH_SECRET acak yang aman
if [[ ! -f ".env" ]]; then
  echo "[2/5] Membuat file .env dari .env.example dengan AUTH_SECRET kriptografis..."
  cp .env.example .env
  RANDOM_SECRET="$(node -e "console.log(require('crypto').randomBytes(48).toString('hex'))")"
  sed -i "s|YOUR_AUTH_SECRET_HERE|${RANDOM_SECRET}|g" .env
  chmod 600 .env
else
  echo "[2/5] File .env ditemukan."
  chmod 600 .env || true
fi

# 3. Pastikan direktori penyimpanan (uploads & pgdata) tersedia
mkdir -p uploads pgdata

# 4. Instalasi dependencies production
echo "[3/5] Menginstal dependencies Node.js untuk Production..."
if [[ -f "package-lock.json" ]]; then
  npm ci --omit=dev || npm install --production
else
  npm install --omit=dev || npm install --production
fi

# 5. Inisialisasi atau Reset Database Production (hanya menyisakan akun Admin)
if [[ "$RESET_DB" == "true" ]]; then
  echo "[4/5] Mengosongkan database Production dan menyiapkan akun Admin utama..."
  NODE_ENV=production npm run db:reset
else
  echo "[4/5] Memastikan skema database dan akun Admin utama tersedia..."
  NODE_ENV=production npm run db:init
  NODE_ENV=production npm run db:seed
fi

# 6. Menjalankan server aplikasi
echo "[5/5] Menjalankan layanan SIMTA pada mode Production..."
if command -v pm2 >/dev/null 2>&1; then
  pm2 startOrReload ecosystem.config.cjs --env production
  pm2 save
  echo "============================================================="
  echo "  SIMTA Production aktif dikelola oleh PM2 Process Manager"
  echo "  Gunakan 'pm2 status' atau 'pm2 logs simta-dte-ui' untuk memantau."
  echo "============================================================="
else
  echo "PM2 tidak ditemukan. Menjalankan server secara langsung dengan NODE_ENV=production..."
  NODE_ENV=production exec node src/server.js
fi
