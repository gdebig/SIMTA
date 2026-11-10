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

# 1. Validasi & Auto-Upgrade Node.js >= 18 LTS (Mengatasi Node v10.19.0 & broken /usr/local npm)
NEED_NODE_UPGRADE=false
if ! command -v node >/dev/null 2>&1; then
  NEED_NODE_UPGRADE=true
else
  NODE_MAJOR="$(node -v | sed 's/^v//' | cut -d. -f1)"
  if [[ "$NODE_MAJOR" -lt 18 ]]; then
    echo "[PERINGATAN] Terdeteksi Node.js versi lama ($(node -v)). Diperlukan Node.js >= 18 LTS."
    NEED_NODE_UPGRADE=true
  fi
fi

if [[ "$NEED_NODE_UPGRADE" == "true" ]]; then
  echo "[1/5] Memperbarui Node.js & npm ke versi v20.18.0 LTS secara otomatis..."
  ARCH="$(uname -m)"
  if [[ "$ARCH" == "x86_64" ]]; then
    NODE_ARCH="x64"
  elif [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
    NODE_ARCH="arm64"
  else
    NODE_ARCH="x64"
  fi

  NODE_VER="v20.18.0"
  TARBALL="node-${NODE_VER}-linux-${NODE_ARCH}.tar.gz"
  DOWNLOAD_URL="https://nodejs.org/dist/${NODE_VER}/${TARBALL}"

  sudo rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/node
  curl -fsSL "$DOWNLOAD_URL" -o "/tmp/${TARBALL}"
  sudo tar -xzf "/tmp/${TARBALL}" -C /usr/local --strip-components=1
  rm -f "/tmp/${TARBALL}"
  export PATH="/usr/local/bin:$PATH"
  hash -r
fi

echo "[1/5] Menggunakan Node.js $(node -v) & npm $(npm -v)"

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
  npm ci --omit=dev || npm install --omit=dev
else
  npm install --omit=dev
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
