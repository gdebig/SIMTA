require('dotenv').config();
const net = require('node:net');
const app = require('./app');
const { startPostgresServer } = require('./db/pg-server');

const PORT = Number(process.env.PORT) || 3000;
const PGHOST = process.env.PGHOST || '127.0.0.1';
const PGPORT = Number(process.env.PGPORT) || 5432;

function isPortOpen(host, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(1000);
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.once('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, host);
  });
}

async function bootstrap() {
  const pgRunning = await isPortOpen(PGHOST, PGPORT);
  if (!pgRunning) {
    console.log(`Menyalakan server PostgreSQL lokal pada ${PGHOST}:${PGPORT}...`);
    await startPostgresServer();
  } else {
    console.log(`Terhubung ke instance PostgreSQL aktif pada ${PGHOST}:${PGPORT}`);
  }

  app.listen(PORT, () => {
    console.log(`=============================================================`);
    console.log(`  SIMTA - Sistem Informasi Manajemen Tugas Akhir (DTE UI)`);
    console.log(`  Server berjalan di: http://localhost:${PORT}`);
    console.log(`=============================================================`);
  });
}

bootstrap().catch((err) => {
  console.error('Gagal menjalankan server SIMTA:', err);
  process.exit(1);
});
