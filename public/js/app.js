const MAX_BYTES = 10 * 1024 * 1024; // 10 MB
const ALLOWED_EXTS = new Set([
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv', '.zip', '.png', '.jpg', '.jpeg'
]);

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const SUPERVISION_LABELS = {
  DALAM_BIMBINGAN: 'Sedang Dalam Bimbingan',
  LULUS: 'Sudah Lulus',
  TIDAK_SELESAI: 'Tidak Selesai'
};

const state = {
  token: localStorage.getItem('simta_token') || null,
  user: null,
  activeViewRole: null,
  users: [],
  allDosen: [],
  adminLogs: [],
  dosenLogs: [],
  selectedDosenStudentId: null,
  selectedDosenStudentName: null,
  selectedAdminStudent: null,
  pagination: {
    adminUsers: { page: 1, pageSize: 5 },
    adminLogs: { page: 1, pageSize: 5 },
    dosenLogs: { page: 1, pageSize: 5 }
  }
};

/**
 * Render kontrol pagination yang dapat diubah jumlah barisnya oleh user
 */
function renderPaginationBar(containerId, pagState, totalItems, onPageOrSizeChange) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const pageSize = pagState.pageSize || 5;
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  if (pagState.page > totalPages) pagState.page = totalPages;
  if (pagState.page < 1) pagState.page = 1;

  const startIdx = totalItems === 0 ? 0 : (pagState.page - 1) * pageSize + 1;
  const endIdx = Math.min(totalItems, pagState.page * pageSize);

  const sizeOptions = [5, 10, 25, 50]
    .map((sz) => `<option value="${sz}" ${sz === pageSize ? 'selected' : ''}>${sz} baris</option>`)
    .join('');

  let pageBtnsHtml = '';
  for (let p = 1; p <= totalPages; p++) {
    pageBtnsHtml += `
      <button type="button" class="page-btn num-page-btn ${p === pagState.page ? 'active' : ''}" data-page="${p}">
        ${p}
      </button>
    `;
  }

  container.innerHTML = `
    <div style="display:flex;align-items:center;gap:0.65rem;flex-wrap:wrap;">
      <span>Tampilkan:</span>
      <select class="form-control page-size-select" style="width:auto;padding:0.24rem 0.55rem;font-size:0.78rem;">
        ${sizeOptions}
      </select>
      <span>Menampilkan <strong>${startIdx}–${endIdx}</strong> dari <strong>${totalItems}</strong> data (Hal. ${pagState.page}/${totalPages})</span>
    </div>
    <div class="pagination-controls">
      <button type="button" class="page-btn prev-page-btn" ${pagState.page <= 1 ? 'disabled' : ''}>
        &laquo; Sebelumnya
      </button>
      ${pageBtnsHtml}
      <button type="button" class="page-btn next-page-btn" ${pagState.page >= totalPages ? 'disabled' : ''}>
        Berikutnya &raquo;
      </button>
    </div>
  `;

  container.querySelector('.page-size-select').addEventListener('change', (e) => {
    pagState.pageSize = Number(e.target.value) || 5;
    pagState.page = 1;
    onPageOrSizeChange();
  });

  container.querySelector('.prev-page-btn').addEventListener('click', () => {
    if (pagState.page > 1) {
      pagState.page -= 1;
      onPageOrSizeChange();
    }
  });

  container.querySelector('.next-page-btn').addEventListener('click', () => {
    if (pagState.page < totalPages) {
      pagState.page += 1;
      onPageOrSizeChange();
    }
  });

  container.querySelectorAll('.num-page-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      pagState.page = Number(btn.getAttribute('data-page')) || 1;
      onPageOrSizeChange();
    });
  });
}

function formatSupervisionStatus(status) {
  const key = status || 'DALAM_BIMBINGAN';
  const label = SUPERVISION_LABELS[key] || 'Sedang Dalam Bimbingan';
  return `<span class="badge badge-${key}">${label}</span>`;
}

function showAlert(message, type = 'info') {
  const el = document.getElementById('globalAlert');
  el.className = `alert alert-${type}`;
  el.textContent = message;
  el.classList.remove('hidden');
  setTimeout(() => {
    el.classList.add('hidden');
  }, 6000);
}

async function apiFetch(url, options = {}) {
  const headers = options.headers ? { ...options.headers } : {};
  if (state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }
  if (!(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  const response = await fetch(url, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `HTTP Error ${response.status}`);
  }
  return data;
}

// 1. Cek Koneksi PostgreSQL & Muat Daftar Dosen Publik untuk Form Registrasi Mandiri
async function checkDatabaseStatus() {
  const dot = document.getElementById('dbStatusDot');
  const text = document.getElementById('dbStatusText');
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    if (res.ok && data.database === 'connected') {
      dot.className = 'db-dot online';
      text.textContent = 'PostgreSQL Terhubung';
    } else {
      dot.className = 'db-dot offline';
      text.textContent = 'PostgreSQL Belum Terhubung';
    }
  } catch {
    dot.className = 'db-dot offline';
    text.textContent = 'Server Offline';
  }
}

async function loadPublicDosenForRegistration() {
  try {
    const dosenList = await apiFetch('/api/public/dosen');
    const selectEl = document.getElementById('regDosenPembimbing');
    if (!selectEl) return;
    selectEl.innerHTML = '<option value="">-- Pilih Dosen Pembimbing (Opsional) --</option>';
    dosenList.forEach((d) => {
      const opt = document.createElement('option');
      opt.value = d.id;
      opt.textContent = `${d.name} (${d.nip_or_npm})`;
      selectEl.appendChild(opt);
    });
  } catch {
    // Abaikan jika gagal dimuat
  }
}

// 2. Inisialisasi Toolbar WYSIWYG HTML Editor (Statik & Dinamis)
function initWysiwygToolbars(root = document) {
  root.querySelectorAll('.wysiwyg-toolbar').forEach((toolbar) => {
    if (toolbar.dataset.bound === 'true') return;
    toolbar.dataset.bound = 'true';

    const targetId = toolbar.getAttribute('data-target');
    const editor = document.getElementById(targetId);
    if (!editor) return;

    toolbar.querySelectorAll('.wysiwyg-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const cmd = btn.getAttribute('data-cmd');
        const val = btn.getAttribute('data-val') || null;
        editor.focus();
        document.execCommand(cmd, false, val);
      });
    });
  });
}

function buildWysiwygHtml(editorId, initialHtml = '', compact = false) {
  return `
    <div class="wysiwyg-wrapper">
      <div class="wysiwyg-toolbar" data-target="${editorId}">
        <button type="button" class="wysiwyg-btn" data-cmd="bold"><b>B</b></button>
        <button type="button" class="wysiwyg-btn" data-cmd="italic"><i>I</i></button>
        <button type="button" class="wysiwyg-btn" data-cmd="formatBlock" data-val="H3">H3</button>
        <button type="button" class="wysiwyg-btn" data-cmd="insertUnorderedList">• List</button>
        <button type="button" class="wysiwyg-btn" data-cmd="insertOrderedList">1. List</button>
        <button type="button" class="wysiwyg-btn" data-cmd="formatBlock" data-val="BLOCKQUOTE">❝ Quote</button>
      </div>
      <div id="${editorId}" class="wysiwyg-editor ${compact ? 'compact' : ''}" contenteditable="true">${initialHtml}</div>
    </div>
  `;
}

// 3. Simulator RBAC & Anti-XSS
function initSandbox() {
  const section = document.getElementById('sandboxSection');
  document.getElementById('btnToggleSandbox').addEventListener('click', () => {
    section.classList.toggle('hidden');
  });
  document.getElementById('btnCloseSandbox').addEventListener('click', () => {
    section.classList.add('hidden');
  });

  document.getElementById('btnTestRbac').addEventListener('click', async () => {
    const roles = Array.from(document.querySelectorAll('.sb-role:checked')).map((el) => el.value);
    const out = document.getElementById('rbacTestResult');
    try {
      const res = await apiFetch('/api/utils/validate-roles', {
        method: 'POST',
        body: JSON.stringify({ roles })
      });
      out.style.color = 'var(--success)';
      out.textContent = `✓ VALID: Kombinasi role [${res.roles.join(', ')}] diizinkan.`;
    } catch (err) {
      out.style.color = 'var(--danger)';
      out.textContent = `✗ DITOLAK: ${err.message}`;
    }
  });

  document.getElementById('btnTestSanitize').addEventListener('click', async () => {
    const html = document.getElementById('sbDirtyEditor').innerHTML;
    const out = document.getElementById('sanitizeTestResult');
    try {
      const res = await apiFetch('/api/utils/sanitize', {
        method: 'POST',
        body: JSON.stringify({ html })
      });
      out.textContent = res.sanitized;
    } catch (err) {
      out.textContent = `Error: ${err.message}`;
    }
  });
}

// 4. Navigasi Multi-Role (Mendukung Dual-Role ADMIN + DOSEN)
function renderRoleSwitcher() {
  const container = document.getElementById('roleSwitcherContainer');
  container.innerHTML = '';

  if (!state.user || !state.user.roles) {
    container.classList.add('hidden');
    return;
  }

  container.classList.remove('hidden');
  state.user.roles.forEach((role) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `role-tab ${state.activeViewRole === role ? 'active' : ''}`;
    btn.textContent = `Mode ${role}`;
    btn.addEventListener('click', () => {
      state.activeViewRole = role;
      renderRoleSwitcher();
      switchActiveRoleView();
    });
    container.appendChild(btn);
  });
}

async function switchActiveRoleView() {
  const adminView = document.getElementById('adminView');
  const dosenView = document.getElementById('dosenView');
  const mahasiswaView = document.getElementById('mahasiswaView');

  adminView.classList.add('hidden');
  dosenView.classList.add('hidden');
  mahasiswaView.classList.add('hidden');

  await loadStats();

  if (state.activeViewRole === 'ADMIN') {
    adminView.classList.remove('hidden');
    await Promise.all([loadAdminData(), loadAdminLogs()]);
  } else if (state.activeViewRole === 'DOSEN') {
    dosenView.classList.remove('hidden');
    await Promise.all([loadDosenStudents(), loadDosenReports(), loadDosenLogs()]);
  } else if (state.activeViewRole === 'MAHASISWA') {
    mahasiswaView.classList.remove('hidden');
    renderMahasiswaProfile();
    await loadMahasiswaReports();
  }
}

function downloadExcelProgress(paramsObj = {}) {
  const params = new URLSearchParams(paramsObj);
  if (state.token) {
    params.set('token', state.token);
  }
  const url = `/api/reports/export/excel?${params.toString()}`;
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', 'Laporan_Progress_SIMTA.xlsx');
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  // Perbarui tabel log setelah unduh excel
  setTimeout(() => {
    if (state.activeViewRole === 'ADMIN') loadAdminLogs();
    if (state.activeViewRole === 'DOSEN') loadDosenLogs();
  }, 800);
}

async function loadStats() {
  const container = document.getElementById('statsContainer');
  try {
    const stats = await apiFetch('/api/stats');

    if (state.activeViewRole === 'ADMIN') {
      const getRoleCount = (r) => stats.roles.find((x) => x.role === r)?.count || 0;
      const getSupCount = (s) => stats.supervisionStatuses?.find((x) => x.supervision_status === s)?.count || 0;
      const totalReports = stats.reportStatuses.reduce((acc, s) => acc + s.count, 0);

      container.innerHTML = `
        <div class="stat-card">
          <div class="stat-label">Jumlah Mahasiswa (${getRoleCount('MAHASISWA')} Total)</div>
          <div class="stat-value" style="font-size:1.15rem;margin-top:0.35rem;">
            ${getSupCount('DALAM_BIMBINGAN')} Bimbingan • ${getSupCount('LULUS')} Lulus • ${getSupCount('TIDAK_SELESAI')} Tidak Selesai
          </div>
        </div>
        <div class="stat-card accent">
          <div class="stat-label">Jumlah Dosen Pembimbing &amp; Admin</div>
          <div class="stat-value">${getRoleCount('DOSEN')} Dosen • ${getRoleCount('ADMIN')} Admin</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Jumlah Laporan Progress</div>
          <div class="stat-value">${totalReports} Laporan</div>
        </div>
      `;
    } else if (state.activeViewRole === 'DOSEN') {
      const supervisedCount = stats.dosenStats?.supervisedStudentsCount ?? 0;
      const inProgressCount = stats.dosenStats?.inProgressReportsCount ?? 0;

      container.innerHTML = `
        <div class="stat-card">
          <div class="stat-label">Jumlah Mahasiswa yang Dibimbing</div>
          <div class="stat-value">${supervisedCount} Mahasiswa</div>
        </div>
        <div class="stat-card accent">
          <div class="stat-label">Jumlah Laporan Sedang Dalam Progress</div>
          <div class="stat-value">${inProgressCount} Laporan</div>
        </div>
      `;
    } else if (state.activeViewRole === 'MAHASISWA') {
      const inProgressCount = stats.mahasiswaStats?.inProgressReportsCount ?? 0;

      container.innerHTML = `
        <div class="stat-card">
          <div class="stat-label">Jumlah Laporan Sedang Dalam Progress</div>
          <div class="stat-value">${inProgressCount} Laporan</div>
        </div>
      `;
    } else {
      container.innerHTML = '';
    }
  } catch {
    container.innerHTML = '';
  }
}

// =========================================================
// LOG AKTIVITAS PENGGUNA (MODE ADMIN & MODE DOSEN)
// =========================================================
function renderLogsRows(logs, tbodyEl) {
  if (!logs || logs.length === 0) {
    tbodyEl.innerHTML = `
      <tr>
        <td colspan="5" style="text-align:center;color:var(--text-secondary);">
          Belum ada catatan log aktivitas yang sesuai filter.
        </td>
      </tr>
    `;
    return;
  }

  tbodyEl.innerHTML = logs
    .map((log) => {
      const timeStr = new Date(log.created_at).toLocaleString('id-ID');
      const roleBadges = (log.actor_roles || '')
        .split(',')
        .map((r) => r.trim())
        .filter(Boolean)
        .map((r) => `<span class="badge badge-${r.toLowerCase()}">${r}</span>`)
        .join(' ');

      return `
        <tr>
          <td style="white-space:nowrap;font-size:0.8rem;color:var(--text-secondary);">${timeStr}</td>
          <td>
            <strong>${log.actor_name}</strong><br/>
            <small style="color:var(--text-secondary);">${log.actor_identifier || '-'}</small>
          </td>
          <td>${roleBadges || '-'}</td>
          <td><span class="badge badge-dosen">${log.action_type}</span></td>
          <td>${log.description}</td>
        </tr>
      `;
    })
    .join('');
}

async function loadAdminLogs() {
  const actionType = document.getElementById('adminLogTypeFilter')?.value || '';
  const params = new URLSearchParams({ mode: 'ADMIN' });
  if (actionType) params.set('action_type', actionType);

  try {
    const logs = await apiFetch(`/api/logs?${params.toString()}`);
    state.adminLogs = logs;
    renderAdminLogsPaginated();
  } catch (err) {
    console.error(err);
  }
}

function renderAdminLogsPaginated() {
  const logs = state.adminLogs || [];
  const pag = state.pagination.adminLogs;
  renderPaginationBar('adminLogsPagination', pag, logs.length, renderAdminLogsPaginated);
  const start = (pag.page - 1) * pag.pageSize;
  const pagedLogs = logs.slice(start, start + pag.pageSize);
  renderLogsRows(pagedLogs, document.getElementById('adminLogsTableBody'));
}

async function loadDosenLogs() {
  const actionType = document.getElementById('dosenLogTypeFilter')?.value || '';
  const params = new URLSearchParams({ mode: 'DOSEN' });
  if (actionType) params.set('action_type', actionType);

  try {
    const logs = await apiFetch(`/api/logs?${params.toString()}`);
    state.dosenLogs = logs;
    renderDosenLogsPaginated();
  } catch (err) {
    console.error(err);
  }
}

function renderDosenLogsPaginated() {
  const logs = state.dosenLogs || [];
  const pag = state.pagination.dosenLogs;
  renderPaginationBar('dosenLogsPagination', pag, logs.length, renderDosenLogsPaginated);
  const start = (pag.page - 1) * pag.pageSize;
  const pagedLogs = logs.slice(start, start + pag.pageSize);
  renderLogsRows(pagedLogs, document.getElementById('dosenLogsTableBody'));
}

// =========================================================
// 5. PANEL ADMIN: DAFTAR SELURUH USER, APPROVE, UBAH/HAPUS, & KLIK MAHASISWA
// =========================================================
async function loadAdminData() {
  const filterRole = document.getElementById('filterUserRole').value;
  const filterApproval = document.getElementById('filterApprovalStatus').value;
  const searchVal = document.getElementById('adminSearchUser')?.value.trim() || '';
  const params = new URLSearchParams();
  if (filterRole) params.set('role', filterRole);
  if (filterApproval) params.set('approval_status', filterApproval);
  if (searchVal) params.set('search', searchVal);

  const [users, dosenList] = await Promise.all([
    apiFetch(`/api/users?${params.toString()}`),
    apiFetch('/api/users?role=DOSEN')
  ]);
  state.users = users;
  state.allDosen = dosenList;

  // Populate dropdown dosen pembimbing di form
  const dosenSelect = document.getElementById('newDosenPembimbing');
  const currentSelectedDosen = dosenSelect.value;
  dosenSelect.innerHTML = '<option value="">-- Pilih Dosen Pembimbing --</option>';
  dosenList.forEach((d) => {
    const opt = document.createElement('option');
    opt.value = d.id;
    opt.textContent = `${d.name} (${d.is_active ? 'Aktif' : 'Tidak Aktif'})`;
    dosenSelect.appendChild(opt);
  });
  if (currentSelectedDosen) {
    dosenSelect.value = currentSelectedDosen;
  }

  renderAdminUsersTablePaginated();
}

function renderAdminUsersTablePaginated() {
  const allUsers = state.users || [];
  const pag = state.pagination.adminUsers;
  renderPaginationBar('adminUsersPagination', pag, allUsers.length, renderAdminUsersTablePaginated);

  const start = (pag.page - 1) * pag.pageSize;
  const users = allUsers.slice(start, start + pag.pageSize);
  const tbody = document.getElementById('usersTableBody');

  if (users.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align:center;color:var(--text-secondary);">
          Tidak ada pengguna yang sesuai dengan pencarian / filter.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = users
    .map((u) => {
      const isMahasiswa = (u.roles || []).includes('MAHASISWA');
      const isPending = u.approval_status === 'PENDING' || (!u.is_active && u.approval_status === 'PENDING');
      const roleBadges = (u.roles || [])
        .map((r) => `<span class="badge badge-${r.toLowerCase()}">${r}</span>`)
        .join(' ');

      // Nama akun: Jika Mahasiswa, bisa diklik untuk melihat laporan & komentar
      const nameHtml = isMahasiswa
        ? `<a href="#adminStudentReportsCard" class="student-name-link" data-student-id="${u.id}" title="Klik untuk melihat proses laporan & komentar mahasiswa ini">
             ${u.name}
           </a>`
        : `<strong>${u.name}</strong>`;

      // Kolom Tahun Ajaran
      const academicYearHtml = isMahasiswa
        ? `<strong>${u.start_academic_year || '-'}</strong><br/><span class="badge badge-degree">${u.degree || 'S1'}</span>`
        : `<span style="color:var(--text-secondary);">-</span>`;

      // Kolom Status
      const pendingBadge = isPending
        ? `<div style="margin-bottom:0.3rem;"><span class="badge badge-mahasiswa">⏳ Menunggu Approval Admin</span></div>`
        : '';

      let statusColumnHtml = '';
      if (isMahasiswa) {
        statusColumnHtml = `
          ${pendingBadge}
          <div style="margin-bottom:0.3rem;">
            ${formatSupervisionStatus(u.supervision_status)}
            ${!u.is_active && !isPending ? '<span class="badge badge-inactive">Akun Nonaktif</span>' : ''}
          </div>
          <div style="font-size:0.78rem;color:var(--text-secondary);">
            Pembimbing: <strong>${u.dosen_pembimbing_name || 'Belum ditetapkan'}</strong>
          </div>
          <div style="font-size:0.78rem;color:var(--text-secondary);margin-top:0.15rem;">
            <em>${u.thesis_title || 'Judul TA belum diisi'}</em>
          </div>
        `;
      } else {
        statusColumnHtml = `
          ${pendingBadge}
          ${
            u.is_active
              ? `<span class="badge badge-active">Aktif</span>`
              : `<span class="badge badge-inactive">Tidak Aktif</span>`
          }
        `;
      }

      // Tombol Setujui (Approve) jika akun menunggu persetujuan atau belum aktif
      const approveBtnHtml =
        isPending || !u.is_active
          ? `<button type="button" class="btn btn-yellow btn-sm btn-approve-user" data-user-id="${u.id}" style="margin-right:0.35rem;">
               ✓ Setujui (Approve)
             </button>`
          : '';

      const viewReportsLink = isMahasiswa
        ? `<button type="button" class="action-link btn-view-student-reports" data-student-id="${u.id}">
             Laporan (${u.report_count || 0})
           </button> • `
        : '';

      return `
        <tr style="${isPending ? 'background:#FFFBEB;' : ''}">
          <td>
            ${nameHtml}<br/>
            <small style="color:var(--text-secondary);">${u.nip_or_npm} • ${u.email}</small>
          </td>
          <td>${roleBadges}</td>
          <td>${academicYearHtml}</td>
          <td>${statusColumnHtml}</td>
          <td style="white-space:nowrap;">
            ${approveBtnHtml}
            ${viewReportsLink}
            <button type="button" class="action-link btn-edit-user" data-user-id="${u.id}">Ubah</button> •
            <button type="button" class="action-link danger btn-delete-user" data-user-id="${u.id}">Hapus</button>
          </td>
        </tr>
      `;
    })
    .join('');

  // Event Listener: Klik Setujui (Approve) Akun
  tbody.querySelectorAll('.btn-approve-user').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const userId = btn.getAttribute('data-user-id');
      try {
        const res = await apiFetch(`/api/users/${userId}/approve`, { method: 'POST' });
        showAlert(`Akun ${res.name} berhasil disetujui (approved) dan telah aktif.`, 'success');
        await Promise.all([loadAdminData(), loadStats(), loadAdminLogs()]);
      } catch (err) {
        showAlert(err.message, 'error');
      }
    });
  });

  // Event Listener: Klik Nama Mahasiswa atau tombol Laporan untuk melihat proses laporan & komentar
  const handleInspectStudent = async (studentId) => {
    const student = state.users.find((x) => x.id === studentId);
    if (!student) return;
    state.selectedAdminStudent = student;
    await renderAdminStudentReportsPanel(student);
  };

  tbody.querySelectorAll('.student-name-link, .btn-view-student-reports').forEach((el) => {
    el.addEventListener('click', (e) => {
      e.preventDefault();
      const studentId = el.getAttribute('data-student-id');
      handleInspectStudent(studentId);
    });
  });

  // Event Listener: Klik Link Ubah Akun
  tbody.querySelectorAll('.btn-edit-user').forEach((btn) => {
    btn.addEventListener('click', () => {
      const userId = btn.getAttribute('data-user-id');
      const user = state.users.find((x) => x.id === userId);
      if (user) {
        populateUserFormForEdit(user);
      }
    });
  });

  // Event Listener: Klik Link Hapus Akun
  tbody.querySelectorAll('.btn-delete-user').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const userId = btn.getAttribute('data-user-id');
      const user = state.users.find((x) => x.id === userId);
      if (!user) return;

      const confirmed = window.confirm(
        `Apakah Anda yakin ingin menghapus akun "${user.name}" (${user.nip_or_npm})?`
      );
      if (!confirmed) return;

      try {
        await apiFetch(`/api/users/${userId}`, { method: 'DELETE' });
        showAlert(`Akun ${user.name} berhasil dihapus.`, 'success');
        if (state.selectedAdminStudent?.id === userId) {
          document.getElementById('adminStudentReportsCard').classList.add('hidden');
          state.selectedAdminStudent = null;
        }
        await Promise.all([loadAdminData(), loadStats(), loadAdminLogs()]);
      } catch (err) {
        showAlert(err.message, 'error');
      }
    });
  });
}

function populateUserFormForEdit(user) {
  document.getElementById('editUserId').value = user.id;
  document.getElementById('userFormTitle').textContent = `Ubah Akun: ${user.name}`;
  document.getElementById('btnSubmitUserForm').textContent = 'Simpan Perubahan Akun';
  document.getElementById('btnCancelEditUser').classList.remove('hidden');
  document.getElementById('passwordFieldLabel').textContent = 'Password Baru (Kosongkan jika tidak diubah)';

  document.getElementById('newNipNpm').value = user.nip_or_npm || '';
  document.getElementById('newName').value = user.name || '';
  document.getElementById('newEmail').value = user.email || '';
  document.getElementById('newPassword').value = '';
  document.getElementById('newIsActive').value = user.is_active ? 'true' : 'false';

  const roleCheckboxes = document.querySelectorAll('input[name="newUserRole"]');
  roleCheckboxes.forEach((cb) => {
    cb.checked = (user.roles || []).includes(cb.value);
  });

  if ((user.roles || []).includes('MAHASISWA')) {
    document.getElementById('newDegree').value = user.degree || 'S1';
    document.getElementById('newAcademicYear').value = user.start_academic_year || '2025/2026';
    document.getElementById('newSupervisionStatus').value = user.supervision_status || 'DALAM_BIMBINGAN';
    document.getElementById('newDosenPembimbing').value = user.dosen_pembimbing_id || '';
    document.getElementById('newThesisEditor').innerHTML = user.thesis_title || '';
  } else {
    document.getElementById('newThesisEditor').innerHTML = '';
  }

  roleCheckboxes[0].dispatchEvent(new Event('change'));
  document.getElementById('userFormCard').scrollIntoView({ behavior: 'smooth' });
}

function resetUserFormToCreate() {
  document.getElementById('editUserId').value = '';
  document.getElementById('userFormTitle').textContent = 'Registrasi Pengguna Baru';
  document.getElementById('btnSubmitUserForm').textContent = 'Simpan Pengguna Baru';
  document.getElementById('btnCancelEditUser').classList.add('hidden');
  document.getElementById('passwordFieldLabel').textContent = 'Password Awal';

  document.getElementById('userForm').reset();
  document.getElementById('newPassword').value = 'simta123';
  document.getElementById('newAcademicYear').value = '2025/2026';
  document.getElementById('newIsActive').value = 'true';
  document.getElementById('newSupervisionStatus').value = 'DALAM_BIMBINGAN';
  document.getElementById('newThesisEditor').innerHTML = '';

  const roleCheckboxes = document.querySelectorAll('input[name="newUserRole"]');
  roleCheckboxes.forEach((cb) => {
    cb.checked = cb.value === 'MAHASISWA';
  });
  roleCheckboxes[0].dispatchEvent(new Event('change'));
}

// Panel Proses Laporan & Komentar Mahasiswa pada Mode Admin
async function renderAdminStudentReportsPanel(student) {
  const card = document.getElementById('adminStudentReportsCard');
  const titleEl = document.getElementById('adminStudentModalTitle');
  const profileEl = document.getElementById('adminStudentProfileInfo');
  const listEl = document.getElementById('adminStudentReportsList');

  card.classList.remove('hidden');
  titleEl.textContent = `Proses Laporan & Komentar Mahasiswa: ${student.name} (${student.nip_or_npm})`;

  profileEl.innerHTML = `
    <div style="background:#FFFFFF;padding:0.9rem 1.1rem;border-radius:8px;border:1px solid var(--border-color);display:flex;justify-content:space-between;flex-wrap:wrap;gap:0.75rem;">
      <div>
        <span class="badge badge-degree">Jenjang ${student.degree || 'S1'}</span>
        <span class="badge badge-mahasiswa">Tahun Ajaran Mulai: ${student.start_academic_year || '-'}</span>
        ${formatSupervisionStatus(student.supervision_status)}
        <div style="margin-top:0.45rem;font-weight:700;color:var(--navy-primary);">
          ${student.thesis_title || 'Judul Tugas Akhir Belum Ditetapkan'}
        </div>
        <div style="font-size:0.82rem;color:var(--text-secondary);margin-top:0.2rem;">
          Dosen Pembimbing: <strong>${student.dosen_pembimbing_name || 'Belum Ditetapkan'}</strong>
        </div>
      </div>
    </div>
  `;

  const reports = await apiFetch(`/api/reports?mahasiswa_id=${encodeURIComponent(student.id)}`);
  renderInteractiveReportsList(reports, listEl, async () => {
    await renderAdminStudentReportsPanel(student);
    await Promise.all([loadAdminData(), loadStats(), loadAdminLogs()]);
  });

  card.scrollIntoView({ behavior: 'smooth' });
}

// =========================================================
// 6. PANEL DOSEN PEMBIMBING: DAFTAR MAHASISWA BIMBINGAN & LAPORAN
// =========================================================
async function loadDosenStudents() {
  const scope = document.getElementById('dosenFilterScope').value;
  const supStatus = document.getElementById('dosenFilterSupervisionStatus').value;
  const searchVal = document.getElementById('dosenSearchStudent')?.value.trim() || '';
  const params = new URLSearchParams({ role: 'MAHASISWA' });

  if (scope === 'mine' && state.user?.id) {
    params.set('dosen_pembimbing_id', state.user.id);
  }
  if (supStatus) {
    params.set('supervision_status', supStatus);
  }
  if (searchVal) {
    params.set('search', searchVal);
  }

  const students = await apiFetch(`/api/users?${params.toString()}`);
  const tbody = document.getElementById('dosenStudentsTableBody');

  if (students.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align:center;color:var(--text-secondary);">
          Tidak ada mahasiswa bimbingan yang sesuai filter.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = students
    .map((m) => {
      const isSelected = state.selectedDosenStudentId === m.id;
      return `
        <tr style="${isSelected ? 'background:#EFF6FF;' : ''}">
          <td>
            <a href="#dosenReportsList" class="student-name-link dosen-select-student" data-student-id="${m.id}" data-student-name="${m.name}">
              ${m.name}
            </a><br/>
            <small style="color:var(--text-secondary);">${m.nip_or_npm}</small>
          </td>
          <td><span class="badge badge-degree">${m.degree || 'S1'}</span></td>
          <td><strong>${m.start_academic_year || '-'}</strong></td>
          <td>
            <div style="font-size:0.84rem;">${m.thesis_title || '<em>Judul belum diisi</em>'}</div>
            <small style="color:var(--text-secondary);">Pembimbing: ${m.dosen_pembimbing_name || '-'}</small>
          </td>
          <td>
            <div style="margin-bottom:0.35rem;">${formatSupervisionStatus(m.supervision_status)}</div>
            <div style="display:flex;gap:0.35rem;align-items:center;flex-wrap:wrap;">
              <select class="form-control dosen-sup-status-select" data-user-id="${m.id}" style="width:auto;padding:0.22rem 0.45rem;font-size:0.75rem;">
                <option value="DALAM_BIMBINGAN" ${m.supervision_status === 'DALAM_BIMBINGAN' ? 'selected' : ''}>Sedang Dalam Bimbingan</option>
                <option value="LULUS" ${m.supervision_status === 'LULUS' ? 'selected' : ''}>Sudah Lulus</option>
                <option value="TIDAK_SELESAI" ${m.supervision_status === 'TIDAK_SELESAI' ? 'selected' : ''}>Tidak Selesai</option>
              </select>
              <button type="button" class="btn btn-outline btn-sm btn-dosen-save-sup-status" data-user-id="${m.id}">
                Ubah Status
              </button>
            </div>
          </td>
          <td>
            <button type="button" class="btn btn-primary btn-sm dosen-select-student" data-student-id="${m.id}" data-student-name="${m.name}">
              Lihat Laporan (${m.report_count || 0})
            </button>
          </td>
        </tr>
      `;
    })
    .join('');

  tbody.querySelectorAll('.dosen-select-student').forEach((el) => {
    el.addEventListener('click', async (e) => {
      e.preventDefault();
      state.selectedDosenStudentId = el.getAttribute('data-student-id');
      state.selectedDosenStudentName = el.getAttribute('data-student-name');
      document.getElementById('btnResetSelectedStudent').classList.remove('hidden');
      document.getElementById('dosenReportsHeaderTitle').textContent =
        `Daftar Laporan & Komentar: ${state.selectedDosenStudentName}`;
      await loadDosenStudents();
      await loadDosenReports();
    });
  });

  tbody.querySelectorAll('.btn-dosen-save-sup-status').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const userId = btn.getAttribute('data-user-id');
      const selectEl = tbody.querySelector(`.dosen-sup-status-select[data-user-id="${userId}"]`);
      const supervision_status = selectEl.value;
      try {
        await apiFetch(`/api/mahasiswa/${userId}`, {
          method: 'PUT',
          body: JSON.stringify({ supervision_status })
        });
        showAlert('Status bimbingan mahasiswa berhasil diperbarui.', 'success');
        await Promise.all([loadDosenStudents(), loadDosenReports(), loadStats(), loadDosenLogs()]);
      } catch (err) {
        showAlert(err.message, 'error');
      }
    });
  });
}

async function loadDosenReports() {
  const scope = document.getElementById('dosenFilterScope').value;
  const degree = document.getElementById('dosenFilterDegree').value;
  const status = document.getElementById('dosenFilterStatus').value;
  const params = new URLSearchParams();

  if (state.selectedDosenStudentId) {
    params.set('mahasiswa_id', state.selectedDosenStudentId);
  } else if (scope === 'mine' && state.user?.id) {
    params.set('dosen_pembimbing_id', state.user.id);
  }

  if (degree) params.set('degree', degree);
  if (status) params.set('status', status);

  const reports = await apiFetch(`/api/reports?${params.toString()}`);
  const listEl = document.getElementById('dosenReportsList');

  renderInteractiveReportsList(reports, listEl, async () => {
    await Promise.all([loadDosenReports(), loadDosenStudents(), loadStats(), loadDosenLogs()]);
  });
}

// Komponen Render Daftar Laporan + Komentar + Form Komentar HTML Editor (Digunakan Dosen & Admin)
function renderInteractiveReportsList(reports, containerEl, onAfterUpdate) {
  if (!reports || reports.length === 0) {
    containerEl.innerHTML =
      '<p style="color:var(--text-secondary);">Belum ada laporan kemajuan untuk ditampilkan.</p>';
    return;
  }

  containerEl.innerHTML = reports
    .map((r) => {
      const attachmentsHtml = (r.attachments || [])
        .map(
          (a) =>
            `<a href="${a.file_path}" target="_blank" rel="noopener" class="badge badge-dosen" style="text-decoration:none;margin-right:0.4rem;">
              📎 ${a.file_name} (${(a.file_size_bytes / (1024 * 1024)).toFixed(2)} MB)
            </a>`
        )
        .join('');

      const feedbacksHtml =
        (r.feedbacks || []).length > 0
          ? r.feedbacks
              .map(
                (f) => `
                <div class="feedback-box">
                  <strong>Komentar / Evaluasi oleh ${f.dosen_name}</strong> •
                  <small>${new Date(f.created_at).toLocaleString('id-ID')}</small>
                  <div style="margin-top:0.35rem;">${f.feedback_html}</div>
                  ${
                    f.followup_notes_html
                      ? `<div style="margin-top:0.4rem;border-top:1px dashed #FCD34D;padding-top:0.35rem;">
                           <strong>Catatan Tindak Lanjut:</strong> ${f.followup_notes_html}
                         </div>`
                      : ''
                  }
                </div>
              `
              )
              .join('')
          : `<p style="font-size:0.82rem;color:var(--text-secondary);margin-top:0.4rem;"><em>Belum ada komentar pada laporan ini.</em></p>`;

      const fbEditorId = `fbEditor_${r.id.replace(/[^a-zA-Z0-9]/g, '')}_${Math.random().toString(36).slice(2, 6)}`;
      const followupEditorId = `fuEditor_${r.id.replace(/[^a-zA-Z0-9]/g, '')}_${Math.random().toString(36).slice(2, 6)}`;

      return `
        <div class="report-item">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;flex-wrap:wrap;">
            <div>
              <span class="badge badge-degree">${r.degree || 'S1'}</span>
              ${formatSupervisionStatus(r.supervision_status)}
              <strong style="font-size:1rem;color:var(--navy-primary);margin-left:0.35rem;">${r.title}</strong>
              <div style="font-size:0.82rem;color:var(--text-secondary);margin-top:0.25rem;">
                Mahasiswa: <strong>${r.mahasiswa_name}</strong> (${r.mahasiswa_npm}) •
                T.A. Laporan: <strong>${r.academic_year_id}</strong> (Mulai Bimbingan: ${r.start_academic_year || '-'}) •
                Pembimbing: ${r.dosen_pembimbing_name || '-'}
              </div>
            </div>
            <div style="display:flex;gap:0.45rem;align-items:center;flex-wrap:wrap;">
              <span class="badge badge-${r.status}">Status Laporan: ${r.status}</span>
              <button type="button" class="btn btn-outline btn-sm btn-export-single-report" data-report-id="${r.id}">
                📥 Unduh Excel
              </button>
            </div>
          </div>

          <div class="report-html-content">${r.report_html}</div>
          ${attachmentsHtml ? `<div style="margin-bottom:0.6rem;">${attachmentsHtml}</div>` : ''}

          <div style="margin-top:0.5rem;">
            <strong style="font-size:0.84rem;color:var(--navy-primary);">
              Daftar Komentar &amp; Asistensi (${(r.feedbacks || []).length}):
            </strong>
            ${feedbacksHtml}
          </div>

          <details style="margin-top:0.85rem;">
            <summary style="cursor:pointer;font-weight:700;font-size:0.85rem;color:var(--navy-primary);">
              + Tambahkan Komentar / Evaluasi Baru &amp; Ubah Status Laporan (HTML Editor)
            </summary>
            <form class="dosen-feedback-form" data-report-id="${r.id}" data-fb-editor="${fbEditorId}" data-fu-editor="${followupEditorId}" style="margin-top:0.75rem;background:#F8FAFC;padding:0.95rem;border-radius:8px;border:1px solid var(--border-color);">
              <div class="form-group">
                <label class="form-label">Komentar / Umpan Balik Evaluasi (HTML Editor — Tersanitasi Anti-XSS)</label>
                ${buildWysiwygHtml(fbEditorId, '<p>Tuliskan komentar evaluasi terhadap laporan mahasiswa...</p>', true)}
              </div>
              <div class="form-group">
                <label class="form-label">Catatan Tindak Lanjut / Follow-up Notes (HTML Editor)</label>
                ${buildWysiwygHtml(followupEditorId, '', true)}
              </div>
              <div class="form-group">
                <label class="form-label">Perbarui Status Laporan</label>
                <select class="form-control fb-status">
                  <option value="REVIEWED" ${r.status === 'REVIEWED' ? 'selected' : ''}>REVIEWED (Telah Direview)</option>
                  <option value="REVISION_NEEDED" ${r.status === 'REVISION_NEEDED' ? 'selected' : ''}>REVISION_NEEDED (Perlu Revisi)</option>
                  <option value="APPROVED" ${r.status === 'APPROVED' ? 'selected' : ''}>APPROVED (Disetujui)</option>
                </select>
              </div>
              <button type="submit" class="btn btn-primary btn-sm">Simpan Komentar &amp; Status</button>
            </form>
          </details>
        </div>
      `;
    })
    .join('');

  initWysiwygToolbars(containerEl);

  containerEl.querySelectorAll('.btn-export-single-report').forEach((btn) => {
    btn.addEventListener('click', () => {
      const report_id = btn.getAttribute('data-report-id');
      downloadExcelProgress({ report_id });
    });
  });

  containerEl.querySelectorAll('.dosen-feedback-form').forEach((form) => {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const reportId = form.getAttribute('data-report-id');
      const fbEditorId = form.getAttribute('data-fb-editor');
      const fuEditorId = form.getAttribute('data-fu-editor');

      const feedback_html = document.getElementById(fbEditorId)?.innerHTML.trim() || '';
      const followup_notes_html = document.getElementById(fuEditorId)?.innerHTML.trim() || '';
      const status = form.querySelector('.fb-status').value;

      if (!feedback_html) {
        showAlert('Isi komentar evaluasi tidak boleh kosong.', 'error');
        return;
      }

      try {
        await apiFetch(`/api/reports/${reportId}/feedback`, {
          method: 'POST',
          body: JSON.stringify({ feedback_html, followup_notes_html, status })
        });
        showAlert('Komentar evaluasi dan status laporan berhasil disimpan.', 'success');
        if (onAfterUpdate) await onAfterUpdate();
      } catch (err) {
        showAlert(err.message, 'error');
      }
    });
  });
}

// =========================================================
// 7. PANEL MAHASISWA: PROFIL, UNGGAH LAPORAN, & DAFTAR KOMENTAR
// =========================================================
function renderMahasiswaProfile() {
  const card = document.getElementById('mahasiswaProfileCard');
  const mp = state.user?.mahasiswa_profile || {};
  const thesisEditorId = 'mhsSelfThesisEditor';

  card.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem;">
      <div style="flex:1;min-width:280px;">
        <div style="display:flex;gap:0.45rem;align-items:center;flex-wrap:wrap;">
          <span class="badge badge-degree">Jenjang ${mp.degree || 'S1'}</span>
          <span class="badge badge-mahasiswa">Tahun Ajaran Mulai: ${mp.start_academic_year || '-'}</span>
          ${formatSupervisionStatus(mp.supervision_status)}
        </div>
        <h3 style="color:var(--navy-primary);margin-top:0.55rem;">
          ${mp.thesis_title || 'Judul Tugas Akhir Belum Ditetapkan'}
        </h3>
        <p style="font-size:0.86rem;color:var(--text-secondary);margin-top:0.25rem;">
          Dosen Pembimbing: <strong>${mp.dosen_pembimbing_name || 'Belum Ditentukan'}</strong>
        </p>

        <details style="margin-top:0.7rem;">
          <summary style="cursor:pointer;font-size:0.82rem;font-weight:700;color:var(--navy-primary);">
            Ubah Judul Tugas Akhir (HTML Editor)
          </summary>
          <div style="margin-top:0.5rem;">
            ${buildWysiwygHtml(thesisEditorId, mp.thesis_title || '', true)}
            <button type="button" class="btn btn-primary btn-sm" id="btnSaveSelfThesis" style="margin-top:0.45rem;">
              Simpan Judul TA
            </button>
          </div>
        </details>
      </div>
    </div>
  `;

  initWysiwygToolbars(card);

  const btnSave = document.getElementById('btnSaveSelfThesis');
  if (btnSave) {
    btnSave.addEventListener('click', async () => {
      const thesis_title = document.getElementById(thesisEditorId)?.innerHTML || '';
      try {
        const updated = await apiFetch(`/api/mahasiswa/${state.user.id}`, {
          method: 'PUT',
          body: JSON.stringify({ thesis_title })
        });
        state.user.mahasiswa_profile.thesis_title = updated.thesis_title;
        renderMahasiswaProfile();
        showAlert('Judul Tugas Akhir berhasil diperbarui.', 'success');
      } catch (err) {
        showAlert(err.message, 'error');
      }
    });
  }
}

async function loadMahasiswaReports() {
  const reports = await apiFetch('/api/reports');
  const listEl = document.getElementById('mahasiswaReportsList');

  if (reports.length === 0) {
    listEl.innerHTML = '<p style="color:var(--text-secondary);">Anda belum mengunggah laporan kemajuan.</p>';
    return;
  }

  listEl.innerHTML = reports
    .map((r) => {
      const attachmentsHtml = (r.attachments || [])
        .map(
          (a) =>
            `<a href="${a.file_path}" target="_blank" rel="noopener" class="badge badge-dosen" style="text-decoration:none;margin-right:0.4rem;">
              📎 ${a.file_name} (${(a.file_size_bytes / (1024 * 1024)).toFixed(2)} MB)
            </a>`
        )
        .join('');

      const feedbacksHtml =
        (r.feedbacks || []).length > 0
          ? r.feedbacks
              .map(
                (f) => `
                <div class="feedback-box">
                  <strong>Komentar Dosen (${f.dosen_name})</strong> •
                  <small>${new Date(f.created_at).toLocaleString('id-ID')}</small>
                  <div style="margin-top:0.25rem;">${f.feedback_html}</div>
                  ${
                    f.followup_notes_html
                      ? `<div style="margin-top:0.35rem;border-top:1px dashed #FCD34D;padding-top:0.3rem;">
                           <strong>Catatan Tindak Lanjut:</strong> ${f.followup_notes_html}
                         </div>`
                      : ''
                  }
                </div>
              `
              )
              .join('')
          : `<p style="font-size:0.8rem;color:var(--text-secondary);margin-top:0.4rem;"><em>Belum ada komentar dari dosen pembimbing.</em></p>`;

      return `
        <div class="report-item">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;flex-wrap:wrap;">
            <strong style="color:var(--navy-primary);">${r.title}</strong>
            <div style="display:flex;gap:0.45rem;align-items:center;flex-wrap:wrap;">
              <span class="badge badge-${r.status}">${r.status}</span>
              <button type="button" class="btn btn-outline btn-sm btn-mhs-export-single" data-report-id="${r.id}">
                📥 Unduh Excel
              </button>
            </div>
          </div>
          <small style="color:var(--text-secondary);">
            Tahun Ajaran ${r.academic_year_id} • Diunggah: ${new Date(r.created_at).toLocaleString('id-ID')}
          </small>
          <div class="report-html-content">${r.report_html}</div>
          ${attachmentsHtml ? `<div style="margin-bottom:0.55rem;">${attachmentsHtml}</div>` : ''}
          <div style="margin-top:0.45rem;">
            <strong style="font-size:0.82rem;color:var(--navy-primary);">
              Komentar &amp; Evaluasi Dosen (${(r.feedbacks || []).length}):
            </strong>
            ${feedbacksHtml}
          </div>
        </div>
      `;
    })
    .join('');

  listEl.querySelectorAll('.btn-mhs-export-single').forEach((btn) => {
    btn.addEventListener('click', () => {
      const report_id = btn.getAttribute('data-report-id');
      downloadExcelProgress({ report_id });
    });
  });
}

// =========================================================
// 8. EVENT LISTENERS UTAMA
// =========================================================
document.addEventListener('DOMContentLoaded', async () => {
  await Promise.all([checkDatabaseStatus(), loadPublicDosenForRegistration()]);
  initWysiwygToolbars();
  initSandbox();

  // Toggle antara Tab Login & Tab Daftar Akun Baru pada halaman Login
  const loginForm = document.getElementById('loginForm');
  const selfRegisterForm = document.getElementById('selfRegisterForm');
  const btnShowLoginTab = document.getElementById('btnShowLoginTab');
  const btnShowRegisterTab = document.getElementById('btnShowRegisterTab');
  const authCardTitle = document.getElementById('authCardTitle');

  const showLoginTab = () => {
    loginForm.classList.remove('hidden');
    selfRegisterForm.classList.add('hidden');
    btnShowLoginTab.className = 'btn btn-primary btn-sm';
    btnShowRegisterTab.className = 'btn btn-outline btn-sm';
    authCardTitle.textContent = 'Masuk ke Portal SIMTA';
  };

  const showRegisterTab = () => {
    loginForm.classList.add('hidden');
    selfRegisterForm.classList.remove('hidden');
    btnShowRegisterTab.className = 'btn btn-primary btn-sm';
    btnShowLoginTab.className = 'btn btn-outline btn-sm';
    authCardTitle.textContent = 'Pendaftaran Akun Baru SIMTA';
    loadPublicDosenForRegistration();
  };

  btnShowLoginTab.addEventListener('click', showLoginTab);
  btnShowRegisterTab.addEventListener('click', showRegisterTab);
  document.getElementById('linkToRegister').addEventListener('click', showRegisterTab);

  // Toggle field khusus mahasiswa pada form pendaftaran mandiri
  const regRoleSelect = document.getElementById('regRole');
  regRoleSelect.addEventListener('change', () => {
    const regMhsFields = document.getElementById('regMahasiswaFields');
    if (regRoleSelect.value === 'MAHASISWA') {
      regMhsFields.classList.remove('hidden');
    } else {
      regMhsFields.classList.add('hidden');
    }
  });

  // Submit Pendaftaran Akun Mandiri
  selfRegisterForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      role: regRoleSelect.value,
      nip_or_npm: document.getElementById('regNipNpm').value,
      name: document.getElementById('regName').value,
      email: document.getElementById('regEmail').value,
      password: document.getElementById('regPassword').value,
      degree: document.getElementById('regDegree').value,
      start_academic_year: document.getElementById('regAcademicYear').value,
      dosen_pembimbing_id: document.getElementById('regDosenPembimbing').value || null,
      thesis_title: document.getElementById('regThesisEditor').innerHTML.trim()
    };

    try {
      const res = await apiFetch('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      showAlert(res.message, 'success');
      selfRegisterForm.reset();
      document.getElementById('regThesisEditor').innerHTML = '';
      showLoginTab();
    } catch (err) {
      showAlert(err.message, 'error');
    }
  });

  // Login submit
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const identifier = document.getElementById('loginIdentifier').value;
    const password = document.getElementById('loginPassword').value;

    try {
      const data = await apiFetch('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ identifier, password })
      });
      state.token = data.token;
      state.user = data.user;
      state.activeViewRole = data.user.roles[0];
      localStorage.setItem('simta_token', data.token);
      document.getElementById('loginPassword').value = '';
      enterAuthenticatedState();
    } catch (err) {
      showAlert(err.message, 'error');
    }
  });

  // Logout
  document.getElementById('btnLogout').addEventListener('click', () => {
    state.token = null;
    state.user = null;
    localStorage.removeItem('simta_token');
    document.getElementById('loginIdentifier').value = '';
    document.getElementById('loginPassword').value = '';
    document.getElementById('appSection').classList.add('hidden');
    document.getElementById('userChip').classList.add('hidden');
    document.getElementById('roleSwitcherContainer').classList.add('hidden');
    document.getElementById('loginSection').classList.remove('hidden');
  });

  // Tutup panel laporan mahasiswa pada mode Admin
  document.getElementById('btnCloseAdminStudentReports').addEventListener('click', () => {
    document.getElementById('adminStudentReportsCard').classList.add('hidden');
    state.selectedAdminStudent = null;
  });

  // Tombol Unduh Excel pada panel laporan mahasiswa di Mode Admin
  document.getElementById('btnExportAdminStudentExcel').addEventListener('click', () => {
    if (state.selectedAdminStudent?.id) {
      downloadExcelProgress({ mahasiswa_id: state.selectedAdminStudent.id });
    }
  });

  // Tombol Unduh Excel pada Mode Dosen
  document.getElementById('btnDosenExportExcel').addEventListener('click', () => {
    const scope = document.getElementById('dosenFilterScope').value;
    const degree = document.getElementById('dosenFilterDegree').value;
    const status = document.getElementById('dosenFilterStatus').value;
    const params = {};

    if (state.selectedDosenStudentId) {
      params.mahasiswa_id = state.selectedDosenStudentId;
    } else if (scope === 'mine' && state.user?.id) {
      params.dosen_pembimbing_id = state.user.id;
    }
    if (degree) params.degree = degree;
    if (status) params.status = status;

    downloadExcelProgress(params);
  });

  // Tombol Unduh Excel pada Mode Mahasiswa
  document.getElementById('btnMahasiswaExportExcel').addEventListener('click', () => {
    downloadExcelProgress({});
  });

  // Filter & Refresh Log Aktivitas pada Mode Admin dan Mode Dosen
  document.getElementById('adminLogTypeFilter').addEventListener('change', () => {
    state.pagination.adminLogs.page = 1;
    loadAdminLogs();
  });
  document.getElementById('btnRefreshAdminLogs').addEventListener('click', loadAdminLogs);
  document.getElementById('dosenLogTypeFilter').addEventListener('change', () => {
    state.pagination.dosenLogs.page = 1;
    loadDosenLogs();
  });
  document.getElementById('btnRefreshDosenLogs').addEventListener('click', loadDosenLogs);

  // Batal ubah akun pada mode Admin
  document.getElementById('btnCancelEditUser').addEventListener('click', () => {
    resetUserFormToCreate();
  });

  // Live RBAC check pada form pengguna
  const roleCheckboxes = document.querySelectorAll('input[name="newUserRole"]');
  const updateRoleFormState = () => {
    const selected = Array.from(roleCheckboxes)
      .filter((c) => c.checked)
      .map((c) => c.value);
    const mhsFields = document.getElementById('mahasiswaExtraFields');
    const staffStatusField = document.getElementById('staffStatusField');
    const hint = document.getElementById('liveRoleHint');

    if (selected.includes('MAHASISWA')) {
      mhsFields.classList.remove('hidden');
      staffStatusField.classList.add('hidden');
    } else {
      mhsFields.classList.add('hidden');
      staffStatusField.classList.remove('hidden');
    }

    const hasMhs = selected.includes('MAHASISWA');
    const hasAdminOrDosen = selected.includes('ADMIN') || selected.includes('DOSEN');

    if (hasMhs && hasAdminOrDosen) {
      hint.style.color = 'var(--danger)';
      hint.textContent =
        '⚠ Pelanggaran RBAC: Role MAHASISWA tidak boleh digabung dengan role ADMIN atau DOSEN.';
    } else if (selected.length === 0) {
      hint.style.color = 'var(--danger)';
      hint.textContent = '⚠ Pilih minimal satu role.';
    } else {
      hint.style.color = 'var(--success)';
      hint.textContent = `✓ Kombinasi role [${selected.join(', ')}] valid.`;
    }
  };
  roleCheckboxes.forEach((cb) => cb.addEventListener('change', updateRoleFormState));
  updateRoleFormState();

  // Submit form Tambah / Ubah Pengguna (Admin)
  document.getElementById('userForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const editUserId = document.getElementById('editUserId').value;
    const roles = Array.from(roleCheckboxes)
      .filter((c) => c.checked)
      .map((c) => c.value);

    const payload = {
      nip_or_npm: document.getElementById('newNipNpm').value,
      name: document.getElementById('newName').value,
      email: document.getElementById('newEmail').value,
      password: document.getElementById('newPassword').value,
      is_active: document.getElementById('newIsActive').value === 'true',
      roles,
      degree: document.getElementById('newDegree').value,
      start_academic_year: document.getElementById('newAcademicYear').value,
      supervision_status: document.getElementById('newSupervisionStatus').value,
      dosen_pembimbing_id: document.getElementById('newDosenPembimbing').value || null,
      thesis_title: document.getElementById('newThesisEditor').innerHTML.trim()
    };

    try {
      if (editUserId) {
        await apiFetch(`/api/users/${editUserId}`, {
          method: 'PUT',
          body: JSON.stringify(payload)
        });
        showAlert('Data akun pengguna berhasil diperbarui.', 'success');
      } else {
        await apiFetch('/api/users', {
          method: 'POST',
          body: JSON.stringify(payload)
        });
        showAlert('Pengguna baru berhasil ditambahkan.', 'success');
      }
      resetUserFormToCreate();
      await Promise.all([loadAdminData(), loadStats(), loadAdminLogs()]);
    } catch (err) {
      showAlert(err.message, 'error');
    }
  });

  document.getElementById('filterUserRole').addEventListener('change', () => {
    state.pagination.adminUsers.page = 1;
    loadAdminData();
  });
  document.getElementById('filterApprovalStatus').addEventListener('change', () => {
    state.pagination.adminUsers.page = 1;
    loadAdminData();
  });
  document.getElementById('adminSearchUser').addEventListener('input', () => {
    state.pagination.adminUsers.page = 1;
    loadAdminData();
  });
  document.getElementById('dosenSearchStudent').addEventListener('input', () => {
    loadDosenStudents();
  });

  // Filter pada mode Dosen
  document.getElementById('dosenFilterScope').addEventListener('change', async () => {
    state.selectedDosenStudentId = null;
    document.getElementById('btnResetSelectedStudent').classList.add('hidden');
    document.getElementById('dosenReportsHeaderTitle').textContent =
      'Daftar Laporan Kemajuan & Komentar Bimbingan';
    await loadDosenStudents();
    await loadDosenReports();
  });
  document.getElementById('dosenFilterSupervisionStatus').addEventListener('change', loadDosenStudents);
  document.getElementById('dosenFilterDegree').addEventListener('change', loadDosenReports);
  document.getElementById('dosenFilterStatus').addEventListener('change', loadDosenReports);

  document.getElementById('btnResetSelectedStudent').addEventListener('click', async () => {
    state.selectedDosenStudentId = null;
    state.selectedDosenStudentName = null;
    document.getElementById('btnResetSelectedStudent').classList.add('hidden');
    document.getElementById('dosenReportsHeaderTitle').textContent =
      'Daftar Laporan Kemajuan & Komentar Bimbingan';
    await loadDosenStudents();
    await loadDosenReports();
  });

  // Validasi live ukuran berkas lampiran (Maks 10MB)
  const fileInput = document.getElementById('reportFiles');
  const quotaBar = document.getElementById('fileQuotaBar');
  const quotaText = document.getElementById('fileQuotaText');
  const submitBtn = document.getElementById('btnSubmitReport');

  fileInput.addEventListener('change', () => {
    const files = Array.from(fileInput.files || []);
    const totalBytes = files.reduce((acc, f) => acc + f.size, 0);
    const totalMb = (totalBytes / (1024 * 1024)).toFixed(2);
    const pct = Math.min(100, (totalBytes / MAX_BYTES) * 100);

    const invalidFile = files.find((f) => {
      const lower = (f.name || '').toLowerCase();
      const dotIdx = lower.lastIndexOf('.');
      const ext = dotIdx >= 0 ? lower.slice(dotIdx) : '';
      return !ALLOWED_EXTS.has(ext);
    });

    quotaBar.style.width = `${pct}%`;
    if (invalidFile) {
      quotaBar.classList.add('danger');
      quotaText.style.color = 'var(--danger)';
      quotaText.textContent = `✗ Berkas "${invalidFile.name}" memiliki ekstensi yang dilarang!`;
      submitBtn.disabled = true;
    } else if (totalBytes > MAX_BYTES) {
      quotaBar.classList.add('danger');
      quotaText.style.color = 'var(--danger)';
      quotaText.textContent = `✗ Total berkas ${totalMb} MB melebihi batas maksimal 10.00 MB!`;
      submitBtn.disabled = true;
    } else {
      quotaBar.classList.remove('danger');
      quotaText.style.color = 'var(--text-secondary)';
      quotaText.textContent = `Total ukuran berkas: ${totalMb} MB / 10.00 MB`;
      submitBtn.disabled = false;
    }
  });

  // Submit Progress Report (Mahasiswa)
  document.getElementById('createReportForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const files = Array.from(fileInput.files || []);
    const totalBytes = files.reduce((acc, f) => acc + f.size, 0);
    if (totalBytes > MAX_BYTES) {
      showAlert('Total berkas melebihi batas maksimal 10MB.', 'error');
      return;
    }

    const formData = new FormData();
    formData.append('academic_year_id', document.getElementById('reportAcademicYear').value);
    formData.append('status', document.getElementById('reportStatusInput').value);
    formData.append('title', document.getElementById('reportTitle').value);
    formData.append('report_html', document.getElementById('reportEditor').innerHTML);
    files.forEach((f) => formData.append('attachments', f));

    try {
      await apiFetch('/api/reports', {
        method: 'POST',
        body: formData
      });
      showAlert('Laporan kemajuan berhasil disimpan.', 'success');
      document.getElementById('reportTitle').value = '';
      fileInput.value = '';
      quotaBar.style.width = '0%';
      quotaText.textContent = 'Total ukuran berkas: 0.00 MB / 10.00 MB';
      await loadMahasiswaReports();
      await loadStats();
    } catch (err) {
      showAlert(err.message, 'error');
    }
  });

  // Restore session jika token tersimpan
  if (state.token) {
    try {
      const me = await apiFetch('/api/auth/me');
      state.user = me;
      state.activeViewRole = me.roles[0];
      enterAuthenticatedState();
    } catch {
      localStorage.removeItem('simta_token');
      state.token = null;
    }
  }
});

function enterAuthenticatedState() {
  document.getElementById('loginSection').classList.add('hidden');
  document.getElementById('appSection').classList.remove('hidden');
  const userChip = document.getElementById('userChip');
  userChip.classList.remove('hidden');
  document.getElementById('currentUserName').textContent = `${state.user.name} (${state.user.roles.join(' + ')})`;
  renderRoleSwitcher();
  switchActiveRoleView();
}
