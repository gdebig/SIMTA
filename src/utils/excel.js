const zlib = require('node:zlib');

/**
 * Konversi HTML sederhana menjadi teks bersih untuk sel Excel
 * @param {string} html
 * @returns {string}
 */
function stripHtmlToText(html) {
  if (!html || typeof html !== 'string') return '';
  return html
    .replace(/<\/(p|div|h1|h2|h3|li|blockquote|pre)>/gi, '\n')
    .replace(/<li>/gi, '• ')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function escapeXml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function colIndexToLetter(index) {
  let letter = '';
  let temp = index;
  while (temp >= 0) {
    letter = String.fromCharCode((temp % 26) + 65) + letter;
    temp = Math.floor(temp / 26) - 1;
  }
  return letter;
}

/**
 * Buat arsip ZIP (OpenXML .xlsx) di memori menggunakan zlib bawaan Node.js
 * @param {Array<{name: string, data: Buffer | string}>} files
 * @returns {Buffer}
 */
function createZipBuffer(files) {
  const localFileHeaders = [];
  const centralDirectoryHeaders = [];
  let offset = 0;

  // CRC32 Lookup Table
  const crcTable = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    crcTable[n] = c;
  }

  function crc32(buf) {
    let crc = 0xffffffff;
    for (let i = 0; i < buf.length; i++) {
      crc = crcTable[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
    }
    return (crc ^ 0xffffffff) >>> 0;
  }

  for (const file of files) {
    const nameBuf = Buffer.from(file.name, 'utf8');
    const uncompressedBuf = Buffer.isBuffer(file.data)
      ? file.data
      : Buffer.from(file.data, 'utf8');
    const compressedBuf = zlib.deflateRawSync(uncompressedBuf);
    const crc = crc32(uncompressedBuf);

    // Local file header (30 bytes + file name)
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0); // signature
    localHeader.writeUInt16LE(20, 4); // version needed
    localHeader.writeUInt16LE(0, 6); // flags
    localHeader.writeUInt16LE(8, 8); // compression method: deflate
    localHeader.writeUInt16LE(0, 10); // mod time
    localHeader.writeUInt16LE(0, 12); // mod date
    localHeader.writeUInt32LE(crc, 14); // crc32
    localHeader.writeUInt32LE(compressedBuf.length, 18); // compressed size
    localHeader.writeUInt32LE(uncompressedBuf.length, 22); // uncompressed size
    localHeader.writeUInt16LE(nameBuf.length, 26); // file name length
    localHeader.writeUInt16LE(0, 28); // extra field length

    localFileHeaders.push(localHeader, nameBuf, compressedBuf);

    // Central directory file header (46 bytes + file name)
    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0); // signature
    centralHeader.writeUInt16LE(20, 4); // version made by
    centralHeader.writeUInt16LE(20, 6); // version needed
    centralHeader.writeUInt16LE(0, 8); // flags
    centralHeader.writeUInt16LE(8, 10); // compression method: deflate
    centralHeader.writeUInt16LE(0, 12); // mod time
    centralHeader.writeUInt16LE(0, 14); // mod date
    centralHeader.writeUInt32LE(crc, 16); // crc32
    centralHeader.writeUInt32LE(compressedBuf.length, 20); // compressed size
    centralHeader.writeUInt32LE(uncompressedBuf.length, 24); // uncompressed size
    centralHeader.writeUInt16LE(nameBuf.length, 28); // file name length
    centralHeader.writeUInt16LE(0, 30); // extra field length
    centralHeader.writeUInt16LE(0, 32); // file comment length
    centralHeader.writeUInt16LE(0, 34); // disk number
    centralHeader.writeUInt16LE(0, 36); // internal attrs
    centralHeader.writeUInt32LE(0, 38); // external attrs
    centralHeader.writeUInt32LE(offset, 42); // relative offset

    centralDirectoryHeaders.push(centralHeader, nameBuf);
    offset += localHeader.length + nameBuf.length + compressedBuf.length;
  }

  const centralDirBuf = Buffer.concat(centralDirectoryHeaders);
  const endOfCentralDir = Buffer.alloc(22);
  endOfCentralDir.writeUInt32LE(0x06054b50, 0); // signature
  endOfCentralDir.writeUInt16LE(0, 4); // disk number
  endOfCentralDir.writeUInt16LE(0, 6); // start disk
  endOfCentralDir.writeUInt16LE(files.length, 8); // entries on disk
  endOfCentralDir.writeUInt16LE(files.length, 10); // total entries
  endOfCentralDir.writeUInt32LE(centralDirBuf.length, 12); // size of central dir
  endOfCentralDir.writeUInt32LE(offset, 16); // offset of central dir
  endOfCentralDir.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([...localFileHeaders, centralDirBuf, endOfCentralDir]);
}

/**
 * Bangun file Excel (.xlsx) dari daftar laporan progres SIMTA.
 * Setiap lampiran memiliki kolom Nama File dan kolom Link Unduh File (HYPERLINK aktif).
 *
 * @param {Array<Object>} reports
 * @param {string} baseUrl Contoh: http://localhost:3000
 * @returns {Buffer}
 */
function generateProgressExcelBuffer(reports, baseUrl) {
  const headers = [
    'No',
    'NPM Mahasiswa',
    'Nama Mahasiswa',
    'Jenjang',
    'Tahun Ajaran',
    'Status Bimbingan',
    'Dosen Pembimbing',
    'Judul Laporan Progress',
    'Status Laporan',
    'Isi Laporan Progress',
    'Komentar & Evaluasi Dosen',
    'Nama File Lampiran',
    'Link Unduh File Lampiran',
    'Waktu Dibuat'
  ];

  const rows = [];
  let rowCounter = 1;

  for (const r of reports) {
    const reportText = stripHtmlToText(r.report_html);
    const feedbackText = (r.feedbacks || [])
      .map((f) => {
        const mainFb = stripHtmlToText(f.feedback_html);
        const followUp = f.followup_notes_html
          ? ` [Tindak Lanjut: ${stripHtmlToText(f.followup_notes_html)}]`
          : '';
        return `${f.dosen_name}: ${mainFb}${followUp}`;
      })
      .join(' | ');

    const createdDate = r.created_at
      ? new Date(r.created_at).toISOString().replace('T', ' ').slice(0, 19)
      : '';

    const attachments = Array.isArray(r.attachments) && r.attachments.length > 0
      ? r.attachments
      : [null];

    for (const att of attachments) {
      const fileName = att ? att.file_name : 'Tidak ada lampiran';
      const downloadUrl = att
        ? `${baseUrl.replace(/\/$/, '')}${att.file_path.startsWith('/') ? '' : '/'}${att.file_path}`
        : '';

      rows.push({
        values: [
          rowCounter++,
          r.mahasiswa_npm || '-',
          r.mahasiswa_name || '-',
          r.degree || 'S1',
          r.academic_year_id || '-',
          r.supervision_status || 'DALAM_BIMBINGAN',
          r.dosen_pembimbing_name || '-',
          r.title || '-',
          r.status || 'SUBMITTED',
          reportText,
          feedbackText || 'Belum ada komentar',
          fileName,
          downloadUrl,
          createdDate
        ],
        attachment: att
          ? {
              fileName,
              downloadUrl
            }
          : null
      });
    }
  }

  const hyperlinks = [];
  let sheetRowsXml = '';

  // Row 1: Header Row (style s="1")
  let headerCellsXml = '';
  headers.forEach((h, colIdx) => {
    const cellRef = `${colIndexToLetter(colIdx)}1`;
    headerCellsXml += `<c r="${cellRef}" s="1" t="inlineStr"><is><t>${escapeXml(h)}</t></is></c>`;
  });
  sheetRowsXml += `<row r="1" ht="24" customHeight="1">${headerCellsXml}</row>`;

  // Data Rows
  rows.forEach((rowObj, idx) => {
    const excelRowNum = idx + 2;
    let rowCellsXml = '';

    rowObj.values.forEach((val, colIdx) => {
      const cellRef = `${colIndexToLetter(colIdx)}${excelRowNum}`;

      // Kolom ke-13 (index 12) adalah Link Unduh File Lampiran
      if (colIdx === 12 && rowObj.attachment) {
        const url = rowObj.attachment.downloadUrl;
        const label = `Unduh ${rowObj.attachment.fileName} (${url})`;
        const safeFormulaUrl = url.replace(/"/g, '""');
        const safeFormulaLabel = label.replace(/"/g, '""');

        hyperlinks.push({
          ref: cellRef,
          url,
          display: label
        });

        rowCellsXml += `<c r="${cellRef}" s="2" t="str"><f>HYPERLINK("${escapeXml(safeFormulaUrl)}","${escapeXml(safeFormulaLabel)}")</f><v>${escapeXml(label)}</v></c>`;
      } else if (typeof val === 'number') {
        rowCellsXml += `<c r="${cellRef}"><v>${val}</v></c>`;
      } else {
        rowCellsXml += `<c r="${cellRef}" t="inlineStr"><is><t>${escapeXml(val)}</t></is></c>`;
      }
    });

    sheetRowsXml += `<row r="${excelRowNum}">${rowCellsXml}</row>`;
  });

  // Hyperlinks XML & Relationships
  let hyperlinksXml = '';
  let sheetRelsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`;

  if (hyperlinks.length > 0) {
    hyperlinksXml = `<hyperlinks>`;
    hyperlinks.forEach((hl, i) => {
      const rId = `rId_hl_${i + 1}`;
      hyperlinksXml += `<hyperlink ref="${hl.ref}" r:id="${rId}" display="${escapeXml(hl.display)}"/>`;
      sheetRelsXml += `<Relationship Id="${rId}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="${escapeXml(hl.url)}" TargetMode="External"/>`;
    });
    hyperlinksXml += `</hyperlinks>`;
  }
  sheetRelsXml += `</Relationships>`;

  const sheetXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <cols>
    <col min="1" max="1" width="6" customWidth="1"/>
    <col min="2" max="2" width="16" customWidth="1"/>
    <col min="3" max="3" width="26" customWidth="1"/>
    <col min="4" max="5" width="14" customWidth="1"/>
    <col min="6" max="7" width="24" customWidth="1"/>
    <col min="8" max="8" width="32" customWidth="1"/>
    <col min="9" max="9" width="18" customWidth="1"/>
    <col min="10" max="11" width="42" customWidth="1"/>
    <col min="12" max="12" width="28" customWidth="1"/>
    <col min="13" max="13" width="48" customWidth="1"/>
    <col min="14" max="14" width="20" customWidth="1"/>
  </cols>
  <sheetData>${sheetRowsXml}</sheetData>
  ${hyperlinksXml}
</worksheet>`;

  const stylesXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="3">
    <font><sz val="11"/><name val="Calibri"/></font>
    <font><b/><sz val="11"/><color rgb="FFF8C300"/><name val="Calibri"/></font>
    <font><u/><sz val="11"/><color rgb="FF0369A1"/><name val="Calibri"/></font>
  </fonts>
  <fills count="3">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF002B49"/></patternFill></fill>
  </fills>
  <borders count="1">
    <border><left/><right/><top/><bottom/><diagonal/></border>
  </borders>
  <cellStyleXfs count="1">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>
  </cellStyleXfs>
  <cellXfs count="3">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>
    <xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/>
  </cellXfs>
</styleSheet>`;

  const workbookXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Laporan Progress SIMTA" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>`;

  const workbookRelsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`;

  const rootRelsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`;

  const contentTypesXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>`;

  return createZipBuffer([
    { name: '[Content_Types].xml', data: contentTypesXml },
    { name: '_rels/.rels', data: rootRelsXml },
    { name: 'xl/workbook.xml', data: workbookXml },
    { name: 'xl/_rels/workbook.xml.rels', data: workbookRelsXml },
    { name: 'xl/styles.xml', data: stylesXml },
    { name: 'xl/worksheets/sheet1.xml', data: sheetXml },
    { name: 'xl/worksheets/_rels/sheet1.xml.rels', data: sheetRelsXml }
  ]);
}

module.exports = {
  generateProgressExcelBuffer,
  stripHtmlToText
};

