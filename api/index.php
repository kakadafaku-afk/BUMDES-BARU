<?php
// =======================================================
// REST API Router Utama untuk InfinityFree (PHP)
// =======================================================

// Jangan tampilkan notice HTML di output JSON
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);
ini_set('display_errors', '0');

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
header("Content-Type: application/json; charset=UTF-8");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once __DIR__ . "/db.php";
require_once __DIR__ . "/auth.php";

$pdo = getDb();
$method = $_SERVER['REQUEST_METHOD'];

// Parse URL Path
$requestUri = $_SERVER['REQUEST_URI'];
$basePath = parse_url($requestUri, PHP_URL_PATH);

// Bersihkan prefix /api
$path = preg_replace('/^.*?\/api(\/|$)/', '', $basePath);
$segments = explode('/', trim($path, '/'));

$resource = isset($segments[0]) ? $segments[0] : '';
$subResource = isset($segments[1]) ? $segments[1] : null;

// Parse Body JSON
$rawInput = file_get_contents('php://input');
$body = json_decode($rawInput, true) ?: [];

try {
    // ----------------------------------------------------
    // HEALTH CHECK
    // ----------------------------------------------------
    if ($resource === "health") {
        echo json_encode(["status" => "ok", "message" => "API PHP InfinityFree Aktif", "time" => date("Y-m-d H:i:s")]);
        exit;
    }

    // ----------------------------------------------------
    // 1. AUTH
    // ----------------------------------------------------
    if ($resource === "auth") {
        if ($subResource === "login" && $method === "POST") {
            $username = isset($body['username']) ? trim($body['username']) : '';
            $password = isset($body['password']) ? trim($body['password']) : '';

            if (!$username || !$password) {
                http_response_code(400);
                echo json_encode(["error" => "Username dan password wajib diisi."]);
                exit;
            }

            $stmt = $pdo->prepare("SELECT * FROM admins WHERE username = ?");
            $stmt->execute([$username]);
            $admin = $stmt->fetch();

            // Self-healing: jika akun default 'admin' belum ada di database, buat otomatis
            if (!$admin && $username === 'admin') {
                $passHash = password_hash('admin123', PASSWORD_BCRYPT);
                $ins = $pdo->prepare("INSERT INTO admins (id, username, password, nama, role) VALUES (1, 'admin', ?, 'Administrator Desa', 'SUPERADMIN')");
                $ins->execute([$passHash]);

                $stmt->execute([$username]);
                $admin = $stmt->fetch();
            }

            if (!$admin) {
                http_response_code(401);
                echo json_encode(["error" => "Username atau kata sandi salah."]);
                exit;
            }

            $plainSaved = isset($admin['password_plain']) && $admin['password_plain'] !== '' ? $admin['password_plain'] : null;
            $match = password_verify($password, $admin['password'])
                || ($plainSaved !== null && hash_equals($plainSaved, $password))
                || ($plainSaved === null && $password === 'admin123' && $username === 'admin');

            if (!$match) {
                http_response_code(401);
                echo json_encode(["error" => "Username atau kata sandi salah."]);
                exit;
            }

            if ($plainSaved !== $password) {
                try {
                    $upPlain = $pdo->prepare("UPDATE admins SET password_plain = ? WHERE id = ?");
                    $upPlain->execute([$password, $admin['id']]);
                    $admin['password_plain'] = $password;
                } catch (Throwable $ignore) {}
            }

            $token = createToken($admin);
            echo json_encode([
                "message" => "Login berhasil",
                "token" => $token,
                "expiresIn" => 7200,
                "user" => [
                    "id" => (int)$admin['id'],
                    "username" => $admin['username'],
                    "nama" => $admin['nama'],
                    "role" => $admin['role'],
                    "passwordPlain" => $admin['password_plain'] ?? $password,
                    "createdAt" => $admin['created_at'] ?? null,
                ]
            ]);
            exit;
        }

        if ($subResource === "logout" && ($method === "POST" || $method === "GET")) {
            header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
            $jwt = getCurrentJwtToken();
            if ($jwt) {
                revokeJwtToken($jwt);
            }
            echo json_encode([
                "message" => "Sesi berhasil diakhiri. Silakan login ulang untuk mengakses halaman Admin."
            ]);
            exit;
        }

        if ($subResource === "me" && $method === "GET") {
            $user = requireAuth();

            $admin = null;
            if (!empty($user['id'])) {
                $stmt = $pdo->prepare("SELECT * FROM admins WHERE id = ?");
                $stmt->execute([$user['id']]);
                $admin = $stmt->fetch();
            }
            if (!$admin && !empty($user['username'])) {
                $stmt = $pdo->prepare("SELECT * FROM admins WHERE username = ?");
                $stmt->execute([$user['username']]);
                $admin = $stmt->fetch();
            }

            // Gunakan payload JWT yang telah terverifikasi secara kriptografis sebagai fallback terpercaya
            if (!$admin) {
                $admin = [
                    "id" => (int)($user['id'] ?? 1),
                    "username" => $user['username'] ?? 'admin',
                    "nama" => $user['nama'] ?? 'Administrator Desa',
                    "role" => $user['role'] ?? 'SUPERADMIN',
                    "password_plain" => 'admin123',
                ];
            }

            echo json_encode([
                "id" => (int)$admin['id'],
                "username" => $admin['username'],
                "nama" => $admin['nama'],
                "role" => $admin['role'],
                "passwordPlain" => !empty($admin['password_plain']) ? $admin['password_plain'] : 'admin123',
                "createdAt" => $admin['created_at'] ?? null,
            ]);
            exit;
        }

        if ($subResource === "account" && ($method === "PUT" || $method === "POST")) {
            $user = requireAuth();

            $admin = null;
            if (!empty($user['id'])) {
                $stmt = $pdo->prepare("SELECT * FROM admins WHERE id = ?");
                $stmt->execute([$user['id']]);
                $admin = $stmt->fetch();
            }
            if (!$admin && !empty($user['username'])) {
                $stmt = $pdo->prepare("SELECT * FROM admins WHERE username = ?");
                $stmt->execute([$user['username']]);
                $admin = $stmt->fetch();
            }

            if (!$admin) {
                http_response_code(404);
                echo json_encode(["error" => "Data akun admin tidak ditemukan."]);
                exit;
            }

            $currentPassword = isset($body['currentPassword']) ? trim($body['currentPassword']) : '';
            $newUsername = isset($body['username']) && trim($body['username']) !== '' ? trim($body['username']) : $admin['username'];
            $newNama = isset($body['nama']) && trim($body['nama']) !== '' ? trim($body['nama']) : $admin['nama'];
            $newPassword = isset($body['newPassword']) ? trim($body['newPassword']) : '';

            if (!$currentPassword) {
                http_response_code(400);
                echo json_encode(["error" => "Masukkan password saat ini untuk verifikasi keamanan."]);
                exit;
            }

            $plainSaved = !empty($admin['password_plain']) ? $admin['password_plain'] : 'admin123';
            $validCurrent = password_verify($currentPassword, $admin['password']) || hash_equals($plainSaved, $currentPassword);
            if (!$validCurrent) {
                http_response_code(400);
                echo json_encode(["error" => "Password saat ini yang Anda masukkan tidak sesuai."]);
                exit;
            }

            if ($newPassword !== '' && strlen($newPassword) < 5) {
                http_response_code(400);
                echo json_encode(["error" => "Password baru minimal harus terdiri dari 5 karakter."]);
                exit;
            }

            // Cek jika username diubah apakah bentrok dengan admin lain
            if ($newUsername !== $admin['username']) {
                $chk = $pdo->prepare("SELECT id FROM admins WHERE username = ? AND id != ?");
                $chk->execute([$newUsername, $admin['id']]);
                if ($chk->fetch()) {
                    http_response_code(400);
                    echo json_encode(["error" => "Username tersebut sudah digunakan."]);
                    exit;
                }
            }

            $finalPlainPassword = $newPassword !== '' ? $newPassword : $currentPassword;
            $finalHashPassword = password_hash($finalPlainPassword, PASSWORD_BCRYPT);

            $upd = $pdo->prepare("UPDATE admins SET username = ?, nama = ?, password = ?, password_plain = ? WHERE id = ?");
            $upd->execute([$newUsername, $newNama, $finalHashPassword, $finalPlainPassword, $admin['id']]);

            $updatedAdmin = [
                "id" => (int)$admin['id'],
                "username" => $newUsername,
                "nama" => $newNama,
                "role" => $admin['role'],
                "passwordPlain" => $finalPlainPassword,
                "createdAt" => $admin['created_at'] ?? null,
            ];

            $newToken = createToken($updatedAdmin);

            echo json_encode([
                "message" => "Akun & kata sandi berhasil diperbarui!",
                "token" => $newToken,
                "user" => $updatedAdmin
            ]);
            exit;
        }
    }

    // ----------------------------------------------------
    // 2. PROFIL DESA
    // ----------------------------------------------------
    if ($resource === "profil") {
        try {
            $pdo->exec("ALTER TABLE profil_desa ADD COLUMN foto_hero LONGTEXT DEFAULT NULL");
        } catch (Throwable $ignore) {}
        try {
            $pdo->exec("ALTER TABLE profil_desa ADD COLUMN foto_unit_wisata LONGTEXT DEFAULT NULL");
        } catch (Throwable $ignore) {}

        if ($method === "GET") {
            $stmt = $pdo->query("SELECT * FROM profil_desa WHERE id = 1");
            $row = $stmt->fetch();
            if (!$row) {
                echo json_encode([
                    "id" => 1,
                    "namaDesa" => "BUMDes Sedya Makmur",
                    "kecamatan" => "Mayong",
                    "kabupaten" => "Jepara",
                    "provinsi" => "Jawa Tengah",
                    "visi" => "Menjadi BUMDes yang profesional, mandiri dan berdaya saing, berbasis potensi lokal untuk kesejahteraan masyarakat Desa Mayong Lor.",
                    "misi" => [
                        "Mengembangkan potensi desa",
                        "Meningkatkan kesejahteraan masyarakat",
                        "Melestarikan budaya lokal",
                        "Mendukung program pemerintah",
                        "Memberikan pelayanan usaha yang profesional dan berkelanjutan",
                    ],
                    "alamatKantor" => "Kompleks Balaidesa Mayong Lor, Kec. Mayong, Kab. Jepara",
                    "jamPelayanan" => "Senin–Sabtu, 08.00–16.00 WIB",
                    "noTelepon" => "0878 2124 4536",
                    "emailDesa" => "bumdesmayonglor@gmail.com",
                    "fotoHero" => null,
                    "fotoUnitWisata" => (object)[],
                ]);
                exit;
            }

            $misiArr = json_decode($row['misi'], true);
            if (!is_array($misiArr)) $misiArr = [$row['misi']];

            $fotoUnitWisata = !empty($row['foto_unit_wisata']) ? json_decode($row['foto_unit_wisata'], true) : [];
            if (!is_array($fotoUnitWisata)) $fotoUnitWisata = [];

            echo json_encode([
                "id" => (int)$row['id'],
                "namaDesa" => $row['nama_desa'],
                "kecamatan" => $row['kecamatan'],
                "kabupaten" => $row['kabupaten'],
                "provinsi" => $row['provinsi'],
                "visi" => $row['visi'],
                "misi" => $misiArr,
                "alamatKantor" => $row['alamat_kantor'],
                "jamPelayanan" => $row['jam_pelayanan'],
                "noTelepon" => $row['no_telepon'],
                "emailDesa" => $row['email_desa'],
                "fotoHero" => $row['foto_hero'] ?? null,
                "fotoUnitWisata" => (object)$fotoUnitWisata,
            ]);
            exit;
        }

        if ($method === "PUT") {
            requireAuth();
            $existingStmt = $pdo->query("SELECT * FROM profil_desa WHERE id = 1");
            $existingRow = $existingStmt->fetch() ?: [];

            $namaDesa = isset($body['namaDesa']) ? $body['namaDesa'] : ($existingRow['nama_desa'] ?? 'BUMDes Sedya Makmur');
            $kecamatan = isset($body['kecamatan']) ? $body['kecamatan'] : ($existingRow['kecamatan'] ?? 'Mayong');
            $kabupaten = isset($body['kabupaten']) ? $body['kabupaten'] : ($existingRow['kabupaten'] ?? 'Jepara');
            $provinsi = isset($body['provinsi']) ? $body['provinsi'] : ($existingRow['provinsi'] ?? 'Jawa Tengah');
            $visi = isset($body['visi']) ? $body['visi'] : ($existingRow['visi'] ?? '');
            $misi = isset($body['misi']) ? (is_array($body['misi']) ? json_encode($body['misi']) : $body['misi']) : ($existingRow['misi'] ?? '[]');
            $alamat = isset($body['alamatKantor']) ? $body['alamatKantor'] : ($existingRow['alamat_kantor'] ?? '');
            $jam = isset($body['jamPelayanan']) ? $body['jamPelayanan'] : ($existingRow['jam_pelayanan'] ?? '');
            $telp = isset($body['noTelepon']) ? $body['noTelepon'] : ($existingRow['no_telepon'] ?? '');
            $email = isset($body['emailDesa']) ? $body['emailDesa'] : ($existingRow['email_desa'] ?? '');
            $fotoHero = array_key_exists('fotoHero', $body)
                ? (trim((string)$body['fotoHero']) !== '' ? trim((string)$body['fotoHero']) : null)
                : ($existingRow['foto_hero'] ?? null);

            $fotoUnitWisataJson = $existingRow['foto_unit_wisata'] ?? '{}';
            if (array_key_exists('fotoUnitWisata', $body)) {
                $fotoUnitWisataJson = is_array($body['fotoUnitWisata'])
                    ? json_encode($body['fotoUnitWisata'])
                    : (is_string($body['fotoUnitWisata']) ? $body['fotoUnitWisata'] : '{}');
            }

            $stmt = $pdo->prepare("
                INSERT INTO profil_desa (
                    id, nama_desa, kecamatan, kabupaten, provinsi, 
                    visi, misi, alamat_kantor, jam_pelayanan, 
                    no_telepon, email_desa, foto_hero, foto_unit_wisata
                ) VALUES (
                    1, ?, ?, ?, ?, 
                    ?, ?, ?, ?, 
                    ?, ?, ?, ?
                )
                ON DUPLICATE KEY UPDATE 
                    nama_desa = VALUES(nama_desa),
                    kecamatan = VALUES(kecamatan),
                    kabupaten = VALUES(kabupaten),
                    provinsi = VALUES(provinsi),
                    visi = VALUES(visi),
                    misi = VALUES(misi),
                    alamat_kantor = VALUES(alamat_kantor),
                    jam_pelayanan = VALUES(jam_pelayanan),
                    no_telepon = VALUES(no_telepon),
                    email_desa = VALUES(email_desa),
                    foto_hero = VALUES(foto_hero),
                    foto_unit_wisata = VALUES(foto_unit_wisata)
            ");
            $stmt->execute([$namaDesa, $kecamatan, $kabupaten, $provinsi, $visi, $misi, $alamat, $jam, $telp, $email, $fotoHero, $fotoUnitWisataJson]);

            $misiArr = json_decode($misi, true);
            if (!is_array($misiArr)) $misiArr = [$misi];
            $fotoUnitWisataOut = json_decode($fotoUnitWisataJson, true);
            if (!is_array($fotoUnitWisataOut)) $fotoUnitWisataOut = [];

            echo json_encode([
                "id" => 1,
                "namaDesa" => $namaDesa,
                "kecamatan" => $kecamatan,
                "kabupaten" => $kabupaten,
                "provinsi" => $provinsi,
                "visi" => $visi,
                "misi" => $misiArr,
                "alamatKantor" => $alamat,
                "jamPelayanan" => $jam,
                "noTelepon" => $telp,
                "emailDesa" => $email,
                "fotoHero" => $fotoHero,
                "fotoUnitWisata" => (object)$fotoUnitWisataOut,
            ]);
            exit;
        }
    }

    // ----------------------------------------------------
    // 3. STATISTIK
    // ----------------------------------------------------
    if ($resource === "stats") {
        if ($method === "GET") {
            $stmt = $pdo->query("SELECT * FROM statistik ORDER BY urutan ASC, id ASC");
            $rows = $stmt->fetchAll();
            $data = array_map(function($r) {
                return [
                    "id" => (int)$r['id'],
                    "label" => $r['label'],
                    "nilai" => (int)$r['nilai'],
                    "icon" => $r['icon'],
                    "urutan" => (int)$r['urutan'],
                ];
            }, $rows);
            echo json_encode($data);
            exit;
        }

        if ($method === "PUT" && $subResource) {
            requireAuth();
            $id = (int)$subResource;
            $nilai = isset($body['nilai']) ? (int)$body['nilai'] : 0;
            $stmt = $pdo->prepare("UPDATE statistik SET nilai = ? WHERE id = ?");
            $stmt->execute([$nilai, $id]);
            echo json_encode(["message" => "Statistik berhasil diperbarui."]);
            exit;
        }
    }

    // ----------------------------------------------------
    // 4. BERITA
    // ----------------------------------------------------
    if ($resource === "berita") {
        try {
            $pdo->exec("ALTER TABLE berita ADD COLUMN gambar LONGTEXT DEFAULT NULL");
        } catch (Throwable $ignore) {}

        $formatTanggalIndoPhp = function () {
            $bulan = [1 => 'Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember'];
            return date('j') . ' ' . $bulan[(int)date('n')] . ' ' . date('Y');
        };

        if ($method === "GET" && !$subResource) {
            $stmt = $pdo->query("SELECT * FROM berita ORDER BY id DESC");
            $rows = $stmt->fetchAll();
            $data = array_map(function($r) {
                return [
                    "id" => (int)$r['id'],
                    "judul" => $r['judul'],
                    "kategori" => $r['kategori'],
                    "tanggal" => $r['tanggal'],
                    "ringkasan" => $r['ringkasan'],
                    "isi" => $r['isi'] ?: $r['ringkasan'],
                    "gambar" => $r['gambar'],
                    "createdAt" => $r['created_at'] ?? null,
                ];
            }, $rows);
            echo json_encode($data);
            exit;
        }

        if ($method === "GET" && $subResource) {
            $stmt = $pdo->prepare("SELECT * FROM berita WHERE id = ? LIMIT 1");
            $stmt->execute([(int)$subResource]);
            $r = $stmt->fetch();
            if (!$r) {
                http_response_code(404);
                echo json_encode(["error" => "Berita tidak ditemukan."]);
                exit;
            }
            echo json_encode([
                "id" => (int)$r['id'],
                "judul" => $r['judul'],
                "kategori" => $r['kategori'],
                "tanggal" => $r['tanggal'],
                "ringkasan" => $r['ringkasan'],
                "isi" => $r['isi'] ?: $r['ringkasan'],
                "gambar" => $r['gambar'],
                "createdAt" => $r['created_at'] ?? null,
            ]);
            exit;
        }

        if ($method === "POST") {
            requireAuth();
            $judul = isset($body['judul']) ? trim($body['judul']) : '';
            $kategori = isset($body['kategori']) ? trim($body['kategori']) : 'Pembangunan';
            $tanggal = isset($body['tanggal']) && trim($body['tanggal']) !== '' ? trim($body['tanggal']) : $formatTanggalIndoPhp();
            $ringkasan = isset($body['ringkasan']) ? trim($body['ringkasan']) : '';
            $isi = isset($body['isi']) ? trim($body['isi']) : $ringkasan;
            $gambar = isset($body['gambar']) ? trim($body['gambar']) : (isset($body['imageUrl']) ? trim($body['imageUrl']) : null);

            if (!$judul || !$ringkasan) {
                http_response_code(400);
                echo json_encode(["error" => "Judul dan ringkasan wajib diisi."]);
                exit;
            }

            $stmt = $pdo->prepare("INSERT INTO berita (judul, kategori, tanggal, ringkasan, isi, gambar) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute([$judul, $kategori, $tanggal, $ringkasan, $isi, $gambar]);
            $newId = $pdo->lastInsertId();

            echo json_encode([
                "id" => (int)$newId,
                "judul" => $judul,
                "kategori" => $kategori,
                "tanggal" => $tanggal,
                "ringkasan" => $ringkasan,
                "isi" => $isi,
                "gambar" => $gambar,
                "imageUrl" => $gambar,
            ]);
            exit;
        }

        if ($method === "PUT" && $subResource) {
            requireAuth();
            $id = (int)$subResource;
            $judul = isset($body['judul']) ? trim($body['judul']) : '';
            $kategori = isset($body['kategori']) ? trim($body['kategori']) : '';
            $tanggal = isset($body['tanggal']) ? trim($body['tanggal']) : '';
            $ringkasan = isset($body['ringkasan']) ? trim($body['ringkasan']) : '';
            $isi = isset($body['isi']) ? trim($body['isi']) : '';
            $hasGambarKey = array_key_exists('gambar', $body) || array_key_exists('imageUrl', $body);
            $gambar = isset($body['gambar']) ? trim((string)$body['gambar']) : (isset($body['imageUrl']) ? trim((string)$body['imageUrl']) : '');

            if ($hasGambarKey) {
                $stmt = $pdo->prepare("
                    UPDATE berita SET 
                        judul = COALESCE(NULLIF(?, ''), judul),
                        kategori = COALESCE(NULLIF(?, ''), kategori),
                        tanggal = COALESCE(NULLIF(?, ''), tanggal),
                        ringkasan = COALESCE(NULLIF(?, ''), ringkasan),
                        isi = COALESCE(NULLIF(?, ''), isi),
                        gambar = ?
                    WHERE id = ?
                ");
                $stmt->execute([$judul, $kategori, $tanggal, $ringkasan, $isi, $gambar !== '' ? $gambar : null, $id]);
            } else {
                $stmt = $pdo->prepare("
                    UPDATE berita SET 
                        judul = COALESCE(NULLIF(?, ''), judul),
                        kategori = COALESCE(NULLIF(?, ''), kategori),
                        tanggal = COALESCE(NULLIF(?, ''), tanggal),
                        ringkasan = COALESCE(NULLIF(?, ''), ringkasan),
                        isi = COALESCE(NULLIF(?, ''), isi)
                    WHERE id = ?
                ");
                $stmt->execute([$judul, $kategori, $tanggal, $ringkasan, $isi, $id]);
            }
            echo json_encode(["message" => "Berita berhasil diperbarui."]);
            exit;
        }

        if ($method === "DELETE" && $subResource) {
            requireAuth();
            $id = (int)$subResource;
            $stmt = $pdo->prepare("DELETE FROM berita WHERE id = ?");
            $stmt->execute([$id]);
            echo json_encode(["message" => "Berita berhasil dihapus."]);
            exit;
        }
    }

    // ----------------------------------------------------
    // 5. UMKM
    // ----------------------------------------------------
    if ($resource === "umkm") {
        try {
            $pdo->exec("ALTER TABLE umkm ADD COLUMN gambar LONGTEXT DEFAULT NULL");
        } catch (Throwable $ignore) {}

        if ($method === "GET") {
            $stmt = $pdo->query("SELECT * FROM umkm ORDER BY id DESC");
            $rows = $stmt->fetchAll();
            $data = array_map(function($r) {
                return [
                    "id" => (int)$r['id'],
                    "nama" => $r['nama'],
                    "kategori" => $r['kategori'],
                    "harga" => $r['harga'],
                    "kontakWa" => $r['kontak_wa'],
                    "deskripsi" => $r['deskripsi'],
                    "gambar" => $r['gambar'],
                    "imageUrl" => $r['gambar'],
                ];
            }, $rows);
            echo json_encode($data);
            exit;
        }

        if ($method === "POST") {
            requireAuth();
            $nama = isset($body['nama']) ? trim($body['nama']) : '';
            $kategori = isset($body['kategori']) ? trim($body['kategori']) : 'Kerajinan';
            $harga = isset($body['harga']) ? trim($body['harga']) : '';
            $kontakWa = isset($body['kontakWa']) ? preg_replace('/[^0-9]/', '', $body['kontakWa']) : '6281234567890';
            $deskripsi = isset($body['deskripsi']) ? trim($body['deskripsi']) : '';
            $gambar = isset($body['gambar']) ? trim($body['gambar']) : (isset($body['imageUrl']) ? trim($body['imageUrl']) : null);

            $stmt = $pdo->prepare("INSERT INTO umkm (nama, kategori, harga, kontak_wa, deskripsi, gambar) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute([$nama, $kategori, $harga, $kontakWa, $deskripsi, $gambar]);
            $newId = $pdo->lastInsertId();

            echo json_encode([
                "id" => (int)$newId,
                "nama" => $nama,
                "kategori" => $kategori,
                "harga" => $harga,
                "kontakWa" => $kontakWa,
                "deskripsi" => $deskripsi,
                "gambar" => $gambar,
                "imageUrl" => $gambar,
            ]);
            exit;
        }

        if ($method === "PUT" && $subResource) {
            requireAuth();
            $id = (int)$subResource;
            $nama = isset($body['nama']) ? trim($body['nama']) : '';
            $kategori = isset($body['kategori']) ? trim($body['kategori']) : '';
            $harga = isset($body['harga']) ? trim($body['harga']) : '';
            $kontakWa = isset($body['kontakWa']) ? preg_replace('/[^0-9]/', '', $body['kontakWa']) : '';
            $deskripsi = isset($body['deskripsi']) ? trim($body['deskripsi']) : '';
            $hasGambarKey = array_key_exists('gambar', $body) || array_key_exists('imageUrl', $body);
            $gambar = isset($body['gambar']) ? trim((string)$body['gambar']) : (isset($body['imageUrl']) ? trim((string)$body['imageUrl']) : '');

            if ($hasGambarKey) {
                $stmt = $pdo->prepare("
                    UPDATE umkm SET 
                        nama = COALESCE(NULLIF(?, ''), nama),
                        kategori = COALESCE(NULLIF(?, ''), kategori),
                        harga = COALESCE(NULLIF(?, ''), harga),
                        kontak_wa = COALESCE(NULLIF(?, ''), kontak_wa),
                        deskripsi = COALESCE(NULLIF(?, ''), deskripsi),
                        gambar = ?
                    WHERE id = ?
                ");
                $stmt->execute([$nama, $kategori, $harga, $kontakWa, $deskripsi, $gambar !== '' ? $gambar : null, $id]);
            } else {
                $stmt = $pdo->prepare("
                    UPDATE umkm SET 
                        nama = COALESCE(NULLIF(?, ''), nama),
                        kategori = COALESCE(NULLIF(?, ''), kategori),
                        harga = COALESCE(NULLIF(?, ''), harga),
                        kontak_wa = COALESCE(NULLIF(?, ''), kontak_wa),
                        deskripsi = COALESCE(NULLIF(?, ''), deskripsi)
                    WHERE id = ?
                ");
                $stmt->execute([$nama, $kategori, $harga, $kontakWa, $deskripsi, $id]);
            }
            echo json_encode(["message" => "Produk UMKM berhasil diperbarui."]);
            exit;
        }

        if ($method === "DELETE" && $subResource) {
            requireAuth();
            $id = (int)$subResource;
            $stmt = $pdo->prepare("DELETE FROM umkm WHERE id = ?");
            $stmt->execute([$id]);
            echo json_encode(["message" => "Produk berhasil dihapus."]);
            exit;
        }
    }

    // ----------------------------------------------------
    // 6. APBDES
    // ----------------------------------------------------
    if ($resource === "apbdes") {
        if ($method === "GET") {
            $stmt = $pdo->query("SELECT * FROM apbdes ORDER BY id ASC");
            $rows = $stmt->fetchAll();

            $pendapatan = [];
            $belanja = [];

            foreach ($rows as $r) {
                $item = [
                    "id" => (int)$r['id'],
                    "n" => $r['nama'],
                    "v" => (float)$r['nominal'],
                ];
                if (strtolower($r['kategori']) === 'pendapatan') {
                    $pendapatan[] = $item;
                } else {
                    $belanja[] = $item;
                }
            }

            echo json_encode([
                "raw" => $rows,
                "pendapatan" => $pendapatan,
                "belanja" => $belanja,
            ]);
            exit;
        }

        if ($method === "POST") {
            requireAuth();
            $kategori = isset($body['kategori']) ? strtolower($body['kategori']) : 'pendapatan';
            $nama = isset($body['nama']) ? trim($body['nama']) : '';
            $nominal = isset($body['nominal']) ? (float)$body['nominal'] : 0;
            $tahun = isset($body['tahun']) ? (int)$body['tahun'] : 2026;

            $stmt = $pdo->prepare("INSERT INTO apbdes (kategori, nama, nominal, tahun) VALUES (?, ?, ?, ?)");
            $stmt->execute([$kategori, $nama, $nominal, $tahun]);

            echo json_encode(["message" => "Pos APBDes berhasil ditambahkan."]);
            exit;
        }

        if ($method === "PUT" && $subResource) {
            requireAuth();
            $id = (int)$subResource;
            $kategori = isset($body['kategori']) ? strtolower($body['kategori']) : 'pendapatan';
            $nama = isset($body['nama']) ? trim($body['nama']) : '';
            $nominal = isset($body['nominal']) ? (float)$body['nominal'] : 0;

            $stmt = $pdo->prepare("UPDATE apbdes SET kategori = ?, nama = ?, nominal = ? WHERE id = ?");
            $stmt->execute([$kategori, $nama, $nominal, $id]);
            echo json_encode(["message" => "Pos APBDes berhasil diperbarui."]);
            exit;
        }

        if ($method === "DELETE" && $subResource) {
            requireAuth();
            $id = (int)$subResource;
            $stmt = $pdo->prepare("DELETE FROM apbdes WHERE id = ?");
            $stmt->execute([$id]);
            echo json_encode(["message" => "Pos APBDes berhasil dihapus."]);
            exit;
        }
    }

    // ----------------------------------------------------
    // 7. PERANGKAT DESA
    // ----------------------------------------------------
    if ($resource === "perangkat") {
        if ($method === "GET") {
            $stmt = $pdo->query("SELECT * FROM perangkat_desa ORDER BY urutan ASC, id ASC");
            $rows = $stmt->fetchAll();
            $data = array_map(function($r) {
                return [
                    "id" => (int)$r['id'],
                    "jabatan" => $r['jabatan'],
                    "nama" => $r['nama'],
                    "foto" => $r['foto'],
                    "urutan" => (int)$r['urutan'],
                ];
            }, $rows);
            echo json_encode($data);
            exit;
        }

        if ($method === "POST") {
            requireAuth();
            $jabatan = isset($body['jabatan']) ? trim($body['jabatan']) : '';
            $nama = isset($body['nama']) ? trim($body['nama']) : '';
            $urutan = isset($body['urutan']) && $body['urutan'] !== '' ? (int)$body['urutan'] : 0;
            $foto = isset($body['foto']) && trim((string)$body['foto']) !== '' ? trim((string)$body['foto']) : null;

            if (!$jabatan || !$nama) {
                http_response_code(400);
                echo json_encode(["error" => "Jabatan dan nama pengurus wajib diisi."]);
                exit;
            }

            $stmt = $pdo->prepare("INSERT INTO perangkat_desa (jabatan, nama, foto, urutan) VALUES (?, ?, ?, ?)");
            $stmt->execute([$jabatan, $nama, $foto, $urutan]);
            $newId = (int)$pdo->lastInsertId();
            http_response_code(201);
            echo json_encode([
                "id" => $newId,
                "jabatan" => $jabatan,
                "nama" => $nama,
                "foto" => $foto,
                "urutan" => $urutan,
                "message" => "Data pengurus berhasil ditambahkan.",
            ]);
            exit;
        }

        if ($method === "PUT" && $subResource) {
            requireAuth();
            $id = (int)$subResource;
            $existing = $pdo->prepare("SELECT * FROM perangkat_desa WHERE id = ?");
            $existing->execute([$id]);
            $row = $existing->fetch();
            if (!$row) {
                http_response_code(404);
                echo json_encode(["error" => "Data pengurus tidak ditemukan."]);
                exit;
            }

            $jabatan = isset($body['jabatan']) && trim($body['jabatan']) !== '' ? trim($body['jabatan']) : $row['jabatan'];
            $nama = isset($body['nama']) && trim($body['nama']) !== '' ? trim($body['nama']) : $row['nama'];
            $urutan = isset($body['urutan']) && $body['urutan'] !== '' ? (int)$body['urutan'] : (int)$row['urutan'];
            $foto = array_key_exists('foto', $body)
                ? (trim((string)$body['foto']) !== '' ? trim((string)$body['foto']) : null)
                : $row['foto'];

            $stmt = $pdo->prepare("UPDATE perangkat_desa SET jabatan = ?, nama = ?, foto = ?, urutan = ? WHERE id = ?");
            $stmt->execute([$jabatan, $nama, $foto, $urutan, $id]);
            echo json_encode([
                "id" => $id,
                "jabatan" => $jabatan,
                "nama" => $nama,
                "foto" => $foto,
                "urutan" => $urutan,
                "message" => "Data pengurus berhasil diperbarui.",
            ]);
            exit;
        }

        if ($method === "DELETE" && $subResource) {
            requireAuth();
            $id = (int)$subResource;
            $stmt = $pdo->prepare("DELETE FROM perangkat_desa WHERE id = ?");
            $stmt->execute([$id]);
            echo json_encode(["message" => "Data pengurus berhasil dihapus."]);
            exit;
        }
    }

    // ----------------------------------------------------
    // 8. PENGADUAN
    // ----------------------------------------------------
    if ($resource === "pengaduan") {
        if ($method === "GET") {
            requireAuth();
            $stmt = $pdo->query("SELECT * FROM pengaduan ORDER BY id DESC");
            $rows = $stmt->fetchAll();
            $data = array_map(function($r) {
                return [
                    "id" => (int)$r['id'],
                    "nama" => $r['nama'],
                    "email" => $r['email'],
                    "pesan" => $r['pesan'],
                    "status" => $r['status'],
                    "tanggapan" => $r['tanggapan'],
                    "createdAt" => $r['created_at'],
                ];
            }, $rows);
            echo json_encode($data);
            exit;
        }

        if ($method === "POST") {
            $nama = isset($body['nama']) ? trim($body['nama']) : '';
            $email = isset($body['email']) ? trim($body['email']) : '';
            $pesan = isset($body['pesan']) ? trim($body['pesan']) : '';

            if (!$nama || !$email || !$pesan) {
                http_response_code(400);
                echo json_encode(["error" => "Nama, email, dan pesan wajib diisi."]);
                exit;
            }

            $stmt = $pdo->prepare("INSERT INTO pengaduan (nama, email, pesan, status) VALUES (?, ?, ?, 'Baru')");
            $stmt->execute([$nama, $email, $pesan]);
            echo json_encode(["message" => "Pengaduan / pesan Anda berhasil dikirim ke pihak desa."]);
            exit;
        }

        if ($method === "PATCH" && $subResource) {
            requireAuth();
            $id = (int)$subResource;
            $status = isset($body['status']) ? trim($body['status']) : 'Baru';
            $tanggapan = isset($body['tanggapan']) ? trim($body['tanggapan']) : null;

            $stmt = $pdo->prepare("UPDATE pengaduan SET status = ?, tanggapan = ? WHERE id = ?");
            $stmt->execute([$status, $tanggapan, $id]);
            echo json_encode(["message" => "Pengaduan berhasil diperbarui."]);
            exit;
        }

        if ($method === "DELETE" && $subResource) {
            requireAuth();
            $id = (int)$subResource;
            $stmt = $pdo->prepare("DELETE FROM pengaduan WHERE id = ?");
            $stmt->execute([$id]);
            echo json_encode(["message" => "Pengaduan berhasil dihapus."]);
            exit;
        }
    }

    // ----------------------------------------------------
    // 9. PESANAN PRODUK & BOOKING WISATA / LAYANAN
    // ----------------------------------------------------
    if ($resource === "pesanan") {
        if (function_exists('ensurePesananTable')) {
            ensurePesananTable($pdo);
        }

        // Endpoint publik khusus Kalender Ketersediaan (tanpa data pribadi pemesan)
        if ($method === "GET" && $subResource === "jadwal") {
            $stmt = $pdo->query("SELECT id, jenis, nama_item, kategori_item, jumlah, tanggal_booking, status FROM pesanan WHERE jenis IN ('Booking Wisata', 'Booking Layanan Unit') AND COALESCE(status, 'Baru') != 'Dibatalkan' AND tanggal_booking IS NOT NULL AND TRIM(tanggal_booking) != '' ORDER BY tanggal_booking ASC, id DESC");
            $rows = $stmt->fetchAll();
            $jadwal = array_map(function($r) {
                return [
                    "id" => (int)$r['id'],
                    "jenis" => $r['jenis'],
                    "namaItem" => $r['nama_item'],
                    "kategoriItem" => $r['kategori_item'],
                    "jumlah" => $r['jumlah'],
                    "tanggalBooking" => trim((string)$r['tanggal_booking']),
                    "status" => $r['status'] ?: 'Baru',
                ];
            }, $rows);
            echo json_encode($jadwal);
            exit;
        }

        if ($method === "GET") {
            requireAuth();
            $stmt = $pdo->query("SELECT * FROM pesanan ORDER BY id DESC");
            $rows = $stmt->fetchAll();
            $data = array_map(function($r) {
                return [
                    "id" => (int)$r['id'],
                    "namaPembeli" => $r['nama_pembeli'],
                    "noWa" => $r['no_wa'],
                    "jenis" => $r['jenis'],
                    "namaItem" => $r['nama_item'],
                    "kategoriItem" => $r['kategori_item'],
                    "jumlah" => $r['jumlah'],
                    "hargaEstimasi" => $r['harga_estimasi'],
                    "tanggalBooking" => $r['tanggal_booking'],
                    "alamatCatatan" => $r['alamat_catatan'],
                    "status" => $r['status'],
                    "createdAt" => $r['created_at'],
                ];
            }, $rows);
            echo json_encode($data);
            exit;
        }

        if ($method === "POST") {
            $namaPembeli = isset($body['namaPembeli']) ? trim($body['namaPembeli']) : '';
            $noWa = isset($body['noWa']) ? trim($body['noWa']) : '';
            $jenis = isset($body['jenis']) && trim($body['jenis']) !== '' ? trim($body['jenis']) : 'Pembelian Produk';
            $namaItem = isset($body['namaItem']) ? trim($body['namaItem']) : '';
            $kategoriItem = isset($body['kategoriItem']) ? trim($body['kategoriItem']) : '';
            $jumlah = isset($body['jumlah']) && trim($body['jumlah']) !== '' ? trim($body['jumlah']) : '1';
            $hargaEstimasi = isset($body['hargaEstimasi']) && trim($body['hargaEstimasi']) !== '' ? trim($body['hargaEstimasi']) : '-';
            $tanggalBooking = isset($body['tanggalBooking']) && trim($body['tanggalBooking']) !== '' ? trim($body['tanggalBooking']) : date('Y-m-d');
            $alamatCatatan = isset($body['alamatCatatan']) ? trim($body['alamatCatatan']) : '';
            $status = isset($body['status']) && trim($body['status']) !== '' ? trim($body['status']) : 'Baru';

            if (!$namaPembeli || !$noWa || !$namaItem) {
                http_response_code(400);
                echo json_encode(["error" => "Nama pemesan, nomor WhatsApp, dan produk/layanan wajib diisi."]);
                exit;
            }

            $stmt = $pdo->prepare("INSERT INTO pesanan (nama_pembeli, no_wa, jenis, nama_item, kategori_item, jumlah, harga_estimasi, tanggal_booking, alamat_catatan, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$namaPembeli, $noWa, $jenis, $namaItem, $kategoriItem, $jumlah, $hargaEstimasi, $tanggalBooking, $alamatCatatan, $status]);
            $newId = (int)$pdo->lastInsertId();

            http_response_code(201);
            echo json_encode([
                "id" => $newId,
                "namaPembeli" => $namaPembeli,
                "noWa" => $noWa,
                "jenis" => $jenis,
                "namaItem" => $namaItem,
                "kategoriItem" => $kategoriItem,
                "jumlah" => $jumlah,
                "hargaEstimasi" => $hargaEstimasi,
                "tanggalBooking" => $tanggalBooking,
                "alamatCatatan" => $alamatCatatan,
                "status" => $status,
                "createdAt" => date("Y-m-d H:i:s"),
                "message" => "Data pembelian / booking berhasil dicatat."
            ]);
            exit;
        }

        if (($method === "PUT" || $method === "PATCH") && $subResource) {
            requireAuth();
            $id = (int)$subResource;

            $chk = $pdo->prepare("SELECT * FROM pesanan WHERE id = ?");
            $chk->execute([$id]);
            $existing = $chk->fetch();
            if (!$existing) {
                http_response_code(404);
                echo json_encode(["error" => "Data pesanan / booking tidak ditemukan."]);
                exit;
            }

            $namaPembeli = isset($body['namaPembeli']) && trim($body['namaPembeli']) !== '' ? trim($body['namaPembeli']) : $existing['nama_pembeli'];
            $noWa = isset($body['noWa']) && trim($body['noWa']) !== '' ? trim($body['noWa']) : $existing['no_wa'];
            $jenis = isset($body['jenis']) && trim($body['jenis']) !== '' ? trim($body['jenis']) : $existing['jenis'];
            $namaItem = isset($body['namaItem']) && trim($body['namaItem']) !== '' ? trim($body['namaItem']) : $existing['nama_item'];
            $kategoriItem = isset($body['kategoriItem']) ? trim($body['kategoriItem']) : $existing['kategori_item'];
            $jumlah = isset($body['jumlah']) && trim($body['jumlah']) !== '' ? trim($body['jumlah']) : $existing['jumlah'];
            $hargaEstimasi = isset($body['hargaEstimasi']) ? trim($body['hargaEstimasi']) : $existing['harga_estimasi'];
            $tanggalBooking = isset($body['tanggalBooking']) ? trim($body['tanggalBooking']) : $existing['tanggal_booking'];
            $alamatCatatan = isset($body['alamatCatatan']) ? trim($body['alamatCatatan']) : $existing['alamat_catatan'];
            $status = isset($body['status']) && trim($body['status']) !== '' ? trim($body['status']) : $existing['status'];

            $stmt = $pdo->prepare("UPDATE pesanan SET nama_pembeli = ?, no_wa = ?, jenis = ?, nama_item = ?, kategori_item = ?, jumlah = ?, harga_estimasi = ?, tanggal_booking = ?, alamat_catatan = ?, status = ? WHERE id = ?");
            $stmt->execute([$namaPembeli, $noWa, $jenis, $namaItem, $kategoriItem, $jumlah, $hargaEstimasi, $tanggalBooking, $alamatCatatan, $status, $id]);

            echo json_encode([
                "id" => $id,
                "namaPembeli" => $namaPembeli,
                "noWa" => $noWa,
                "jenis" => $jenis,
                "namaItem" => $namaItem,
                "kategoriItem" => $kategoriItem,
                "jumlah" => $jumlah,
                "hargaEstimasi" => $hargaEstimasi,
                "tanggalBooking" => $tanggalBooking,
                "alamatCatatan" => $alamatCatatan,
                "status" => $status,
                "createdAt" => $existing['created_at'],
                "message" => "Catatan pesanan / booking berhasil diperbarui."
            ]);
            exit;
        }

        if ($method === "DELETE" && $subResource) {
            requireAuth();
            $id = (int)$subResource;
            $stmt = $pdo->prepare("DELETE FROM pesanan WHERE id = ?");
            $stmt->execute([$id]);
            echo json_encode(["message" => "Catatan pesanan / booking berhasil dihapus."]);
            exit;
        }
    }

    // ----------------------------------------------------
    // 10. UPLOAD FOTO PRODUK (PNG / JPG / JPEG, MAKS 2 MB)
    // ----------------------------------------------------
    if ($resource === "upload" && $method === "POST") {
        requireAuth();
        $maxBytes = 2 * 1024 * 1024; // 2 MB = 2,097,152 bytes

        // A. Jika dikirim via multipart/form-data ($_FILES)
        $fileEntry = $_FILES['foto'] ?? $_FILES['file'] ?? null;
        if ($fileEntry && isset($fileEntry['tmp_name']) && is_uploaded_file($fileEntry['tmp_name'])) {
            $fileSize = (int)$fileEntry['size'];
            if ($fileSize <= 0) {
                http_response_code(400);
                echo json_encode(["error" => "File foto kosong atau gagal diunggah."]);
                exit;
            }
            if ($fileSize > $maxBytes) {
                http_response_code(400);
                echo json_encode(["error" => "Ukuran foto maksimal 2 MB."]);
                exit;
            }

            $imgInfo = @getimagesize($fileEntry['tmp_name']);
            $mime = $imgInfo ? ($imgInfo['mime'] ?? '') : '';
            if (!in_array($mime, ['image/png', 'image/jpeg', 'image/jpg'], true)) {
                http_response_code(400);
                echo json_encode(["error" => "Format foto harus PNG atau JPG/JPEG."]);
                exit;
            }

            $ext = ($mime === 'image/png') ? 'png' : 'jpg';
            $uploadDir = dirname(__DIR__) . '/uploads/produk';
            if (!is_dir($uploadDir)) {
                @mkdir($uploadDir, 0755, true);
            }
            $fileName = 'produk_' . date('Ymd_His') . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
            $targetPath = $uploadDir . '/' . $fileName;

            if (@move_uploaded_file($fileEntry['tmp_name'], $targetPath)) {
                echo json_encode([
                    "url" => "/uploads/produk/" . $fileName,
                    "size" => $fileSize,
                    "mime" => $mime,
                    "message" => "Foto produk berhasil diunggah."
                ]);
                exit;
            }

            $rawBytes = file_get_contents($fileEntry['tmp_name']);
            echo json_encode([
                "url" => "data:" . $mime . ";base64," . base64_encode($rawBytes),
                "size" => $fileSize,
                "mime" => $mime,
                "message" => "Foto produk berhasil diproses."
            ]);
            exit;
        }

        // B. Jika dikirim via JSON body (dataUrl base64)
        $dataUrl = isset($body['dataUrl']) ? trim((string)$body['dataUrl']) : '';
        if (!$dataUrl) {
            http_response_code(400);
            echo json_encode(["error" => "Data foto tidak ditemukan. Pilih foto PNG atau JPG maksimal 2 MB."]);
            exit;
        }

        if (!preg_match('/^data:image\/(png|jpe?g);base64,(.+)$/i', $dataUrl, $matches)) {
            http_response_code(400);
            echo json_encode(["error" => "Format foto tidak didukung. Gunakan format PNG atau JPG/JPEG."]);
            exit;
        }

        $formatType = strtolower($matches[1]);
        $base64Data = $matches[2];
        $decodedBytes = base64_decode($base64Data, true);
        if ($decodedBytes === false) {
            http_response_code(400);
            echo json_encode(["error" => "File foto rusak atau tidak valid."]);
            exit;
        }

        $byteLength = strlen($decodedBytes);
        if ($byteLength > $maxBytes) {
            http_response_code(400);
            echo json_encode(["error" => "Ukuran foto melebihi batas maksimal 2 MB."]);
            exit;
        }

        $imgInfo = @getimagesizefromstring($decodedBytes);
        $mime = $imgInfo ? ($imgInfo['mime'] ?? '') : '';
        if (!in_array($mime, ['image/png', 'image/jpeg', 'image/jpg'], true)) {
            http_response_code(400);
            echo json_encode(["error" => "File yang dipilih bukan gambar PNG atau JPG yang valid."]);
            exit;
        }

        $ext = ($mime === 'image/png') ? 'png' : 'jpg';
        $uploadDir = dirname(__DIR__) . '/uploads/produk';
        if (!is_dir($uploadDir)) {
            @mkdir($uploadDir, 0755, true);
        }
        $fileName = 'produk_' . date('Ymd_His') . '_' . bin2hex(random_bytes(4)) . '.' . $ext;
        $targetPath = $uploadDir . '/' . $fileName;

        if (@file_put_contents($targetPath, $decodedBytes) !== false) {
            echo json_encode([
                "url" => "/uploads/produk/" . $fileName,
                "size" => $byteLength,
                "mime" => $mime,
                "message" => "Foto produk berhasil diunggah."
            ]);
            exit;
        }

        // Fallback ke Data URL jika direktori lokal read-only
        echo json_encode([
            "url" => "data:" . $mime . ";base64," . base64_encode($decodedBytes),
            "size" => $byteLength,
            "mime" => $mime,
            "message" => "Foto produk berhasil disimpan."
        ]);
        exit;
    }

    // Endpoint tidak ditemukan
    http_response_code(404);
    echo json_encode(["error" => "Endpoint tidak ditemukan: /api/{$path}"]);

} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        "error" => "Terjadi kesalahan server: " . $e->getMessage(),
        "file" => basename($e->getFile()),
        "line" => $e->getLine()
    ]);
}
