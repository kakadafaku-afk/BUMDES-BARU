<?php
// =======================================================
// REST API Router Utama untuk InfinityFree (PHP)
// =======================================================

// Jangan tampilkan notice HTML di output JSON
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);
ini_set('display_errors', '0');

// Batasi CORS hanya ke domain resmi & localhost pengembangan
$reqOrigin = isset($_SERVER['HTTP_ORIGIN']) ? trim((string)$_SERVER['HTTP_ORIGIN']) : '';
$allowedOrigins = [
    'https://bumdessedyamakmur.my.id',
    'https://www.bumdessedyamakmur.my.id',
];
if ($reqOrigin !== '') {
    $parsedHost = strtolower((string)parse_url($reqOrigin, PHP_URL_HOST));
    $currHost = strtolower(explode(':', (string)($_SERVER['HTTP_HOST'] ?? ''))[0]);
    if (
        in_array($reqOrigin, $allowedOrigins, true) ||
        $parsedHost === 'localhost' ||
        $parsedHost === '127.0.0.1' ||
        ($currHost !== '' && $parsedHost === $currHost)
    ) {
        header("Access-Control-Allow-Origin: " . $reqOrigin);
        header("Vary: Origin");
    }
}
header("Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Authorization, X-Admin-Token, X-Requested-With");
header("Content-Type: application/json; charset=UTF-8");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Referrer-Policy: strict-origin-when-cross-origin");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$sanitizeImageValue = function ($val) {
    if (!is_string($val)) return null;
    $v = trim($val);
    if ($v === '') return null;
    if (preg_match('/^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+\/=]+$/i', $v) && strlen($v) <= 3000000) {
        return $v;
    }
    if (preg_match('#^https?://[^\s<>"\']+$#i', $v) && strlen($v) <= 1000) {
        return $v;
    }
    if (preg_match('#^/[A-Za-z0-9_\-./]+$#', $v) && strpos($v, '..') === false && strlen($v) <= 500) {
        return $v;
    }
    return null;
};

$dbConfigFile = file_exists(__DIR__ . "/db.php") ? (__DIR__ . "/db.php") : (__DIR__ . "/db.example.php");
require_once $dbConfigFile;
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
        echo json_encode(["status" => "ok", "message" => "API BUMDes Sedya Makmur Aktif", "time" => date("Y-m-d H:i:s")]);
        exit;
    }

    // ----------------------------------------------------
    // 1. AUTH
    // ----------------------------------------------------
    if ($resource === "auth") {
        if ($subResource === "login" && $method === "POST") {
            // Batasi maksimal 5 percobaan login gagal dalam 10 menit per IP
            if (!checkRateLimit('login_fail', 5, 600, false)) {
                http_response_code(429);
                echo json_encode(["error" => "Terlalu banyak percobaan login gagal. Silakan tunggu 10 menit lalu coba lagi."]);
                exit;
            }

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

            // Self-healing HANYA jika tabel admins benar-benar kosong sama sekali (0 akun)
            if (!$admin && $username === 'admin') {
                $totalAdmins = (int)($pdo->query("SELECT COUNT(*) FROM admins")->fetchColumn() ?: 0);
                if ($totalAdmins === 0) {
                    $passHash = password_hash('admin123', PASSWORD_BCRYPT);
                    $ins = $pdo->prepare("INSERT INTO admins (id, username, password, nama, role) VALUES (1, 'admin', ?, 'Administrator Desa', 'SUPERADMIN')");
                    $ins->execute([$passHash]);

                    $stmt->execute([$username]);
                    $admin = $stmt->fetch();
                }
            }

            if (!$admin) {
                recordRateLimitHit('login_fail', 600);
                http_response_code(401);
                echo json_encode(["error" => "Username atau kata sandi salah."]);
                exit;
            }

            $match = !empty($admin['password']) && password_verify($password, (string)$admin['password']);

            if (!$match) {
                recordRateLimitHit('login_fail', 600);
                http_response_code(401);
                echo json_encode(["error" => "Username atau kata sandi salah."]);
                exit;
            }

            clearRateLimit('login_fail');

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

            if (!$admin) {
                http_response_code(401);
                echo json_encode(["error" => "Akun admin tidak ditemukan atau sesi tidak lagi valid."]);
                exit;
            }

            echo json_encode([
                "id" => (int)$admin['id'],
                "username" => $admin['username'],
                "nama" => $admin['nama'],
                "role" => $admin['role'],
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
            $newUsername = isset($body['username']) && trim($body['username']) !== '' ? mb_substr(trim($body['username']), 0, 50) : $admin['username'];
            $newNama = isset($body['nama']) && trim($body['nama']) !== '' ? mb_substr(trim($body['nama']), 0, 100) : $admin['nama'];
            $newPassword = isset($body['newPassword']) ? trim($body['newPassword']) : '';

            if (!$currentPassword) {
                http_response_code(400);
                echo json_encode(["error" => "Masukkan password saat ini untuk verifikasi keamanan."]);
                exit;
            }

            $validCurrent = !empty($admin['password']) && password_verify($currentPassword, (string)$admin['password']);
            if (!$validCurrent) {
                http_response_code(400);
                echo json_encode(["error" => "Password saat ini yang Anda masukkan tidak sesuai."]);
                exit;
            }

            if ($newPassword !== '' && strlen($newPassword) < 6) {
                http_response_code(400);
                echo json_encode(["error" => "Password baru minimal harus terdiri dari 6 karakter."]);
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

            $upd = $pdo->prepare("UPDATE admins SET username = ?, nama = ?, password = ? WHERE id = ?");
            $upd->execute([$newUsername, $newNama, $finalHashPassword, $admin['id']]);
            // Bersihkan kolom legacy password_plain jika masih ada di skema DB lama
            try {
                $clr = $pdo->prepare("UPDATE admins SET password_plain = NULL WHERE id = ?");
                $clr->execute([$admin['id']]);
            } catch (Throwable $ignore) {}

            // Cabut token lama agar sesi lama tidak bisa dipakai ulang setelah kredensial diubah
            $oldJwt = getCurrentJwtToken();
            if ($oldJwt) {
                revokeJwtToken($oldJwt);
            }

            $updatedAdmin = [
                "id" => (int)$admin['id'],
                "username" => $newUsername,
                "nama" => $newNama,
                "role" => $admin['role'],
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
                "fotoHero" => null,
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
            $fotoHero = null;

            $fotoUnitWisataJson = $existingRow['foto_unit_wisata'] ?? '{}';
            if (array_key_exists('fotoUnitWisata', $body)) {
                $rawMap = is_array($body['fotoUnitWisata'])
                    ? $body['fotoUnitWisata']
                    : (is_string($body['fotoUnitWisata']) ? (json_decode($body['fotoUnitWisata'], true) ?: []) : []);
                $cleanMap = [];
                foreach ($rawMap as $k => $v) {
                    if (preg_match('/^(unit_[1-6]|wisata_[1-3])$/', (string)$k)) {
                        $cleanVal = $sanitizeImageValue($v);
                        if ($cleanVal !== null) {
                            $cleanMap[$k] = $cleanVal;
                        }
                    }
                }
                $fotoUnitWisataJson = json_encode($cleanMap);
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
        $formatTanggalIndoPhp = function () {
            $bulan = [1 => 'Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember'];
            return date('j') . ' ' . $bulan[(int)date('n')] . ' ' . date('Y');
        };

        $extractGaleriRow = function ($r) {
            $list = [];
            if (!empty($r['galeri'])) {
                $decoded = json_decode((string)$r['galeri'], true);
                if (is_array($decoded)) {
                    foreach ($decoded as $item) {
                        if (is_string($item) && trim($item) !== '') {
                            $list[] = trim($item);
                        }
                    }
                }
            }
            $cover = isset($r['gambar']) && is_string($r['gambar']) && trim($r['gambar']) !== '' ? trim($r['gambar']) : null;
            if (empty($list) && $cover !== null) {
                $list = [$cover];
            }
            if (!empty($list) && $cover === null) {
                $cover = $list[0];
            }
            return [$cover, array_slice($list, 0, 8)];
        };

        $normalizeGaleriInput = function ($bodyData) use ($sanitizeImageValue) {
            $hasGaleriKey = array_key_exists('galeri', $bodyData);
            $hasGambarKey = array_key_exists('gambar', $bodyData) || array_key_exists('imageUrl', $bodyData);
            if (!$hasGaleriKey && !$hasGambarKey) {
                return [false, null, null];
            }
            $list = [];
            if ($hasGaleriKey && is_array($bodyData['galeri'])) {
                foreach ($bodyData['galeri'] as $item) {
                    $clean = $sanitizeImageValue($item);
                    if ($clean !== null) {
                        $list[] = $clean;
                    }
                }
            } else {
                $single = isset($bodyData['gambar'])
                    ? $sanitizeImageValue($bodyData['gambar'])
                    : (isset($bodyData['imageUrl']) ? $sanitizeImageValue($bodyData['imageUrl']) : null);
                if ($single !== null) {
                    $list[] = $single;
                }
            }
            $list = array_slice(array_values($list), 0, 8);
            $cover = !empty($list) ? $list[0] : null;
            $galeriJson = !empty($list) ? json_encode($list) : null;
            return [true, $cover, $galeriJson, $list];
        };

        if ($method === "GET" && !$subResource) {
            // Daftar berita hanya mengirim 1 foto sampul + jumlahFoto agar loading Beranda di HP super cepat
            $stmt = $pdo->query("SELECT id, judul, kategori, tanggal, ringkasan, isi, gambar, galeri, created_at FROM berita ORDER BY id DESC");
            $rows = $stmt->fetchAll();
            $data = array_map(function($r) use ($extractGaleriRow) {
                list($cover, $galeriList) = $extractGaleriRow($r);
                return [
                    "id" => (int)$r['id'],
                    "judul" => $r['judul'],
                    "kategori" => $r['kategori'],
                    "tanggal" => $r['tanggal'],
                    "ringkasan" => $r['ringkasan'],
                    "isi" => $r['isi'] ?: $r['ringkasan'],
                    "gambar" => $cover,
                    "jumlahFoto" => count($galeriList),
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
            list($cover, $galeriList) = $extractGaleriRow($r);
            echo json_encode([
                "id" => (int)$r['id'],
                "judul" => $r['judul'],
                "kategori" => $r['kategori'],
                "tanggal" => $r['tanggal'],
                "ringkasan" => $r['ringkasan'],
                "isi" => $r['isi'] ?: $r['ringkasan'],
                "gambar" => $cover,
                "galeri" => $galeriList,
                "jumlahFoto" => count($galeriList),
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
            list(, $gambar, $galeriJson, $galeriList) = $normalizeGaleriInput($body);
            if (!is_array($galeriList)) $galeriList = [];

            if (!$judul || !$ringkasan) {
                http_response_code(400);
                echo json_encode(["error" => "Judul dan ringkasan wajib diisi."]);
                exit;
            }

            $stmt = $pdo->prepare("INSERT INTO berita (judul, kategori, tanggal, ringkasan, isi, gambar, galeri) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([$judul, $kategori, $tanggal, $ringkasan, $isi, $gambar, $galeriJson]);
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
                "galeri" => $galeriList,
                "jumlahFoto" => count($galeriList),
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
            list($hasPhotoPayload, $gambar, $galeriJson) = $normalizeGaleriInput($body);

            if ($hasPhotoPayload) {
                $stmt = $pdo->prepare("
                    UPDATE berita SET 
                        judul = COALESCE(NULLIF(?, ''), judul),
                        kategori = COALESCE(NULLIF(?, ''), kategori),
                        tanggal = COALESCE(NULLIF(?, ''), tanggal),
                        ringkasan = COALESCE(NULLIF(?, ''), ringkasan),
                        isi = COALESCE(NULLIF(?, ''), isi),
                        gambar = ?,
                        galeri = ?
                    WHERE id = ?
                ");
                $stmt->execute([$judul, $kategori, $tanggal, $ringkasan, $isi, $gambar, $galeriJson, $id]);
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
            $gambar = isset($body['gambar']) ? $sanitizeImageValue($body['gambar']) : (isset($body['imageUrl']) ? $sanitizeImageValue($body['imageUrl']) : null);

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
            $gambar = isset($body['gambar']) ? $sanitizeImageValue($body['gambar']) : (isset($body['imageUrl']) ? $sanitizeImageValue($body['imageUrl']) : null);

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
                $stmt->execute([$nama, $kategori, $harga, $kontakWa, $deskripsi, $gambar, $id]);
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
            $foto = isset($body['foto']) ? $sanitizeImageValue($body['foto']) : null;

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
                ? $sanitizeImageValue($body['foto'])
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
            if (!checkRateLimit('public_pengaduan', 5, 600, true)) {
                http_response_code(429);
                echo json_encode(["error" => "Terlalu banyak pengiriman pesan dalam waktu singkat. Silakan coba lagi beberapa menit lagi."]);
                exit;
            }

            $nama = isset($body['nama']) ? mb_substr(trim((string)$body['nama']), 0, 100) : '';
            $email = isset($body['email']) ? mb_substr(trim((string)$body['email']), 0, 120) : '';
            $pesan = isset($body['pesan']) ? mb_substr(trim((string)$body['pesan']), 0, 3000) : '';

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
            $hasAdminJwt = false;
            $rawJwt = getCurrentJwtToken();
            if ($rawJwt !== '' && !isJwtTokenRevoked($rawJwt)) {
                $parts = explode('.', $rawJwt);
                if (count($parts) === 3) {
                    $sig = base64UrlEncode(hash_hmac('sha256', $parts[0] . "." . $parts[1], $JWT_SECRET, true));
                    $pl = json_decode(base64UrlDecode($parts[1]), true);
                    if (hash_equals($sig, $parts[2]) && is_array($pl) && (!isset($pl['exp']) || $pl['exp'] >= time())) {
                        $hasAdminJwt = true;
                    }
                }
            }

            if (!$hasAdminJwt && !checkRateLimit('public_pesanan', 8, 600, true)) {
                http_response_code(429);
                echo json_encode(["error" => "Terlalu banyak pengajuan pesanan/booking dalam waktu singkat. Silakan tunggu beberapa menit."]);
                exit;
            }

            $namaPembeli = isset($body['namaPembeli']) ? mb_substr(trim((string)$body['namaPembeli']), 0, 120) : '';
            $noWa = isset($body['noWa']) ? mb_substr(trim((string)$body['noWa']), 0, 40) : '';
            $jenis = isset($body['jenis']) && trim((string)$body['jenis']) !== '' ? mb_substr(trim((string)$body['jenis']), 0, 50) : 'Pembelian Produk';
            $namaItem = isset($body['namaItem']) ? mb_substr(trim((string)$body['namaItem']), 0, 200) : '';
            $kategoriItem = isset($body['kategoriItem']) ? mb_substr(trim((string)$body['kategoriItem']), 0, 100) : '';
            $jumlah = isset($body['jumlah']) && trim((string)$body['jumlah']) !== '' ? mb_substr(trim((string)$body['jumlah']), 0, 100) : '1';
            $hargaEstimasi = isset($body['hargaEstimasi']) && trim((string)$body['hargaEstimasi']) !== '' ? mb_substr(trim((string)$body['hargaEstimasi']), 0, 100) : '-';
            $tanggalBooking = isset($body['tanggalBooking']) && trim((string)$body['tanggalBooking']) !== '' ? mb_substr(trim((string)$body['tanggalBooking']), 0, 50) : date('Y-m-d');
            $alamatCatatan = isset($body['alamatCatatan']) ? mb_substr(trim((string)$body['alamatCatatan']), 0, 2000) : '';
            $allowedStatuses = ['Baru', 'Diproses', 'Selesai', 'Dibatalkan'];
            $requestedStatus = isset($body['status']) ? trim((string)$body['status']) : 'Baru';
            $status = ($hasAdminJwt && in_array($requestedStatus, $allowedStatuses, true)) ? $requestedStatus : 'Baru';

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
    // 10. MEDIA STREAMING DARI DATABASE (UNTUK PREVIEW OG/WA)
    // ----------------------------------------------------
    if ($resource === "media" && $method === "GET" && $subResource === "berita" && isset($segments[2])) {
        $beritaId = (int)$segments[2];
        $stmt = $pdo->prepare("SELECT gambar FROM berita WHERE id = ? LIMIT 1");
        $stmt->execute([$beritaId]);
        $row = $stmt->fetch();
        $img = trim((string)($row['gambar'] ?? ''));

        if (preg_match('/^data:(image\/(?:png|jpe?g|webp|gif));base64,(.+)$/i', $img, $m)) {
            $mime = strtolower($m[1]);
            if ($mime === 'image/jpg') $mime = 'image/jpeg';
            $bytes = base64_decode($m[2], true);
            if ($bytes !== false && strlen($bytes) > 0) {
                header("Content-Type: " . $mime);
                header("Content-Length: " . strlen($bytes));
                header("Cache-Control: public, max-age=86400, must-revalidate");
                echo $bytes;
                exit;
            }
        } elseif ($img !== '' && strpos($img, '/uploads/') === 0) {
            $localPath = realpath(dirname(__DIR__) . $img);
            $uploadsRoot = realpath(dirname(__DIR__) . '/uploads');
            if ($localPath && $uploadsRoot && strpos($localPath, $uploadsRoot) === 0 && is_file($localPath)) {
                $info = @getimagesize($localPath);
                $mime = $info['mime'] ?? 'image/jpeg';
                header("Content-Type: " . $mime);
                header("Content-Length: " . filesize($localPath));
                header("Cache-Control: public, max-age=86400, must-revalidate");
                readfile($localPath);
                exit;
            }
        }

        http_response_code(404);
        echo json_encode(["error" => "Media berita tidak ditemukan."]);
        exit;
    }

    // ----------------------------------------------------
    // 11. UPLOAD FOTO TERKOMPRESI (DISIMPAN KE DATABASE AGAR KEBAL REDEPLOY)
    // ----------------------------------------------------
    if ($resource === "upload" && $method === "POST") {
        requireAuth();
        $maxBytes = 2 * 1024 * 1024; // 2 MB = 2,097,152 bytes
        $allowedMimes = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];

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
            $mime = $imgInfo ? strtolower($imgInfo['mime'] ?? '') : '';
            if (!in_array($mime, $allowedMimes, true)) {
                http_response_code(400);
                echo json_encode(["error" => "Format foto harus PNG, JPG/JPEG, atau WebP."]);
                exit;
            }
            if ($mime === 'image/jpg') $mime = 'image/jpeg';

            $rawBytes = file_get_contents($fileEntry['tmp_name']);
            if ($rawBytes === false) {
                http_response_code(500);
                echo json_encode(["error" => "Gagal membaca file foto."]);
                exit;
            }

            echo json_encode([
                "url" => "data:" . $mime . ";base64," . base64_encode($rawBytes),
                "size" => $fileSize,
                "mime" => $mime,
                "storage" => "database",
                "message" => "Foto berhasil diproses untuk disimpan ke database."
            ]);
            exit;
        }

        // B. Jika dikirim via JSON body (dataUrl base64 terkompresi dari browser)
        $dataUrl = isset($body['dataUrl']) ? trim((string)$body['dataUrl']) : '';
        if (!$dataUrl) {
            http_response_code(400);
            echo json_encode(["error" => "Data foto tidak ditemukan. Pilih foto PNG, JPG, atau WebP maksimal 2 MB."]);
            exit;
        }

        if (!preg_match('/^data:image\/(png|jpe?g|webp);base64,(.+)$/i', $dataUrl, $matches)) {
            http_response_code(400);
            echo json_encode(["error" => "Format foto tidak didukung. Gunakan format PNG, JPG/JPEG, atau WebP."]);
            exit;
        }

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
        $mime = $imgInfo ? strtolower($imgInfo['mime'] ?? '') : '';
        if (!in_array($mime, $allowedMimes, true)) {
            http_response_code(400);
            echo json_encode(["error" => "File yang dipilih bukan gambar PNG, JPG, atau WebP yang valid."]);
            exit;
        }
        if ($mime === 'image/jpg') $mime = 'image/jpeg';

        // Kembalikan Data URL terkompresi agar tersimpan permanen di kolom LONGTEXT database (kebal redeploy)
        echo json_encode([
            "url" => "data:" . $mime . ";base64," . base64_encode($decodedBytes),
            "size" => $byteLength,
            "mime" => $mime,
            "storage" => "database",
            "message" => "Foto berhasil diproses untuk disimpan ke database."
        ]);
        exit;
    }

    // Endpoint tidak ditemukan
    http_response_code(404);
    echo json_encode(["error" => "Endpoint tidak ditemukan: /api/{$path}"]);

} catch (Throwable $e) {
    error_log("BUMDes API runtime error: " . $e->getMessage() . " in " . basename($e->getFile()) . ":" . $e->getLine());
    $reqHost = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
    $isLocal = ($reqHost === '' || strpos($reqHost, 'localhost') === 0 || strpos($reqHost, '127.0.0.1') === 0);
    http_response_code(500);
    $errOut = ["error" => "Terjadi kesalahan pada server. Silakan coba sesaat lagi."];
    if ($isLocal) {
        $errOut["detail"] = $e->getMessage();
        $errOut["file"] = basename($e->getFile());
        $errOut["line"] = $e->getLine();
    }
    echo json_encode($errOut);
}
