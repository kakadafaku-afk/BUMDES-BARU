<?php
// Wrapper SPA ringan untuk menyuntikkan <title> dan meta Open Graph (WhatsApp/medsos) dinamis per rute
header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: no-cache, no-store, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

$indexFile = __DIR__ . '/index.html';
if (!file_exists($indexFile)) {
    http_response_code(404);
    echo 'index.html tidak ditemukan.';
    exit;
}

$html = file_get_contents($indexFile);

$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$host = $_SERVER['HTTP_HOST'] ?? 'sedyamakmur2026.site.je';
$baseUrl = $scheme . '://' . $host;
$rawUri = $_SERVER['REQUEST_URI'] ?? '/';
$path = rtrim((string)parse_url($rawUri, PHP_URL_PATH), '/');
if ($path === '') {
    $path = '/';
}

$title = 'BUMDes Sedya Makmur - Desa Mayong Lor, Jepara';
$desc = 'Portal resmi BUMDes Sedya Makmur Desa Mayong Lor, Kec. Mayong, Kab. Jepara. Mengelola 6 unit usaha produktif, produk UMKM & gerabah, serta wisata edukasi desa.';
$ogImage = $baseUrl . '/og-hero.jpg';
$ogType = 'website';

$routeMeta = [
    '/profil' => [
        'title' => 'Profil & Pengurus — BUMDes Sedya Makmur',
        'desc'  => 'Sejarah pendirian berbadan hukum Kemenkumham, visi misi, prestasi, serta struktur pengurus aktif BUMDes Sedya Makmur Desa Mayong Lor.',
    ],
    '/unit-usaha' => [
        'title' => '6 Unit Usaha — BUMDes Sedya Makmur',
        'desc'  => 'Unit Simpan Pinjam, Sewa Bekisting, Sembako & Supplier SPPG MBG, Kantin PT. TBS, Gerabah & Kerajinan, serta Unit Ketahanan Pangan Mayong Lor.',
    ],
    '/wisata' => [
        'title' => 'Wisata Edukasi Desa Mayong Lor — BUMDes Sedya Makmur',
        'desc'  => 'Pilihan paket wisata edukasi sekolah & komunitas: Pertanian & Peternakan, Cooking Class UMKM, dan Edukasi Gerabah Mayong Lor.',
    ],
    '/produk' => [
        'title' => 'Produk Unggulan & Kerajinan — BUMDes Sedya Makmur',
        'desc'  => 'Katalog produk Desa Mayong Lor: Susu Kambing Etawa, Sayur Hidroponik, Bibit Hortikultura, Gerabah, Genteng, dan Bata Tempel.',
    ],
    '/berita' => [
        'title' => 'Berita Kegiatan Terkini — BUMDes Sedya Makmur',
        'desc'  => 'Liputan kegiatan, kemitraan usaha, ekspor genteng ke Spanyol, dan pengumuman resmi BUMDes Sedya Makmur.',
    ],
    '/kontak' => [
        'title' => 'Kontak & Lokasi Kantor — BUMDes Sedya Makmur',
        'desc'  => 'Hubungi pengelola BUMDes Sedya Makmur atau kunjungi Kompleks Balaidesa Mayong Lor, Kec. Mayong, Kab. Jepara.',
    ],
    '/admin/login' => [
        'title' => 'Login Pengelola — SIM BUMDes Sedya Makmur',
        'desc'  => 'Portal masuk resmi administrator dan pengurus BUMDes Sedya Makmur Desa Mayong Lor.',
    ],
];

if (isset($routeMeta[$path])) {
    $title = $routeMeta[$path]['title'];
    $desc = $routeMeta[$path]['desc'];
} elseif (strpos($path, '/admin') === 0) {
    $title = 'Dashboard Admin — SIM BUMDes Sedya Makmur';
    $desc = 'Sistem Informasi Manajemen BUMDes Sedya Makmur Desa Mayong Lor.';
} elseif (preg_match('#^/berita/(\d+)$#', $path, $m)) {
    $beritaId = (int)$m[1];
    $ogType = 'article';
    $title = 'Berita Kegiatan — BUMDes Sedya Makmur';
    $desc = 'Artikel dan informasi kegiatan terbaru BUMDes Sedya Makmur Desa Mayong Lor, Jepara.';

    // Ambil judul, ringkasan, dan URL foto artikel secara aman tanpa gagal fatal bila DB sibuk
    $dbConfig = file_exists(__DIR__ . '/api/db.php')
        ? (__DIR__ . '/api/db.php')
        : (__DIR__ . '/api/db.example.php');
    if (file_exists($dbConfig)) {
        try {
            require_once $dbConfig;
            if (isset($DB_HOST, $DB_NAME, $DB_USER, $DB_PASS)) {
                $pdo = new PDO(
                    "mysql:host={$DB_HOST};dbname={$DB_NAME};charset=utf8mb4",
                    $DB_USER,
                    $DB_PASS,
                    [
                        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                        PDO::ATTR_TIMEOUT => 2,
                    ]
                );
                $stmt = $pdo->prepare('SELECT judul, ringkasan, gambar FROM berita WHERE id = ? LIMIT 1');
                $stmt->execute([$beritaId]);
                $row = $stmt->fetch();
                if ($row) {
                    if (!empty($row['judul'])) {
                        $title = trim($row['judul']) . ' — BUMDes Sedya Makmur';
                    }
                    if (!empty($row['ringkasan'])) {
                        $desc = trim($row['ringkasan']);
                    }
                    $img = trim((string)($row['gambar'] ?? ''));
                    if ($img !== '') {
                        if (stripos($img, 'data:image/') === 0) {
                            $ogImage = $baseUrl . '/api/media/berita/' . $beritaId;
                        } elseif (preg_match('#^https?://#i', $img)) {
                            $ogImage = $img;
                        } elseif (strpos($img, '/') === 0) {
                            $ogImage = $baseUrl . $img;
                        } else {
                            $ogImage = $baseUrl . '/' . $img;
                        }
                    }
                }
            }
        } catch (Throwable $ignore) {
            // Fallback tetap menggunakan judul/gambar default bila DB tidak terjangkau
        }
    }
}

$pageUrl = $baseUrl . ($path === '/' ? '/' : $path);
$esc = function ($val) {
    return htmlspecialchars((string)$val, ENT_QUOTES, 'UTF-8');
};

$eTitle = $esc($title);
$eDesc = $esc($desc);
$eUrl = $esc($pageUrl);
$eImg = $esc($ogImage);
$eType = $esc($ogType);

$replaceRegex = function ($pattern, $replacement, $subject) {
    return preg_replace_callback($pattern, function () use ($replacement) {
        return $replacement;
    }, $subject, 1);
};

$html = $replaceRegex('/<title>.*?<\/title>/is', '<title>' . $eTitle . '</title>', $html);
$html = $replaceRegex('/<meta\s+name="description"\s+content="[^"]*"\s*\/?>/i', '<meta name="description" content="' . $eDesc . '" />', $html);
$html = $replaceRegex('/<meta\s+property="og:type"\s+content="[^"]*"\s*\/?>/i', '<meta property="og:type" content="' . $eType . '" />', $html);
$html = $replaceRegex('/<meta\s+property="og:url"\s+content="[^"]*"\s*\/?>/i', '<meta property="og:url" content="' . $eUrl . '" />', $html);
$html = $replaceRegex('/<meta\s+property="og:title"\s+content="[^"]*"\s*\/?>/i', '<meta property="og:title" content="' . $eTitle . '" />', $html);
$html = $replaceRegex('/<meta\s+property="og:description"\s+content="[^"]*"\s*\/?>/i', '<meta property="og:description" content="' . $eDesc . '" />', $html);
$html = $replaceRegex('/<meta\s+property="og:image"\s+content="[^"]*"\s*\/?>/i', '<meta property="og:image" content="' . $eImg . '" />', $html);
$html = $replaceRegex('/<meta\s+name="twitter:title"\s+content="[^"]*"\s*\/?>/i', '<meta name="twitter:title" content="' . $eTitle . '" />', $html);
$html = $replaceRegex('/<meta\s+name="twitter:description"\s+content="[^"]*"\s*\/?>/i', '<meta name="twitter:description" content="' . $eDesc . '" />', $html);
$html = $replaceRegex('/<meta\s+name="twitter:image"\s+content="[^"]*"\s*\/?>/i', '<meta name="twitter:image" content="' . $eImg . '" />', $html);

echo $html;
