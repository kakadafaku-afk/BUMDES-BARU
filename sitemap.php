<?php
header('Content-Type: application/xml; charset=UTF-8');
header('Cache-Control: public, max-age=3600, must-revalidate');

$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower((string)$_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') {
    $scheme = 'https';
}
$host = $_SERVER['HTTP_HOST'] ?? 'bumdessedyamakmur.my.id';
$baseUrl = ($host === 'localhost' || strpos($host, 'localhost:') === 0 || strpos($host, '127.0.0.1') === 0)
    ? ($scheme . '://' . $host)
    : 'https://' . $host;

$today = date('Y-m-d');
$staticRoutes = [
    ['loc' => '/', 'priority' => '1.0', 'changefreq' => 'daily'],
    ['loc' => '/profil', 'priority' => '0.8', 'changefreq' => 'monthly'],
    ['loc' => '/unit-usaha', 'priority' => '0.9', 'changefreq' => 'weekly'],
    ['loc' => '/wisata', 'priority' => '0.9', 'changefreq' => 'weekly'],
    ['loc' => '/produk', 'priority' => '0.9', 'changefreq' => 'weekly'],
    ['loc' => '/berita', 'priority' => '0.9', 'changefreq' => 'daily'],
    ['loc' => '/kontak', 'priority' => '0.7', 'changefreq' => 'monthly'],
];

$beritaUrls = [];
$dbConfig = file_exists(__DIR__ . '/api/db.php')
    ? (__DIR__ . '/api/db.php')
    : (__DIR__ . '/api/db.example.php');

if (file_exists($dbConfig)) {
    try {
        require_once $dbConfig;
        if (isset($DB_HOST, $DB_NAME, $DB_USER, $DB_PASS)) {
            $portPart = !empty($DB_PORT) ? ";port={$DB_PORT}" : "";
            $pdo = new PDO(
                "mysql:host={$DB_HOST}{$portPart};dbname={$DB_NAME};charset=utf8mb4",
                $DB_USER,
                $DB_PASS,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_TIMEOUT => 2,
                ]
            );
            $stmt = $pdo->query("SELECT id, created_at FROM berita ORDER BY id DESC LIMIT 500");
            foreach ($stmt->fetchAll() as $row) {
                $lastmod = !empty($row['created_at']) ? substr((string)$row['created_at'], 0, 10) : $today;
                if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $lastmod)) {
                    $lastmod = $today;
                }
                $beritaUrls[] = [
                    'loc' => '/berita/' . (int)$row['id'],
                    'lastmod' => $lastmod,
                    'priority' => '0.8',
                    'changefreq' => 'monthly',
                ];
            }
        }
    } catch (Throwable $ignore) {
        // Tetap hasilkan sitemap rute utama jika koneksi DB sedang sibuk
    }
}

$escXml = function ($s) {
    return htmlspecialchars((string)$s, ENT_XML1 | ENT_QUOTES, 'UTF-8');
};

echo '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' . "\n";

foreach ($staticRoutes as $r) {
    echo "  <url>\n";
    echo "    <loc>" . $escXml($baseUrl . $r['loc']) . "</loc>\n";
    echo "    <lastmod>" . $escXml($today) . "</lastmod>\n";
    echo "    <changefreq>" . $escXml($r['changefreq']) . "</changefreq>\n";
    echo "    <priority>" . $escXml($r['priority']) . "</priority>\n";
    echo "  </url>\n";
}

foreach ($beritaUrls as $b) {
    echo "  <url>\n";
    echo "    <loc>" . $escXml($baseUrl . $b['loc']) . "</loc>\n";
    echo "    <lastmod>" . $escXml($b['lastmod']) . "</lastmod>\n";
    echo "    <changefreq>" . $escXml($b['changefreq']) . "</changefreq>\n";
    echo "    <priority>" . $escXml($b['priority']) . "</priority>\n";
    echo "  </url>\n";
}

echo "</urlset>\n";
