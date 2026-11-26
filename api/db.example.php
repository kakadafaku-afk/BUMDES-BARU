<?php
// =======================================================
// Template Konfigurasi Database MySQL & Secret Key
// - Untuk hosting berbasis container (RuPa Cloud / Docker):
//   cukup isi Environment Variables (DB_HOST, DB_NAME, DB_USER, DB_PASS, JWT_SECRET)
// - Untuk XAMPP / Shared Hosting (Hostinger / cPanel):
//   salin file ini menjadi api/db.php lalu isi kredensial Anda
// =======================================================

$dotEnvVars = [];
foreach ([dirname(__DIR__) . '/.env', __DIR__ . '/.env'] as $envPath) {
    if (@is_file($envPath) && @is_readable($envPath)) {
        $envLines = @file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (is_array($envLines)) {
            foreach ($envLines as $envLine) {
                $trimmed = trim($envLine);
                if ($trimmed === '' || $trimmed[0] === '#') continue;
                if (strpos($trimmed, 'export ') === 0) {
                    $trimmed = trim(substr($trimmed, 7));
                }
                $eqPos = strpos($trimmed, '=');
                if ($eqPos === false) continue;
                $k = trim(substr($trimmed, 0, $eqPos));
                $v = trim(substr($trimmed, $eqPos + 1));
                if ($v !== '' && (($v[0] === '"' && substr($v, -1) === '"') || ($v[0] === "'" && substr($v, -1) === "'"))) {
                    $v = substr($v, 1, -1);
                }
                if ($k !== '' && !array_key_exists($k, $dotEnvVars)) {
                    $dotEnvVars[$k] = $v;
                }
            }
        }
    }
}

$readEnvConfig = function ($keys, $default, $allowEmpty = false) use ($dotEnvVars) {
    $keyList = is_array($keys) ? $keys : [$keys];
    foreach ($keyList as $key) {
        $val = getenv($key);
        if ($val !== false && ($allowEmpty || $val !== '')) return $val;
        if (array_key_exists($key, $_ENV) && ($allowEmpty || $_ENV[$key] !== '')) return $_ENV[$key];
        if (array_key_exists($key, $_SERVER) && is_string($_SERVER[$key]) && ($allowEmpty || $_SERVER[$key] !== '')) return $_SERVER[$key];
        if (array_key_exists($key, $dotEnvVars) && ($allowEmpty || $dotEnvVars[$key] !== '')) return $dotEnvVars[$key];
    }
    return $default;
};

$DB_HOST = $readEnvConfig(['DB_HOST', 'MYSQL_HOST'], 'localhost');
$DB_PORT = $readEnvConfig(['DB_PORT', 'MYSQL_PORT'], '3306');
$DB_NAME = $readEnvConfig(['DB_DATABASE', 'DB_NAME', 'MYSQL_DATABASE'], 'nama_database');
$DB_USER = $readEnvConfig(['DB_USERNAME', 'DB_USER', 'MYSQL_USER'], 'username_db');
$DB_PASS = $readEnvConfig(['DB_PASSWORD', 'DB_PASS', 'MYSQL_PASSWORD'], 'password_db', true);
$JWT_SECRET = $readEnvConfig(
    ['JWT_SECRET', 'APP_KEY'],
    hash('sha256', 'bumdes-jwt|' . $DB_HOST . '|' . $DB_NAME . '|' . $DB_USER . '|' . $DB_PASS)
);

function getDb() {
    global $DB_HOST, $DB_PORT, $DB_NAME, $DB_USER, $DB_PASS;
    static $pdoInstance = null;
    if ($pdoInstance !== null) {
        return $pdoInstance;
    }

    try {
        $portPart = !empty($DB_PORT) ? ";port={$DB_PORT}" : "";
        $pdo = new PDO(
            "mysql:host={$DB_HOST}{$portPart};dbname={$DB_NAME};charset=utf8mb4",
            $DB_USER,
            $DB_PASS,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]
        );

        ensureTablesExist($pdo);
        $pdoInstance = $pdo;
        return $pdo;
    } catch (PDOException $e) {
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode([
            "error" => "Koneksi ke Database MySQL gagal. Pastikan konfigurasi di api/db.php sudah benar.",
            "detail" => $e->getMessage()
        ]);
        exit;
    }
}

function ensureTablesExist($pdo) {
    try {
        $check = $pdo->query("SELECT COUNT(*) as cnt FROM admins")->fetch();
        if (!$check || (int)$check['cnt'] === 0) {
            initDatabase($pdo);
            return;
        }

        // Migrasi otomatis satu kali jika database masih berisi data contoh lama (Lebuawu)
        $profil = $pdo->query("SELECT email_desa, alamat_kantor FROM profil_desa WHERE id = 1")->fetch();
        if ($profil && (
            $profil['email_desa'] === 'desa.lebuawu@example.id' ||
            stripos((string)$profil['alamat_kantor'], 'Lebuawu') !== false
        )) {
            seedSedyaMakmurData($pdo, true);
        }

        // Pastikan kolom password_plain tersedia pada tabel admins untuk fitur Lihat Detail Akun Admin
        try {
            $pdo->exec("ALTER TABLE admins ADD COLUMN password_plain VARCHAR(255) DEFAULT 'admin123'");
        } catch (Throwable $ignore) {
            // Kolom sudah ada
        }

        // Bersihkan entri Notaris/Akta & narasi modal 2016 lama jika masih tersisa di DB
        $pdo->exec("UPDATE perangkat_desa SET jabatan = 'Pengelola Unit Usaha', nama = 'Tim Operasional BUMDes' WHERE jabatan LIKE '%Notaris%' OR nama LIKE '%Akta No. 14%'");
        $pdo->exec("UPDATE berita SET isi = 'Sejak tahun 2017, BUMDes Sedya Makmur Desa Mayong Lor konsisten menyumbang Pendapatan Asli Desa setiap tahun. Dengan 6 unit usaha yang berkembang, BUMDes diproyeksikan menyumbang PAD Desa sebesar Rp 30.000.000 pada tahun 2026.' WHERE id = 4 AND isi LIKE '%modal desa Rp 25 juta%'");

        // Migrasi otomatis standarisasi BUMDES menjadi BUMDes baku & kata baku KBBI (Hortikultura, Cabai)
        $pdo->exec("UPDATE profil_desa SET nama_desa = REPLACE(nama_desa, 'BUMDES', 'BUMDes'), visi = REPLACE(visi, 'BUMDES', 'BUMDes') WHERE nama_desa LIKE '%BUMDES%' OR visi LIKE '%BUMDES%'");
        $pdo->exec("UPDATE berita SET judul = REPLACE(judul, 'BUMDES', 'BUMDes'), ringkasan = REPLACE(ringkasan, 'BUMDES', 'BUMDes'), isi = REPLACE(isi, 'BUMDES', 'BUMDes') WHERE judul LIKE '%BUMDES%' OR ringkasan LIKE '%BUMDES%' OR isi LIKE '%BUMDES%'");
        $pdo->exec("UPDATE berita SET judul = REPLACE(REPLACE(judul, 'Holtikultura', 'Hortikultura'), 'holtikultura', 'hortikultura'), ringkasan = REPLACE(REPLACE(ringkasan, 'Holtikultura', 'Hortikultura'), 'holtikultura', 'hortikultura'), isi = REPLACE(REPLACE(isi, 'Holtikultura', 'Hortikultura'), 'holtikultura', 'hortikultura') WHERE judul LIKE '%oltikultura%' OR ringkasan LIKE '%oltikultura%' OR isi LIKE '%oltikultura%'");
        $pdo->exec("UPDATE umkm SET nama = REPLACE(nama, 'BUMDES', 'BUMDes'), deskripsi = REPLACE(deskripsi, 'BUMDES', 'BUMDes') WHERE nama LIKE '%BUMDES%' OR deskripsi LIKE '%BUMDES%'");
        $pdo->exec("UPDATE umkm SET nama = REPLACE(REPLACE(nama, 'Holtikultura', 'Hortikultura'), 'Cabe', 'Cabai'), kategori = REPLACE(kategori, 'Holtikultura', 'Hortikultura'), deskripsi = REPLACE(REPLACE(REPLACE(deskripsi, 'Holtikultura', 'Hortikultura'), 'holtikultura', 'hortikultura'), 'cabe', 'cabai') WHERE nama LIKE '%oltikultura%' OR nama LIKE '%Cabe%' OR kategori LIKE '%oltikultura%' OR deskripsi LIKE '%oltikultura%' OR deskripsi LIKE '%cabe%'");
        $pdo->exec("UPDATE admins SET nama = REPLACE(nama, 'BUMDES', 'BUMDes') WHERE nama LIKE '%BUMDES%'");
        $pdo->exec("UPDATE statistik SET nilai = 6 WHERE label = 'Unit Usaha Aktif' AND nilai = 7");

        // Pastikan kolom gambar tersedia dan bertipe LONGTEXT di tabel umkm, berita, dan profil_desa (foto_hero)
        try {
            $pdo->exec("ALTER TABLE umkm ADD COLUMN gambar LONGTEXT DEFAULT NULL");
        } catch (Throwable $ignore) {}
        try {
            $pdo->exec("ALTER TABLE umkm MODIFY COLUMN gambar LONGTEXT DEFAULT NULL");
        } catch (Throwable $ignore) {}
        try {
            $pdo->exec("ALTER TABLE berita ADD COLUMN gambar LONGTEXT DEFAULT NULL");
        } catch (Throwable $ignore) {}
        try {
            $pdo->exec("ALTER TABLE berita MODIFY COLUMN gambar LONGTEXT DEFAULT NULL");
        } catch (Throwable $ignore) {}
        try {
            $pdo->exec("ALTER TABLE profil_desa ADD COLUMN foto_hero LONGTEXT DEFAULT NULL");
        } catch (Throwable $ignore) {}
        try {
            $pdo->exec("ALTER TABLE profil_desa MODIFY COLUMN foto_hero LONGTEXT DEFAULT NULL");
        } catch (Throwable $ignore) {}
        try {
            $pdo->exec("ALTER TABLE profil_desa ADD COLUMN foto_unit_wisata LONGTEXT DEFAULT NULL");
        } catch (Throwable $ignore) {}
        try {
            $pdo->exec("ALTER TABLE profil_desa MODIFY COLUMN foto_unit_wisata LONGTEXT DEFAULT NULL");
        } catch (Throwable $ignore) {}
        try {
            $pdo->exec("ALTER TABLE perangkat_desa ADD COLUMN foto LONGTEXT DEFAULT NULL");
        } catch (Throwable $ignore) {}
        try {
            $pdo->exec("ALTER TABLE perangkat_desa MODIFY COLUMN foto LONGTEXT DEFAULT NULL");
        } catch (Throwable $ignore) {}

        // Pastikan baris data utama profil_desa (id = 1) selalu ada dan tidak kosong
        $cekProfilRow = $pdo->query("SELECT COUNT(*) as cnt FROM profil_desa WHERE id = 1")->fetch();
        if (!$cekProfilRow || (int)$cekProfilRow['cnt'] === 0) {
            $misiJson = json_encode([
                "Mengembangkan potensi desa",
                "Meningkatkan kesejahteraan masyarakat",
                "Melestarikan budaya lokal",
                "Mendukung program pemerintah",
                "Memberikan pelayanan usaha yang profesional dan berkelanjutan"
            ]);
            $visi = "Menjadi BUMDes yang profesional, mandiri dan berdaya saing, berbasis potensi lokal untuk kesejahteraan masyarakat Desa Mayong Lor.";
            $stmt = $pdo->prepare("INSERT INTO profil_desa (id, nama_desa, kecamatan, kabupaten, provinsi, visi, misi, alamat_kantor, jam_pelayanan, no_telepon, email_desa) VALUES (1, 'BUMDes Sedya Makmur', 'Mayong', 'Jepara', 'Jawa Tengah', ?, ?, 'Kompleks Balaidesa Mayong Lor, Kec. Mayong, Kab. Jepara', 'Senin–Sabtu, 08.00–16.00 WIB', '0878 2124 4536', 'bumdesmayonglor@gmail.com')");
            $stmt->execute([$visi, $misiJson]);
        }

        // Pastikan nama pengurus tampil bersih tanpa gelar akademis (SP, SAP, A.Md, S.Kom, dll)
        $pdo->exec("UPDATE perangkat_desa SET nama = 'Budi Agus Trianto' WHERE nama LIKE '%Budi Agus Trianto%'");
        $pdo->exec("UPDATE perangkat_desa SET nama = 'Mulyono' WHERE nama LIKE '%Mulyono%'");
        $pdo->exec("UPDATE perangkat_desa SET nama = 'Eman Prasojo' WHERE nama LIKE '%Eman Prasojo%'");
        $pdo->exec("UPDATE perangkat_desa SET nama = 'Sri Hartatik' WHERE nama LIKE '%Sri Hartatik%'");
        $pdo->exec("UPDATE perangkat_desa SET nama = REPLACE(nama, ', SP, SAP', '')");
        $pdo->exec("UPDATE perangkat_desa SET nama = REPLACE(nama, ', A.Md', '')");
        $pdo->exec("UPDATE perangkat_desa SET nama = REPLACE(nama, ', S.Kom.', '')");
        $pdo->exec("UPDATE perangkat_desa SET nama = REPLACE(nama, ' S.Kom.', '')");
        $pdo->exec("UPDATE perangkat_desa SET nama = REPLACE(nama, ' S.Kom', '')");
        $pdo->exec("UPDATE perangkat_desa SET nama = REPLACE(nama, ' A.Md', '')");
        $pdo->exec("UPDATE perangkat_desa SET nama = REPLACE(nama, ' SP, SAP', '')");

        // Migrasi berita #3 Order dari Spanyol: koreksi dari Mebel menjadi Genting tanpa menghapus gambar yang sudah diunggah
        $pdo->exec("UPDATE berita SET 
            judul = 'Tembus Pasar Global: Produk Genting Mayong Lor BUMDes Sedya Makmur Raih Order Ekspor ke Spanyol',
            kategori = 'Ekspor & Genting',
            ringkasan = 'Kualitas produk genting tanah liat khas Desa Mayong Lor di bawah naungan BUMDes Sedya Makmur sukses menembus pasar Eropa melalui pesanan ekspor langsung ke Spanyol.',
            isi = 'Produk genting dan kerajinan tanah liat terakota berkualitas tinggi hasil karya pengrajin lokal binaan BUMDes Sedya Makmur Desa Mayong Lor mencatatkan pencapaian membanggakan dengan berhasil menembus pasar internasional melalui pesanan ekspor langsung dari buyer asal Spanyol. Keunggulan kualitas pembakaran, ketahanan material, serta presisi bentuk khas pengrajin Mayong Lor membuktikan bahwa produk genting desa memiliki standar unggul dan berdaya saing global melalui Unit Usaha Gerabah & Kerajinan BUMDes Sedya Makmur.'
            WHERE judul LIKE '%Spanyol%' AND (judul LIKE '%Mebel%' OR ringkasan LIKE '%mebel%' OR isi LIKE '%mebel%')");

        // Pastikan daftar berita awal (Gebyar, Potorono, Order Genting Spanyol) tersedia jika belum ada berita Spanyol
        $cekBeritaGenting = $pdo->query("SELECT id FROM berita WHERE judul LIKE '%Spanyol%' LIMIT 1")->fetch();
        if (!$cekBeritaGenting) {
            $pdo->exec("TRUNCATE TABLE berita");
            $pdo->exec("INSERT INTO berita (id, judul, kategori, tanggal, ringkasan, isi) VALUES 
                (1, 'Gebyar BUMDes Jepara: BUMDes Sedya Makmur Tampilkan Inovasi Produk Unggulan Mayong Lor', 'Event & Prestasi', '15 Oktober 2026', 'BUMDes Sedya Makmur berpartisipasi aktif dalam ajang Gebyar BUMDes Kabupaten Jepara, memamerkan produk gerabah, hortikultura, hingga kemitraan kuliner UMKM desa.', 'Dalam rangka memeriahkan ajang Gebyar BUMDes Kabupaten Jepara, BUMDes Sedya Makmur Desa Mayong Lor hadir memamerkan berbagai produk unggulan dan potensi ekonomi desa. Di stan pameran, BUMDes menampilkan kerajinan gerabah dan bata tempel terakota, produk pertanian hortikultura dan hidroponik, susu kambing etawa, serta olahan kuliner UMKM lokal. Partisipasi ini menjadi momentum strategis untuk memperluas jejaring pasar, mengenalkan inovasi desa, serta memperkokoh posisi BUMDes Sedya Makmur sebagai lembaga usaha desa yang mandiri dan berdaya saing di tingkat kabupaten.'),
                (2, 'Studi Banding ke BUMDes Desa Potorono untuk Penguatan Tata Kelola & Wisata Edukasi', 'Studi Banding', '24 September 2026', 'Pengurus BUMDes Sedya Makmur melaksanakan kunjungan studi tiru ke BUMDes Mekar Makmur Desa Potorono, Bantul guna mengadopsi pengelolaan wisata terpadu dan digitalisasi usaha.', 'Guna terus meningkatkan kapasitas manajerial dan kualitas pengelolaan unit usaha, jajaran pengurus dan pengelola BUMDes Sedya Makmur Desa Mayong Lor melaksanakan kegiatan studi banding ke BUMDes Potorono di Kabupaten Bantul, D.I. Yogyakarta. Fokus studi tiru ini mencakup tata kelola kawasan wisata edukasi desa yang terintegrasi dengan UMKM lokal, sistem akuntansi keuangan transparan, serta pemanfaatan teknologi digital dalam pelayanan warga. Wawasan yang diperoleh dari kunjungan ini akan diadopsi untuk mematangkan pengembangan paket wisata edukasi dan optimalisasi 6 unit usaha BUMDes Sedya Makmur.'),
                (3, 'Tembus Pasar Global: Produk Genting Mayong Lor BUMDes Sedya Makmur Raih Order Ekspor ke Spanyol', 'Ekspor & Genting', '5 November 2026', 'Kualitas produk genting tanah liat khas Desa Mayong Lor di bawah naungan BUMDes Sedya Makmur sukses menembus pasar Eropa melalui pesanan ekspor langsung ke Spanyol.', 'Produk genting dan kerajinan tanah liat terakota berkualitas tinggi hasil karya pengrajin lokal binaan BUMDes Sedya Makmur Desa Mayong Lor mencatatkan pencapaian membanggakan dengan berhasil menembus pasar internasional melalui pesanan ekspor langsung dari buyer asal Spanyol. Keunggulan kualitas pembakaran, ketahanan material, serta presisi bentuk khas pengrajin Mayong Lor membuktikan bahwa produk genting desa memiliki standar unggul dan berdaya saing global melalui Unit Usaha Gerabah & Kerajinan BUMDes Sedya Makmur.')");
        }

        // Lengkapi format tanggal (tanggal, bulan, tahun) pada 3 berita awal bila masih berisi '2026' saja
        $pdo->exec("UPDATE berita SET tanggal = '15 Oktober 2026' WHERE id = 1 AND (tanggal = '2026' OR tanggal = '')");
        $pdo->exec("UPDATE berita SET tanggal = '24 September 2026' WHERE id = 2 AND (tanggal = '2026' OR tanggal = '')");
        $pdo->exec("UPDATE berita SET tanggal = '5 November 2026' WHERE id = 3 AND (tanggal = '2026' OR tanggal = '')");

        // Pastikan tabel pesanan (pencatatan pembelian produk & booking wisata/layanan) tersedia
        ensurePesananTable($pdo);
    } catch (Throwable $e) {
        // Tabel belum ada, buat otomatis
        initDatabase($pdo);
    }
}

function ensurePesananTable($pdo) {
    $pdo->exec("CREATE TABLE IF NOT EXISTS pesanan (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nama_pembeli VARCHAR(120) NOT NULL,
        no_wa VARCHAR(40) NOT NULL,
        jenis VARCHAR(50) NOT NULL DEFAULT 'Pembelian Produk',
        nama_item VARCHAR(200) NOT NULL,
        kategori_item VARCHAR(100) DEFAULT '',
        jumlah VARCHAR(100) NOT NULL DEFAULT '1',
        harga_estimasi VARCHAR(100) DEFAULT '-',
        tanggal_booking VARCHAR(50) DEFAULT NULL,
        alamat_catatan TEXT DEFAULT NULL,
        status VARCHAR(30) DEFAULT 'Baru',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

function initDatabase($pdo) {
    // 1. Admins
    $pdo->exec("CREATE TABLE IF NOT EXISTS admins (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        password_plain VARCHAR(255) DEFAULT 'admin123',
        nama VARCHAR(100) NOT NULL,
        role VARCHAR(20) DEFAULT 'SUPERADMIN',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // Seed admin default: admin / admin123
    $passHash = password_hash('admin123', PASSWORD_BCRYPT);
    $stmt = $pdo->prepare("INSERT IGNORE INTO admins (id, username, password, password_plain, nama, role) VALUES (1, 'admin', ?, 'admin123', 'Admin BUMDes Sedya Makmur', 'SUPERADMIN')");
    $stmt->execute([$passHash]);

    // 2. Profil Desa / BUMDes
    $pdo->exec("CREATE TABLE IF NOT EXISTS profil_desa (
        id INT PRIMARY KEY,
        nama_desa VARCHAR(100) DEFAULT 'BUMDes Sedya Makmur',
        kecamatan VARCHAR(100) DEFAULT 'Mayong',
        kabupaten VARCHAR(100) DEFAULT 'Jepara',
        provinsi VARCHAR(100) DEFAULT 'Jawa Tengah',
        visi TEXT,
        misi TEXT,
        alamat_kantor VARCHAR(255) DEFAULT 'Kompleks Balaidesa Mayong Lor, Kec. Mayong, Kab. Jepara',
        jam_pelayanan VARCHAR(100) DEFAULT 'Senin–Sabtu, 08.00–16.00 WIB',
        no_telepon VARCHAR(50) DEFAULT '0878 2124 4536',
        email_desa VARCHAR(100) DEFAULT 'bumdesmayonglor@gmail.com',
        foto_hero LONGTEXT DEFAULT NULL,
        foto_unit_wisata LONGTEXT DEFAULT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // 3. Statistik
    $pdo->exec("CREATE TABLE IF NOT EXISTS statistik (
        id INT AUTO_INCREMENT PRIMARY KEY,
        label VARCHAR(100) NOT NULL,
        nilai INT NOT NULL,
        icon VARCHAR(50) DEFAULT 'Building2',
        urutan INT DEFAULT 0
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // 4. Berita
    $pdo->exec("CREATE TABLE IF NOT EXISTS berita (
        id INT AUTO_INCREMENT PRIMARY KEY,
        judul VARCHAR(255) NOT NULL,
        kategori VARCHAR(50) NOT NULL,
        tanggal VARCHAR(50) NOT NULL,
        ringkasan TEXT NOT NULL,
        isi LONGTEXT,
        gambar LONGTEXT DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // 5. UMKM / Produk BUMDes
    $pdo->exec("CREATE TABLE IF NOT EXISTS umkm (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nama VARCHAR(150) NOT NULL,
        kategori VARCHAR(50) NOT NULL,
        harga VARCHAR(100) NOT NULL,
        kontak_wa VARCHAR(30) DEFAULT '6287821244536',
        deskripsi TEXT,
        gambar LONGTEXT DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    try {
        $pdo->exec("ALTER TABLE umkm ADD COLUMN gambar LONGTEXT DEFAULT NULL");
    } catch (Throwable $ignore) {}
    try {
        $pdo->exec("ALTER TABLE umkm MODIFY COLUMN gambar LONGTEXT DEFAULT NULL");
    } catch (Throwable $ignore) {}

    // 6. Transparansi Kinerja / APBDes
    $pdo->exec("CREATE TABLE IF NOT EXISTS apbdes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        kategori VARCHAR(20) NOT NULL,
        nama VARCHAR(150) NOT NULL,
        nominal DOUBLE NOT NULL,
        tahun INT DEFAULT 2026,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // 7. Pengurus BUMDes / Perangkat
    $pdo->exec("CREATE TABLE IF NOT EXISTS perangkat_desa (
        id INT AUTO_INCREMENT PRIMARY KEY,
        jabatan VARCHAR(100) NOT NULL,
        nama VARCHAR(100) NOT NULL,
        foto LONGTEXT DEFAULT NULL,
        urutan INT DEFAULT 0
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // 8. Pengaduan / Pesan Masuk
    $pdo->exec("CREATE TABLE IF NOT EXISTS pengaduan (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nama VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL,
        pesan TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'Baru',
        tanggapan TEXT DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // 9. Pesanan Produk & Booking Wisata/Layanan
    ensurePesananTable($pdo);

    seedSedyaMakmurData($pdo, false);
}

function seedSedyaMakmurData($pdo, $replaceOldSeed = false) {
    $misiJson = json_encode([
        "Mengembangkan potensi desa",
        "Meningkatkan kesejahteraan masyarakat",
        "Melestarikan budaya lokal",
        "Mendukung program pemerintah",
        "Memberikan pelayanan usaha yang profesional dan berkelanjutan"
    ]);
    $visi = "Menjadi BUMDes yang profesional, mandiri dan berdaya saing, berbasis potensi lokal untuk kesejahteraan masyarakat Desa Mayong Lor.";

    if ($replaceOldSeed) {
        $stmt = $pdo->prepare("UPDATE profil_desa SET nama_desa='BUMDes Sedya Makmur', kecamatan='Mayong', kabupaten='Jepara', provinsi='Jawa Tengah', visi=?, misi=?, alamat_kantor='Kompleks Balaidesa Mayong Lor, Kec. Mayong, Kab. Jepara', jam_pelayanan='Senin–Sabtu, 08.00–16.00 WIB', no_telepon='0878 2124 4536', email_desa='bumdesmayonglor@gmail.com' WHERE id=1");
        $stmt->execute([$visi, $misiJson]);

        $pdo->exec("TRUNCATE TABLE statistik");
        $pdo->exec("TRUNCATE TABLE berita");
        $pdo->exec("TRUNCATE TABLE umkm");
        $pdo->exec("TRUNCATE TABLE apbdes");
        $pdo->exec("TRUNCATE TABLE perangkat_desa");
    } else {
        $stmt = $pdo->prepare("INSERT IGNORE INTO profil_desa (id, nama_desa, kecamatan, kabupaten, provinsi, visi, misi, alamat_kantor, jam_pelayanan, no_telepon, email_desa) VALUES (1, 'BUMDes Sedya Makmur', 'Mayong', 'Jepara', 'Jawa Tengah', ?, ?, 'Kompleks Balaidesa Mayong Lor, Kec. Mayong, Kab. Jepara', 'Senin–Sabtu, 08.00–16.00 WIB', '0878 2124 4536', 'bumdesmayonglor@gmail.com')");
        $stmt->execute([$visi, $misiJson]);
    }

    // Statistik BUMDes
    $pdo->exec("INSERT IGNORE INTO statistik (id, label, nilai, icon, urutan) VALUES 
        (1, 'Unit Usaha Aktif', 6, 'Building2', 1),
        (2, 'Nasabah Simpan Pinjam', 50, 'Users', 2),
        (3, 'Modal Simpan Pinjam', 38, 'Wallet', 3),
        (4, 'Proyeksi PAD 2026', 30, 'Landmark', 4)");

    // Berita & Milestone BUMDes
    $pdo->exec("INSERT IGNORE INTO berita (id, judul, kategori, tanggal, ringkasan, isi) VALUES 
        (1, 'Gebyar BUMDes Jepara: BUMDes Sedya Makmur Tampilkan Inovasi Produk Unggulan Mayong Lor', 'Event & Prestasi', '15 Oktober 2026', 'BUMDes Sedya Makmur berpartisipasi aktif dalam ajang Gebyar BUMDes Kabupaten Jepara, memamerkan produk gerabah, hortikultura, hingga kemitraan kuliner UMKM desa.', 'Dalam rangka memeriahkan ajang Gebyar BUMDes Kabupaten Jepara, BUMDes Sedya Makmur Desa Mayong Lor hadir memamerkan berbagai produk unggulan dan potensi ekonomi desa. Di stan pameran, BUMDes menampilkan kerajinan gerabah dan bata tempel terakota, produk pertanian hortikultura dan hidroponik, susu kambing etawa, serta olahan kuliner UMKM lokal. Partisipasi ini menjadi momentum strategis untuk memperluas jejaring pasar, mengenalkan inovasi desa, serta memperkokoh posisi BUMDes Sedya Makmur sebagai lembaga usaha desa yang mandiri dan berdaya saing di tingkat kabupaten.'),
        (2, 'Studi Banding ke BUMDes Desa Potorono untuk Penguatan Tata Kelola & Wisata Edukasi', 'Studi Banding', '24 September 2026', 'Pengurus BUMDes Sedya Makmur melaksanakan kunjungan studi tiru ke BUMDes Mekar Makmur Desa Potorono, Bantul guna mengadopsi pengelolaan wisata terpadu dan digitalisasi usaha.', 'Guna terus meningkatkan kapasitas manajerial dan kualitas pengelolaan unit usaha, jajaran pengurus dan pengelola BUMDes Sedya Makmur Desa Mayong Lor melaksanakan kegiatan studi banding ke BUMDes Potorono di Kabupaten Bantul, D.I. Yogyakarta. Fokus studi tiru ini mencakup tata kelola kawasan wisata edukasi desa yang terintegrasi dengan UMKM lokal, sistem akuntansi keuangan transparan, serta pemanfaatan teknologi digital dalam pelayanan warga. Wawasan yang diperoleh dari kunjungan ini akan diadopsi untuk mematangkan pengembangan paket wisata edukasi dan optimalisasi 6 unit usaha BUMDes Sedya Makmur.'),
        (3, 'Tembus Pasar Global: Produk Genting Mayong Lor BUMDes Sedya Makmur Raih Order Ekspor ke Spanyol', 'Ekspor & Genting', '5 November 2026', 'Kualitas produk genting tanah liat khas Desa Mayong Lor di bawah naungan BUMDes Sedya Makmur sukses menembus pasar Eropa melalui pesanan ekspor langsung ke Spanyol.', 'Produk genting dan kerajinan tanah liat terakota berkualitas tinggi hasil karya pengrajin lokal binaan BUMDes Sedya Makmur Desa Mayong Lor mencatatkan pencapaian membanggakan dengan berhasil menembus pasar internasional melalui pesanan ekspor langsung dari buyer asal Spanyol. Keunggulan kualitas pembakaran, ketahanan material, serta presisi bentuk khas pengrajin Mayong Lor membuktikan bahwa produk genting desa memiliki standar unggul dan berdaya saing global melalui Unit Usaha Gerabah & Kerajinan BUMDes Sedya Makmur.')");

    // 7 Produk BUMDes Sedya Makmur
    $pdo->exec("INSERT IGNORE INTO umkm (id, nama, kategori, harga, kontak_wa, deskripsi) VALUES 
        (1, 'Susu Kambing Etawa', 'Peternakan & Pangan', 'Hubungi BUMDes', '6287821244536', 'Susu kambing peranakan etawa segar dan bernutrisi dari Unit Ketahanan Pangan BUMDes Sedya Makmur Mayong Lor.'),
        (2, 'Bibit Cabai, Sayur Kale & Tomat Siap Berbuah', 'Bibit & Pertanian', 'Hubungi BUMDes', '6287821244536', 'Bibit tanaman hortikultura siap tanam dan siap berbuah berkualitas unggul.'),
        (3, 'Cabai, Sayuran Segar & Hortikultura', 'Hortikultura', 'Eceran / Supplier', '6287821244536', 'Sayuran segar, cabai, tahu, dan buah lokal untuk kebutuhan rumah tangga maupun pasokan dapur/SPPG.'),
        (4, 'Pupuk Organik & Media Tanam', 'Bibit & Pertanian', 'Hubungi BUMDes', '6287821244536', 'Pupuk organik subur dan media tanam siap pakai untuk pekarangan maupun kebun.'),
        (5, 'Selada & Pakcoy Hidroponik', 'Hidroponik', 'Hubungi BUMDes', '6287821244536', 'Sayuran hidroponik segar (selada dan pakcoy) bebas pestisida dari kebun Unit Ketahanan Pangan.'),
        (6, 'Remitan, Gerabah, Celengan & Kendi', 'Gerabah & Kerajinan', 'Harga Pengrajin', '6287821244536', 'Kerajinan gerabah tanah liat warisan budaya Desa Mayong Lor meliputi remitan, kendi, celengan, dan peralatan tradisional.'),
        (7, 'Produk Arsitektur: Genteng & Bata Tempel', 'Produk Arsitektur', 'Harga Pengrajin', '6287821244536', 'Genteng kokoh dan bata tempel ukir terakota berkualitas karya pengrajin Desa Mayong Lor.')");

    // Transparansi Kinerja / Permodalan
    $pdo->exec("INSERT IGNORE INTO apbdes (id, kategori, nama, nominal, tahun) VALUES 
        (1, 'pendapatan', 'Penyertaan Modal Ketapang (Perdes 4/2025)', 281, 2025),
        (2, 'pendapatan', 'Penyertaan Modal APBDes Unit Gerabah (2022)', 50, 2022),
        (3, 'pendapatan', 'Investasi Pembangunan Kantin PT. TBS (Nov 2025)', 45, 2025),
        (4, 'pendapatan', 'Modal Simpan Pinjam (2016 Rp 25 jt + 2017 Rp 10 jt)', 35, 2017),
        (5, 'pendapatan', 'Banprov Jateng (Begisting 2019 & Sembako 2020)', 40, 2020),
        (6, 'belanja', 'Unit Ketahanan Pangan (Hidroponik, PE, Hortikultura)', 281, 2025),
        (7, 'belanja', 'Unit Usaha Gerabah & Kerajinan', 50, 2022),
        (8, 'belanja', 'Pembangunan Kantin Baja Ringan PT. TBS', 45, 2025),
        (9, 'belanja', 'Perkembangan Modal Simpan Pinjam (50+ Nasabah)', 38, 2026),
        (10, 'belanja', 'Proyeksi Kontribusi PAD Desa Tahun 2026', 30, 2026)");

    // 3 Pengurus Inti BUMDes
    $pdo->exec("INSERT IGNORE INTO perangkat_desa (id, jabatan, nama, urutan) VALUES 
        (1, 'Direktur BUMDes', 'Mulyono', 1),
        (2, 'Sekretaris', 'Eman Prasojo', 2),
        (3, 'Bendahara', 'Sri Hartatik', 3)");
}
