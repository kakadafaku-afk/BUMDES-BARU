<?php
// =======================================================
// Helper Autentikasi JWT / Bearer Token Sederhana (Standalone PHP)
// =======================================================

if (empty($JWT_SECRET)) {
    $JWT_SECRET = getenv('JWT_SECRET') ?: "ganti-secret-key-jwt-anda-di-api-db-php";
}

function base64UrlEncode($data) {
    return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
}

function base64UrlDecode($data) {
    $remainder = strlen($data) % 4;
    if ($remainder) {
        $padlen = 4 - $remainder;
        $data .= str_repeat('=', $padlen);
    }
    return base64_decode(str_replace(['-', '_'], ['+', '/'], $data));
}

function createToken($user) {
    global $JWT_SECRET;
    $now = time();
    $jti = function_exists('random_bytes') ? bin2hex(random_bytes(8)) : uniqid('sess_', true);
    $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
    $payload = json_encode([
        'id' => (int)$user['id'],
        'username' => $user['username'],
        'nama' => $user['nama'],
        'role' => $user['role'],
        'iat' => $now,
        'jti' => $jti,
        'exp' => $now + (2 * 60 * 60) // Masa aktif sesi: 2 jam
    ]);

    $base64Header = base64UrlEncode($header);
    $base64Payload = base64UrlEncode($payload);
    $signature = hash_hmac('sha256', $base64Header . "." . $base64Payload, $JWT_SECRET, true);
    $base64Signature = base64UrlEncode($signature);

    return $base64Header . "." . $base64Payload . "." . $base64Signature;
}

function getRevokedTokensFile() {
    $dir = sys_get_temp_dir();
    return rtrim($dir, '/\\') . '/bumdes_revoked_sessions.json';
}

function revokeJwtToken($jwt) {
    if (!$jwt) return;
    $hash = hash('sha256', trim($jwt));
    $file = getRevokedTokensFile();
    $now = time();
    $data = [];
    if (@file_exists($file)) {
        $raw = @file_get_contents($file);
        $decoded = @json_decode($raw, true);
        if (is_array($decoded)) {
            foreach ($decoded as $k => $expTime) {
                if ($expTime > $now) {
                    $data[$k] = $expTime;
                }
            }
        }
    }
    $data[$hash] = $now + (3 * 60 * 60);
    @file_put_contents($file, json_encode($data));
}

function isJwtTokenRevoked($jwt) {
    if (!$jwt) return true;
    $hash = hash('sha256', trim($jwt));
    $file = getRevokedTokensFile();
    if (!@file_exists($file)) return false;
    $raw = @file_get_contents($file);
    $decoded = @json_decode($raw, true);
    if (!is_array($decoded)) return false;
    return isset($decoded[$hash]) && $decoded[$hash] > time();
}

function getAuthHeader() {
    // 1. Cek dari Custom HTTP Headers (tidak pernah dihapus oleh Apache/FastCGI di cPanel/InfinityFree)
    if (!empty($_SERVER['HTTP_X_AUTHORIZATION'])) {
        return $_SERVER['HTTP_X_AUTHORIZATION'];
    }
    if (!empty($_SERVER['HTTP_X_ADMIN_TOKEN'])) {
        return "Bearer " . $_SERVER['HTTP_X_ADMIN_TOKEN'];
    }

    // 2. Cek dari Query Parameter URL (?auth_token=... atau ?token=...)
    if (!empty($_GET['auth_token'])) {
        return "Bearer " . $_GET['auth_token'];
    }
    if (!empty($_GET['token'])) {
        return "Bearer " . $_GET['token'];
    }

    // 3. Cek $_SERVER standar
    if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
        return $_SERVER['HTTP_AUTHORIZATION'];
    }
    if (!empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
        return $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
    }

    // 4. Cek apache_request_headers / getallheaders
    if (function_exists('apache_request_headers')) {
        $headers = apache_request_headers();
        foreach ($headers as $k => $v) {
            if (strcasecmp($k, 'X-Authorization') === 0) return $v;
            if (strcasecmp($k, 'X-Admin-Token') === 0) return "Bearer " . $v;
            if (strcasecmp($k, 'Authorization') === 0) return $v;
        }
    }
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
        foreach ($headers as $k => $v) {
            if (strcasecmp($k, 'X-Authorization') === 0) return $v;
            if (strcasecmp($k, 'X-Admin-Token') === 0) return "Bearer " . $v;
            if (strcasecmp($k, 'Authorization') === 0) return $v;
        }
    }

    return '';
}

function getCurrentJwtToken() {
    $authHeader = getAuthHeader();
    if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        return trim($matches[1]);
    }
    return '';
}

function requireAuth() {
    global $JWT_SECRET;
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    header("Pragma: no-cache");

    $authHeader = getAuthHeader();

    if (!$authHeader || !preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        http_response_code(401);
        echo json_encode(["error" => "Akses ditolak. Sesi login tidak ditemukan, silakan login ulang."]);
        exit;
    }

    $jwt = trim($matches[1]);
    if (isJwtTokenRevoked($jwt)) {
        http_response_code(401);
        echo json_encode(["error" => "Sesi Anda telah diakhiri (logout). Silakan login ulang."]);
        exit;
    }

    $tokenParts = explode('.', $jwt);
    if (count($tokenParts) != 3) {
        http_response_code(401);
        echo json_encode(["error" => "Format token tidak valid."]);
        exit;
    }

    $header = $tokenParts[0];
    $payload = $tokenParts[1];
    $signatureProvided = $tokenParts[2];

    $expectedSignature = base64UrlEncode(hash_hmac('sha256', $header . "." . $payload, $JWT_SECRET, true));

    if (!hash_equals($expectedSignature, $signatureProvided)) {
        http_response_code(401);
        echo json_encode(["error" => "Sesi tidak valid atau telah dimodifikasi."]);
        exit;
    }

    $payloadData = json_decode(base64UrlDecode($payload), true);
    if (!$payloadData || (isset($payloadData['exp']) && $payloadData['exp'] < time())) {
        http_response_code(401);
        echo json_encode(["error" => "Sesi telah kedaluwarsa. Silakan masuk kembali."]);
        exit;
    }

    return $payloadData;
}

function getClientIpAddress() {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return trim(explode(',', (string)$_SERVER['HTTP_CF_CONNECTING_IP'])[0]);
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return trim(explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
    }
    return (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
}

function getRateLimitFile($bucket) {
    $safeBucket = preg_replace('/[^a-zA-Z0-9_-]/', '_', (string)$bucket);
    return rtrim(sys_get_temp_dir(), '/\\') . '/bumdes_rl_' . $safeBucket . '.json';
}

function checkRateLimit($bucket, $maxAttempts, $windowSeconds, $recordHit = true) {
    $ipHash = hash('sha256', getClientIpAddress() . '|' . $bucket);
    $file = getRateLimitFile($bucket);
    $now = time();
    $store = [];

    if (@is_file($file)) {
        $raw = @file_get_contents($file);
        $decoded = @json_decode((string)$raw, true);
        if (is_array($decoded)) {
            foreach ($decoded as $k => $timestamps) {
                if (is_array($timestamps)) {
                    $valid = array_values(array_filter($timestamps, function ($ts) use ($now, $windowSeconds) {
                        return is_int($ts) && ($now - $ts) < $windowSeconds;
                    }));
                    if (!empty($valid)) {
                        $store[$k] = $valid;
                    }
                }
            }
        }
    }

    $hits = $store[$ipHash] ?? [];
    if (count($hits) >= $maxAttempts) {
        return false;
    }

    if ($recordHit) {
        $hits[] = $now;
        $store[$ipHash] = $hits;
        @file_put_contents($file, json_encode($store), LOCK_EX);
    }
    return true;
}

function recordRateLimitHit($bucket, $windowSeconds) {
    $ipHash = hash('sha256', getClientIpAddress() . '|' . $bucket);
    $file = getRateLimitFile($bucket);
    $now = time();
    $store = [];

    if (@is_file($file)) {
        $raw = @file_get_contents($file);
        $decoded = @json_decode((string)$raw, true);
        if (is_array($decoded)) {
            foreach ($decoded as $k => $timestamps) {
                if (is_array($timestamps)) {
                    $valid = array_values(array_filter($timestamps, function ($ts) use ($now, $windowSeconds) {
                        return is_int($ts) && ($now - $ts) < $windowSeconds;
                    }));
                    if (!empty($valid)) {
                        $store[$k] = $valid;
                    }
                }
            }
        }
    }

    $hits = $store[$ipHash] ?? [];
    $hits[] = $now;
    $store[$ipHash] = $hits;
    @file_put_contents($file, json_encode($store), LOCK_EX);
}

function clearRateLimit($bucket) {
    $ipHash = hash('sha256', getClientIpAddress() . '|' . $bucket);
    $file = getRateLimitFile($bucket);
    if (!@is_file($file)) return;
    $raw = @file_get_contents($file);
    $decoded = @json_decode((string)$raw, true);
    if (is_array($decoded) && isset($decoded[$ipHash])) {
        unset($decoded[$ipHash]);
        @file_put_contents($file, json_encode($decoded), LOCK_EX);
    }
}
