composer create-project https://github.com/looserouting/skeleton myproject

# jwt-auth
jwt auth library wir Access-Token, Refresh-Token and Token-Revocation

# Exmaple Usage
<?php
require_once __DIR__ . '/../vendor/autoload.php';

use JwtAuth\Auth;
use JwtAuth\ConfigVO;
use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

$config = new ConfigVO(
    secret: $_ENV['JWT_SECRET'],
    algo: $_ENV['JWT_ALGO'] ?? 'HS256',
    accessTokenTTL: (int)($_ENV['JWT_ACCESS_TTL'] ?? 900),
    refreshTokenTTL: (int)($_ENV['JWT_REFRESH_TTL'] ?? 604800),
    storagePath: $_ENV['JWT_STORAGE_PATH'] ?? __DIR__ . '/../storage'
);

$auth = new Auth($config);

// Beispiel: Login
$tokens = $auth->generateTokens('user_123');
echo "Access: {$tokens['access']}\n";
echo "Refresh: {$tokens['refresh']}\n";

// Beispiel: Prüfung
$userId = $auth->validate($tokens['access']);
echo "Benutzer-ID: " . ($userId ?? 'Ungültig') . "\n";

// Beispiel: Refresh
$newTokens = $auth->refresh($tokens['refresh']);
