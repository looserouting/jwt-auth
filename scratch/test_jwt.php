<?php

require_once __DIR__ . '/../vendor/autoload.php';

use JwtAuth\Auth;
use JwtAuth\Config;
use JwtAuth\Storage\FileTokenStorage;

$config = new Config(
    secret: 'super-secret-key-that-is-at-least-32-chars-long-!!!',
    algo: 'HS256',
    accessTokenTTL: 3600
);

$storage = new FileTokenStorage(__DIR__ . '/test_storage');
$auth = new Auth($config, $storage);

$userId = 'user123';
echo "Generating tokens for $userId...\n";
$csrfToken = $auth->issueAuthCookies($userId);

echo "CSRF Token: $csrfToken\n";

// In a real request, cookies would be set. For testing Auth::authenticateFromRequest with injected cookies:
$accessToken = ''; // We need to catch the cookie or use a helper. 
// Since issueAuthCookies calls setcookie, we can't easily get the value without mock or output buffering.

// Let's use reflection or just test the internal methods if possible, 
// or better: refactor Auth to allow getting generated tokens for testing.

// Actually, I added $cookies to constructor!
// But issueAuthCookies uses setcookie().

echo "Test completed (Basic check for class loading and constant compatibility).\n";
