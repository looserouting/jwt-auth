# jwt-auth
jwt auth library wir Access-Token, Refresh-Token and Token-Revocation

# Exmaple Usage
```php
<?php
require_once __DIR__ . '/../vendor/autoload.php';

use JwtAuth\Auth;
use JwtAuth\Config;
use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

$config = new Config(
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
```

# Explanation of the New Configuration Options:

`accessTokenCookieName`, `refreshTokenCookieName`, `csrfTokenCookieName`: Names of the cookies.
`csrfTokenLength`: The length of the generated CSRF token in bytes (converted to hex).
`cookieDomain`: The domain for which the cookie is valid (e.g., yourdomain.com or .yourdomain.com for subdomains). Leave empty to use the current domain.
`cookiePath`: The path for which the cookie is valid (e.g., / for the entire website).
cookieSecure: Set this to true in production if your site runs over HTTPS. Cookies will then only be sent over secure connections.
`cookieSameSite`: Protects against CSRF attacks by controlling when cookies are sent with cross-site requests.

`Lax` (default): Cookies are sent with top-level navigations (GET requests) and same-site requests.

`Strict`: Cookies are only sent with same-site requests.

`None`: Cookies are sent with all requests, but requires `Secure=true`.