<?php
namespace JwtAuth;

class Config {
    public function __construct(
        public readonly string $secret,
        public readonly string $algo = 'HS256',
        public readonly int $accessTokenTTL = 900,
        public readonly int $refreshTokenTTL = 604800,
        public readonly string $storagePath = __DIR__ . '/../storage',
        // Cookie settings for HTTP-only tokens and CSRF
        public readonly string $accessTokenCookieName = 'access_token',
        public readonly string $refreshTokenCookieName = 'refresh_token',
        public readonly string $csrfTokenCookieName = 'X-CSRF-TOKEN',
        public readonly int $csrfTokenLength = 32, // Length in bytes for random_bytes
        public readonly string $cookieDomain = '', // e.g., '.yourdomain.com'
        public readonly string $cookiePath = '/',
        public readonly bool $cookieSecure = false, // Set to true in production with HTTPS
        public readonly string $cookieSameSite = 'Lax' // 'Lax', 'Strict', 'None'
    ) {}
}