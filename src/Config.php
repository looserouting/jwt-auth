<?php
namespace JwtAuth;

/**
 * Class Config
 *
 * Configuration holder for JWT authentication.
 *
 * @property string $accessTokenCookieName Name of the Access Token cookie.
 * @property string $refreshTokenCookieName Name of the Refresh Token cookie.
 * @property string $csrfTokenCookieName Name of the CSRF Token cookie.
 * @property int $csrfTokenLength Length of the CSRF token in bytes.
 * @property int $accessTokenTTL Access Token time-to-live in seconds.
 * @property int $refreshTokenTTL Refresh Token time-to-live in seconds.
 * @property string $secret Secret key for JWT signing.
 * @property string $algo Algorithm used for JWT.
 * @property string $cookiePath Cookie path for authentication tokens.
 * @property string $cookieDomain Domain for cookies.
 * @property bool $cookieSecure Set true for Secure cookies.
 * @property string $cookieSameSite SameSite value for cookies.
 */
class Config {
    public function __construct(
        public readonly string $secret,
        public readonly string $algo = 'HS256',
        public readonly int $accessTokenTTL = 900,
        public readonly int $refreshTokenTTL = 604800,
        // Cookie settings for HTTP-only tokens and CSRF
        public readonly string $accessTokenCookieName = 'access_token',
        public readonly string $refreshTokenCookieName = 'refresh_token',
        public readonly string $csrfTokenCookieName = 'X-CSRF-TOKEN',
        public readonly int $csrfTokenLength = 32, // Length in bytes for random_bytes
        public readonly string $cookieDomain = '', // e.g., '.yourdomain.com', empty means same domain
        public readonly string $cookiePath = '/', // slash means all paths
        public readonly bool $cookieSecure = false, // Set to true in production with HTTPS
        public readonly string $cookieSameSite = 'Lax' // 'Lax', 'Strict', 'None'
    ) {}
}