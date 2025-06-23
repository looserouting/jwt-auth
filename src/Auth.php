<?php

namespace JwtAuth;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use JwtAuth\Storage\TokenStorageInterface;

class Auth
{
    private Config $config;
    private TokenStorageInterface $storage;

    public function __construct(Config $config, TokenStorageInterface $storage)
    {
        $this->config = $config;
        $this->storage = $storage;
    }

    /**
     * Erzeugt ein Access- und ein Refresh-Token für eine Benutzer-ID.
     * Sowie einen CSRF-Token.
     *
     * @return array{access: string, refresh: string, csrf_token: string}
     */
    public function generateTokens(string $userId): array // Changed return type hint in docblock
    {
        $now = time();
        $csrfToken = bin2hex(random_bytes($this->config->csrfTokenLength));
        $csrfHash = hash('sha256', $csrfToken);

        $accessJti = bin2hex(random_bytes(16));
        $accessToken = JWT::encode([
            'sub' => $userId,
            'jti' => $accessJti,
            'iat' => $now,
            'exp' => $now + $this->config->accessTokenTTL,
            'csrf' => $csrfHash, // CSRF Token Binding
        ], $this->config->secret, $this->config->algo);

        $refreshJti = bin2hex(random_bytes(16));
        $refreshToken = JWT::encode([
            'sub' => $userId,
            'jti' => $refreshJti,
            'iat' => $now,
            'exp' => $now + $this->config->refreshTokenTTL,
        ], $this->config->secret, $this->config->algo);

        return [
            'access' => $accessToken,
            'refresh' => $refreshToken,
            'csrf_token' => $csrfToken,
        ];
    }

    /**
     * Setzt Access- und Refresh-Tokens als HTTP-only Cookies und den CSRF-Token
     * als reguläres, für JavaScript lesbares Cookie.
     *
     * @param string $userId
     * @return string Der generierte CSRF-Token (für die Client-Antwort).
     */
    public function issueAuthCookies(string $userId): string
    {
        $tokens = $this->generateTokens($userId);
        $now = time();

        // Access Token Cookie (HTTP-only)
        setcookie(
            $this->config->accessTokenCookieName,
            $tokens['access'],
            [
                'expires' => $now + $this->config->accessTokenTTL,
                'path' => $this->config->cookiePath,
                'domain' => $this->config->cookieDomain,
                'secure' => $this->config->cookieSecure,
                'httponly' => true,
                'samesite' => $this->config->cookieSameSite,
            ]
        );

        // Refresh Token Cookie (HTTP-only)
        setcookie(
            $this->config->refreshTokenCookieName,
            $tokens['refresh'],
            [
                'expires' => $now + $this->config->refreshTokenTTL,
                'path' => $this->config->cookiePath,
                'domain' => $this->config->cookieDomain,
                'secure' => $this->config->cookieSecure,
                'httponly' => true,
                'samesite' => $this->config->cookieSameSite,
            ]
        );

        // CSRF Token Cookie (NOT HTTP-only, so JavaScript can read it for double-submit pattern)
        setcookie(
            $this->config->csrfTokenCookieName,
            $tokens['csrf_token'],
            [
                'expires' => $now + $this->config->refreshTokenTTL, // Tie CSRF token lifetime to refresh token
                'path' => $this->config->cookiePath,
                'domain' => $this->config->cookieDomain,
                'secure' => $this->config->cookieSecure,
                'httponly' => false, // Important: JS needs to read this
                'samesite' => $this->config->cookieSameSite,
            ]
        );

        return $tokens['csrf_token'];
    }

    /**
     * Löscht alle Authentifizierungs- und CSRF-Cookies.
     */
    public function clearAuthCookies(): void
    {
        $now = time(); // Current time

        // Set expiration to a past date to delete the cookie
        $pastTime = $now - 3600; // 1 hour in the past

        $cookieOptions = [
            'expires' => $pastTime,
            'path' => $this->config->cookiePath,
            'domain' => $this->config->cookieDomain,
            'secure' => $this->config->cookieSecure,
            'samesite' => $this->config->cookieSameSite,
        ];

        // Access Token Cookie (HTTP-only)
        setcookie($this->config->accessTokenCookieName, '', array_merge($cookieOptions, ['httponly' => true]));
        // Refresh Token Cookie (HTTP-only)
        setcookie($this->config->refreshTokenCookieName, '', array_merge($cookieOptions, ['httponly' => true]));
        // CSRF Token Cookie (NOT HTTP-only)
        setcookie($this->config->csrfTokenCookieName, '', array_merge($cookieOptions, ['httponly' => false]));
    }

    /**
     * Prüft ein JWT-Access-Token und gibt die Benutzer-ID zurück, wenn gültig.
     */
    public function validate(string $token): ?string
    {
        try {
            $decoded = JWT::decode($token, new Key($this->config->secret, $this->config->algo));

            if (isset($decoded->jti) && $this->storage->isBlacklisted($decoded->jti)) {
                return null;
            }

            return $decoded->sub ?? null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * Validiert einen CSRF-Token mittels "Double Submit Cookie" und "Token Binding".
     * Der Access-Token muss hier mitübergeben werden, um den darin enthaltenen
     * CSRF-Hash zu vergleichen.
     *
     * @param string $requestCsrfToken Der CSRF-Token aus dem Request-Header (z.B. X-CSRF-TOKEN).
     * @param string $cookieCsrfToken Der CSRF-Token aus dem Cookie (z.B. $_COOKIE['X-CSRF-TOKEN']).
     * @param string $accessToken Der Access-Token, typischerweise aus dem Cookie.
     * @return bool True, wenn die Tokens gültig und aneinander gebunden sind, sonst false.
     */
    public function validateCsrfToken(string $requestCsrfToken, string $cookieCsrfToken, string $accessToken): bool
    {
        // 1. Standard "Double Submit" Prüfung: Stimmen Header und Cookie überein?
        if (empty($requestCsrfToken) || !hash_equals($cookieCsrfToken, $requestCsrfToken)) {
            return false;
        }

        // 2. "Token Binding" Prüfung: Ist der CSRF-Token an den Access-Token gebunden?
        try {
            $decodedAccessToken = JWT::decode($accessToken, new Key($this->config->secret, $this->config->algo));

            // Prüfen, ob der 'csrf'-Claim im Access-Token existiert
            if (!isset($decodedAccessToken->csrf)) {
                return false;
            }

            // Hash des übermittelten CSRF-Tokens berechnen
            $requestCsrfHash = hash('sha256', $requestCsrfToken);

            // Vergleichen des Hash aus dem Access-Token mit dem berechneten Hash
            return hash_equals($decodedAccessToken->csrf, $requestCsrfHash);
        } catch (\Throwable) {
            // Wenn der Access-Token ungültig ist (z.B. abgelaufen, falsche Signatur),
            // ist die CSRF-Prüfung ebenfalls fehlgeschlagen.
            return false;
        }
    }

    /**
     * Refresh-Token verarbeiten: Wenn gültig, neue Token generieren und alten Refresh-Token sperren.
     */
    public function refresh(string $refreshToken): ?string // Changed return type hint
    {
        try {
            $decoded = JWT::decode($refreshToken, new Key($this->config->secret, $this->config->algo));

            if (!isset($decoded->sub, $decoded->jti)) {
                return null;
            }

            if ($this->storage->isBlacklisted($decoded->jti)) {
                return null;
            }

            // Refresh-Token blacklisten
            $this->storage->blacklist($decoded->jti);

            // Neue Tokens ausstellen
            return $this->issueAuthCookies($decoded->sub); // Use the new method to set cookies
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * JWT-Token manuell sperren und Auth-Cookies löschen (z.B. beim Logout).
     * Das Löschen der Cookies wird immer versucht, auch wenn der Token ungültig ist.
     */
    public function blacklist(string $token): bool // Added clearAuthCookies
    {
        $isBlacklisted = false;
        try {
            $decoded = JWT::decode($token, new Key($this->config->secret, $this->config->algo));

            if (isset($decoded->jti)) {
                $this->storage->blacklist($decoded->jti);
                $isBlacklisted = true;
            }
        } catch (\Throwable) {
            // Token war nicht dekodierbar (z.B. abgelaufen, ungültig).
            // Das Blacklisting ist nicht möglich, aber die Cookies müssen trotzdem gelöscht werden.
        }
        
        $this->clearAuthCookies(); // Wichtig: Immer Cookies löschen beim Logout-Versuch.
        return $isBlacklisted;
    }
}
