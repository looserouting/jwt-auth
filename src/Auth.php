<?php

declare(strict_types=1);

namespace JwtAuth;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use InvalidArgumentException;
use JwtAuth\Storage\TokenStorageInterface;
use UnexpectedValueException;

class Auth
{
    public function __construct(
        private readonly Config $config,
        private readonly TokenStorageInterface $storage,
    ) {
    }

    /**
     * Reads access token, refresh token, and CSRF token from the cookies.
     *
     * @return array{access: ?string, refresh: ?string, csrf: ?string}
     */
    private function getTokens(): array
    {
        $access = $_COOKIE[$this->config->accessTokenCookieName] ?? null;
        $refresh = $_COOKIE[$this->config->refreshTokenCookieName] ?? null;
        $csrf = $_COOKIE[$this->config->csrfTokenCookieName] ?? null;
        return [
            'access' => $access,
            'refresh' => $refresh,
            'csrf' => $csrf,
        ];
    }

    
    /**
     * Generates access token, refresh token, and CSRF token for a user ID.
     *
     * @return array{access: string, refresh: string, csrf_token: string}
     */
    private function generateTokens(string $userId): array
    {
        $csrfToken = $this->generateCsrfToken();
        $accessToken = $this->generateAccessToken($userId, $csrfToken);
        $refreshToken = $this->generateRefreshToken($userId);

        return [
            'access' => $accessToken,
            'refresh' => $refreshToken,
            'csrf_token' => $csrfToken,
        ];
    }

    /**
     * Generates a secure CSRF token.
     *
     * @return string The generated CSRF token.
     */
    private function generateCsrfToken(): string
    {
        return bin2hex(random_bytes($this->config->csrfTokenLength));
    }

    /**
     * Generates an access token for a user ID, which is bound to a CSRF token.
     *
     * @param string $userId The user ID.
     * @param string $csrfToken The CSRF token to bind.
     * @return string The generated access token.
     */
    private function generateAccessToken(string $userId, string $csrfToken): string
    {
        $now = time();
        $csrfHash = hash('sha256', $csrfToken);
        $accessJti = bin2hex(random_bytes(16));

        return JWT::encode([
            'sub' => $userId,
            'jti' => $accessJti,
            'iat' => $now,
            'exp' => $now + $this->config->accessTokenTTL,
            'csrf' => $csrfHash, // CSRF Token Binding
        ], $this->config->secret, $this->config->algo);
    }

    /**
     * Generates a refresh token for a user ID.
     *
     * @param string $userId The user ID.
     * @return string The generated refresh token.
     */
    private function generateRefreshToken(string $userId): string
    {
        $now = time();
        $refreshJti = bin2hex(random_bytes(16));

        return JWT::encode([
            'sub' => $userId,
            'jti' => $refreshJti,
            'iat' => $now,
            'exp' => $now + $this->config->refreshTokenTTL,
        ], $this->config->secret, $this->config->algo);
    }

    /**
     * Sets the access and refresh tokens as HTTP-only cookies, and the CSRF token
     * as a regular JavaScript-readable cookie.
     *
     * @param string $userId The user ID.
     * @return string The generated CSRF token
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
     * Clears all authentication and CSRF cookies.
     *
     * @return void
     */
    private function clearAuthCookies(): void
    {
        $options = [
            'expires' => time() - 3600,
            'path' => $this->config->cookiePath,
            'domain' => $this->config->cookieDomain,
            'secure' => $this->config->cookieSecure,
            'samesite' => $this->config->cookieSameSite,
        ];

        setcookie($this->config->accessTokenCookieName, '', array_merge($options, ['httponly' => true]));
        setcookie($this->config->refreshTokenCookieName, '', array_merge($options, ['httponly' => true]));
        setcookie($this->config->csrfTokenCookieName, '', array_merge($options, ['httponly' => false]));
    }

    /**
     * Validates a JWT access token and returns the user ID if valid.
     *
     * @param string $token The JWT access token to validate.
     * @return string|null The user ID if the token is valid, null otherwise.
     */
    private function validate(string $token): ?string
    {
        try {
            $decoded = JWT::decode($token, new Key($this->config->secret, $this->config->algo));

            if (isset($decoded->jti) && $this->storage->isBlacklisted($decoded->jti)) {
                return null;
            }

            return $decoded->sub ?? null;
        } catch (InvalidArgumentException | UnexpectedValueException | SignatureInvalidException | BeforeValidException | ExpiredException) {
            return null;
        }
    }

    /**
     * Validates a CSRF token using the "Double Submit Cookie" and "Token Binding" technique.
     * The access token must also be provided to compare the contained CSRF hash.
     *
     * @param string $requestCsrfToken The CSRF token from the request header (e.g. X-CSRF-TOKEN).
     * @param string $cookieCsrfToken The CSRF token from the cookie (e.g. $_COOKIE['X-CSRF-TOKEN']).
     * @param string $accessToken The access token, typically from the cookie.
     * @return bool True if the tokens are valid and bound together, false otherwise.
     */
    private function validateCsrfToken(string $requestCsrfToken, string $cookieCsrfToken, string $accessToken): bool
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
        } catch (InvalidArgumentException | UnexpectedValueException | SignatureInvalidException | BeforeValidException | ExpiredException) {
            // Wenn der Access-Token ungültig ist (z.B. abgelaufen, falsche Signatur),
            // ist die CSRF-Prüfung ebenfalls fehlgeschlagen.
            return false;
        }
    }

    /**
     * Processes the refresh token: if valid, generates new tokens, blacklists the old refresh token,
     * and sets the new tokens as cookies. The refresh token is read directly from the cookie.
     *
     * @return ?array Returns an array with 'user_id' and 'csrf_token' on success, otherwise null.
     */
    private function refresh(): ?array
    {
        $refreshToken = $_COOKIE[$this->config->refreshTokenCookieName] ?? null;
        if ($refreshToken === null) {
            return null;
        }

        try {
            $decoded = JWT::decode($refreshToken, new Key($this->config->secret, $this->config->algo));

            if (!isset($decoded->sub, $decoded->jti)) {
                return null;
            }

            if ($this->storage->isBlacklisted($decoded->jti)) {
                return null;
            }

            // Alten Refresh-Token blacklisten
            $this->storage->blacklist($decoded->jti);

            // Neue Tokens ausstellen und Cookies setzen
            $newCsrfToken = $this->issueAuthCookies($decoded->sub);
            
            return [
                'user_id' => $decoded->sub,
                'csrf_token' => $newCsrfToken,
            ];
        } catch (InvalidArgumentException | UnexpectedValueException | SignatureInvalidException | BeforeValidException | ExpiredException) {
            return null;
        }
    }

    /**
     * Logs out the user by blacklisting the current access token and removing all authentication cookies.
     * This method should be called from your logout endpoint.
     *
     * @return bool True if the access token was found and blacklisted, false otherwise.
     *              Note: Cookies are deleted regardless of whether a token was found.
     */
    public function logout(): bool
    {
        $accessToken = $_COOKIE[$this->config->accessTokenCookieName] ?? null;
        $isBlacklisted = false;

        if ($accessToken) {
            try {
                $decoded = JWT::decode($accessToken, new Key($this->config->secret, $this->config->algo));

                if (isset($decoded->jti)) {
                    $this->storage->blacklist($decoded->jti);
                    $isBlacklisted = true;
                }
            } catch (InvalidArgumentException | UnexpectedValueException | SignatureInvalidException | BeforeValidException | ExpiredException) {
                // Token war nicht dekodierbar (z.B. abgelaufen, ungültig).
                // Das Blacklisting ist nicht möglich, aber die Cookies müssen trotzdem gelöscht werden.
            }
        }

        $this->clearAuthCookies(); // Wichtig: Cookies bei jedem Logout-Versuch löschen.
        return $isBlacklisted;
    }

    /**
     * Authenticates a request by validating the access token and optionally the CSRF token (Double Submit).
     * If the access token is invalid or expired, it attempts to use the refresh token to issue new tokens.
     *
     * This method is the recommended entry point for authentication checks on every request.
     *
     * Important: This method does NOT validate the CSRF token for state-changing requests. The CSRF validation
     * should be performed separately via `validateCsrfToken()` after this method succeeds (for POST, PUT, DELETE, etc.).
     *
     * @param string|null $requestCsrfToken The CSRF token from the request header, e.g. X-CSRF-TOKEN
     * @return string|null The user ID on successful authentication (valid access token or refresh), null on failure.
     */
    public function authenticateFromRequest(?string $requestCsrfToken = null): ?string
    {
        $tokens = $this->getTokens();

        // 1. Versuchen, den Access-Token zu validieren
        if (!empty($tokens['access'])) {
            $userId = $this->validate($tokens['access']);
            if ($userId !== null) {
                // Nach erfolgreicher Access-Token-Prüfung CSRF validieren
                // Die Prüfung ist nur relevant für zustandsändernde Requests (POST, PUT, DELETE),
                // daher wird der CSRF-Header nur geprüft, falls er mitgegeben wird
                if ($requestCsrfToken !== null) {
                    // token in cookie und access werden für die bindung benötigt
                    if (!$this->validateCsrfToken($requestCsrfToken, $tokens['csrf'], $tokens['access'])) {
                        return null; // CSRF ungültig
                    }
                }
                return $userId; // Access- und ggf. CSRF-Token sind gültig
            }
        }

        // 2. Access-Token ist ungültig, abgelaufen oder fehlt. Refresh versuchen.
        if (!empty($tokens['refresh'])) {
            $refreshResult = $this->refresh();
            if ($refreshResult !== null) {
                // Refresh war erfolgreich, neue Cookies wurden gesetzt.
                // Die Anfrage kann als authentifiziert betrachtet werden.
                return $refreshResult['user_id'];
            }
        }

        // 3. Kein gültiger Access-Token und kein (gültiger) Refresh-Token gefunden.
        return null;
    }
}
