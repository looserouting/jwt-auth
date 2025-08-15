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
     * Liest Access-Token, Refresh-Token und CSRF-Token aus den Cookies aus.
     *
     * @return array{access: ?string, refresh: ?string, csrf: ?string}
     */
    public function getTokens(): array
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
     * Erzeugt ein Access- und ein Refresh-Token für eine Benutzer-ID.
     * Sowie einen CSRF-Token.
     *
     * @return array{access: string, refresh: string, csrf_token: string}
     */
    public function generateTokens(string $userId): array
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
     * Erzeugt einen sicheren CSRF-Token.
     */
    private function generateCsrfToken(): string
    {
        return bin2hex(random_bytes($this->config->csrfTokenLength));
    }

    /**
     * Erzeugt ein Access-Token für eine Benutzer-ID, das an einen CSRF-Token gebunden ist.
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
     * Erzeugt ein Refresh-Token für eine Benutzer-ID.
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
     * Setzt Access- und Refresh-Tokens als HTTP-only Cookies und den CSRF-Token
     * als reguläres, für JavaScript lesbares Cookie.
     *
     * @param string $userId
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
        $options = [
            'expires' => time() - 3600,
            'path' => $this->config->cookiePath,
            'domain' => $this->config->cookieDomain,
            'secure' => $this->config->cookieSecure,
            'samesite' => $this->config->cookieSameSite,
        ];

        setcookie($this->config->accessTokenCookieName, '', $options + ['httponly' => true]);
        setcookie($this->config->refreshTokenCookieName, '', $options + ['httponly' => true]);
        setcookie($this->config->csrfTokenCookieName, '', $options + ['httponly' => false]);
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
        } catch (InvalidArgumentException | UnexpectedValueException | SignatureInvalidException | BeforeValidException | ExpiredException) {
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
        } catch (InvalidArgumentException | UnexpectedValueException | SignatureInvalidException | BeforeValidException | ExpiredException) {
            // Wenn der Access-Token ungültig ist (z.B. abgelaufen, falsche Signatur),
            // ist die CSRF-Prüfung ebenfalls fehlgeschlagen.
            return false;
        }
    }

    /**
     * Refresh-Token verarbeiten: Wenn gültig, neue Token generieren, alten Refresh-Token sperren
     * und die neuen Tokens als Cookies setzen.
     * Der Refresh-Token wird dabei direkt aus dem Cookie gelesen.
     *
     * @return ?array Gibt bei Erfolg ein Array mit 'user_id' und 'csrf_token' zurück, sonst null.
     */
    public function refresh(): ?array
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
     * Meldet den Benutzer ab, indem der aktuelle Access-Token auf die Blacklist gesetzt
     * und alle Authentifizierungs-Cookies gelöscht werden.
     * Diese Methode sollte von Ihrem Logout-Endpunkt aufgerufen werden.
     *
     * @return bool True, wenn der Token erfolgreich gefunden und auf die Blacklist gesetzt wurde, sonst false.
     *              Hinweis: Cookies werden unabhängig davon gelöscht, ob ein Token gefunden wurde.
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
     * Authentifiziert eine Anfrage durch Validierung des Access-Tokens. Wenn der Access-Token
     * ungültig oder abgelaufen ist, wird versucht, mit dem Refresh-Token neue Tokens auszustellen.
     *
     * Diese Methode ist der empfohlene Einstiegspunkt für die Authentifizierung bei jeder Anfrage.
     *
     * Wichtiger Hinweis: Diese Methode validiert NICHT den CSRF-Token. Die CSRF-Validierung
     * sollte für zustandsändernde Anfragen (POST, PUT, DELETE etc.) separat mit
     * `validateCsrfToken()` durchgeführt werden, nachdem diese Methode erfolgreich war.
     *
     * @return ?string Die User-ID bei erfolgreicher Authentifizierung (entweder durch einen
     *                 gültigen Access-Token oder einen erfolgreichen Refresh), oder null,
     *                 wenn die Authentifizierung fehlschlägt.
     */
    public function authenticateFromRequest(): ?string
    {
        $tokens = $this->getTokens();

        // 1. Versuchen, den Access-Token zu validieren
        if (!empty($tokens['access'])) {
            $userId = $this->validate($tokens['access']);
            if ($userId !== null) {
                return $userId; // Access-Token ist gültig
            }
        }

        // 2. Access-Token ist ungültig, abgelaufen oder fehlt. Refresh versuchen.
        if (!empty($tokens['refresh'])) {
            $refreshResult = $this->refresh();
            if ($refreshResult !== null) {
                // Refresh war erfolgreich, neue Cookies wurden gesetzt.
                // Die Anfrage kann als authentifiziert betrachtet werden.
                return $refreshResult['user_id']; // Jetzt korrekt
            }
        }

        // 3. Kein gültiger Access-Token und kein (gültiger) Refresh-Token gefunden.
        return null;
    }
}
