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
     */
    public function generateTokens(string $userId): array
    {
        $now = time();

        $accessJti = bin2hex(random_bytes(16));
        $accessToken = JWT::encode([
            'sub' => $userId,
            'jti' => $accessJti,
            'iat' => $now,
            'exp' => $now + $this->config->accessTokenTTL,
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
        ];
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
     * Refresh-Token verarbeiten: Wenn gültig, neue Token generieren und alten Refresh-Token sperren.
     */
    public function refresh(string $refreshToken): ?array
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
            return $this->generateTokens($decoded->sub);
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * JWT-Token manuell sperren (z. B. beim Logout).
     */
    public function blacklist(string $token): bool
    {
        try {
            $decoded = JWT::decode($token, new Key($this->config->secret, $this->config->algo));

            if (isset($decoded->jti)) {
                $this->storage->blacklist($decoded->jti);
                return true;
            }
        } catch (\Throwable) {
            // token war nicht dekodierbar – ignorieren
        }

        return false;
    }
}
