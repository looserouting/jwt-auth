<?php
namespace JwtAuth;

class Config {
    public function __construct(
        public readonly string $secret,
        public readonly string $algo = 'HS256',
        public readonly int $accessTokenTTL = 900,
        public readonly int $refreshTokenTTL = 604800,
        public readonly string $storagePath = __DIR__ . '/../storage'
    ) {}
}