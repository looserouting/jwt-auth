<?php

namespace JwtAuth\Storage;

use Redis;

class ValkeyTokenStorage implements TokenStorageInterface {
    private Redis $redis;

    public function __construct(Redis $redis) {
        $this->redis = $redis;
    }

    public function blacklist(string $jti): void {
        $this->redis->setex("jwt:blacklist:$jti", 3600 * 24 * 14, 1); // z.B. 14 Tage
    }

    public function isBlacklisted(string $jti): bool {
        return $this->redis->exists("jwt:blacklist:$jti") > 0;
    }
}
