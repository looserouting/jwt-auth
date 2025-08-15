<?php

namespace JwtAuth\Storage;

use Redis;

/**
 * Redis-based implementation of TokenStorageInterface for JWT blacklisting.
 *
 * Stores blacklisted JWT IDs (jti) with an expiration using Redis.
 */
class ValkeyTokenStorage implements TokenStorageInterface {
    /**
     * @var Redis The Redis client instance.
     */
    private Redis $redis;

    /**
     * Constructor.
     *
     * @param Redis $redis A connected Redis client instance.
     */
    public function __construct(Redis $redis) {
        $this->redis = $redis;
    }

    /**
     * Blacklists a JWT ID (jti) by storing it in Redis with a 14-day expiration.
     *
     * @param string $jti JWT ID to blacklist.
     * @return void
     */
    public function blacklist(string $jti): void {
        $this->redis->setex("jwt:blacklist:$jti", 3600 * 24 * 14, 1); // e.g. 14 days
    }

    /**
     * Checks whether the given JWT ID (jti) is blacklisted in Redis.
     *
     * @param string $jti JWT ID to check.
     * @return bool True if the token is blacklisted, false otherwise.
     */
    public function isBlacklisted(string $jti): bool {
        return $this->redis->exists("jwt:blacklist:$jti") > 0;
    }
}
