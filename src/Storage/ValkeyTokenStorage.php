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
     * @var int TTL for blacklisted tokens in seconds.
     */
    private int $ttl;

    /**
     * Constructor.
     *
     * @param Redis $redis A connected Redis client instance.
     * @param int $ttl TTL for blacklisted tokens (default 7 days).
     */
    public function __construct(Redis $redis, int $ttl = 604800) {
        $this->redis = $redis;
        $this->ttl = $ttl;
    }

    /**
     * Blacklists a JWT ID (jti) by storing it in Redis.
     *
     * @param string $jti JWT ID to blacklist.
     * @return void
     */
    public function blacklist(string $jti): void {
        $this->redis->setex("jwt:blacklist:$jti", $this->ttl, 1);
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
