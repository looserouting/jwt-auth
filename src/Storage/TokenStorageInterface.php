<?php

namespace JwtAuth\Storage;

/**
 * Interface for token blacklisting storage mechanisms.
 *
 * Implementations should provide a mechanism for tracking and checking JWT IDs (jti) that are blacklisted.
 */
interface TokenStorageInterface {
    /**
     * Add a JWT ID (jti) to the blacklist, invalidating future use of the token.
     *
     * @param string $jti The JWT ID to put on the blacklist.
     * @return void
     */
    public function blacklist(string $jti): void;
    /**
     * Check whether a given JWT ID (jti) is blacklisted.
     *
     * @param string $jti The JWT ID to check.
     * @return bool True if the token is blacklisted, false otherwise.
     */
    public function isBlacklisted(string $jti): bool;
}
