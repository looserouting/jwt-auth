<?php

namespace JwtAuth\Storage;

interface TokenStorageInterface {
    public function blacklist(string $jti): void;
    public function isBlacklisted(string $jti): bool;
}
