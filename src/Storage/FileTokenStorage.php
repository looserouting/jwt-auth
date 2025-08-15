<?php

namespace JwtAuth\Storage;

/**
 * File-based implementation of TokenStorageInterface for JWT blacklisting.
 *
 * Uses a JSON file to store a mapping of blacklisted JWT IDs (jti) to timestamps.
 */
class FileTokenStorage implements TokenStorageInterface {
    /**
     * @var string Path to the blacklist JSON file.
     */
    private string $file;

    /**
     * Constructor.
     *
     * Creates the storage directory if it does not exist and sets the blacklist file path.
     *
     * @param string $path Directory for storage. A file named 'blacklist.json' will be created here.
     */
    public function __construct(string $path) {
        if (!is_dir($path)) {
            mkdir($path, 0755, true);
        }
        $this->file = rtrim($path, '/') . '/blacklist.json';
    }

    /**
     * Blacklists a JWT ID (jti) and stores the time it was blacklisted.
     *
     * @param string $jti JWT ID to blacklist.
     * @return void
     */
    public function blacklist(string $jti): void {
        $list = $this->load();
        $list[$jti] = time();
        file_put_contents($this->file, json_encode($list));
    }

    /**
     * Checks whether the given JWT ID (jti) is blacklisted.
     *
     * @param string $jti JWT ID to check.
     * @return bool True if the token is blacklisted, false otherwise.
     */
    public function isBlacklisted(string $jti): bool {
        return array_key_exists($jti, $this->load());
    }

    /**
     * Loads the blacklist from file.
     *
     * @return array Associative array of blacklisted JWT IDs mapped to timestamps.
     */
    private function load(): array {
        if (!file_exists($this->file)) {
            return [];
        }
        return json_decode(file_get_contents($this->file), true) ?? [];
    }
}
