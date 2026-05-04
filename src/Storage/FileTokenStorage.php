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
    /**
     * @var int TTL for blacklisted tokens in seconds.
     */
    private int $ttl;

    /**
     * Constructor.
     *
     * @param string $path Directory for storage. A file named 'blacklist.json' will be created here.
     * @param int $ttl TTL for blacklisted tokens (default 7 days).
     */
    public function __construct(string $path, int $ttl = 604800) {
        if (!is_dir($path)) {
            mkdir($path, 0755, true);
        }
        $this->file = rtrim($path, '/') . '/blacklist.json';
        $this->ttl = $ttl;
    }

    /**
     * Blacklists a JWT ID (jti) and stores the time it was blacklisted.
     *
     * @param string $jti JWT ID to blacklist.
     * @return void
     */
    public function blacklist(string $jti): void {
        $fp = fopen($this->file, 'c+');
        if (!$fp) {
            return;
        }

        if (flock($fp, LOCK_EX)) {
            $content = stream_get_contents($fp);
            $list = $content ? json_decode($content, true) : [];
            
            // Cleanup expired entries
            $list = $this->cleanup($list);
            
            $list[$jti] = time();
            
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode($list));
            fflush($fp);
            flock($fp, LOCK_UN);
        }
        fclose($fp);
    }

    /**
     * Checks whether the given JWT ID (jti) is blacklisted.
     *
     * @param string $jti JWT ID to check.
     * @return bool True if the token is blacklisted, false otherwise.
     */
    public function isBlacklisted(string $jti): bool {
        $list = $this->load();
        return array_key_exists($jti, $list);
    }

    /**
     * Loads the blacklist from file with shared lock.
     *
     * @return array Associative array of blacklisted JWT IDs mapped to timestamps.
     */
    private function load(): array {
        if (!file_exists($this->file)) {
            return [];
        }

        $fp = fopen($this->file, 'r');
        if (!$fp) {
            return [];
        }

        $list = [];
        if (flock($fp, LOCK_SH)) {
            $content = stream_get_contents($fp);
            $list = $content ? json_decode($content, true) : [];
            flock($fp, LOCK_UN);
        }
        fclose($fp);

        return $list ?? [];
    }

    /**
     * Removes expired entries from the blacklist.
     *
     * @param array $list
     * @return array
     */
    private function cleanup(array $list): array {
        $now = time();
        return array_filter($list, fn($timestamp) => ($now - $timestamp) < $this->ttl);
    }
}
