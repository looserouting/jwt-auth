<?php
namespace JwtAuth;

class TokenStorage {
    private string $file;

    public function __construct(string $storagePath) {
        if (!is_dir($storagePath)) {
            mkdir($storagePath, 0755, true);
        }
        $this->file = rtrim($storagePath, '/') . '/blacklist.json';
    }

    public function blacklist(string $jti): void {
        $list = $this->load();
        $list[$jti] = time();
        file_put_contents($this->file, json_encode($list));
    }

    public function isBlacklisted(string $jti): bool {
        $list = $this->load();
        return isset($list[$jti]);
    }

    private function load(): array {
        if (!file_exists($this->file)) {
            return [];
        }
        return json_decode(file_get_contents($this->file), true) ?? [];
    }
}
