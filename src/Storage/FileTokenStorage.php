<?php

namespace JwtAuth\Storage;

class FileTokenStorage implements TokenStorageInterface {
    private string $file;

    public function __construct(string $path) {
        if (!is_dir($path)) {
            mkdir($path, 0755, true);
        }
        $this->file = rtrim($path, '/') . '/blacklist.json';
    }

    public function blacklist(string $jti): void {
        $list = $this->load();
        $list[$jti] = time();
        file_put_contents($this->file, json_encode($list));
    }

    public function isBlacklisted(string $jti): bool {
        return array_key_exists($jti, $this->load());
    }

    private function load(): array {
        if (!file_exists($this->file)) {
            return [];
        }
        return json_decode(file_get_contents($this->file), true) ?? [];
    }
}
