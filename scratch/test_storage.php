<?php

require_once __DIR__ . '/../vendor/autoload.php';

use JwtAuth\Storage\FileTokenStorage;

$storagePath = __DIR__ . '/test_storage';
$ttl = 5; // 5 seconds for testing
$storage = new FileTokenStorage($storagePath, $ttl);

echo "Blacklisting 'test1'...\n";
$storage->blacklist('test1');
var_dump($storage->isBlacklisted('test1'));

echo "Waiting 6 seconds for expiration...\n";
sleep(6);

echo "Blacklisting 'test2' (should trigger cleanup of 'test1')...\n";
$storage->blacklist('test2');

var_dump($storage->isBlacklisted('test1')); // Should be false
var_dump($storage->isBlacklisted('test2')); // Should be true

$content = file_get_contents($storagePath . '/blacklist.json');
echo "File content: $content\n";

// Cleanup
unlink($storagePath . '/blacklist.json');
rmdir($storagePath);
