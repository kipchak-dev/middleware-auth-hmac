<?php

declare(strict_types=1);

/*
 * One "worker" in the replay race: connects to the store, waits for the shared start time, claims the key once
 * and prints "won" or "lost". Run by ReplayStoresTest as a separate PHP process.
 *
 * Usage: php claim-worker.php <valkey|memcached> <host> <port> <key> <start microtime>
 */

use Kipchak\Middleware\Auth\HMAC\Replay\MemcachedNonceStore;
use Kipchak\Middleware\Auth\HMAC\Replay\RedisNonceStore;

require __DIR__ . '/../../vendor/autoload.php';

[, $type, $host, $port, $key, $start] = $argv;

if ($type === 'valkey') {
    $client = new Redis();
    $client->connect($host, (int) $port, 2.0);
    $store = new RedisNonceStore($client);
} else {
    $client = new Memcached();
    $client->addServer($host, (int) $port);
    $client->getVersion(); // connect before the start line
    $store = new MemcachedNonceStore($client);
}

time_sleep_until((float) $start);

echo $store->claim($key, 60) ? 'won' : 'lost';
