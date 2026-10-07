<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Replay;

use Kipchak\Middleware\Auth\HMAC\Exceptions\ReplayStoreException;

/**
 * Atomic replay store over Memcached's add(), which only succeeds when the key does not exist yet.
 */
final readonly class MemcachedNonceStore implements NonceStore
{
    public function __construct(private \Memcached $client)
    {
    }

    public function claim(string $key, int $ttlSeconds): bool
    {
        if ($this->client->add($key, 1, max(1, $ttlSeconds))) {
            return true;
        }

        // add() also returns false when the server is unreachable; only NOTSTORED means "already claimed".
        $code = $this->client->getResultCode();
        if ($code === \Memcached::RES_NOTSTORED || $code === \Memcached::RES_DATA_EXISTS) {
            return false;
        }

        throw new ReplayStoreException('Replay store write failed: ' . $this->client->getResultMessage());
    }
}
