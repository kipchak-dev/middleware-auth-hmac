<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Replay;

use Kipchak\Middleware\Auth\HMAC\Exceptions\ReplayStoreException;

/**
 * Remembers which signed messages have been seen, for as long as they could still verify.
 */
interface NonceStore
{
    /**
     * Records the key if it has not been seen. Returns true for the first claim and false for every later one
     * until the TTL passes.
     *
     * @throws ReplayStoreException When the store cannot answer. The middleware fails closed unless configured otherwise.
     */
    public function claim(string $key, int $ttlSeconds): bool;
}
