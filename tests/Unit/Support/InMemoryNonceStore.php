<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Tests\Unit\Support;

use Kipchak\Middleware\Auth\HMAC\Exceptions\ReplayStoreException;
use Kipchak\Middleware\Auth\HMAC\Replay\NonceStore;

final class InMemoryNonceStore implements NonceStore
{
    /** @var array<string, int> key => ttl it was claimed with */
    public array $claims = [];

    public bool $broken = false;

    public function claim(string $key, int $ttlSeconds): bool
    {
        if ($this->broken) {
            throw new ReplayStoreException('store is down');
        }
        if (isset($this->claims[$key])) {
            return false;
        }
        $this->claims[$key] = $ttlSeconds;

        return true;
    }
}
