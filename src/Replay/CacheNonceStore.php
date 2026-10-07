<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Replay;

use Kipchak\Middleware\Auth\HMAC\Exceptions\ReplayStoreException;
use Psr\Cache\CacheItemPoolInterface;

/**
 * Replay store over any PSR-6 pool (file cache, or a custom pool).
 *
 * PSR-6 has no atomic "add", so this is check-then-set: copies of one request fired at the same moment at
 * different workers can all pass. In a 24-process burst against Valkey through a PSR-6 adapter, 4 to 21 copies
 * got through. Sequential replays are always caught. Use the Valkey or Memcached store in production.
 */
final readonly class CacheNonceStore implements NonceStore
{
    public function __construct(private CacheItemPoolInterface $pool)
    {
    }

    public function claim(string $key, int $ttlSeconds): bool
    {
        try {
            $item = $this->pool->getItem($key);
            if ($item->isHit()) {
                return false;
            }

            $item->set(1);
            $item->expiresAfter(max(1, $ttlSeconds));
            $saved = $this->pool->save($item);
        } catch (\Throwable $exception) {
            throw new ReplayStoreException('Replay store failed: ' . $exception->getMessage(), 0, $exception);
        }

        // Symfony adapters report a lost connection as a miss followed by a failed save, so a failed save
        // is the only signal that nothing was recorded.
        if (!$saved) {
            throw new ReplayStoreException('Replay store refused the write');
        }

        return true;
    }
}
