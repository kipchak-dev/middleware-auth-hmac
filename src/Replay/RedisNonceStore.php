<?php

declare(strict_types=1);

namespace Kipchak\Middleware\Auth\HMAC\Replay;

use Kipchak\Middleware\Auth\HMAC\Exceptions\ReplayStoreException;

/**
 * Atomic replay store: one SET NX EX per request, so concurrent workers and hosts can never both accept
 * the same signature. Works with Valkey and Redis through phpredis, Relay or Predis.
 *
 * A phpredis client that fails a command while the server is down stays broken after the server returns,
 * which in a long-lived worker would mean every request fails until the worker restarts. Given a $reconnect
 * callback, the store swaps in a fresh client and retries once after any failure.
 */
final class RedisNonceStore implements NonceStore
{
    /**
     * @param (\Closure(): (\Redis|\RedisCluster|\Relay\Relay|\Relay\Cluster|\Predis\ClientInterface))|null $reconnect
     */
    public function __construct(
        private \Redis|\RedisCluster|\Relay\Relay|\Relay\Cluster|\Predis\ClientInterface $client,
        private readonly ?\Closure $reconnect = null,
    ) {
    }

    public function claim(string $key, int $ttlSeconds): bool
    {
        $ttlSeconds = max(1, $ttlSeconds);

        try {
            return $this->set($key, $ttlSeconds);
        } catch (\Throwable $exception) {
            if ($this->reconnect === null) {
                throw new ReplayStoreException('Replay store write failed: ' . $exception->getMessage(), 0, $exception);
            }
        }

        try {
            $this->client = ($this->reconnect)();

            return $this->set($key, $ttlSeconds);
        } catch (\Throwable $exception) {
            throw new ReplayStoreException('Replay store write failed after reconnecting: ' . $exception->getMessage(), 0, $exception);
        }
    }

    private function set(string $key, int $ttlSeconds): bool
    {
        if ($this->client instanceof \Predis\ClientInterface) {
            // Predis returns a Status "OK" when the key was set and null when NX refused it.
            return $this->client->set($key, '1', 'EX', $ttlSeconds, 'NX') !== null;
        }

        // phpredis and Relay return true when set, false when NX refused it.
        return $this->client->set($key, '1', ['nx', 'ex' => $ttlSeconds]) === true;
    }
}
